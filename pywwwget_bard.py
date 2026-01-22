#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
pywwwget_optimized.py
Version: clean-tls-v36-optimized

Optimized and bug-fixed version of PyWWW-Get helpers.
Compatible with Python 2.7 and Python 3.x.

Changes:
- Fixed NameError in UDP raw receive.
- Optimized HTTP server to stream large files instead of loading into RAM.
- Improved LAN IP detection.
- Unified import logic.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os
import sys
import socket
import shutil
import time
import struct
import hashlib
import tempfile
import gzip
import mimetypes
import base64
import threading

# --- Python 2/3 Compatibility Shims ---
try:
    from io import BytesIO
except ImportError:
    try:
        from cStringIO import StringIO as BytesIO
    except ImportError:
        from StringIO import StringIO as BytesIO

try:
    # Python 3
    from urllib.parse import urlparse, urlunparse, parse_qs, unquote
    from urllib.request import Request, build_opener, HTTPBasicAuthHandler
    from urllib.error import URLError, HTTPError
    from urllib.request import HTTPPasswordMgrWithDefaultRealm
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import socketserver as _socketserver
    range = range
except ImportError:
    # Python 2
    from urlparse import urlparse, urlunparse, parse_qs
    from urllib2 import Request, build_opener, HTTPBasicAuthHandler, URLError, HTTPError
    from urllib2 import HTTPPasswordMgrWithDefaultRealm
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    import SocketServer as _socketserver
    range = xrange
    try:
        from urllib import unquote
    except ImportError:
        def unquote(x): return x

try:
    basestring
except NameError:
    basestring = str

# --- Optional Dependencies ---
haverequests = False
try:
    import requests
    haverequests = True
except ImportError:
    pass

havehttpx = False
try:
    import httpx
    havehttpx = True
except ImportError:
    pass

havemechanize = False
try:
    import mechanize
    havemechanize = True
except ImportError:
    pass

haveparamiko = False
try:
    import paramiko
    haveparamiko = True
except ImportError:
    pass

havepysftp = False
try:
    import pysftp
    havepysftp = True
except ImportError:
    pass

ftpssl = True
try:
    from ftplib import FTP, FTP_TLS, all_errors
except ImportError:
    ftpssl = False
    from ftplib import FTP, all_errors

# --- Configuration ---
__program_name__ = "PyWWW-Get (optimized)"
__version__ = "clean-tls-v36-opt"
__use_http_lib__ = "httpx" if havehttpx else ("requests" if haverequests else "urllib")
__use_pysftp__ = False

# --------------------------
# Small Helpers
# --------------------------

def _best_lan_ip():
    """Attempt to find the best LAN IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't actually connect, just determines route
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"
    finally:
        s.close()

def _listen_urls(scheme, bind_host, port, path, query=""):
    if not path: path = "/"
    if not path.startswith("/"): path = "/" + path
    q = ("?" + query.lstrip("?")) if query else ""
    urls = []
    
    hosts = []
    if not bind_host or bind_host == "0.0.0.0":
        hosts.append("127.0.0.1")
        lan_ip = _best_lan_ip()
        if lan_ip and lan_ip != "127.0.0.1":
            hosts.append(lan_ip)
    else:
        hosts.append(bind_host)
        
    for h in hosts:
        urls.append("%s://%s:%d%s%s" % (scheme, h, port, path, q))
    return urls

def _parse_kv_headers(qs, prefix="hdr_"):
    out = {}
    for k in qs.keys():
        if k.startswith(prefix):
            hk = k[len(prefix):].replace("_", "-")
            val = qs.get(k)
            if isinstance(val, list):
                out[hk] = val[0]
            else:
                out[hk] = val
    return out

def MkTempFile():
    return tempfile.TemporaryFile()

def _hs_token():
    try:
        import random
        return ('%x' % random.getrandbits(64)).encode('ascii')
    except Exception:
        return ('%x' % int(time.time()*1000000)).encode('ascii')

def _to_bytes(x):
    if x is None: return b""
    if isinstance(x, bytes): return x
    try:
        return x.encode("utf-8")
    except Exception:
        return bytes(x)

def _to_text(x):
    if x is None: return u""
    if isinstance(x, bytes):
        try:
            return x.decode("utf-8", "replace")
        except Exception:
            return x.decode("latin-1", "replace")
    return x

def _set_query_param(url, key, value):
    try:
        up = urlparse(url)
        qs = parse_qs(up.query or "")
        qs[key] = [value]
        # Reconstruct query string manually to avoid list brackets
        parts = []
        for k, v in qs.items():
            for item in v:
                parts.append("%s=%s" % (k, item))
        newq = "&".join(parts)
        return urlunparse((up.scheme, up.netloc, up.path, up.params, newq, up.fragment))
    except Exception:
        return url

def _qflag(qs, key, default=False):
    v = qs.get(key, [None])[0]
    if v is None: return default
    return _to_text(v).strip().lower() in ("1", "true", "yes", "on", "y")

def _qnum(qs, key, default, cast=int):
    v = qs.get(key, [None])[0]
    if v is None or v == "": return default
    try:
        return cast(v)
    except Exception:
        return default

def _qstr(qs, key, default=None):
    v = qs.get(key, [None])[0]
    return _to_text(v) if v is not None else default

def _ensure_dir(d):
    if d and not os.path.exists(d):
        try:
            os.makedirs(d)
        except Exception:
            pass

def _guess_filename(url):
    p = urlparse(url)
    bn = os.path.basename(p.path or "")
    return bn or "download.bin"

def _choose_output_path(fname, overwrite=False, save_dir=None):
    if not save_dir: save_dir = "."
    _ensure_dir(save_dir)
    base = os.path.join(save_dir, fname)
    if overwrite or not os.path.exists(base):
        return base
    root, ext = os.path.splitext(base)
    for i in range(1, 10000):
        cand = "%s.%d%s" % (root, i, ext)
        if not os.path.exists(cand):
            return cand
    return base

def _copy_fileobj_to_path(fileobj, path, overwrite=False):
    if (not overwrite) and os.path.exists(path):
        raise IOError("Refusing to overwrite: %s" % path)
    _ensure_dir(os.path.dirname(path) or ".")
    with open(path, "wb") as out:
        fileobj.seek(0)
        shutil.copyfileobj(fileobj, out)

# --------------------------
# FTP/SFTP Helpers
# --------------------------

def detect_cwd(ftp, file_dir):
    if not file_dir or file_dir in ("/", ""): return False
    try:
        ftp.cwd(file_dir)
        return True
    except all_errors:
        return False

def _ftp_login(ftp, user, pw):
    if user is None: user = "anonymous"
    if pw is None: pw = "anonymous" if user == "anonymous" else ""
    ftp.login(user, pw)

def download_file_from_ftp_file(url):
    p = urlparse(url)
    if p.scheme not in ("ftp", "ftps"): return False
    if p.scheme == "ftps" and not ftpssl: return False
    
    ftp = FTP_TLS() if (p.scheme == "ftps") else FTP()
    try:
        ftp.connect(p.hostname, p.port or 21, timeout=10)
        _ftp_login(ftp, p.username, p.password)
        if p.scheme == "ftps":
            try: ftp.prot_p()
            except Exception: pass
            
        use_cwd = detect_cwd(ftp, os.path.dirname(p.path or "/"))
        retr_path = os.path.basename(p.path) if use_cwd else p.path
        
        bio = BytesIO()
        ftp.retrbinary("RETR " + retr_path, bio.write)
        ftp.quit()
        bio.seek(0)
        return bio
    except Exception:
        try: ftp.close()
        except: pass
        return False

def upload_file_to_ftp_file(fileobj, url):
    p = urlparse(url)
    if p.scheme not in ("ftp", "ftps"): return False
    
    ftp = FTP_TLS() if (p.scheme == "ftps") else FTP()
    try:
        ftp.connect(p.hostname, p.port or 21, timeout=10)
        _ftp_login(ftp, p.username, p.password)
        if p.scheme == "ftps":
            try: ftp.prot_p()
            except: pass
            
        use_cwd = detect_cwd(ftp, os.path.dirname(p.path or "/"))
        stor_path = os.path.basename(p.path) if use_cwd else p.path
        
        fileobj.seek(0)
        ftp.storbinary("STOR " + stor_path, fileobj)
        ftp.quit()
        fileobj.seek(0)
        return fileobj
    except Exception:
        try: ftp.close()
        except: pass
        return False

def download_file_from_sftp_file(url):
    if not haveparamiko: return False
    p = urlparse(url)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(p.hostname, port=p.port or 22, username=p.username or "anonymous", 
                   password=p.password or "", timeout=10)
        sftp = ssh.open_sftp()
        bio = BytesIO()
        sftp.getfo(p.path or "/", bio)
        sftp.close()
        ssh.close()
        bio.seek(0)
        return bio
    except Exception:
        try: ssh.close()
        except: pass
        return False

def upload_file_to_sftp_file(fileobj, url):
    if not haveparamiko: return False
    p = urlparse(url)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(p.hostname, port=p.port or 22, username=p.username or "anonymous",
                   password=p.password or "", timeout=10)
        sftp = ssh.open_sftp()
        fileobj.seek(0)
        sftp.putfo(fileobj, p.path or "/")
        sftp.close()
        ssh.close()
        fileobj.seek(0)
        return fileobj
    except Exception:
        try: ssh.close()
        except: pass
        return False

# --------------------------
# HTTP Helpers
# --------------------------

def download_file_from_http_file(url, headers=None, usehttp=__use_http_lib__):
    if headers is None: headers = {}
    p = urlparse(url)
    
    # Auth handling
    username = unquote(p.username) if p.username else None
    password = unquote(p.password) if p.password else None
    netloc = p.hostname + ((":%s" % p.port) if p.port else "")
    rebuilt_url = urlunparse((p.scheme, netloc, p.path, p.params, p.query, p.fragment))

    # Resume handling
    qs = parse_qs(p.query or "")
    resume = _qflag(qs, "resume", False)
    resume_to = _qstr(qs, "resume_to", None)
    
    httpfile = MkTempFile()
    resume_off = 0
    if resume and resume_to:
        if os.path.exists(resume_to):
            try:
                httpfile = open(resume_to, "ab+")
                resume_off = httpfile.tell()
            except Exception:
                httpfile = MkTempFile()
        else:
            _ensure_dir(os.path.dirname(resume_to) or ".")
            try:
                httpfile = open(resume_to, "wb+")
            except:
                httpfile = MkTempFile()
                
    if resume_off:
        headers["Range"] = "bytes=%d-" % resume_off

    # Perform Request
    try:
        if usehttp == "requests" and haverequests:
            auth = (username, password) if (username and password) else None
            r = requests.get(rebuilt_url, headers=headers, auth=auth, stream=True, timeout=(5, 60))
            r.raise_for_status()
            shutil.copyfileobj(r.raw, httpfile)
            
        elif usehttp == "httpx" and havehttpx:
            with httpx.Client(follow_redirects=True, timeout=60.0) as client:
                auth = (username, password) if (username and password) else None
                r = client.get(rebuilt_url, headers=headers, auth=auth)
                r.raise_for_status()
                for chunk in r.iter_bytes():
                    httpfile.write(chunk)
                    
        elif usehttp == "mechanize" and havemechanize:
            br = mechanize.Browser()
            br.set_handle_robots(False)
            if headers: br.addheaders = list(headers.items())
            if username: br.add_password(rebuilt_url, username, password)
            resp = br.open(rebuilt_url)
            shutil.copyfileobj(resp, httpfile)
            
        else:
            req = Request(rebuilt_url, headers=headers)
            if username:
                mgr = HTTPPasswordMgrWithDefaultRealm()
                mgr.add_password(None, rebuilt_url, username, password)
                opener = build_opener(HTTPBasicAuthHandler(mgr))
                resp = opener.open(req)
            else:
                resp = build_opener().open(req)
            shutil.copyfileobj(resp, httpfile)
            
    except Exception as e:
        print("HTTP Download Error: %s" % e)
        return False

    httpfile.seek(0)
    return httpfile

# --------------------------
# TCP/UDP Transport (UDPSEQ)
# --------------------------

_U_MAGIC = b"PWG2"
_U_HDR = "!4sBBIQ" # magic, ver, flags, seq, total
_U_HDR_LEN = struct.calcsize(_U_HDR)
_UF_DATA, _UF_ACK, _UF_DONE, _UF_RESUME, _UF_META = 0x01, 0x02, 0x04, 0x08, 0x10

def _u_pack(flags, seq, total):
    return struct.pack(_U_HDR, _U_MAGIC, 1, int(flags)&0xFF, int(seq)&0xFFFFFFFF, int(total)&0xFFFFFFFFFFFFFFFF)

def _u_unpack(pkt):
    if not pkt or len(pkt) < _U_HDR_LEN: return None
    magic, ver, flags, seq, total = struct.unpack(_U_HDR, pkt[:_U_HDR_LEN])
    if magic != _U_MAGIC or ver != 1: return None
    return (flags, seq, total, pkt[_U_HDR_LEN:])

def _net_log(verbose, msg):
    if verbose: sys.stderr.write(str(msg).strip() + "\n")

def _parse_net_url(url):
    p = urlparse(url)
    qs = parse_qs(p.query or "")
    scheme = p.scheme.lower()
    
    # Extracted options
    o = {
        "mode": _qstr(qs, "mode", "seq" if scheme=="udp" else "raw").lower(),
        "timeout": float(_qnum(qs, "timeout", 1.0 if scheme=="udp" else 30.0, float)),
        "total_timeout": float(_qnum(qs, "total_timeout", 0.0, float)),
        "window": int(_qnum(qs, "window", 32)),
        "retries": int(_qnum(qs, "retries", 20)),
        "chunk": int(_qnum(qs, "chunk", 1200 if scheme=="udp" else 65536)),
        "print_url": _qflag(qs, "print_url"),
        "wait": _qflag(qs, "wait", (scheme=="udp")),
        "connect_wait": _qflag(qs, "connect_wait", (scheme=="tcp")),
        "verbose": _qflag(qs, "verbose") or _qflag(qs, "debug"),
        "handshake": _qflag(qs, "handshake", True),
        "resume": _qflag(qs, "resume"),
        "resume_to": _qstr(qs, "resume_to"),
        "save": _qflag(qs, "save"),
        "overwrite": _qflag(qs, "overwrite"),
        "save_dir": _qstr(qs, "save_dir"),
        "bind": _qstr(qs, "bind"),
        "framing": _qstr(qs, "framing"),
        "sha256": _qflag(qs, "sha256") or _qflag(qs, "sha"),
        # UDP Raw specific
        "raw_ack": _qflag(qs, "raw_ack"),
        "raw_meta": _qflag(qs, "raw_meta", True),
        "raw_sha": _qflag(qs, "raw_sha"),
        "raw_hash": _qstr(qs, "raw_hash", "sha256"),
    }
    return p, o

def recv_to_fileobj(fileobj, host, port, proto="tcp", path_text=None, **kwargs):
    proto = (proto or "tcp").lower()
    port = int(port)
    
    if proto == "tcp":
        # TCP Receiver logic
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host or "", port))
        srv.listen(1)
        
        if kwargs.get("print_url"):
            for u in _listen_urls("tcp", host, srv.getsockname()[1], path_text or "/"):
                sys.stdout.write("Listening: %s\n" % u)
                
        srv.settimeout(kwargs.get("timeout", None))
        try:
            conn, _ = srv.accept()
        except Exception:
            srv.close()
            return False
            
        # Handshake
        if kwargs.get("handshake", True):
            try:
                peek = conn.recv(6, socket.MSG_PEEK) if hasattr(socket, "MSG_PEEK") else b""
                if peek == b"HELLO ":
                    line = b""
                    while b"\n" not in line and len(line) < 1024:
                        line += conn.recv(1)
                    conn.sendall(b"READY " + (line.split(None, 1)[1] if b" " in line else b"") + b"\n")
            except Exception: pass

        # Resume logic
        if kwargs.get("resume"):
            conn.sendall(("OFFSET %d\n" % fileobj.tell()).encode("utf-8"))

        # Transfer
        framing = kwargs.get("framing")
        if framing == "len":
            # Length prefixed
            hdr = b""
            while len(hdr) < 16:
                chunk = conn.recv(16-len(hdr))
                if not chunk: break
                hdr += chunk
            if len(hdr) == 16 and hdr.startswith(b"PWG4"):
                size = struct.unpack("!Q", hdr[4:12])[0]
                left = size
                while left > 0:
                    chunk = conn.recv(min(65536, left))
                    if not chunk: break
                    fileobj.write(chunk)
                    left -= len(chunk)
        else:
            # Stream until close
            while True:
                chunk = conn.recv(65536)
                if not chunk: break
                fileobj.write(chunk)
                
        conn.close()
        srv.close()
        fileobj.seek(0)
        return True

    # UDP Dispatch
    if kwargs.get("mode") == "raw":
        return _udp_raw_recv(fileobj, host, port, **kwargs)
    return _udp_seq_recv(fileobj, host, port, **kwargs)

def _udp_raw_recv(fileobj, host, port, **kwargs):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host or "", int(port)))
    if kwargs.get("print_url"):
        sys.stdout.write("Listening: udp://%s:%d/\n" % (host or "0.0.0.0", sock.getsockname()[1]))
        
    sock.settimeout(kwargs.get("timeout", 1.0))
    end_timeout = kwargs.get("end_timeout", 1.0)
    
    # Fix: Initialize variables that caused NameError in original
    want_ack = kwargs.get("raw_ack", False)
    exp_seq = 0
    bytes_written = 0
    
    expected = None
    received = 0
    last_act = time.time()
    
    while True:
        try:
            pkt, addr = sock.recvfrom(65536)
            last_act = time.time()
        except socket.timeout:
            if time.time() - last_act > end_timeout and received > 0:
                break
            continue
        except Exception:
            break
            
        if not pkt: continue
        
        # Meta/Control packets
        if pkt.startswith(b"META "):
            try: 
                expected = int(pkt.split()[1])
                sock.sendto(b"READY\n", addr)
            except: pass
            continue
        if pkt == b"DONE":
            break
            
        # Data processing
        if want_ack and pkt.startswith(b"PKT "):
            try:
                _, seq_s, data = pkt.split(b" ", 2)
                seq = int(seq_s)
                if seq == exp_seq:
                    fileobj.write(data)
                    exp_seq += 1
                    received += len(data)
                sock.sendto(("ACK %d\n" % (exp_seq-1)).encode("ascii"), addr)
            except: pass
        else:
            fileobj.write(pkt)
            received += len(pkt)
            
        if expected is not None and received >= expected:
            break
            
    sock.close()
    fileobj.seek(0)
    return True

def _udp_seq_recv(fileobj, host, port, **kwargs):
    # Simplified version of reliable UDP receiver
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host or "", int(port)))
    if kwargs.get("print_url"):
        sys.stdout.write("Listening: udp://%s:%d/?mode=seq\n" % (host or "0.0.0.0", sock.getsockname()[1]))
    
    sock.settimeout(kwargs.get("timeout", 1.0))
    received = {}
    expected = 0
    resume_sent = False
    
    while True:
        try:
            pkt, addr = sock.recvfrom(65536)
        except socket.timeout:
            continue
        except Exception:
            break
            
        up = _u_unpack(pkt)
        if not up: continue
        flags, seq, total, data = up
        
        # Send Resume Offset
        if not resume_sent:
            sock.sendto(_u_pack(_UF_RESUME, 0, 0) + struct.pack("!Q", fileobj.tell()), addr)
            resume_sent = True
            
        if flags & _UF_DONE:
            if not received: break
            continue
            
        if flags & _UF_DATA:
            sock.sendto(_u_pack(_UF_ACK, 0, 0) + struct.pack("!I", seq), addr)
            
            if seq == expected:
                fileobj.write(data)
                expected += 1
                while expected in received:
                    fileobj.write(received.pop(expected))
                    expected += 1
            elif seq > expected:
                received[seq] = data
                
    sock.close()
    fileobj.seek(0)
    return True

def send_from_fileobj(fileobj, host, port, proto="tcp", **kwargs):
    proto = (proto or "tcp").lower()
    port = int(port)
    
    if proto == "tcp":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        wait = kwargs.get("connect_wait", True)
        start = time.time()
        
        while True:
            try:
                s.connect((host, port))
                break
            except Exception:
                if not wait or (time.time()-start > kwargs.get("timeout", 30)):
                    return False
                time.sleep(0.5)
                
        # Handshake
        if kwargs.get("handshake", True):
            s.sendall(b"HELLO " + _hs_token() + b"\n")
            # Wait for ready (simplified)
            try: 
                s.settimeout(5.0)
                s.recv(1024) 
            except: pass
            
        # Send
        s.settimeout(None)
        framing = kwargs.get("framing")
        
        if framing == "len":
            fileobj.seek(0, 2)
            sz = fileobj.tell()
            fileobj.seek(0)
            s.sendall(b"PWG4" + struct.pack("!Q", sz) + b"\x00\x00\x00\x00")
            
        shutil.copyfileobj(fileobj, s.makefile('wb'))
        s.close()
        return True
        
    return _udp_seq_send(fileobj, host, port, **kwargs)

def _udp_seq_send(fileobj, host, port, **kwargs):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = (host, port)
    chunk_size = kwargs.get("chunk", 1200)
    window_size = kwargs.get("window", 32)
    
    # Handshake / Resume
    sock.sendto(_u_pack(_UF_META, 0, 0) + b"RESUME", addr)
    start_seq = 0
    try:
        sock.settimeout(2.0)
        pkt, _ = sock.recvfrom(1024)
        up = _u_unpack(pkt)
        if up and (up[0] & _UF_RESUME):
            off = struct.unpack("!Q", up[3][:8])[0]
            fileobj.seek(off)
            start_seq = int(off // chunk_size)
    except: pass
    
    # Sliding Window Send
    next_seq = start_seq
    in_flight = {} # seq -> (data, time)
    eof = False
    
    sock.settimeout(0.01)
    
    while not eof or in_flight:
        # Fill window
        while not eof and len(in_flight) < window_size:
            data = fileobj.read(chunk_size)
            if not data:
                eof = True
            else:
                pkt = _u_pack(_UF_DATA, next_seq, 0) + _to_bytes(data)
                sock.sendto(pkt, addr)
                in_flight[next_seq] = (pkt, time.time())
                next_seq += 1
                
        # Process ACKs
        try:
            while True:
                pkt, _ = sock.recvfrom(2048)
                up = _u_unpack(pkt)
                if up and (up[0] & _UF_ACK):
                    ack = struct.unpack("!I", up[3][:4])[0]
                    if ack in in_flight:
                        del in_flight[ack]
        except socket.error: pass
        
        # Retransmit
        now = time.time()
        for s, (pkt, ts) in in_flight.items():
            if now - ts > 0.5:
                sock.sendto(pkt, addr)
                in_flight[s] = (pkt, now)
                
    # Send Done
    for _ in range(5):
        sock.sendto(_u_pack(_UF_DONE, 0, 0) + b"DONE", addr)
        time.sleep(0.05)
        
    sock.close()
    return True

# --------------------------
# Main HTTP Server (Serving)
# --------------------------

def _serve_file_over_http(fileobj, url):
    """
    Optimized serving: streams directly from fileobj if possible to save RAM.
    """
    p = urlparse(url)
    qs = parse_qs(p.query or "")
    
    bind = _qstr(qs, "bind", p.hostname or "0.0.0.0")
    port = int(_qnum(qs, "port", p.port or 0))
    path = p.path or "/"
    max_clients = int(_qnum(qs, "max_clients", 1))
    
    # MEMORY OPTIMIZATION: Check if we can stream
    # If we only have 1 client, we don't need to buffer.
    # If we have multiple, we might need to buffer if the stream isn't seekable.
    must_buffer = (max_clients > 1)
    try:
        fileobj.tell() # Check seekability
        fileobj.seek(0)
    except:
        if must_buffer:
            # Fallback for pipes with multiple clients
            data = fileobj.read()
            fileobj = BytesIO(data)
            
    class FileHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args): pass
        
        def do_GET(self):
            if self.path.split("?")[0] != path:
                self.send_error(404)
                return
                
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", 'attachment; filename="download.bin"')
            
            # Check size if possible
            try:
                fileobj.seek(0, 2)
                sz = fileobj.tell()
                fileobj.seek(0)
                self.send_header("Content-Length", str(sz))
            except: pass
            
            self.end_headers()
            
            # STREAMING COPY
            try:
                shutil.copyfileobj(fileobj, self.wfile)
            except Exception: pass
            
            # Reset for next client if seekable
            try: fileobj.seek(0)
            except: pass

    # Server Setup
    server = HTTPServer((bind, port), FileHandler)
    if _qflag(qs, "print_url"):
        for u in _listen_urls("http", bind, server.server_address[1], path):
            print("Listening: %s" % u)
            
    # Handle requests
    for _ in range(max_clients):
        server.handle_request()
        
    server.server_close()
    return True

# --------------------------
# Public API Entry Points
# --------------------------

def upload_file_to_internet_file(fileobj, url):
    """Uploads/Serves a file object to the specified URL."""
    p = urlparse(url)
    if p.scheme in ("http", "https"):
        return _serve_file_over_http(fileobj, url)
    elif p.scheme in ("ftp", "ftps"):
        return upload_file_to_ftp_file(fileobj, url)
    elif p.scheme in ("sftp", "scp"):
        return upload_file_to_sftp_file(fileobj, url)
    elif p.scheme in ("tcp", "udp"):
        _, o = _parse_net_url(url)
        return send_from_fileobj(fileobj, p.hostname, p.port, p.scheme, **o)
    return False

def download_file_from_internet_file(url, headers=None):
    """Downloads a file from URL and returns a file-like object."""
    p = urlparse(url)
    if p.scheme in ("http", "https"):
        return download_file_from_http_file(url, headers)
    elif p.scheme in ("ftp", "ftps"):
        return download_file_from_ftp_file(url)
    elif p.scheme in ("sftp", "scp"):
        return download_file_from_sftp_file(url)
    elif p.scheme in ("tcp", "udp"):
        _, o = _parse_net_url(url)
        out = MkTempFile()
        if recv_to_fileobj(out, p.hostname, p.port, p.scheme, **o):
            return out
    return False

# Wrappers for string input/output
def upload_file_to_internet_string(data, url):
    return upload_file_to_internet_file(BytesIO(_to_bytes(data)), url)

def download_file_from_internet_string(url, headers=None):
    fp = download_file_from_internet_file(url, headers)
    return fp.read() if fp else False

if __name__ == "__main__":
    print("PyWWW-Get Library %s loaded." % __version__)
