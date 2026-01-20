#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
pywwwgetadv_clean.py

A small, self-contained subset of PyWWW-Get style helpers that keeps the same
public API shape you were using:

- download_file_from_internet_file(url, headers=..., usehttp=...)
- download_file_from_internet_string(url, headers=..., usehttp=...)
- upload_file_to_internet_file(fileobj, url)
- upload_file_to_internet_string(bytestr, url)

Plus protocol-specific helpers (http/ftp/ftps/sftp/tcp/udp) and detect_cwd().

Design goals:
- Python 2.7 + Python 3.x compatible
- Minimal dependencies (stdlib first; requests/httpx/mechanize/paramiko/pysftp optional)
- TCP: stream + explicit end (FIN)
- UDP: reliable "udpseq" mode with explicit DONE frame (no silence wait), plus resume support
- Same "file-like object returned" behavior: caller can .read() and write it elsewhere.

URL formats (examples):
  HTTP:
    http://example.com/file
    http://user:pass@example.com/file

  FTP/FTPS:
    ftp://user:pass@host:21/path/to/file
    ftps://user:pass@host:990/path/to/file

  SFTP:
    sftp://user:pass@host:22/path/to/file

  TCP receive (download):
    tcp://0.0.0.0:7000/test.png?print_url=1&bind=0.0.0.0
    tcp://0.0.0.0:0/test.png?print_url=1     (port=0 => auto-pick)

  TCP send (upload):
    tcp://host:7000/test.png

  UDPSEQ receive (download, reliable UDP):
    udp://0.0.0.0:7000/test.png?mode=seq&print_url=1
    udp://0.0.0.0:0/test.png?mode=seq&print_url=1

  UDPSEQ resume (receiver resumes into a file on disk):
    udp://0.0.0.0:7000/test.png?mode=seq&resume=1&resume_to=/sdcard/Download/test.png&print_url=1

  UDPSEQ send:
    udp://host:7000/test.png?mode=seq&resume=1   (sender will ask receiver for offset)

Notes:
- For HTTP resume, use ?resume=1&resume_to=/path to append using Range header.
- For FTP/FTPS, see detect_cwd() (cwd fallback to absolute RETR paths).
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os
import sys
import socket
import shutil
import time
import struct
import tempfile

try:
    from io import BytesIO
except ImportError:
    try:
        from cStringIO import StringIO as BytesIO  # py2 fallback
    except Exception:
        from StringIO import StringIO as BytesIO

try:
    from urllib.parse import urlparse, urlunparse, parse_qs, unquote
    from urllib.request import Request, build_opener, HTTPBasicAuthHandler
    from urllib.error import URLError, HTTPError
    from urllib.request import HTTPPasswordMgrWithDefaultRealm
except Exception:
    from urlparse import urlparse, urlunparse, parse_qs  # type: ignore
    from urllib2 import Request, build_opener, HTTPBasicAuthHandler, URLError, HTTPError  # type: ignore
    from urllib2 import HTTPPasswordMgrWithDefaultRealm  # type: ignore
    try:
        from urllib import unquote  # py2
    except Exception:
        def unquote(x):  # very small fallback
            return x

# Optional deps
haverequests = False
try:
    import requests  # noqa
    haverequests = True
except Exception:
    pass

havehttpx = False
try:
    import httpx  # noqa
    havehttpx = True
except Exception:
    pass

havemechanize = False
try:
    import mechanize  # noqa
    havemechanize = True
except Exception:
    pass

haveparamiko = False
try:
    import paramiko  # noqa
    haveparamiko = True
except Exception:
    pass

havepysftp = False
try:
    import pysftp  # noqa
    havepysftp = True
except Exception:
    pass

# FTP
ftpssl = True
try:
    from ftplib import FTP, FTP_TLS, all_errors
except Exception:
    ftpssl = False
    from ftplib import FTP, all_errors  # type: ignore

try:
    basestring
except NameError:
    basestring = str


__program_name__ = "PyWWW-Get (clean)"
__project__ = __program_name__
__project_url__ = "https://github.com/GameMaker2k/PyWWW-Get"
__version__ = "clean-1.0"

__use_http_lib__ = "httpx" if havehttpx else ("requests" if haverequests else "urllib")
__use_pysftp__ = False  # can toggle

# --------------------------
# Small helpers
# --------------------------

def MkTempFile():
    # NamedTemporaryFile behaves differently on Windows; this keeps a file-like object.
    return tempfile.TemporaryFile()

def _to_bytes(x):
    if x is None:
        return b""
    if isinstance(x, bytes):
        return x
    try:
        return x.encode("utf-8")
    except Exception:
        return bytes(x)

def _to_text(x):
    if x is None:
        return u""
    if isinstance(x, bytes):
        try:
            return x.decode("utf-8", "replace")
        except Exception:
            return x.decode("latin-1", "replace")
    return x

def _qflag(qs, key, default=False):
    v = qs.get(key, [None])[0]
    if v is None:
        return default
    v = _to_text(v).strip().lower()
    return v in ("1", "true", "yes", "on", "y")

def _qnum(qs, key, default, cast=int):
    v = qs.get(key, [None])[0]
    if v is None or v == "":
        return default
    try:
        return cast(v)
    except Exception:
        try:
            return cast(_to_text(v))
        except Exception:
            return default

def _qstr(qs, key, default=None):
    v = qs.get(key, [None])[0]
    if v is None:
        return default
    return _to_text(v)

def _ensure_dir(d):
    if not d:
        return
    if not os.path.isdir(d):
        try:
            os.makedirs(d)
        except Exception:
            pass

def _guess_filename(url):
    p = urlparse(url)
    bn = os.path.basename(p.path or "")
    return bn or "download.bin"

def _choose_output_path(fname, overwrite=False, save_dir=None):
    if not save_dir:
        save_dir = "."
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
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        shutil.copyfileobj(fileobj, out)

# --------------------------
# FTP helpers
# --------------------------

def detect_cwd(ftp, file_dir):
    """
    Test whether cwd into file_dir works. Returns True if it does,
    False if not (so absolute paths should be used).
    """
    if not file_dir or file_dir in ("/", ""):
        return False  # nothing to cwd into
    try:
        ftp.cwd(file_dir)
        return True
    except all_errors:
        return False

def _ftp_login(ftp, user, pw):
    # ftplib wants empty string for anonymous password sometimes; keep consistent
    if user is None:
        user = "anonymous"
    if pw is None:
        pw = "anonymous" if user == "anonymous" else ""
    ftp.login(user, pw)

def download_file_from_ftp_file(url):
    p = urlparse(url)
    if p.scheme not in ("ftp", "ftps"):
        return False
    if p.scheme == "ftps" and not ftpssl:
        return False

    host = p.hostname
    port = p.port or 21
    user = p.username
    pw = p.password
    path = p.path or "/"
    file_dir = os.path.dirname(path)

    ftp = FTP_TLS() if (p.scheme == "ftps") else FTP()
    try:
        ftp.connect(host, port, timeout=10)
        _ftp_login(ftp, user, pw)
        if p.scheme == "ftps":
            try:
                ftp.prot_p()
            except Exception:
                pass

        # Try cwd into directory; if it works, RETR just basename.
        use_cwd = detect_cwd(ftp, file_dir)
        retr_path = os.path.basename(path) if use_cwd else path

        bio = BytesIO()
        ftp.retrbinary("RETR " + retr_path, bio.write)
        ftp.quit()
        bio.seek(0, 0)
        return bio
    except Exception:
        try:
            ftp.close()
        except Exception:
            pass
        return False

def download_file_from_ftp_string(url):
    fp = download_file_from_ftp_file(url)
    return fp.read() if fp else False

def upload_file_to_ftp_file(fileobj, url):
    p = urlparse(url)
    if p.scheme not in ("ftp", "ftps"):
        return False
    if p.scheme == "ftps" and not ftpssl:
        return False

    host = p.hostname
    port = p.port or 21
    user = p.username
    pw = p.password
    path = p.path or "/"
    file_dir = os.path.dirname(path)
    fname = os.path.basename(path) or "upload.bin"

    ftp = FTP_TLS() if (p.scheme == "ftps") else FTP()
    try:
        ftp.connect(host, port, timeout=10)
        _ftp_login(ftp, user, pw)
        if p.scheme == "ftps":
            try:
                ftp.prot_p()
            except Exception:
                pass

        use_cwd = detect_cwd(ftp, file_dir)
        stor_path = fname if use_cwd else path

        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        ftp.storbinary("STOR " + stor_path, fileobj)
        ftp.quit()
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        return fileobj
    except Exception:
        try:
            ftp.close()
        except Exception:
            pass
        return False

def upload_file_to_ftp_string(data, url):
    bio = BytesIO(_to_bytes(data))
    out = upload_file_to_ftp_file(bio, url)
    try:
        bio.close()
    except Exception:
        pass
    return out

# --------------------------
# SFTP helpers
# --------------------------

def download_file_from_sftp_file(url):
    if not haveparamiko:
        return False
    p = urlparse(url)
    if p.scheme not in ("sftp", "scp"):
        return False
    host = p.hostname
    port = p.port or 22
    user = p.username or "anonymous"
    pw = p.password or ("anonymous" if user == "anonymous" else "")
    path = p.path or "/"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=port, username=user, password=pw, timeout=10)
        sftp = ssh.open_sftp()
        bio = BytesIO()
        sftp.getfo(path, bio)
        sftp.close()
        ssh.close()
        bio.seek(0, 0)
        return bio
    except Exception:
        try:
            ssh.close()
        except Exception:
            pass
        return False

def download_file_from_sftp_string(url):
    fp = download_file_from_sftp_file(url)
    return fp.read() if fp else False

def upload_file_to_sftp_file(fileobj, url):
    if not haveparamiko:
        return False
    p = urlparse(url)
    if p.scheme not in ("sftp", "scp"):
        return False
    host = p.hostname
    port = p.port or 22
    user = p.username or "anonymous"
    pw = p.password or ("anonymous" if user == "anonymous" else "")
    path = p.path or "/"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=port, username=user, password=pw, timeout=10)
        sftp = ssh.open_sftp()
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        sftp.putfo(fileobj, path)
        sftp.close()
        ssh.close()
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        return fileobj
    except Exception:
        try:
            ssh.close()
        except Exception:
            pass
        return False

def upload_file_to_sftp_string(data, url):
    bio = BytesIO(_to_bytes(data))
    out = upload_file_to_sftp_file(bio, url)
    try:
        bio.close()
    except Exception:
        pass
    return out

# Optional pysftp shims (kept for compatibility)
def download_file_from_pysftp_file(url):
    if not havepysftp:
        return False
    # pysftp is a thin wrapper over paramiko; keep behavior similar by delegating.
    return download_file_from_sftp_file(url)

def download_file_from_pysftp_string(url):
    fp = download_file_from_pysftp_file(url)
    return fp.read() if fp else False

def upload_file_to_pysftp_file(fileobj, url):
    if not havepysftp:
        return False
    return upload_file_to_sftp_file(fileobj, url)

def upload_file_to_pysftp_string(data, url):
    if not havepysftp:
        return False
    return upload_file_to_sftp_string(data, url)

# --------------------------
# HTTP helpers (download only)
# --------------------------

def download_file_from_http_file(url, headers=None, usehttp=__use_http_lib__):
    if headers is None:
        headers = {}
    p = urlparse(url)
    username = unquote(p.username) if p.username else None
    password = unquote(p.password) if p.password else None

    # Strip auth from URL
    netloc = p.hostname or ""
    if p.port:
        netloc += ":" + str(p.port)
    rebuilt_url = urlunparse((p.scheme, netloc, p.path, p.params, p.query, p.fragment))

    # HTTP resume: ?resume=1&resume_to=/path
    qs = parse_qs(p.query or "")
    resume = _qflag(qs, "resume", False)
    resume_to = _qstr(qs, "resume_to", None)
    httpfile = MkTempFile()
    resume_off = 0
    if resume and resume_to:
        try:
            if os.path.exists(resume_to):
                httpfile = open(resume_to, "ab+")
                httpfile.seek(0, 2)
                resume_off = int(httpfile.tell())
            else:
                _ensure_dir(os.path.dirname(resume_to) or ".")
                httpfile = open(resume_to, "wb+")
                resume_off = 0
        except Exception:
            httpfile = MkTempFile()
            resume_off = 0
    if resume_off and "Range" not in headers and "range" not in headers:
        headers["Range"] = "bytes=%d-" % resume_off

    # Requests
    if usehttp == "requests" and haverequests:
        auth = (username, password) if (username and password) else None
        r = requests.get(rebuilt_url, headers=headers, auth=auth, stream=True, timeout=(5, 60))
        r.raise_for_status()
        shutil.copyfileobj(r.raw, httpfile)

    # HTTPX
    elif usehttp == "httpx" and havehttpx:
        with httpx.Client(follow_redirects=True, timeout=60.0) as client:
            auth = (username, password) if (username and password) else None
            r = client.get(rebuilt_url, headers=headers, auth=auth)
            r.raise_for_status()
            for chunk in r.iter_bytes():
                if chunk:
                    httpfile.write(chunk)

    # Mechanize
    elif usehttp == "mechanize" and havemechanize:
        br = mechanize.Browser()
        br.set_handle_robots(False)
        if headers:
            br.addheaders = list(headers.items())
        if username and password:
            br.add_password(rebuilt_url, username, password)
        resp = br.open(rebuilt_url)
        shutil.copyfileobj(resp, httpfile)

    # urllib fallback
    else:
        req = Request(rebuilt_url, headers=headers)
        if username and password:
            mgr = HTTPPasswordMgrWithDefaultRealm()
            mgr.add_password(None, rebuilt_url, username, password)
            opener = build_opener(HTTPBasicAuthHandler(mgr))
        else:
            opener = build_opener()
        resp = opener.open(req)
        shutil.copyfileobj(resp, httpfile)

    try:
        httpfile.seek(0, 0)
    except Exception:
        pass
    return httpfile

def download_file_from_http_string(url, headers=None, usehttp=__use_http_lib__):
    fp = download_file_from_http_file(url, headers=headers, usehttp=usehttp)
    return fp.read() if fp else False

# --------------------------
# TCP/UDP transport (receiver + sender)
# --------------------------

# UDPSEQ protocol (simple, robust, explicit DONE, supports resume)
_U_MAGIC = b"PWG2"         # 4
_U_VER = 1                 # 1 byte
_U_HDR = "!4sBBIQ"         # magic, ver, flags, seq(u32), total(u64)
_U_HDR_LEN = struct.calcsize(_U_HDR)

_UF_DATA   = 0x01
_UF_ACK    = 0x02
_UF_DONE   = 0x04
_UF_RESUME = 0x08
_UF_META   = 0x10

def _u_pack(flags, seq, total):
    return struct.pack(_U_HDR, _U_MAGIC, _U_VER, int(flags) & 0xFF, int(seq) & 0xFFFFFFFF, int(total) & 0xFFFFFFFFFFFFFFFF)

def _u_unpack(pkt):
    if not pkt or len(pkt) < _U_HDR_LEN:
        return None
    magic, ver, flags, seq, total = struct.unpack(_U_HDR, pkt[:_U_HDR_LEN])
    if magic != _U_MAGIC or ver != _U_VER:
        return None
    return (flags, seq, total, pkt[_U_HDR_LEN:])

def _parse_net_url(url):
    p = urlparse(url)
    qs = parse_qs(p.query or "")
    mode = _qstr(qs, "mode", "seq" if p.scheme == "udp" else "raw").lower()
    timeout = float(_qnum(qs, "timeout", 1.0, cast=float))
    total_timeout = float(_qnum(qs, "total_timeout", 0.0, cast=float))
    window = int(_qnum(qs, "window", 32, cast=int))
    retries = int(_qnum(qs, "retries", 20, cast=int))
    chunk = int(_qnum(qs, "chunk", 1200 if p.scheme == "udp" else 65536, cast=int))
    print_url = _qflag(qs, "print_url", False)
    bind = _qstr(qs, "bind", None)
    resume = _qflag(qs, "resume", False)
    resume_to = _qstr(qs, "resume_to", None)
    save = _qflag(qs, "save", False)
    overwrite = _qflag(qs, "overwrite", False)
    save_dir = _qstr(qs, "save_dir", None)

    return p, {
        "mode": mode,
        "timeout": timeout,
        "total_timeout": total_timeout,
        "window": window,
        "retries": retries,
        "chunk": chunk,
        "print_url": print_url,
        "bind": bind,
        "resume": resume,
        "resume_to": resume_to,
        "save": save,
        "overwrite": overwrite,
        "save_dir": save_dir,
    }

def recv_to_fileobj(fileobj, host, port, proto="tcp", path_text=None, **kwargs):
    """
    Receive bytes into fileobj.
    - TCP: accept one connection, optionally consume a PATH line, optionally emit OFFSET for resume, then stream until FIN.
    - UDP raw: receive until DONE frame (best effort).
    - UDP seq: reliable with ACK/DONE, explicit RESUME handshake.
    """
    proto = (proto or "tcp").lower()
    port = int(port)

    if proto == "tcp":
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception:
            pass
        srv.bind((host or "", port))
        srv.listen(1)
        # If port=0, reveal chosen port
        chosen_port = srv.getsockname()[1]
        if kwargs.get("print_url"):
            path = path_text or "/"
            sys.stdout.write("Listening: tcp://%s:%d%s\n" % (host or "0.0.0.0", chosen_port, path))
            sys.stdout.flush()

        srv.settimeout(float(kwargs.get("timeout", 30.0)))
        try:
            conn, _ = srv.accept()
        except Exception:
            try:
                srv.close()
            except Exception:
                pass
            return False

        # PATH preface (optional)
        try:
            conn.settimeout(float(kwargs.get("timeout", 30.0)))
        except Exception:
            pass
        try:
            peek = conn.recv(5)
            buf = peek
            if buf.startswith(b"PATH "):
                while b"\n" not in buf and len(buf) < 4096:
                    more = conn.recv(4096)
                    if not more:
                        break
                    buf += more
                # discard PATH line; any extra bytes after newline belong to payload
                if b"\n" in buf:
                    _, rest = buf.split(b"\n", 1)
                else:
                    rest = b""
            else:
                rest = buf
        except Exception:
            rest = b""

        # Resume: if caller opened file in r+b and seeked to end, send OFFSET
        resume_off = 0
        try:
            resume_off = int(kwargs.get("resume_offset", 0) or 0)
        except Exception:
            resume_off = 0
        if resume_off > 0:
            try:
                conn.sendall(b"OFFSET %d\n" % resume_off)
            except Exception:
                pass

        # write any leftover bytes
        if rest:
            fileobj.write(rest)

        # payload loop
        while True:
            try:
                chunk = conn.recv(65536)
            except Exception:
                break
            if not chunk:
                break
            fileobj.write(chunk)

        try:
            conn.close()
        except Exception:
            pass
        try:
            srv.close()
        except Exception:
            pass
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        return True

    # UDP modes
    mode = (kwargs.get("mode") or "seq").lower()
    if mode == "raw":
        return _udp_raw_recv(fileobj, host, port, **kwargs)
    return _udp_seq_recv(fileobj, host, port, **kwargs)

def send_from_fileobj(fileobj, host, port, proto="tcp", path_text=None, resume=False, **kwargs):
    proto = (proto or "tcp").lower()
    port = int(port)

    if proto == "tcp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(float(kwargs.get("timeout", 30.0)))
        sock.connect((host, port))

        # PATH preface
        if path_text:
            line = b"PATH " + _to_bytes(path_text).lstrip(b"/") + b"\n"
            sock.sendall(line)

        # Resume probe: read optional OFFSET line
        if resume:
            try:
                sock.settimeout(0.5)
                buf = b""
                while b"\n" not in buf and len(buf) < 64:
                    data = sock.recv(64)
                    if not data:
                        break
                    buf += data
                if buf.startswith(b"OFFSET "):
                    off = int(buf.split(None, 1)[1].strip().split(b"\n")[0])
                    if off > 0:
                        try:
                            fileobj.seek(off, os.SEEK_SET)
                        except Exception:
                            pass
            except Exception:
                pass
            finally:
                try:
                    sock.settimeout(float(kwargs.get("timeout", 30.0)))
                except Exception:
                    pass

        # stream send
        try:
            while True:
                data = fileobj.read(65536)
                if not data:
                    break
                sock.sendall(_to_bytes(data))
        finally:
            try:
                sock.shutdown(socket.SHUT_WR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
        return True

    # UDP
    mode = (kwargs.get("mode") or "seq").lower()
    if mode == "raw":
        return _udp_raw_send(fileobj, host, port, **kwargs)
    return _udp_seq_send(fileobj, host, port, resume=resume, path_text=path_text, **kwargs)

def _udp_raw_send(fileobj, host, port, **kwargs):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(float(kwargs.get("timeout", 1.0)))
    except Exception:
        pass
    addr = (host, int(port))
    # naive: send chunks then DONE
    chunk = int(kwargs.get("chunk", 1200))
    while True:
        data = fileobj.read(chunk)
        if not data:
            break
        sock.sendto(_to_bytes(data), addr)
    sock.sendto(b"DONE", addr)
    try:
        sock.close()
    except Exception:
        pass
    return True

def _udp_raw_recv(fileobj, host, port, **kwargs):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host or "", int(port)))
    if kwargs.get("print_url"):
        sys.stdout.write("Listening: udp://%s:%d/\n" % (host or "0.0.0.0", sock.getsockname()[1]))
        sys.stdout.flush()
    sock.settimeout(float(kwargs.get("timeout", 1.0)))
    end_timeout = float(kwargs.get("end_timeout", 0.25))
    last = time.time()
    while True:
        try:
            pkt, _ = sock.recvfrom(65536)
            if pkt == b"DONE":
                break
            fileobj.write(pkt)
            last = time.time()
        except socket.timeout:
            if (time.time() - last) >= end_timeout:
                break
    try:
        sock.close()
    except Exception:
        pass
    try:
        fileobj.seek(0, 0)
    except Exception:
        pass
    return True

def _udp_seq_send(fileobj, host, port, resume=False, path_text=None, **kwargs):
    addr = (host, int(port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(float(kwargs.get("timeout", 1.0)))

    chunk = int(kwargs.get("chunk", 1200))
    window = int(kwargs.get("window", 32))
    retries = int(kwargs.get("retries", 20))
    total_timeout = float(kwargs.get("total_timeout", 0.0))

    # discover total length if possible
    total = 0
    start_pos = None
    try:
        start_pos = fileobj.tell()
        fileobj.seek(0, os.SEEK_END)
        total = int(fileobj.tell())
        fileobj.seek(start_pos, os.SEEK_SET)
    except Exception:
        total = 0
        start_pos = None

    # Resume handshake: ask receiver for offset
    start_seq = 0
    if resume:
        sock.sendto(_u_pack(_UF_META, 0xFFFFFFFF, total) + b"RESUME", addr)
        t0 = time.time()
        while True:
            if total_timeout and (time.time() - t0) > total_timeout:
                break
            try:
                pkt, _peer = sock.recvfrom(2048)
            except Exception:
                break
            up = _u_unpack(pkt)
            if not up:
                continue
            flags, seq, _t, payload = up
            if flags & _UF_RESUME and len(payload) >= 8:
                off = struct.unpack("!Q", payload[:8])[0]
                try:
                    fileobj.seek(int(off), os.SEEK_SET)
                    start_seq = int(off // chunk)
                except Exception:
                    start_seq = 0
                break

    next_seq = start_seq
    in_flight = {}  # seq -> (data, ts, tries)
    base = next_seq
    t_start = time.time()

    def _send_pkt(seq, data):
        sock.sendto(_u_pack(_UF_DATA, seq, total) + data, addr)

    # Prime window
    eof = False
    while not eof and len(in_flight) < window:
        data = fileobj.read(chunk)
        if not data:
            eof = True
            break
        data = _to_bytes(data)
        _send_pkt(next_seq, data)
        in_flight[next_seq] = (data, time.time(), 0)
        next_seq += 1

    while in_flight or not eof:
        if total_timeout and (time.time() - t_start) > total_timeout:
            break

        # receive ACKs
        try:
            pkt, _peer = sock.recvfrom(2048)
            up = _u_unpack(pkt)
            if up:
                flags, seq, _t, payload = up
                if flags & _UF_ACK:
                    # payload: acked seq (u32)
                    if len(payload) >= 4:
                        ack_seq = struct.unpack("!I", payload[:4])[0]
                        if ack_seq in in_flight:
                            del in_flight[ack_seq]
        except socket.timeout:
            pass
        except Exception:
            pass

        # retransmit
        now = time.time()
        for seq in list(in_flight.keys()):
            data, ts, tries = in_flight[seq]
            if (now - ts) >= float(kwargs.get("timeout", 1.0)):
                if tries >= retries:
                    del in_flight[seq]
                    continue
                _send_pkt(seq, data)
                in_flight[seq] = (data, now, tries + 1)

        # fill window
        while not eof and len(in_flight) < window:
            data = fileobj.read(chunk)
            if not data:
                eof = True
                break
            data = _to_bytes(data)
            _send_pkt(next_seq, data)
            in_flight[next_seq] = (data, time.time(), 0)
            next_seq += 1

    # DONE (explicit end marker)
    for _i in range(3):
        sock.sendto(_u_pack(_UF_DONE, 0xFFFFFFFE, total) + b"DONE", addr)
        time.sleep(0.02)

    try:
        sock.close()
    except Exception:
        pass
    return True

def _udp_seq_recv(fileobj, host, port, **kwargs):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host or "", int(port)))
    chosen_port = sock.getsockname()[1]
    if kwargs.get("print_url"):
        sys.stdout.write("Listening: udp://%s:%d/\n" % (host or "0.0.0.0", chosen_port))
        sys.stdout.flush()
    sock.settimeout(float(kwargs.get("timeout", 1.0)))

    chunk = int(kwargs.get("chunk", 1200))
    window = int(kwargs.get("window", 32))
    total_timeout = float(kwargs.get("total_timeout", 0.0))

    # resume offset
    resume_off = 0
    try:
        resume_off = int(kwargs.get("resume_offset", 0) or 0)
    except Exception:
        resume_off = 0
    expected = int(resume_off // chunk)

    received = {}
    done = False
    peer = None
    t0 = time.time()

    def _ack(addr, seq):
        sock.sendto(_u_pack(_UF_ACK, 0, 0) + struct.pack("!I", int(seq) & 0xFFFFFFFF), addr)

    # Immediately allow sender to know our offset (TCP-like "FIN" equivalent for resume negotiation)
    resume_sent = False

    while True:
        if total_timeout and (time.time() - t0) > total_timeout:
            break
        try:
            pkt, addr = sock.recvfrom(65536)
        except socket.timeout:
            if done and not received:
                break
            continue
        except Exception:
            break

        peer = addr

        up = _u_unpack(pkt)
        if not up:
            continue
        flags, seq, total, payload = up

        if not resume_sent:
            try:
                sock.sendto(_u_pack(_UF_RESUME, 0xFFFFFFFE, 0) + struct.pack("!Q", int(resume_off)), addr)
            except Exception:
                pass
            resume_sent = True

        if flags & _UF_META:
            # "RESUME" ping, respond again
            try:
                sock.sendto(_u_pack(_UF_RESUME, 0xFFFFFFFE, 0) + struct.pack("!Q", int(resume_off)), addr)
            except Exception:
                pass
            continue

        if flags & _UF_DONE:
            done = True
            # If nothing buffered, we can finish immediately
            if not received:
                break
            continue

        if not (flags & _UF_DATA):
            continue

        # ACK every data packet (even duplicates)
        _ack(addr, seq)

        if seq < expected:
            continue  # already have these bytes (resume or duplicates)
        if seq >= expected + window * 8:
            continue  # too far ahead; ignore

        if seq == expected:
            fileobj.write(payload)
            expected += 1
            # flush contiguous buffered
            while expected in received:
                fileobj.write(received.pop(expected))
                expected += 1
        else:
            if seq not in received:
                received[seq] = payload

        if done and not received:
            break

    try:
        sock.close()
    except Exception:
        pass
    try:
        fileobj.seek(0, 0)
    except Exception:
        pass
    return True

# --------------------------
# Public "internet" API
# --------------------------

def download_file_from_internet_file(url, headers=None, usehttp=__use_http_lib__):
    p = urlparse(url)
    if p.scheme in ("http", "https"):
        return download_file_from_http_file(url, headers=headers or {}, usehttp=usehttp)
    if p.scheme in ("ftp", "ftps"):
        return download_file_from_ftp_file(url)
    if p.scheme in ("sftp", "scp"):
        if __use_pysftp__ and havepysftp:
            return download_file_from_pysftp_file(url)
        return download_file_from_sftp_file(url)

    if p.scheme in ("tcp", "udp"):
        parts, o = _parse_net_url(url)
        host = o.get("bind") or parts.hostname or ""
        port = parts.port or 0
        path_text = parts.path or "/"

        # Destination selection for resume/save
        outfile = None
        dest_path = None
        resume_off = 0

        if o.get("resume"):
            dest_path = o.get("resume_to")
            if not dest_path and o.get("save"):
                dest_path = _choose_output_path(_guess_filename(url), o.get("overwrite", False), o.get("save_dir"))
            if dest_path:
                try:
                    if os.path.exists(dest_path):
                        outfile = open(dest_path, "r+b")
                        outfile.seek(0, 2)
                        resume_off = int(outfile.tell())
                    else:
                        _ensure_dir(os.path.dirname(dest_path) or ".")
                        outfile = open(dest_path, "w+b")
                        resume_off = 0
                except Exception:
                    outfile = None
                    dest_path = None
                    resume_off = 0

        if outfile is None:
            outfile = MkTempFile()

        ok = recv_to_fileobj(
            outfile, host=host, port=port, proto=p.scheme,
            mode=o.get("mode"), timeout=o.get("timeout"), total_timeout=o.get("total_timeout"),
            window=o.get("window"), retries=o.get("retries"), chunk=o.get("chunk"),
            print_url=o.get("print_url"), resume_offset=resume_off, path_text=path_text
        )
        if not ok:
            return False

        # If writing directly to disk (resume_to/save), return that file object
        if dest_path:
            try:
                outfile.seek(0, 0)
            except Exception:
                pass
            return outfile

        # Save-to-disk option for temp file
        if o.get("save"):
            out_path = _choose_output_path(_guess_filename(url), o.get("overwrite", False), o.get("save_dir"))
            try:
                _copy_fileobj_to_path(outfile, out_path, overwrite=o.get("overwrite", False))
                sys.stdout.write("Saved: %s\n" % out_path)
                sys.stdout.flush()
            except Exception:
                return False

        try:
            outfile.seek(0, 0)
        except Exception:
            pass
        return outfile

    return False

def download_file_from_internet_string(url, headers=None, usehttp=__use_http_lib__):
    fp = download_file_from_internet_file(url, headers=headers, usehttp=usehttp)
    return fp.read() if fp else False

def upload_file_to_internet_file(fileobj, url):
    p = urlparse(url)
    if p.scheme in ("http", "https"):
        return False  # not implemented here (mirrors original)
    if p.scheme in ("ftp", "ftps"):
        return upload_file_to_ftp_file(fileobj, url)
    if p.scheme in ("sftp", "scp"):
        if __use_pysftp__ and havepysftp:
            return upload_file_to_pysftp_file(fileobj, url)
        return upload_file_to_sftp_file(fileobj, url)

    if p.scheme in ("tcp", "udp"):
        parts, o = _parse_net_url(url)
        host = parts.hostname
        port = parts.port or 0
        path_text = parts.path or "/"
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        ok = send_from_fileobj(
            fileobj, host=host, port=port, proto=p.scheme,
            mode=o.get("mode"), timeout=o.get("timeout"), total_timeout=o.get("total_timeout"),
            window=o.get("window"), retries=o.get("retries"), chunk=o.get("chunk"),
            resume=o.get("resume"), path_text=path_text
        )
        return fileobj if ok else False

    return False

def upload_file_to_internet_string(data, url):
    bio = BytesIO(_to_bytes(data))
    out = upload_file_to_internet_file(bio, url)
    try:
        bio.close()
    except Exception:
        pass
    return out
