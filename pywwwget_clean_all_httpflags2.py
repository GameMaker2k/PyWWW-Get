#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
pywwwget_clean_all_httpflags2.py

Same as pywwwget_clean_all_httpflags.py, plus:
- allow_net=<CIDR> (IPv4 CIDR allowlist, e.g. 192.168.1.0/24)
- self-signed HTTPS auto-cert generation:
    * use scheme=https and add https=1 (or selfsigned=1) without cert/key
    * it will try to generate a temporary cert/key using `openssl` (if available)
    * if openssl is missing, it falls back to plain HTTP with a warning

Public API unchanged:
  download_file_from_internet_file(url)
  download_file_from_internet_string(url)
  upload_file_to_internet_file(fileobj, url)
  upload_file_to_internet_string(data, url)

HTTP server send flags include (superset):
  bind=, timeout=, max_clients=, range=/resume=, rate=, gzip=, min_gzip=,
  max_bytes=, name=, mime=, headers=, auth=, allow_ip=, allow_net=,
  log=, cert=, key=, https=1/selfsigned=1
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os
import sys
import time
import socket
import shutil
import logging
import tempfile
import base64
import hashlib
import subprocess

try:
    from urllib.parse import urlparse, urlunparse, parse_qs
except Exception:
    from urlparse import urlparse, urlunparse, parse_qs  # Py2

try:
    from urllib.request import Request, build_opener, HTTPBasicAuthHandler, HTTPPasswordMgrWithDefaultRealm
except Exception:
    from urllib2 import Request, build_opener, HTTPBasicAuthHandler  # Py2
    try:
        from urllib2 import HTTPPasswordMgrWithDefaultRealm
    except Exception:
        HTTPPasswordMgrWithDefaultRealm = None

try:
    from io import BytesIO
except Exception:
    from StringIO import StringIO as BytesIO  # Py2

# --- http.server compatibility ---
try:
    # Py3
    import http.server as _http_server
    import socketserver as _socketserver
except Exception:
    # Py2
    import BaseHTTPServer as _http_server
    import SocketServer as _socketserver

log = logging.getLogger("pywwwget_all_httpflags2")
if not log.handlers:
    logging.basicConfig(level=logging.INFO)

DEFAULT_CHUNK = 65536


def MkTempFile():
    try:
        return tempfile.SpooledTemporaryFile(max_size=32 * 1024 * 1024, mode="w+b")
    except Exception:
        return BytesIO()


def _gi(q, k, d):
    try:
        return int(q.get(k, [d])[0])
    except Exception:
        return d


def _gs(q, k, d=None):
    return q.get(k, [d])[0]


def _parse_opts(url):
    p = urlparse(url)
    q = parse_qs(p.query or "")
    opts = {
        "timeout": _gi(q, "timeout", 10),
        "chunk": _gi(q, "chunk", DEFAULT_CHUNK),
        "rate": _gi(q, "rate", 0),
        "max_bytes": _gi(q, "max_bytes", 0),
        "max_clients": _gi(q, "max_clients", 1),
        "range": _gi(q, "range", _gi(q, "resume", 0)),
        "gzip": _gi(q, "gzip", 0),
        "min_gzip": _gi(q, "min_gzip", 1024),
        "name": _gs(q, "name", None),
        "mime": _gs(q, "mime", None),
        "headers": _gi(q, "headers", 0),
        "auth": _gi(q, "auth", 0),
        "allow_ip": _gs(q, "allow_ip", None),
        "allow_net": _gs(q, "allow_net", None),
        "log": _gi(q, "log", 1),
        "bind": _gs(q, "bind", None),
        "port": _gi(q, "port", 0),
        "cert": _gs(q, "cert", None),
        "key": _gs(q, "key", None),
        "https": _gi(q, "https", _gi(q, "selfsigned", 0)),
    }
    return p, opts


def _rebuild_url_without_creds(p):
    netloc = p.hostname or ""
    if p.port:
        netloc += ":" + str(p.port)
    return urlunparse((p.scheme, netloc, p.path, p.params, p.query, p.fragment))


def _basic_auth_header(user, pw):
    token = ("%s:%s" % (user or "", pw or "")).encode("utf-8")
    return "Basic " + base64.b64encode(token).decode("ascii")


def _throttle(rate, sent, started):
    if not rate:
        return
    elapsed = time.time() - started
    if elapsed <= 0:
        return
    expected = sent / float(rate)
    if expected > elapsed:
        time.sleep(expected - elapsed)


def _guess_mime(path):
    lower = (path or "").lower()
    if lower.endswith(".html") or lower.endswith(".htm"):
        return "text/html; charset=utf-8"
    if lower.endswith(".txt"):
        return "text/plain; charset=utf-8"
    if lower.endswith(".json"):
        return "application/json; charset=utf-8"
    if lower.endswith(".xml"):
        return "application/xml; charset=utf-8"
    if lower.endswith(".png"):
        return "image/png"
    if lower.endswith(".jpg") or lower.endswith(".jpeg"):
        return "image/jpeg"
    if lower.endswith(".gif"):
        return "image/gif"
    return "application/octet-stream"


# --------------------------
# allow_net (IPv4 CIDR only)
# --------------------------

def _ipv4_to_int(ip):
    try:
        return int.from_bytes(socket.inet_aton(ip), "big")  # Py3
    except Exception:
        # Py2
        a = socket.inet_aton(ip)
        return (ord(a[0]) << 24) | (ord(a[1]) << 16) | (ord(a[2]) << 8) | ord(a[3])

def _parse_cidr_v4(cidr):
    # "192.168.1.0/24"
    try:
        net, bits = cidr.split("/", 1)
        bits = int(bits)
        if bits < 0 or bits > 32:
            return None
        mask = (0xffffffff << (32 - bits)) & 0xffffffff if bits else 0
        n = _ipv4_to_int(net) & mask
        return n, mask
    except Exception:
        return None

def _ip_in_cidr_v4(ip, cidr):
    parsed = _parse_cidr_v4(cidr)
    if not parsed:
        return False
    n, mask = parsed
    try:
        v = _ipv4_to_int(ip)
    except Exception:
        return False
    return (v & mask) == n


# --------------------------
# Self-signed HTTPS helper
# --------------------------

def _openssl_exists():
    try:
        p = subprocess.Popen(["openssl", "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = p.communicate()
        return p.returncode == 0
    except Exception:
        return False

def _make_self_signed_cert(tmpdir):
    cert = os.path.join(tmpdir, "pywwwget_cert.pem")
    key = os.path.join(tmpdir, "pywwwget_key.pem")
    # 1-day cert, no passphrase, CN=pywwwget
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key, "-out", cert, "-days", "1",
        "-subj", "/CN=pywwwget"
    ]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, err = p.communicate()
    if p.returncode != 0:
        raise RuntimeError("openssl failed: %s" % (err.decode("utf-8", "ignore") if hasattr(err, "decode") else err))
    return cert, key


# =========================
# HTTP SERVER (send fileobj)
# =========================

def send_via_http(fileobj, url):
    p, o = _parse_opts(url)
    scheme = (p.scheme or "http").lower()

    bind = o["bind"] or (p.hostname or "127.0.0.1")
    port = o["port"] or (p.port or 8000)
    path = p.path or "/"
    if not path.startswith("/"):
        path = "/" + path

    expect_user = p.username
    expect_pw = p.password or ""

    # determine file length for range (best effort)
    try:
        cur = fileobj.tell()
    except Exception:
        cur = None
    try:
        fileobj.seek(0, 2)
        file_len = fileobj.tell()
        fileobj.seek(0, 0)
    except Exception:
        file_len = None
        try:
            if cur is not None:
                fileobj.seek(cur, 0)
        except Exception:
            pass

    class Handler(_http_server.BaseHTTPRequestHandler):
        server_version = "pywwwget/clean"

        def log_message(self, fmt, *args):
            if o["log"]:
                try:
                    _http_server.BaseHTTPRequestHandler.log_message(self, fmt, *args)
                except Exception:
                    pass

        def _deny(self, code, msg=""):
            try:
                self.send_response(code)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                if msg:
                    self.wfile.write(msg.encode("utf-8"))
            except Exception:
                pass

        def _client_allowed(self):
            try:
                ip = self.client_address[0]
            except Exception:
                return False

            if o["allow_ip"] and ip != o["allow_ip"]:
                return False
            if o["allow_net"]:
                # IPv4 CIDR only; if non-IPv4, deny
                if "." not in ip:
                    return False
                if not _ip_in_cidr_v4(ip, o["allow_net"]):
                    return False
            return True

        def _check_auth(self):
            if not o["auth"]:
                return True
            if not expect_user:
                return False
            hdr = self.headers.get("Authorization")
            if not hdr:
                return False
            expected = _basic_auth_header(expect_user, expect_pw)
            return hdr.strip() == expected

        def do_HEAD(self):
            return self.do_GET(head_only=True)

        def do_GET(self, head_only=False):
            if not self._client_allowed():
                return self._deny(403, "Forbidden\n")

            if o["auth"] and not self._check_auth():
                try:
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="pywwwget"')
                    self.end_headers()
                except Exception:
                    pass
                return

            req_path = self.path.split("?", 1)[0] or "/"
            if req_path != path and not (path == "/" and req_path == "/"):
                return self._deny(404, "Not Found\n")

            start = 0
            end = None
            if o["range"] and file_len is not None:
                rng = self.headers.get("Range")
                if rng and rng.startswith("bytes="):
                    try:
                        spec = rng.split("=", 1)[1].strip()
                        a, b = spec.split("-", 1)
                        if a:
                            start = int(a)
                        if b:
                            end = int(b)
                    except Exception:
                        start, end = 0, None

            cap = o["max_bytes"] if o["max_bytes"] else None

            mime = o["mime"] or _guess_mime(path)
            disp_name = o["name"] or os.path.basename(path.strip("/")) or "download.bin"

            do_gzip = False
            accept = self.headers.get("Accept-Encoding", "")
            if o["gzip"] and ("gzip" in accept.lower()) and (file_len is None or file_len >= o["min_gzip"]):
                if mime.startswith("text/") or ("json" in mime) or ("xml" in mime):
                    do_gzip = True

            try:
                fileobj.seek(start, 0)
            except Exception:
                start = 0
                try:
                    fileobj.seek(0, 0)
                except Exception:
                    pass

            if file_len is not None:
                if end is None or end >= file_len:
                    end_eff = file_len - 1
                else:
                    end_eff = end
                length = max(0, end_eff - start + 1)
            else:
                end_eff = None
                length = None

            if cap is not None and length is not None:
                length = min(length, cap)

            try:
                if o["range"] and file_len is not None and (start != 0 or end is not None):
                    self.send_response(206)
                    self.send_header("Accept-Ranges", "bytes")
                    self.send_header("Content-Range", "bytes %d-%d/%d" % (start, start + (length - 1 if length is not None else 0), file_len))
                else:
                    self.send_response(200)
                    if file_len is not None:
                        self.send_header("Accept-Ranges", "bytes" if o["range"] else "none")

                self.send_header("Content-Type", mime)
                self.send_header("Content-Disposition", 'attachment; filename="%s"' % disp_name)
                if o["headers"]:
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("X-Content-Type-Options", "nosniff")

                if do_gzip:
                    self.send_header("Content-Encoding", "gzip")

                if (length is not None) and (not do_gzip):
                    self.send_header("Content-Length", str(length))

                self.end_headers()

                if head_only:
                    return

                sent = 0
                started = time.time()

                if do_gzip:
                    import gzip as _gzip
                    gz = _gzip.GzipFile(fileobj=self.wfile, mode="wb")
                    try:
                        remaining = length if length is not None else None
                        while True:
                            n = o["chunk"] if remaining is None else min(o["chunk"], remaining)
                            if n <= 0:
                                break
                            data = fileobj.read(n)
                            if not data:
                                break
                            gz.write(data)
                            sent += len(data)
                            if remaining is not None:
                                remaining -= len(data)
                            if cap is not None and sent >= cap:
                                break
                            _throttle(o["rate"], sent, started)
                    finally:
                        try:
                            gz.close()
                        except Exception:
                            pass
                else:
                    remaining = length if length is not None else None
                    while True:
                        n = o["chunk"] if remaining is None else min(o["chunk"], remaining)
                        if n <= 0:
                            break
                        data = fileobj.read(n)
                        if not data:
                            break
                        self.wfile.write(data)
                        sent += len(data)
                        if remaining is not None:
                            remaining -= len(data)
                        if cap is not None and sent >= cap:
                            break
                        _throttle(o["rate"], sent, started)

                try:
                    self.server._served_bytes += sent
                    self.server._served_clients += 1
                except Exception:
                    pass

            except Exception:
                return

    class ThreadingHTTPServer(_socketserver.ThreadingMixIn, _http_server.HTTPServer):
        daemon_threads = True

    httpd = ThreadingHTTPServer((bind, int(port)), Handler)
    httpd.timeout = o["timeout"]
    httpd._served_bytes = 0
    httpd._served_clients = 0

    tmpdir = None
    if scheme == "https":
        try:
            import ssl
            if o["cert"] and o["key"]:
                httpd.socket = ssl.wrap_socket(httpd.socket, server_side=True, certfile=o["cert"], keyfile=o["key"])
            elif o["https"]:
                # auto-generate self-signed using openssl
                if _openssl_exists():
                    tmpdir = tempfile.mkdtemp(prefix="pywwwget_ssl_")
                    cert, key = _make_self_signed_cert(tmpdir)
                    httpd.socket = ssl.wrap_socket(httpd.socket, server_side=True, certfile=cert, keyfile=key)
                    log.warning("Serving self-signed HTTPS on %s:%s", bind, port)
                else:
                    log.warning("https requested but openssl not found; serving plain HTTP.")
            else:
                log.warning("https requested but cert/key not provided; serving plain HTTP.")
        except Exception:
            log.warning("ssl wrap failed; serving plain HTTP.")

    try:
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass

        while httpd._served_clients < max(1, int(o["max_clients"])):
            httpd.handle_request()
        return httpd._served_bytes
    except Exception:
        return False
    finally:
        try:
            httpd.server_close()
        except Exception:
            pass
        try:
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass
        try:
            if cur is not None:
                fileobj.seek(cur, 0)
        except Exception:
            pass


# =========================
# HTTP CLIENT (download)
# =========================

def download_file_from_http_file(url, headers=None):
    if headers is None:
        headers = {}

    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return False

    rebuilt = _rebuild_url_without_creds(p)

    req = Request(rebuilt, headers=headers)
    if p.username and p.password and HTTPPasswordMgrWithDefaultRealm is not None:
        mgr = HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, rebuilt, p.username, p.password)
        opener = build_opener(HTTPBasicAuthHandler(mgr))
    else:
        opener = build_opener()

    out = MkTempFile()
    try:
        resp = opener.open(req, timeout=10)
        shutil.copyfileobj(resp, out, length=DEFAULT_CHUNK)
        out.seek(0, 0)
        return out
    except Exception:
        return False


def download_file_from_http_string(url, headers=None):
    f = download_file_from_http_file(url, headers=headers)
    return f.read() if f else False


# =========================
# TCP/UDP minimal push/pull
# =========================

def _tcp_send_fileobj(fileobj, url):
    p, o = _parse_opts(url)
    host = p.hostname or "127.0.0.1"
    port = p.port or o["port"] or 0

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(o["timeout"])
    s.connect((host, port))
    try:
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        sent = 0
        started = time.time()
        while True:
            data = fileobj.read(o["chunk"])
            if not data:
                break
            s.sendall(data)
            sent += len(data)
            _throttle(o["rate"], sent, started)
        return sent
    finally:
        s.close()


def _tcp_recv_to_temp(url):
    p, o = _parse_opts(url)
    bind = o["bind"] or (p.hostname or "0.0.0.0")
    port = p.port or o["port"] or 0

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(o["timeout"])
    s.bind((bind, port))
    s.listen(1)
    c, _ = s.accept()

    out = MkTempFile()
    total = 0
    try:
        while True:
            data = c.recv(o["chunk"])
            if not data:
                break
            total += len(data)
            if o["max_bytes"] and total > o["max_bytes"]:
                raise IOError("max_bytes exceeded")
            out.write(data)
        out.seek(0, 0)
        return out
    finally:
        try:
            c.close()
        except Exception:
            pass
        s.close()


def _udp_send_fileobj(fileobj, url):
    p, o = _parse_opts(url)
    host = p.hostname or "127.0.0.1"
    port = p.port or o["port"] or 0

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(o["timeout"])
    s.connect((host, port))
    try:
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        sent = 0
        started = time.time()
        while True:
            data = fileobj.read(o["chunk"])
            if not data:
                break
            s.send(data)
            sent += len(data)
            _throttle(o["rate"], sent, started)
        return sent
    finally:
        s.close()


def _udp_recv_to_temp(url):
    p, o = _parse_opts(url)
    bind = o["bind"] or (p.hostname or "0.0.0.0")
    port = p.port or o["port"] or 0

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(o["timeout"])
    s.bind((bind, port))

    out = MkTempFile()
    total = 0
    try:
        while True:
            try:
                data = s.recv(o["chunk"])
            except socket.timeout:
                break
            if not data:
                break
            total += len(data)
            if o["max_bytes"] and total > o["max_bytes"]:
                raise IOError("max_bytes exceeded")
            out.write(data)
        out.seek(0, 0)
        return out
    finally:
        s.close()


# =========================
# PUBLIC API (same names)
# =========================

def download_file_from_internet_file(url, headers=None):
    p = urlparse(url)
    if p.scheme in ("http", "https"):
        return download_file_from_http_file(url, headers=headers)
    if p.scheme == "tcp":
        return _tcp_recv_to_temp(url)
    if p.scheme == "udp":
        return _udp_recv_to_temp(url)
    return False


def download_file_from_internet_string(url, headers=None):
    f = download_file_from_internet_file(url, headers=headers)
    return f.read() if f else False


def upload_file_to_internet_file(fileobj, url):
    p = urlparse(url)
    if p.scheme in ("http", "https"):
        return send_via_http(fileobj, url)
    if p.scheme == "tcp":
        return _tcp_send_fileobj(fileobj, url)
    if p.scheme == "udp":
        return _udp_send_fileobj(fileobj, url)
    return False


def upload_file_to_internet_string(data, url):
    bio = BytesIO(data)
    try:
        return upload_file_to_internet_file(bio, url)
    finally:
        try:
            bio.close()
        except Exception:
            pass
