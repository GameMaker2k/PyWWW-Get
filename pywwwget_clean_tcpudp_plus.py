#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
pywwwget_clean_tcpudp_plus.py

TCP/UDP transfer helper (Python 2 & 3) with:
- AUTH (user:pass@host)
- PATH enforcement
- SHA-256 verification
- IPv4 / IPv6
- Rate limiting
- Size limits
- Timeouts

PUBLIC API (unchanged):
  download_file_from_internet_file(url)
  download_file_from_internet_string(url)
  upload_file_to_internet_file(fileobj, url)
  upload_file_to_internet_string(data, url)

QUERY OPTIONS:
  timeout=<sec>
  total_timeout=<sec>
  chunk=<bytes>
  max_bytes=<bytes>
  rate=<bytes/sec>
  auth=0|1
  enforce_path=0|1
  sha=0|1
"""

from __future__ import absolute_import, division, print_function, unicode_literals
import socket, time, tempfile, logging, hashlib

try:
    from urllib.parse import urlparse, parse_qs
except Exception:
    from urlparse import urlparse, parse_qs

try:
    from io import BytesIO
except Exception:
    from StringIO import StringIO as BytesIO

log = logging.getLogger("pywwwget_tcpudp_plus")
if not log.handlers:
    logging.basicConfig(level=logging.INFO)

DEFAULT_CHUNK = 65536

def MkTempFile():
    try:
        return tempfile.SpooledTemporaryFile(max_size=8*1024*1024, mode="w+b")
    except Exception:
        return BytesIO()

def _gi(q, name, default):
    try:
        return int(q.get(name, [default])[0])
    except Exception:
        return default

def _parse(url):
    p = urlparse(url)
    q = parse_qs(p.query or "")
    return p, {
        "timeout": _gi(q, "timeout", 10),
        "total_timeout": _gi(q, "total_timeout", 0),
        "chunk": _gi(q, "chunk", DEFAULT_CHUNK),
        "max_bytes": _gi(q, "max_bytes", 0),
        "rate": _gi(q, "rate", 0),
        "auth": _gi(q, "auth", 0),
        "enforce_path": _gi(q, "enforce_path", 1),
        "sha": _gi(q, "sha", 0),
    }

def _make_socket(proto, timeout):
    fam = socket.AF_INET6 if ":" in proto[0] else socket.AF_INET
    typ = socket.SOCK_STREAM if proto[1] == "tcp" else socket.SOCK_DGRAM
    s = socket.socket(fam, typ)
    s.settimeout(timeout)
    return s

def _send_line(sock, s):
    sock.sendall(s.encode("utf-8") + b"\n")

def _recv_line(sock):
    buf = b""
    while not buf.endswith(b"\n"):
        d = sock.recv(1)
        if not d:
            break
        buf += d
    return buf.rstrip(b"\n").decode("utf-8", "replace")

def send_from_fileobj(sock, f, p, opts):
    sent = 0
    sha = hashlib.sha256() if opts["sha"] else None
    start = time.time()

    if opts["enforce_path"]:
        _send_line(sock, "PATH " + (p.path or "/"))

    if opts["auth"] and p.username:
        _send_line(sock, "AUTH %s %s" % (p.username, p.password or ""))

    while True:
        data = f.read(opts["chunk"])
        if not data:
            break
        sock.sendall(data)
        sent += len(data)
        if sha:
            sha.update(data)
        if opts["rate"]:
            elapsed = time.time() - start
            expect = sent / float(opts["rate"])
            if expect > elapsed:
                time.sleep(expect - elapsed)

    if sha:
        _send_line(sock, "SHA256 " + sha.hexdigest())

    return sent

def recv_to_fileobj(sock, f, p, opts):
    total = 0
    sha = hashlib.sha256() if opts["sha"] else None
    start = time.time()

    if opts["enforce_path"]:
        line = _recv_line(sock)
        if not line.startswith("PATH ") or line[5:] != (p.path or "/"):
            raise IOError("PATH mismatch")

    if opts["auth"] and p.username:
        line = _recv_line(sock)
        if not line.startswith("AUTH "):
            raise IOError("AUTH missing")
        _, u, pw = line.split(" ", 2)
        if u != p.username or pw != (p.password or ""):
            raise IOError("AUTH failed")

    while True:
        if opts["total_timeout"] and time.time() - start > opts["total_timeout"]:
            break
        data = sock.recv(opts["chunk"])
        if not data:
            break
        total += len(data)
        if opts["max_bytes"] and total > opts["max_bytes"]:
            raise IOError("max_bytes exceeded")
        if sha:
            sha.update(data)
        f.write(data)

    if sha:
        line = _recv_line(sock)
        if not line.startswith("SHA256 ") or sha.hexdigest() != line.split(" ", 1)[1]:
            raise IOError("SHA mismatch")

    return total

def upload_file_to_internet_file(fileobj, url):
    p, opts = _parse(url)
    sock = _make_socket((p.hostname or "0.0.0.0", p.scheme), opts["timeout"])
    sock.connect((p.hostname or "0.0.0.0", p.port or 0))
    try:
        try:
            fileobj.seek(0)
        except Exception:
            pass
        return send_from_fileobj(sock, fileobj, p, opts)
    finally:
        sock.close()

def download_file_from_internet_file(url):
    p, opts = _parse(url)
    sock = _make_socket((p.hostname or "0.0.0.0", p.scheme), opts["timeout"])
    sock.bind((p.hostname or "0.0.0.0", p.port or 0))
    if p.scheme == "tcp":
        sock.listen(1)
        conn, _ = sock.accept()
    else:
        conn = sock
    out = MkTempFile()
    try:
        recv_to_fileobj(conn, out, p, opts)
        out.seek(0)
        return out
    finally:
        try:
            conn.close()
        except Exception:
            pass
        sock.close()

def download_file_from_internet_string(url):
    return download_file_from_internet_file(url).read()

def upload_file_to_internet_string(data, url):
    return upload_file_to_internet_file(BytesIO(data), url)
