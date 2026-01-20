#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
pywwwget_clean_tcpudp.py

Cleaned, optimized, Python 2/3 compatible TCP/UDP transfer helper.
Keeps the SAME API style as pywwwget.

SUPPORTED SCHEMES:
  tcp, udp

PUBLIC API:
  download_file_from_internet_file(url)
  download_file_from_internet_string(url)
  upload_file_to_internet_file(fileobj, url)
  upload_file_to_internet_string(data, url)

QUERY OPTIONS (?key=value):
  timeout=<sec>
  total_timeout=<sec>
  chunk=<bytes>
  max_bytes=<bytes>
  rate=<bytes/sec>
"""

from __future__ import absolute_import, division, print_function, unicode_literals
import socket, time, tempfile, logging

try:
    from urllib.parse import urlparse, parse_qs
except Exception:
    from urlparse import urlparse, parse_qs

try:
    from io import BytesIO
except Exception:
    from StringIO import StringIO as BytesIO

log = logging.getLogger("pywwwget_clean")
if not log.handlers:
    logging.basicConfig(level=logging.INFO)

DEFAULT_CHUNK = 65536

def MkTempFile():
    try:
        return tempfile.SpooledTemporaryFile(max_size=8*1024*1024, mode="w+b")
    except Exception:
        return BytesIO()

def _parse_opts(url):
    p = urlparse(url)
    q = parse_qs(p.query or "")
    def gi(name, default):
        try:
            return int(q.get(name, [default])[0])
        except Exception:
            return default
    return {
        "timeout": gi("timeout", 10),
        "total_timeout": gi("total_timeout", 0),
        "chunk": gi("chunk", DEFAULT_CHUNK),
        "max_bytes": gi("max_bytes", 0),
        "rate": gi("rate", 0),
    }

def send_from_fileobj(sock, f, opts):
    sent = 0
    start = time.time()
    while True:
        data = f.read(opts["chunk"])
        if not data:
            break
        sock.sendall(data)
        sent += len(data)
        if opts["rate"]:
            elapsed = time.time() - start
            expected = sent / float(opts["rate"])
            if expected > elapsed:
                time.sleep(expected - elapsed)
    return sent

def recv_to_fileobj(sock, f, opts):
    total = 0
    start = time.time()
    while True:
        if opts["total_timeout"] and time.time() - start > opts["total_timeout"]:
            break
        data = sock.recv(opts["chunk"])
        if not data:
            break
        total += len(data)
        if opts["max_bytes"] and total > opts["max_bytes"]:
            raise IOError("max_bytes exceeded")
        f.write(data)
    return total

def upload_file_to_internet_file(fileobj, url):
    p = urlparse(url)
    opts = _parse_opts(url)
    sock = socket.socket(socket.AF_INET,
                         socket.SOCK_STREAM if p.scheme == "tcp" else socket.SOCK_DGRAM)
    sock.settimeout(opts["timeout"])
    sock.connect((p.hostname or "0.0.0.0", p.port or 0))
    try:
        try:
            fileobj.seek(0)
        except Exception:
            pass
        return send_from_fileobj(sock, fileobj, opts)
    finally:
        sock.close()

def download_file_from_internet_file(url):
    p = urlparse(url)
    opts = _parse_opts(url)
    sock = socket.socket(socket.AF_INET,
                         socket.SOCK_STREAM if p.scheme == "tcp" else socket.SOCK_DGRAM)
    sock.settimeout(opts["timeout"])
    sock.bind((p.hostname or "0.0.0.0", p.port or 0))
    if p.scheme == "tcp":
        sock.listen(1)
        conn, _ = sock.accept()
    else:
        conn = sock
    out = MkTempFile()
    try:
        recv_to_fileobj(conn, out, opts)
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
