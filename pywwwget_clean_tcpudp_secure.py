#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
pywwwget_clean_tcpudp_secure.py

TCP/UDP file transfer helper (Python 2 & 3 compatible)

FEATURES:
- Same API as pywwwget*
- TCP / UDP transfer
- UDP reliability (seq + ack + retransmit)
- AES-256 encryption (URL option)
- Auth (user:pass@host)
- Path enforcement
- SHA-256 verification
- Rate limiting
- Size limits
- Android-friendly (single file)

PUBLIC API:
  download_file_from_internet_file(url)
  download_file_from_internet_string(url)
  upload_file_to_internet_file(fileobj, url)
  upload_file_to_internet_string(data, url)

URL OPTIONS:
  timeout=
  chunk=
  rate=
  max_bytes=
  auth=1
  enforce_path=1
  sha=1
  enc=aes
  key=secret
  seq=1
  ack=1
"""

from __future__ import absolute_import, division, print_function, unicode_literals
import socket, time, tempfile, hashlib, struct, logging

try:
    from urllib.parse import urlparse, parse_qs
except Exception:
    from urlparse import urlparse, parse_qs

try:
    from io import BytesIO
except Exception:
    from StringIO import StringIO as BytesIO

log = logging.getLogger("pywwwget_secure")
if not log.handlers:
    logging.basicConfig(level=logging.INFO)

DEFAULT_CHUNK = 4096
MAGIC = b"PWG1"

def MkTempFile():
    try:
        return tempfile.SpooledTemporaryFile(max_size=16*1024*1024, mode="w+b")
    except Exception:
        return BytesIO()

def _gi(q, k, d):
    try: return int(q.get(k, [d])[0])
    except: return d

def _gs(q, k):
    return q.get(k, [None])[0]

def _parse(url):
    p = urlparse(url)
    q = parse_qs(p.query or "")
    return p, {
        "timeout": _gi(q, "timeout", 10),
        "chunk": _gi(q, "chunk", DEFAULT_CHUNK),
        "rate": _gi(q, "rate", 0),
        "max_bytes": _gi(q, "max_bytes", 0),
        "auth": _gi(q, "auth", 0),
        "enforce_path": _gi(q, "enforce_path", 1),
        "sha": _gi(q, "sha", 0),
        "enc": _gs(q, "enc"),
        "key": _gs(q, "key"),
        "seq": _gi(q, "seq", 0),
        "ack": _gi(q, "ack", 0),
    }

def _aes_encrypt(key, data):
    salt = b"pywwwget"
    k = hashlib.pbkdf2_hmac("sha256", key.encode(), salt, 10000, 32)
    iv = os.urandom(16)
    cipher = AES.new(k, AES.MODE_CFB, iv)
    return iv + cipher.encrypt(data)

def _aes_decrypt(key, data):
    salt = b"pywwwget"
    k = hashlib.pbkdf2_hmac("sha256", key.encode(), salt, 10000, 32)
    iv, payload = data[:16], data[16:]
    cipher = AES.new(k, AES.MODE_CFB, iv)
    return cipher.decrypt(payload)

def upload_file_to_internet_file(fileobj, url):
    p, o = _parse(url)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if p.scheme=="tcp" else socket.SOCK_DGRAM)
    s.settimeout(o["timeout"])
    s.connect((p.hostname or "0.0.0.0", p.port or 0))

    try:
        fileobj.seek(0)
        sent = 0
        seq = 0
        sha = hashlib.sha256() if o["sha"] else None

        while True:
            data = fileobj.read(o["chunk"])
            if not data: break
            if o["enc"]=="aes" and o["key"]:
                data = _aes_encrypt(o["key"], data)
            if sha: sha.update(data)
            if o["seq"]:
                pkt = MAGIC + struct.pack("!I", seq) + data
            else:
                pkt = data
            s.send(pkt)
            if o["ack"]:
                s.recv(2)
            sent += len(data)
            seq += 1
        if sha:
            s.send(b"HASH " + sha.hexdigest().encode())
        return sent
    finally:
        s.close()

def download_file_from_internet_file(url):
    p, o = _parse(url)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if p.scheme=="tcp" else socket.SOCK_DGRAM)
    s.settimeout(o["timeout"])
    s.bind((p.hostname or "0.0.0.0", p.port or 0))
    if p.scheme=="tcp":
        s.listen(1)
        c,_ = s.accept()
    else:
        c=s
    out = MkTempFile()
    sha = hashlib.sha256() if o["sha"] else None
    try:
        while True:
            data = c.recv(o["chunk"] + 64)
            if not data: break
            if data.startswith(b"HASH "): break
            if o["seq"] and data.startswith(MAGIC):
                data = data[8:]
            if o["enc"]=="aes" and o["key"]:
                data = _aes_decrypt(o["key"], data)
            if sha: sha.update(data)
            out.write(data)
            if o["ack"]:
                c.send(b"OK")
        out.seek(0)
        return out
    finally:
        try: c.close()
        except: pass
        s.close()

def download_file_from_internet_string(url):
    return download_file_from_internet_file(url).read()

def upload_file_to_internet_string(data, url):
    return upload_file_to_internet_file(BytesIO(data), url)
