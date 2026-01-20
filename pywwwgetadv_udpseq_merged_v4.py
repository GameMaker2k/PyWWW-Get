#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
    This program is free software; you can redistribute it and/or modify
    it under the terms of the Revised BSD License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Revised BSD License for more details.

    Copyright 2015-2024 Game Maker 2k - https://github.com/GameMaker2k
    Copyright 2015-2024 Kazuki Przyborowski - https://github.com/KazukiPrzyborowski

    $FileInfo: pywwwget.py - Last Update: 8/14/2025 Ver. 2.1.6 RC 1 - Author: cooldude2k $
'''

from __future__ import absolute_import, division, print_function, unicode_literals, generators, with_statement, nested_scopes

import os
import re
import sys
import time
import socket
import shutil
import logging
import platform
import tempfile
import struct

try:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import urlparse, parse_qs
except ImportError:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from urlparse import urlparse, parse_qs

# URL Parsing
try:
    # Python 3
    from urllib.parse import urlparse, urlunparse, parse_qs, unquote
    from urllib.request import url2pathname
except ImportError:
    # Python 2
    from urlparse import urlparse, urlunparse, parse_qs
    from urllib import unquote, url2pathname

# FTP Support
ftpssl = True
try:
    from ftplib import FTP, FTP_TLS, all_errors
except ImportError:
    ftpssl = False
    from ftplib import FTP
    all_errors = (Exception,)

try:
    basestring
except NameError:
    basestring = str

# URL Parsing
try:
    from urllib.parse import urlparse, urlunparse
except ImportError:
    from urlparse import urlparse, urlunparse

# Paramiko support
haveparamiko = False
try:
    import paramiko
    haveparamiko = True
except ImportError:
    pass

# PySFTP support
havepysftp = False
try:
    import pysftp
    havepysftp = True
except ImportError:
    pass

# Add the mechanize import check
havemechanize = False
try:
    import mechanize
    havemechanize = True
except ImportError:
    pass

# Requests support
haverequests = False
try:
    import requests
    haverequests = True
    try:
        import urllib3
        logging.getLogger("urllib3").setLevel(logging.WARNING)
    except Exception:
        pass
except ImportError:
    pass

# HTTPX support
havehttpx = False
try:
    import httpx
    havehttpx = True
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
except ImportError:
    pass

# HTTP and URL parsing (urllib)
try:
    from urllib.request import Request, build_opener, HTTPBasicAuthHandler, HTTPPasswordMgrWithDefaultRealm
except ImportError:
    from urllib2 import Request, build_opener, HTTPBasicAuthHandler
    try:
        from urllib2 import HTTPPasswordMgrWithDefaultRealm
    except Exception:
        HTTPPasswordMgrWithDefaultRealm = None

# StringIO and BytesIO
try:
    from io import StringIO, BytesIO
except ImportError:
    try:
        from cStringIO import StringIO
        from cStringIO import StringIO as BytesIO
    except ImportError:
        from StringIO import StringIO
        from StringIO import StringIO as BytesIO

try:
    file
except NameError:
    from io import IOBase
    file = IOBase
#if isinstance(outfile, file) or isinstance(outfile, IOBase):

try:
    basestring
except NameError:
    basestring = str

PY2 = (sys.version_info[0] == 2)
try:
    unicode  # Py2
except NameError:  # Py3
    unicode = str
try:
    long
except NameError:  # Py3
    long = int
try:
    PermissionError
except NameError:  # Py2
    PermissionError = OSError

if PY2:
    # In Py2, 'str' is bytes; define a 'bytes' alias for clarity
    bytes_type = str
    text_type = unicode  # noqa: F821 (Py2-only)
else:
    bytes_type = bytes
    text_type = str

# Text streams (as provided by Python)
PY_STDIN_TEXT  = sys.stdin
PY_STDOUT_TEXT = sys.stdout
PY_STDERR_TEXT = sys.stderr

# Binary-friendly streams (use .buffer on Py3, fall back on Py2)
PY_STDIN_BUF  = getattr(sys.stdin,  "buffer", sys.stdin)
PY_STDOUT_BUF = getattr(sys.stdout, "buffer", sys.stdout)
PY_STDERR_BUF = getattr(sys.stderr, "buffer", sys.stderr)

# Text vs bytes tuples you can use with isinstance()
TEXT_TYPES   = (basestring,)                  # "str or unicode" on Py2, "str" on Py3
BINARY_TYPES = (bytes,) if not PY2 else (str,)  # bytes on Py3, str on Py2
# Optional: support os.PathLike on Py3
try:
    from os import PathLike
    PATH_TYPES = (basestring, PathLike)
except Exception:
    PATH_TYPES = (basestring,)

def running_interactively():
    main = sys.modules.get("__main__")
    no_main_file = not hasattr(main, "__file__")
    interactive_flag = bool(getattr(sys.flags, "interactive", 0))
    return no_main_file or interactive_flag

if running_interactively():
    logging.basicConfig(format="%(message)s", stream=PY_STDOUT_TEXT, level=logging.DEBUG)

def _ensure_text(s, encoding="utf-8", errors="replace", allow_none=False):
    """
    Normalize any input to text_type (unicode on Py2, str on Py3).

    - bytes/bytearray/memoryview -> decode
    - os.PathLike -> fspath then normalize
    - None -> "" (unless allow_none=True, then return None)
    - everything else -> text_type(s)
    """
    if s is None:
        return None if allow_none else text_type("")

    if isinstance(s, text_type):
        return s

    if isinstance(s, (bytes_type, bytearray, memoryview)):
        return bytes(s).decode(encoding, errors)

    # Handle pathlib.Path & other path-like objects
    try:
        if hasattr(os, "fspath"):
            fs = os.fspath(s)
            if isinstance(fs, text_type):
                return fs
            if isinstance(fs, (bytes_type, bytearray, memoryview)):
                return bytes(fs).decode(encoding, errors)
    except Exception:
        pass

    return text_type(s)

def to_text(s, encoding="utf-8", errors="ignore"):
    if s is None:
        return u""
    if isinstance(s, unicode):
        return s
    if isinstance(s, (bytes, bytearray)):
        return s.decode(encoding, errors)
    return unicode(s)

baseint = []
try:
    baseint.append(long)
    baseint.insert(0, int)
except NameError:
    baseint.append(int)
baseint = tuple(baseint)

__use_inmem__ = True
__use_memfd__ = True
__use_spoolfile__ = False
__use_spooldir__ = tempfile.gettempdir()
BYTES_PER_KiB = 1024
BYTES_PER_MiB = 1024 * BYTES_PER_KiB
# Spool: not tiny, but won’t blow up RAM if many are in use
DEFAULT_SPOOL_MAX = 4 * BYTES_PER_MiB      # 4 MiB per spooled temp file
__spoolfile_size__ = DEFAULT_SPOOL_MAX
# Buffer: bigger than stdlib default (16 KiB), but still modest
DEFAULT_BUFFER_MAX = 256 * BYTES_PER_KiB   # 256 KiB copy buffer
__filebuff_size__ = DEFAULT_BUFFER_MAX

__use_pysftp__ = False
if(not havepysftp):
    __use_pysftp__ = False

__use_http_lib__ = "httpx"
if(__use_http_lib__ == "httpx" and haverequests and not havehttpx):
    __use_http_lib__ = "requests"
if(__use_http_lib__ == "requests" and havehttpx and not haverequests):
    __use_http_lib__ = "httpx"
if((__use_http_lib__ == "httpx" or __use_http_lib__ == "requests") and not havehttpx and not haverequests):
    __use_http_lib__ = "urllib"

__program_name__ = "PyWWW-Get"
__program_alt_name__ = "PyWWWGet"
__program_small_name__ = "wwwget"
__project__ = __program_name__
__project_url__ = "https://github.com/GameMaker2k/PyWWW-Get"
__version_info__ = (2, 1, 6, "RC 1", 1)
__version_date_info__ = (2025, 8, 14, "RC 1", 1)
__version_date__ = str(__version_date_info__[0])+"."+str(__version_date_info__[
    1]).zfill(2)+"."+str(__version_date_info__[2]).zfill(2)
__revision__ = __version_info__[3]
__revision_id__ = "$Id$"
if(__version_info__[4] is not None):
    __version_date_plusrc__ = __version_date__ + \
        "-"+str(__version_date_info__[4])
if(__version_info__[4] is None):
    __version_date_plusrc__ = __version_date__
if(__version_info__[3] is not None):
    __version__ = str(__version_info__[0])+"."+str(__version_info__[1])+"."+str(
        __version_info__[2])+" "+str(__version_info__[3])
if(__version_info__[3] is None):
    __version__ = str(
        __version_info__[0])+"."+str(__version_info__[1])+"."+str(__version_info__[2])

PyBitness = platform.architecture()
if(PyBitness == "32bit" or PyBitness == "32"):
    PyBitness = "32"
elif(PyBitness == "64bit" or PyBitness == "64"):
    PyBitness = "64"
else:
    PyBitness = "32"

geturls_ua_pywwwget_python = "Mozilla/5.0 (compatible; {proname}/{prover}; +{prourl})".format(
    proname=__project__, prover=__version__, prourl=__project_url__)
if(platform.python_implementation() != ""):
    py_implementation = platform.python_implementation()
if(platform.python_implementation() == ""):
    py_implementation = "Python"

geturls_ua_pywwwget_python_alt = "Mozilla/5.0 ({osver}; {archtype}; +{prourl}) {pyimp}/{pyver} (KHTML, like Gecko) {proname}/{prover}".format(
    osver=platform.system()+" "+platform.release(),
    archtype=platform.machine(),
    prourl=__project_url__,
    pyimp=py_implementation,
    pyver=platform.python_version(),
    proname=__project__,
    prover=__version__
)

geturls_ua_googlebot_google = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
geturls_ua_googlebot_google_old = "Googlebot/2.1 (+http://www.google.com/bot.html)"

geturls_headers_pywwwget_python = {
    'Referer': "http://google.com/",
    'User-Agent': geturls_ua_pywwwget_python,
    'Accept-Encoding': "none",
    'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6",
    'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7",
    'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    'Connection': "close",
    'SEC-CH-UA': "\""+__project__+"\";v=\""+str(__version__)+"\", \"Not;A=Brand\";v=\"8\", \""+py_implementation+"\";v=\""+str(platform.release())+"\"",
    'SEC-CH-UA-FULL-VERSION': str(__version__),
    'SEC-CH-UA-PLATFORM': ""+py_implementation+"",
    'SEC-CH-UA-ARCH': ""+platform.machine()+"",
    'SEC-CH-UA-BITNESS': str(PyBitness)
}

geturls_headers_pywwwget_python_alt = {
    'Referer': "http://google.com/",
    'User-Agent': geturls_ua_pywwwget_python_alt,
    'Accept-Encoding': "none",
    'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6",
    'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7",
    'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    'Connection': "close",
    'SEC-CH-UA': "\""+__project__+"\";v=\""+str(__version__)+"\", \"Not;A=Brand\";v=\"8\", \""+py_implementation+"\";v=\""+str(platform.release())+"\"",
    'SEC-CH-UA-FULL-VERSION': str(__version__),
    'SEC-CH-UA-PLATFORM': ""+py_implementation+"",
    'SEC-CH-UA-ARCH': ""+platform.machine()+"",
    'SEC-CH-UA-BITNESS': str(PyBitness)
}

geturls_headers_googlebot_google = {
    'Referer': "http://google.com/",
    'User-Agent': geturls_ua_googlebot_google,
    'Accept-Encoding': "none",
    'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6",
    'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7",
    'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    'Connection': "close"
}

geturls_headers_googlebot_google_old = {
    'Referer': "http://google.com/",
    'User-Agent': geturls_ua_googlebot_google_old,
    'Accept-Encoding': "none",
    'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6",
    'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7",
    'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    'Connection': "close"
}

# Logger used throughout original code
log = logging.getLogger(__project__)
if not log.handlers:
    logging.basicConfig(level=logging.INFO)

def to_ns(timestamp):
    """
    Convert a second-resolution timestamp (int or float)
    into a nanosecond timestamp (int) by zero-padding.
    Works in Python 2 and Python 3.
    """
    try:
        # Convert incoming timestamp to float so it works for int or float
        seconds = float(timestamp)
    except (TypeError, ValueError):
        raise ValueError("Timestamp must be int or float")

    # Multiply by 1e9 to get nanoseconds, then cast to int
    return int(seconds * 1000000000)

def format_ns_utc(ts_ns, fmt='%Y-%m-%d %H:%M:%S'):
    ts_ns = int(ts_ns)
    sec, ns = divmod(ts_ns, 10**9)
    dt = datetime.datetime.utcfromtimestamp(sec).replace(microsecond=ns // 1000)
    base = dt.strftime(fmt)
    ns_str = "%09d" % ns
    return base + "." + ns_str

def _split_posix(name):
    """
    Return a list of path parts without collapsing '..'.
    - Normalize backslashes to '/'
    - Strip leading './' (repeated)
    - Remove '' and '.' parts; keep '..' for traversal detection
    """
    if not name:
        return []
    n = name.replace(u"\\", u"/")
    while n.startswith(u"./"):
        n = n[2:]
    return [p for p in n.split(u"/") if p not in (u"", u".")]

def _is_abs_like(name):
    """Detect absolute-like paths across platforms (/, \\, drive letters, UNC)."""
    if not name:
        return False
    n = name.replace(u"\\", u"/")

    # POSIX absolute
    if n.startswith(u"/"):
        return True

    # Windows UNC (\\server\share\...) -> after replace: startswith '//'
    if n.startswith(u"//"):
        return True

    # Windows drive: 'C:/', 'C:\', or bare 'C:' (treat as absolute-like conservatively)
    if len(n) >= 2 and n[1] == u":":
        if len(n) == 2:
            return True
        if n[2:3] in (u"/", u"\\"):
            return True
    return False

def _resolves_outside(parent, target):
    """
    Does a symlink from 'parent' to 'target' escape parent?
    - Absolute-like target => escape.
    - Compare normalized '/<parent>/<target>' against '/<parent>'.
    - 'parent' is POSIX-style ('' means archive root).
    """
    parent = _ensure_text(parent or u"")
    target = _ensure_text(target or u"")

    # Absolute target is unsafe by definition
    if _is_abs_like(target):
        return True

    import posixpath as pp
    root = u"/"
    base = posixpath.normpath(posixpath.join(root, parent))   # '/dir/sub' or '/'
    cand = posixpath.normpath(posixpath.join(base, target))   # resolved target under '/'

    # ensure trailing slash on base for the prefix test
    base_slash = base if base.endswith(u"/") else (base + u"/")
    return not (cand == base or cand.startswith(base_slash))

def _to_bytes(data, encoding="utf-8", errors="strict"):
    """
    Robustly coerce `data` to bytes:
      - None -> b""
      - bytes/bytearray/memoryview -> bytes(...)
      - unicode/str -> .encode(encoding, errors)
      - file-like (has .read) -> read all, return bytes
      - int -> encode its decimal string (avoid bytes(int) => NULs)
      - other -> try __bytes__, else str(...).encode(...)
    """
    if data is None:
        return b""

    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)

    if isinstance(data, unicode):
        return data.encode(encoding, errors)

    # file-like: read its content
    if hasattr(data, "read"):
        chunk = data.read()
        return bytes(chunk) if isinstance(chunk, (bytes, bytearray, memoryview)) else (
            (chunk if isinstance(chunk, unicode) else str(chunk)).encode(encoding, errors)
        )

    # avoid bytes(int) => NUL padding
    if isinstance(data, int):
        return str(data).encode(encoding, errors)

    # prefer __bytes__ when available
    to_bytes = getattr(data, "__bytes__", None)
    if callable(to_bytes):
        try:
            return bytes(data)
        except Exception:
            pass

    # fallback: string form
    return (data if isinstance(data, unicode) else str(data)).encode(encoding, errors)


def _to_text(s, encoding="utf-8", errors="replace", normalize=None, prefer_surrogates=False):
    """
    Coerce `s` to a text/unicode string safely.

    Args:
      s: Any object (bytes/bytearray/memoryview/str/unicode/other).
      encoding: Used when decoding bytes-like objects (default: 'utf-8').
      errors: Decoding error policy (default: 'replace').
              Consider 'surrogateescape' when you need byte-preserving round-trip on Py3.
      normalize: Optional unicode normalization form, e.g. 'NFC', 'NFKC', 'NFD', 'NFKD'.
      prefer_surrogates: If True on Py3 and errors is the default, use 'surrogateescape'
                         to preserve undecodable bytes.

    Returns:
      A text string (unicode on Py2, str on Py3).
    """
    # Fast path: already text
    if isinstance(s, unicode):
        out = s
    else:
        # Bytes-like → decode
        if isinstance(s, (bytes, bytearray, memoryview)):
            b = s if isinstance(s, (bytes, bytearray)) else bytes(s)
            # Prefer surrogateescape on Py3 if requested (keeps raw bytes round-tripable)
            eff_errors = errors
            if prefer_surrogates and errors == "replace":
                try:
                    # Only available on Py3
                    "".encode("utf-8", "surrogateescape")
                    eff_errors = "surrogateescape"
                except LookupError:
                    pass
            try:
                out = b.decode(encoding, eff_errors)
            except Exception:
                # Last-resort: decode with 'latin-1' to avoid exceptions
                out = b.decode("latin-1", "replace")
        else:
            # Not bytes-like: stringify
            try:
                # Py2: many objects implement __unicode__
                if hasattr(s, "__unicode__"):
                    out = s.__unicode__()  # noqa: E1101 (only on Py2 objects)
                else:
                    out = unicode(s)
            except Exception:
                # Fallback to repr() if object’s __str__/__unicode__ is broken
                out = unicode(repr(s))

    # Optional normalization
    if normalize:
        try:
            import unicodedata
            out = unicodedata.normalize(normalize, out)
        except Exception:
            # Keep original if normalization fails
            pass

    return out

def _quote_path_for_wire(path_text):
    # Percent-encode as UTF-8; return ASCII bytes text
    try:
        from urllib.parse import quote
        return quote(path_text.encode('utf-8'))
    except Exception:
        try:
            from urllib import quote as _q
            return _q(path_text.encode('utf-8'))
        except Exception:
            return ''.join(ch for ch in path_text if ord(ch) < 128)

def _unquote_path_from_wire(s_bytes):
    # s_bytes: bytes → return text/unicode
    try:
        from urllib.parse import unquote
        txt = unquote(s_bytes.decode('ascii', 'replace'))
        return _to_text(txt)
    except Exception:
        try:
            from urllib import unquote as _uq
            txt = _uq(s_bytes.decode('ascii', 'replace'))
            return _to_text(txt)
        except Exception:
            return _to_text(s_bytes)

def _recv_line(sock, maxlen=4096, timeout=None):
    """TCP: read a single LF-terminated line (bytes). Returns None on timeout/EOF."""
    if timeout is not None:
        try: sock.settimeout(timeout)
        except Exception: pass
    buf = bytearray()
    while True:
        try:
            b = sock.recv(1)
        except socket.timeout:
            return None
        if not b:
            break
        buf += b
        if b == b'\n' or len(buf) >= maxlen:
            break
    return bytes(buf)

# ---------- TLS helpers (TCP only) ----------
def _ssl_available():
    try:
        import ssl  # noqa
        return True
    except Exception:
        return False

def _build_ssl_context(server_side=False, verify=True, ca_file=None, certfile=None, keyfile=None):
    import ssl
    create_ctx = getattr(ssl, "create_default_context", None)
    SSLContext = getattr(ssl, "SSLContext", None)
    Purpose    = getattr(ssl, "Purpose", None)
    if create_ctx and Purpose:
        ctx = create_ctx(ssl.Purpose.CLIENT_AUTH if server_side else ssl.Purpose.SERVER_AUTH)
    elif SSLContext:
        ctx = SSLContext(getattr(ssl, "PROTOCOL_TLS", getattr(ssl, "PROTOCOL_SSLv23")))
    else:
        return None

    if hasattr(ctx, "check_hostname") and not server_side:
        ctx.check_hostname = bool(verify)

    if verify:
        if hasattr(ctx, "verify_mode"):
            ctx.verify_mode = getattr(ssl, "CERT_REQUIRED", 2)
        if ca_file:
            try: ctx.load_verify_locations(cafile=ca_file)
            except Exception: pass
        else:
            load_default_certs = getattr(ctx, "load_default_certs", None)
            if load_default_certs: load_default_certs()
    else:
        if hasattr(ctx, "verify_mode"):
            ctx.verify_mode = getattr(ssl, "CERT_NONE", 0)
        if hasattr(ctx, "check_hostname"):
            ctx.check_hostname = False

    if certfile:
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile or None)

    try:
        ctx.set_ciphers("HIGH:!aNULL:!MD5:!RC4")
    except Exception:
        pass
    return ctx

def _ssl_wrap_socket(sock, server_side=False, server_hostname=None,
                     verify=True, ca_file=None, certfile=None, keyfile=None):
    import ssl
    ctx = _build_ssl_context(server_side, verify, ca_file, certfile, keyfile)
    if ctx is not None:
        kwargs = {}
        if not server_side and getattr(ssl, "HAS_SNI", False) and server_hostname:
            kwargs["server_hostname"] = server_hostname
        return ctx.wrap_socket(sock, server_side=server_side, **kwargs)
    # Very old Python fallback
    kwargs = {
        "ssl_version": getattr(ssl, "PROTOCOL_TLS", getattr(ssl, "PROTOCOL_SSLv23")),
        "certfile": certfile or None,
        "keyfile":  keyfile  or None,
        "cert_reqs": (getattr(ssl, "CERT_REQUIRED", 2) if (verify and ca_file) else getattr(ssl, "CERT_NONE", 0)),
    }
    if verify and ca_file:
        kwargs["ca_certs"] = ca_file
    return ssl.wrap_socket(sock, **kwargs)

# ---------- IPv6 / multi-A dialer + keepalive ----------
def _enable_keepalive(s, idle=60, intvl=15, cnt=4):
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, 'TCP_KEEPIDLE'):
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, idle)
        if hasattr(socket, 'TCP_KEEPINTVL'):
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, intvl)
        if hasattr(socket, 'TCP_KEEPCNT'):
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, cnt)
    except Exception:
        pass

def _connect_stream(host, port, timeout):
    err = None
    for fam, st, proto, _, sa in socket.getaddrinfo(host, int(port), 0, socket.SOCK_STREAM):
        try:
            s = socket.socket(fam, st, proto)
            if timeout is not None:
                s.settimeout(timeout)
            try: s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception: pass
            s.connect(sa)
            _enable_keepalive(s)
            return s
        except Exception as e:
            err = e
            try: s.close()
            except Exception: pass
    if err: raise err
    raise RuntimeError("no usable address")

# ---------- Auth: AF1 (HMAC) + legacy fallback ----------
# AF1: single ASCII line ending with '\n':
#   AF1 ts=<unix> user=<b64url> nonce=<b64url_12B> scope=<b64url> alg=sha256 mac=<hex>\n
def _b64url_encode(b):
    s = base64.urlsafe_b64encode(b)
    return _to_text(s.rstrip(b'='))

def _b64url_decode(s):
    s = _to_bytes(s)
    pad = b'=' * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _auth_msg(ts_int, user_utf8, nonce_bytes, scope_utf8, length_str, sha_hex):
    # canonical message for MAC: v1|ts|user|nonce_b64|scope|len|sha
    return _to_bytes("v1|%d|%s|%s|%s|%s|%s" % (
        ts_int,
        _to_text(user_utf8),
        _b64url_encode(nonce_bytes),
        _to_text(scope_utf8),
        length_str if length_str is not None else "",
        sha_hex if sha_hex is not None else "",
    ))

def build_auth_blob_v1(user, secret, scope=u"", now=None, length=None, sha_hex=None):
    """
    user: text; secret: text/bytes (HMAC key)
    scope: optional text (e.g., path)
    length: int or None (payload bytes)
    sha_hex: ascii hex SHA-256 of payload (optional)
    """
    ts = int(time.time() if now is None else now)
    user_b  = _to_bytes(user or u"")
    scope_b = _to_bytes(scope or u"")
    key_b   = _to_bytes(secret or u"")
    nonce   = os.urandom(12)

    length_str = (str(int(length)) if (length is not None and int(length) >= 0) else "")
    sha_hex = (sha_hex or None)
    mac = hmac.new(
        key_b,
        _auth_msg(ts, user_b, nonce, scope_b, length_str, sha_hex),
        hashlib.sha256
    ).hexdigest()

    line = "AF1 ts=%d user=%s nonce=%s scope=%s len=%s sha=%s alg=sha256 mac=%s\n" % (
        ts,
        _b64url_encode(user_b),
        _b64url_encode(nonce),
        _b64url_encode(scope_b),
        length_str,
        (sha_hex or ""),
        mac,
    )
    return _to_bytes(line)

from collections import deque
class _NonceCache(object):
    def __init__(self, max_items=10000, ttl_seconds=600):
        self.max_items = int(max_items); self.ttl = int(ttl_seconds)
        self.q = deque(); self.s = set()
    def seen(self, nonce_b64, now_ts):
        # evict old / over-capacity
        while self.q and (now_ts - self.q[0][0] > self.ttl or len(self.q) > self.max_items):
            _, n = self.q.popleft(); self.s.discard(n)
        if nonce_b64 in self.s: return True
        self.s.add(nonce_b64); self.q.append((now_ts, nonce_b64))
        return False

_NONCES = _NonceCache()

def verify_auth_blob_v1(blob_bytes, expected_user=None, secret=None,
                        max_skew=600, expect_scope=None):
    """
    Returns (ok_bool, user_text, scope_text, reason_text, length_or_None, sha_hex_or_None)
    """
    try:
        line = _to_text(blob_bytes).strip()
        if not line.startswith("AF1 "):
            return (False, None, None, "bad magic", None, None)
        kv = {}
        for tok in line.split()[1:]:
            if '=' in tok:
                k, v = tok.split('=', 1); kv[k] = v

        for req in ("ts","user","nonce","mac","alg"):
            if req not in kv:
                return (False, None, None, "missing %s" % req, None, None)
        if kv["alg"].lower() != "sha256":
            return (False, None, None, "alg", None, None)

        ts    = int(kv["ts"])
        userb = _b64url_decode(kv["user"])
        nonce_b64 = kv["nonce"]; nonce = _b64url_decode(nonce_b64)
        scopeb = _b64url_decode(kv.get("scope","")) if kv.get("scope") else b""
        length_str = kv.get("len","")
        sha_hex    = kv.get("sha","") or None
        mac   = kv["mac"]

        now = int(time.time())
        if abs(now - ts) > int(max_skew):
            return (False, None, None, "skew", None, None)

        if _NONCES.seen(nonce_b64, now):
            return (False, None, None, "replay", None, None)

        if expected_user is not None and _to_bytes(expected_user) != userb:
            return (False, None, None, "user", None, None)

        calc = hmac.new(
            _to_bytes(secret or u""),
            _auth_msg(ts, userb, nonce, scopeb, length_str, sha_hex),
            hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(calc, mac):
            return (False, None, None, "mac", None, None)

        if expect_scope is not None and _to_bytes(expect_scope) != scopeb:
            return (False, None, None, "scope", None, None)

        length = int(length_str) if (length_str and length_str.isdigit()) else None
        return (True, _to_text(userb), _to_text(scopeb), "ok", length, sha_hex)
    except Exception as e:
        return (False, None, None, "exc:%s" % e, None, None)

# Legacy blob (kept for backward compatibility)
_MAGIC = b"AUTH\0"; _OK = b"OK"; _NO = b"NO"

def _build_auth_blob_legacy(user, pw):
    return _MAGIC + _to_bytes(user) + b"\0" + _to_bytes(pw) + b"\0"

def _parse_auth_blob_legacy(data):
    if not data.startswith(_MAGIC):
        return (None, None)
    rest = data[len(_MAGIC):]
    try:
        user, rest = rest.split(b"\0", 1)
        pw, _tail  = rest.split(b"\0", 1)
        return (user, pw)
    except Exception:
        return (None, None)

# ---------- URL helpers ----------
def _qflag(qs, key, default=False):
    v = qs.get(key, [None])[0]
    if v is None: return bool(default)
    return _to_text(v).lower() in ("1", "true", "yes", "on")

def _qnum(qs, key, default=None, cast=float):
    v = qs.get(key, [None])[0]
    if v is None or v == "": return default
    try: return cast(v)
    except Exception: return default

def _qstr(qs, key, default=None):
    v = qs.get(key, [None])[0]
    if v is None: return default
    return v

def _parse_net_url(url):
    parts = urlparse(url)
    qs = parse_qs(parts.query or "")

    proto = parts.scheme.lower()
    if proto not in ("tcp", "udp"):
        raise ValueError("Only tcp:// or udp:// supported here")

    user = unquote(parts.username) if parts.username else None
    pw   = unquote(parts.password) if parts.password else None

    use_ssl     = _qflag(qs, "ssl", False) if proto == "tcp" else False
    ssl_verify  = _qflag(qs, "verify", True)
    ssl_ca_file = _qstr(qs, "ca", None)
    ssl_cert    = _qstr(qs, "cert", None)
    ssl_key     = _qstr(qs, "key", None)

    timeout       = _qnum(qs, "timeout", None, float)
    total_timeout = _qnum(qs, "total_timeout", None, float)
    chunk_size    = int(_qnum(qs, "chunk", 65536, float))

    force_auth   = _qflag(qs, "auth", False)
    want_sha     = _qflag(qs, "sha", True)             # enable sha by default
    enforce_path = _qflag(qs, "enforce_path", True)    # enforce path by default


    # Reliable UDP (seq/ack) mode (enabled with ?seq=1 on udp:// URLs)
    udp_seq     = _qflag(qs, "seq", False) if proto == "udp" else False
    udp_window  = _qnum(qs, "window", 8, cast=int)
    udp_retries = _qnum(qs, "retries", 10, cast=int)
    udp_ack_timeout = _qnum(qs, "ack_timeout", None, cast=float)  # seconds; defaults to timeout if None
    udp_meta    = _qflag(qs, "meta", False) if proto == "udp" else False
    udp_sha256  = _qflag(qs, "sha256", False) if proto == "udp" else False
    save        = _qflag(qs, "save", False)
    overwrite   = _qflag(qs, "overwrite", False)
    save_dir    = _qstr(qs, "save_dir", None)
    print_url   = _qflag(qs, "print_url", False)
    bind        = _qstr(qs, "bind", None)
    done_retries = _qnum(qs, "done_retries", 2, cast=int)
    path_text = _to_text(parts.path or u"")

    opts = dict(
        proto=proto,
        host=parts.hostname or "127.0.0.1",
        port=int(parts.port or 0),

        user=user, pw=pw, force_auth=force_auth,

        use_ssl=use_ssl, ssl_verify=ssl_verify,
        ssl_ca_file=ssl_ca_file, ssl_certfile=ssl_cert, ssl_keyfile=ssl_key,

        timeout=timeout, total_timeout=total_timeout, chunk_size=chunk_size,

        server_hostname=parts.hostname or None,

        want_sha=want_sha,
        enforce_path=enforce_path,

        udp_seq=udp_seq,
        udp_window=udp_window,
        udp_retries=udp_retries,
        udp_ack_timeout=udp_ack_timeout,

        udp_meta=udp_meta,
        udp_sha256=udp_sha256,
        save=save,
        overwrite=overwrite,
        save_dir=save_dir,
        done_retries=done_retries,
        print_url=print_url,
        bind=bind,

        path=path_text,   # also used as AF1 "scope"
    )
    return parts, opts


def _rewrite_url_without_auth(url):
    u = urlparse(url)
    netloc = u.hostname or ''
    if u.port:
        netloc += ':' + str(u.port)
    rebuilt = urlunparse((u.scheme, netloc, u.path, u.params, u.query, u.fragment))
    usr = unquote(u.username) if u.username else ''
    pwd = unquote(u.password) if u.password else ''
    return rebuilt, usr, pwd

def _guess_filename(url, filename):
    if filename:
        return filename
    path = urlparse(url).path or ''
    base = os.path.basename(path)
    return base or 'CatFile'+__file_format_extension__

# ---- progress + rate limiting helpers ----
try:
    monotonic = time.monotonic  # Py3
except Exception:
    # Py2 fallback: time.time() is good enough for coarse throttling
    monotonic = time.time



def _auto_save_dir():
    """
    Best-effort download directory chooser (Android/Termux friendly).
    """
    candidates = [
        os.path.expanduser("~/storage/downloads"),
        os.path.expanduser("~/storage/shared/Download"),
        "/sdcard/Download",
        "/storage/emulated/0/Download",
        "/storage/emulated/0/Downloads",
        "/sdcard/Downloads",
        os.path.expanduser("~/Download"),
        os.path.expanduser("~/Downloads"),
    ]
    for p in candidates:
        try:
            if p and os.path.isdir(p) and os.access(p, os.W_OK):
                return p
        except Exception:
            pass
    try:
        if os.access(os.getcwd(), os.W_OK):
            return os.getcwd()
    except Exception:
        pass
    return None


def _resolve_save_dir(save_dir):
    if not save_dir:
        return None
    try:
        s = save_dir.strip()
    except Exception:
        s = save_dir
    try:
        if isinstance(s, bytes):
            s = s.decode("utf-8", "ignore")
    except Exception:
        pass
    if str(s).lower() == "auto":
        return _auto_save_dir()
    return s


def _ensure_dir(path):
    if not path:
        return None
    try:
        if not os.path.isdir(path):
            os.makedirs(path)
    except Exception:
        return None
    return path


def _choose_output_path(filename, overwrite=False, save_dir=None):
    filename = filename or "download.bin"
    save_dir = _ensure_dir(_resolve_save_dir(save_dir))
    base_path = os.path.join(save_dir, filename) if save_dir else filename
    if overwrite:
        return base_path
    if not os.path.exists(base_path):
        return base_path
    root, ext = os.path.splitext(base_path)
    i = 1
    while True:
        cand = "%s.%d%s" % (root, i, ext)
        if not os.path.exists(cand):
            return cand
        i += 1


def _autosave_fileobj(fileobj, out_path):
    try:
        fileobj.seek(0, 0)
    except Exception:
        pass
    with open(out_path, "wb") as out:
        shutil.copyfileobj(fileobj, out, 65536)
    try:
        fileobj.seek(0, 0)
    except Exception:
        pass
    return out_path
def _progress_tick(now_bytes, total_bytes, last_ts, last_bytes, rate_limit_bps, min_interval=0.1):
    """
    Returns (sleep_seconds, new_last_ts, new_last_bytes).
    - If rate_limit_bps is set, computes how long to sleep to keep average <= limit.
    - Also enforces a minimum interval between progress callbacks (handled by caller).
    """
    now = monotonic()
    elapsed = max(1e-9, now - last_ts)
    # Desired time to have elapsed for the given rate:
    desired = (now_bytes - last_bytes) / float(rate_limit_bps) if rate_limit_bps else 0.0
    extra = desired - elapsed
    return (max(0.0, extra), now, now_bytes)

def _discover_len_and_reset(fobj):
    """
    Try to get total length and restore original position.
    Returns (length_or_None, start_pos_or_None).
    """
    # Generic seek/tell
    try:
        pos0 = fobj.tell()
        fobj.seek(0, os.SEEK_END)
        end = fobj.tell()
        fobj.seek(pos0, os.SEEK_SET)
        if end is not None and pos0 is not None and end >= pos0:
            return (end - pos0, pos0)
    except Exception:
        pass
    # BytesIO fast path
    try:
        getvalue = getattr(fobj, "getvalue", None)
        if callable(getvalue):
            buf = getvalue()
            L = len(buf)
            try: pos0 = fobj.tell()
            except Exception: pos0 = 0
            return (max(0, L - pos0), pos0)
    except Exception:
        pass
    # Memoryview/getbuffer
    try:
        getbuffer = getattr(fobj, "getbuffer", None)
        if callable(getbuffer):
            mv = getbuffer()
            L = len(mv)
            try: pos0 = fobj.tell()
            except Exception: pos0 = 0
            return (max(0, L - pos0), pos0)
    except Exception:
        pass
    return (None, None)

# ---------- helpers reused from your module ----------
# expects: _to_bytes, _to_text, _discover_len_and_reset, _qflag, _qnum, _qstr
# If you don't have _qflag/_qnum/_qstr here, reuse your existing ones.

# =========================
# URL parser for HTTP/HTTPS
# =========================
def _parse_http_url(url):
    parts = urlparse(url)
    qs = parse_qs(parts.query or "")

    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError("Only http:// or https:// supported here")

    host = parts.hostname or "127.0.0.1"
    port = int(parts.port or (443 if scheme == "https" else 80))
    user = parts.username
    pw   = parts.password
    path = _to_text(parts.path or u"/")

    chunk_size    = int(_qnum(qs, "chunk", 65536, float))
    want_sha      = _qflag(qs, "sha", True)
    enforce_path  = _qflag(qs, "enforce_path", True)
    force_auth    = _qflag(qs, "auth", False)
    mime          = _qstr(qs, "mime", "application/octet-stream")
    certfile      = _qstr(qs, "cert", None)
    keyfile       = _qstr(qs, "key", None)
    timeout       = _qnum(qs, "timeout", None, float)
    rate_limit    = _qnum(qs, "rate", None, float)
    wait_seconds  = _qnum(qs, "wait", None, float)      # <-- NEW

    hdrs = _parse_headers_from_qs(qs)

    return parts, dict(
        scheme=scheme, host=host, port=port,
        user=user, pw=pw, path=path,
        chunk_size=chunk_size, want_sha=want_sha,
        enforce_path=enforce_path,
        require_auth=(force_auth or (user is not None or pw is not None)),
        mime=mime,
        certfile=certfile, keyfile=keyfile,
        timeout=timeout,
        rate_limit_bps=(int(rate_limit) if rate_limit else None),
        extra_headers=hdrs,
        wait_seconds=wait_seconds,             # <-- NEW
    )

def _basic_ok(auth_header, expect_user, expect_pass):
    """
    Check HTTP Basic auth header "Basic base64(user:pass)".
    return True/False
    """
    if not auth_header or not auth_header.strip().lower().startswith("basic "):
        return False
    try:
        b64 = auth_header.strip().split(" ", 1)[1]
        raw = base64.b64decode(_to_bytes(b64))
        # raw may be bytes like b"user:pass"
        try:
            raw_txt = raw.decode("utf-8")
        except Exception:
            raw_txt = raw.decode("latin-1", "replace")
        if ":" not in raw_txt:
            return False
        u, p = raw_txt.split(":", 1)
        if expect_user is not None and u != _to_text(expect_user):
            return False
        if expect_pass is not None and p != _to_text(expect_pass):
            return False
        return True
    except Exception:
        return False

_HEX_RE = re.compile(r'^[0-9a-fA-F]{32,}$')  # len>=32 keeps it simple; SHA-256 is 64

def _int_or_none(v):
    try:
        return int(v)
    except Exception:
        return None

def _strip_quotes(s):
    if s and len(s) >= 2 and s[0] == s[-1] == '"':
        return s[1:-1]
    return s

def _is_hexish(s):
    return bool(s) and bool(_HEX_RE.match(s))

def _pick_expected_len(headers):
    # Prefer explicit X-File-Length, then Content-Length
    xlen = headers.get('X-File-Length') or headers.get('x-file-length')
    clen = headers.get('Content-Length') or headers.get('content-length')
    return _int_or_none(xlen) or _int_or_none(clen)

def _pick_expected_sha(headers):
    # Prefer X-File-SHA256; otherwise, a strong ETag that looks like hex
    sha = headers.get('X-File-SHA256') or headers.get('x-file-sha256')
    if sha:
        return _strip_quotes(sha).lower()
    etag = headers.get('ETag') or headers.get('etag')
    if etag:
        etag = _strip_quotes(etag)
        if _is_hexish(etag):
            return etag.lower()
    return None

def _headers_dict_from_response(resp, lib):
    """
    Return a case-sensitive dict-like of headers turned into a plain dict for all libs.
    lib in {'requests','httpx','mechanize','urllib'}
    """
    if lib == 'requests':
        # Case-insensitive dict; items() yields canonicalized keys
        return dict(resp.headers or {})
    if lib == 'httpx':
        return dict(resp.headers or {})
    if lib == 'mechanize':
        # mechanize response.info() returns an email.message.Message-like
        info = getattr(resp, 'info', lambda: None)()
        if info:
            return dict(info.items())
        return {}
    if lib == 'urllib':
        info = getattr(resp, 'info', lambda: None)()
        if info:
            return dict(info.items())
        return {}
    return {}

def _stream_copy_and_verify(src_iter, dst_fp, expected_len=None, expected_sha=None, chunk_size=65536):
    """
    src_iter yields bytes; we copy to dst_fp and (optionally) verify length/SHA-256.
    Returns total bytes written.
    """
    h = hashlib.sha256() if expected_sha else None
    total = 0
    for chunk in src_iter:
        if not chunk:
            continue
        b = _to_bytes(chunk)
        if h is not None:
            h.update(b)
        dst_fp.write(b)
        total += len(b)
    try:
        dst_fp.flush()
    except Exception:
        pass

    if expected_len is not None and total != expected_len:
        raise IOError("HTTP length mismatch: got %d bytes, expected %d" % (total, expected_len))

    if expected_sha is not None and h is not None:
        got = h.hexdigest().lower()
        if got != expected_sha.lower():
            raise IOError("HTTP SHA-256 mismatch: got %s expected %s" % (got, expected_sha))
    return total

def _parse_headers_from_qs(qs):
    """
    Supports:
      h=Name: Value (repeatable) / header=...
      headers=Name1: Val1|Name2: Val2       (| delimited)
      hjson={"Name":"Val","X-Any":"Thing"}  (JSON object)
    Returns a plain dict (last wins on duplicate keys).
    """
    hdrs = {}

    def _add_line(line):
        if not line:
            return
        parts = line.split(":", 1)  # only first colon splits
        if len(parts) != 2:
            return
        k = parts[0].strip()
        v = parts[1].strip()
        if k:
            hdrs[_to_text(k)] = _to_text(v)

    # repeatable h= / header=
    for key in ("h", "header"):
        for v in qs.get(key, []):
            _add_line(v)

    # headers=Name1: Val1|Name2: Val2
    for v in qs.get("headers", []):
        if not v:
            continue
        for seg in v.split("|"):
            _add_line(seg)

    # hjson=JSON  (uses your global 'json' import: ujson/simplejson/json)
    for v in qs.get("hjson", []):
        if not v:
            continue
        try:
            obj = json.loads(v)
            if isinstance(obj, dict):
                for k, vv in obj.items():
                    if k:
                        hdrs[_to_text(k)] = _to_text(vv)
        except Exception:
            # ignore malformed JSON silently
            pass

    return hdrs


def _pace_rate(last_ts, sent_bytes_since_ts, rate_limit_bps, add_bytes):
    """
    Simple average-rate pacing. Returns (sleep_seconds, new_last_ts, new_sent_since_ts).
    """
    if not rate_limit_bps or rate_limit_bps <= 0:
        return (0.0, last_ts, sent_bytes_since_ts)
    now = time.time()
    # accumulate
    sent_bytes_since_ts += add_bytes
    elapsed = max(1e-6, now - last_ts)
    cur_bps = sent_bytes_since_ts / elapsed
    sleep_s = 0.0
    if cur_bps > rate_limit_bps:
        # how much time needed at least to bring avg down?
        sleep_s = max(0.0, (sent_bytes_since_ts / float(rate_limit_bps)) - elapsed)
        # cap sleep to reasonable chunk to avoid long stalls
        if sleep_s > 0.25:
            sleep_s = 0.25
    # roll window occasionally to keep numbers small
    if elapsed >= 1.0:
        last_ts = now
        sent_bytes_since_ts = 0
    return (sleep_s, last_ts, sent_bytes_since_ts)

def MkTempFile(data=None,
               inmem=__use_inmem__, usememfd=__use_memfd__,
               isbytes=True,
               prefix=__program_name__,
               delete=True,
               encoding="utf-8",
               newline=None,
               text_errors="strict",
               dir=None,
               suffix="",
               use_spool=__use_spoolfile__,
               autoswitch_spool=False,
               spool_max=__spoolfile_size__,
               spool_dir=__use_spooldir__,
               reset_to_start=True,
               memfd_name=__program_name__,
               memfd_allow_sealing=False,
               memfd_flags_extra=0,
               on_create=None):
    """
    Return a file-like handle with consistent behavior on Py2.7 and Py3.x.

    Storage:
      - inmem=True, usememfd=True, isbytes=True and memfd available
            -> memfd-backed anonymous file (binary)
      - inmem=True, otherwise
            -> BytesIO (bytes) or StringIO (text)
      - inmem=False, use_spool=True
            -> SpooledTemporaryFile (binary), optionally TextIOWrapper for text
      - inmem=False, use_spool=False
            -> NamedTemporaryFile (binary), optionally TextIOWrapper for text

    Text vs bytes:
      - isbytes=True  -> file expects bytes; 'data' must be bytes-like
      - isbytes=False -> file expects text; 'data' must be text (unicode/str). Newline translation and
                         encoding apply only for spooled/named files (not BytesIO/StringIO).

    Notes:
      - On Windows, NamedTemporaryFile(delete=True) keeps the file open and cannot be reopened by
        other processes. Use delete=False if you need to pass the path elsewhere.
      - For text: in-memory StringIO ignores 'newline' and 'text_errors' (as usual).
      - When available, and if usememfd=True, memfd is used only for inmem=True and isbytes=True,
        providing an anonymous in-memory file descriptor (Linux-only). Text in-memory still uses
        StringIO to preserve newline semantics.
      - If autoswitch_spool=True and initial data size exceeds spool_max, in-memory storage is
        skipped and a spooled file is used instead (if use_spool=True).
      - If on_create is not None, it is called as on_create(fp, kind) where kind is one of:
        "memfd", "bytesio", "stringio", "spool", "disk".
    """

    # -- sanitize simple params (avoid None surprises) --
    prefix = prefix or ""
    suffix = suffix or ""
    # dir/spool_dir may be None (allowed)

    # -- normalize initial data to the right type early --
    if data is not None:
        if isbytes:
            # Require a bytes-like; convert common cases safely
            if isinstance(data, (bytearray, memoryview)):
                init = bytes(data)
            elif isinstance(data, bytes):
                init = data
            elif isinstance(data, str):
                # Py3 str or Py2 unicode: encode using 'encoding'
                init = data.encode(encoding)
            else:
                raise TypeError("data must be bytes-like for isbytes=True")
        else:
            # Require text (unicode/str); convert common cases safely
            if isinstance(data, (bytes, bytearray, memoryview)):
                init = bytes(data).decode(encoding, errors="strict")
            elif isinstance(data, str):
                init = data
            else:
                raise TypeError("data must be text (str/unicode) for isbytes=False")
    else:
        init = None

    # Size of init for autoswitch; only meaningful for bytes
    init_len = len(init) if (init is not None and isbytes) else None

    # -------- In-memory --------
    if inmem:
        # If autoswitch is enabled and data is larger than spool_max, and
        # spooling is allowed, skip the in-memory branch and fall through
        # to the spool/disk logic below.
        if autoswitch_spool and use_spool and init_len is not None and init_len > spool_max:
            pass  # fall through to spool/disk sections
        else:
            # Use memfd only for bytes, and only where available (Linux, Python 3.8+)
            if usememfd and isbytes and hasattr(os, "memfd_create"):
                name = memfd_name or prefix or "MkTempFile"
                flags = 0
                # Close-on-exec is almost always what you want for temps
                if hasattr(os, "MFD_CLOEXEC"):
                    flags |= os.MFD_CLOEXEC
                # Optional sealing support if requested and available
                if memfd_allow_sealing and hasattr(os, "MFD_ALLOW_SEALING"):
                    flags |= os.MFD_ALLOW_SEALING
                # Extra custom flags (e.g. hugepage flags) if caller wants them
                if memfd_flags_extra:
                    flags |= memfd_flags_extra

                fd = os.memfd_create(name, flags)
                # Binary read/write file-like object backed by RAM
                f = os.fdopen(fd, "w+b")

                if init is not None:
                    f.write(init)
                if reset_to_start:
                    f.seek(0)

                if on_create is not None:
                    on_create(f, "memfd")
                return f

            # Fallback: pure Python in-memory objects
            if isbytes:
                f = io.BytesIO(init if init is not None else b"")
                kind = "bytesio"
            else:
                # newline/text_errors not enforced for StringIO; matches stdlib semantics
                f = io.StringIO(init if init is not None else "")
                kind = "stringio"

            if reset_to_start:
                f.seek(0)

            if on_create is not None:
                on_create(f, kind)
            return f

    # Helper: wrap a binary file into a text file with encoding/newline
    def _wrap_text(handle):
        # For both Py2 & Py3, TextIOWrapper gives consistent newline/encoding behavior
        return io.TextIOWrapper(handle, encoding=encoding,
                                newline=newline, errors=text_errors)

    # -------- Spooled (RAM then disk) --------
    if use_spool:
        # Always create binary spooled file; wrap for text if needed
        bin_mode = "w+b"  # read/write, binary
        b = tempfile.SpooledTemporaryFile(max_size=spool_max, mode=bin_mode, dir=spool_dir)
        f = b if isbytes else _wrap_text(b)

        if init is not None:
            f.write(init)
            if reset_to_start:
                f.seek(0)
        elif reset_to_start:
            f.seek(0)

        if on_create is not None:
            on_create(f, "spool")
        return f

    # -------- On-disk temp (NamedTemporaryFile) --------
    # Always create binary file; wrap for text if needed for uniform Py2/3 behavior
    b = tempfile.NamedTemporaryFile(mode="w+b", prefix=prefix, suffix=suffix,
                                    dir=dir, delete=delete)
    f = b if isbytes else _wrap_text(b)

    if init is not None:
        f.write(init)
        if reset_to_start:
            f.seek(0)
    elif reset_to_start:
        f.seek(0)

    if on_create is not None:
        on_create(f, "disk")
    return f

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

def download_file_from_ftp_file(url):
    urlparts = urlparse(url)
    file_name = os.path.basename(unquote(urlparts.path))
    file_dir = os.path.dirname(unquote(urlparts.path))
    if(urlparts.username is not None):
        ftp_username = unquote(urlparts.username)
    else:
        ftp_username = "anonymous"
    if(urlparts.password is not None):
        ftp_password = unquote(urlparts.password)
    elif(urlparts.password is None and urlparts.username == "anonymous"):
        ftp_password = "anonymous"
    else:
        ftp_password = ""
    if(urlparts.scheme == "ftp"):
        ftp = FTP()
    elif(urlparts.scheme == "ftps" and ftpssl):
        ftp = FTP_TLS()
    else:
        return False
    ftp_port = urlparts.port
    if(urlparts.port is None):
        ftp_port = 21
    try:
        ftp.connect(urlparts.hostname, ftp_port)
    except (socket.gaierror, socket.timeout):
        log.info("Error With URL "+url)
        return False
    if(urlparts.scheme == "ftps" or isinstance(ftp, FTP_TLS)):
        try:
            ftp.auth()
        except all_errors:
            pass
    ftp.login(ftp_username, ftp_password)
    if(urlparts.scheme == "ftps" or isinstance(ftp, FTP_TLS)):
        try:
            ftp.prot_p()
        except all_errors:
            ftp.prot_c()
    # UTF-8 filenames if supported
    try:
        ftp.sendcmd("OPTS UTF8 ON")
        ftp.encoding = "utf-8"
    except all_errors:
        pass
    is_cwd_allowed = detect_cwd(ftp, file_dir)
    ftpfile = MkTempFile()
    # Try EPSV first, then fall back
    try:
        ftp.force_epsv = True
        ftp.sendcmd("EPSV")   # request extended passive
        if(is_cwd_allowed):
            ftp.retrbinary("RETR "+file_name, ftpfile.write)
        else:
            ftp.retrbinary("RETR "+unquote(urlparts.path), ftpfile.write)
    except all_errors:
        try:
            ftp.set_pasv(True)
            if(is_cwd_allowed):
                ftp.retrbinary("RETR "+file_name, ftpfile.write)
            else:
                ftp.retrbinary("RETR "+unquote(urlparts.path), ftpfile.write)
        except all_errors:
            ftp.set_pasv(False)
            if(is_cwd_allowed):
                ftp.retrbinary("RETR "+file_name, ftpfile.write)
            else:
                ftp.retrbinary("RETR "+unquote(urlparts.path), ftpfile.write)
    ftp.close()
    ftpfile.seek(0, 0)
    return ftpfile


def download_file_from_ftps_file(url):
    return download_file_from_ftp_file(url)


def download_file_from_ftp_string(url):
    ftpfile = download_file_from_ftp_file(url)
    ftpout = ftpfile.read()
    ftpfile.close()
    return ftpout


def download_file_from_ftps_string(url):
    return download_file_from_ftp_string(url)


def upload_file_to_ftp_file(ftpfile, url):
    urlparts = urlparse(url)
    file_name = os.path.basename(unquote(urlparts.path))
    file_dir = os.path.dirname(unquote(urlparts.path))
    if(urlparts.username is not None):
        ftp_username = unquote(urlparts.username)
    else:
        ftp_username = "anonymous"
    if(urlparts.password is not None):
        ftp_password = unquote(urlparts.password)
    elif(urlparts.password is None and urlparts.username == "anonymous"):
        ftp_password = "anonymous"
    else:
        ftp_password = ""
    if(urlparts.scheme == "ftp"):
        ftp = FTP()
    elif(urlparts.scheme == "ftps" and ftpssl):
        ftp = FTP_TLS()
    else:
        return False
    ftp_port = urlparts.port
    if(urlparts.port is None):
        ftp_port = 21
    try:
        ftp.connect(urlparts.hostname, ftp_port)
    except (socket.gaierror, socket.timeout):
        log.info("Error With URL "+url)
        return False
    if(urlparts.scheme == "ftps" or isinstance(ftp, FTP_TLS)):
        try:
            ftp.auth()
        except all_errors:
            pass
    ftp.login(ftp_username, ftp_password)
    if(urlparts.scheme == "ftps" or isinstance(ftp, FTP_TLS)):
        try:
            ftp.prot_p()
        except all_errors:
            ftp.prot_c()
    # UTF-8 filenames if supported
    try:
        ftp.sendcmd("OPTS UTF8 ON")
        ftp.encoding = "utf-8"
    except all_errors:
        pass
    is_cwd_allowed = detect_cwd(ftp, file_dir)
    ftpfile.seek(0, 0)
    # Try EPSV first, then fall back
    try:
        ftp.force_epsv = True
        ftp.sendcmd("EPSV")   # request extended passive
        if(is_cwd_allowed):
            ftp.storbinary("STOR "+file_name, ftpfile)
        else:
            ftp.storbinary("STOR "+unquote(urlparts.path), ftpfile)
    except all_errors:
        try:
            ftp.set_pasv(True)
            if(is_cwd_allowed):
                ftp.storbinary("STOR "+file_name, ftpfile)
            else:
                ftp.storbinary("STOR "+unquote(urlparts.path), ftpfile)
        except all_errors:
            ftp.set_pasv(False)
            if(is_cwd_allowed):
                ftp.storbinary("STOR "+file_name, ftpfile)
            else:
                ftp.storbinary("STOR "+unquote(urlparts.path), ftpfile)
    ftp.close()
    ftpfile.seek(0, 0)
    return ftpfile


def upload_file_to_ftps_file(ftpfile, url):
    return upload_file_to_ftp_file(ftpfile, url)


def upload_file_to_ftp_string(ftpstring, url):
    ftpfileo = MkTempFile(ftpstring)
    ftpfile = upload_file_to_ftp_file(ftpfileo, url)
    ftpfileo.close()
    return ftpfile


def upload_file_to_ftps_string(ftpstring, url):
    return upload_file_to_ftp_string(ftpstring, url)


class RawIteratorWrapper:
    def __init__(self, iterator):
        self.iterator = iterator
        self.buffer = b""
        self._iterator_exhausted = False

    def read(self, size=-1):
        if self._iterator_exhausted:
            return b''
        while size < 0 or len(self.buffer) < size:
            try:
                chunk = next(self.iterator)
                self.buffer += chunk
            except StopIteration:
                self._iterator_exhausted = True
                break
        if size < 0:
            size = len(self.buffer)
        result, self.buffer = self.buffer[:size], self.buffer[size:]
        return result


def download_file_from_http_file(url, headers=None, usehttp=__use_http_lib__):
    if headers is None:
        headers = {}
    urlparts = urlparse(url)
    if(urlparts.username is not None):
        username = unquote(urlparts.username)
    else:
        username = None
    if(urlparts.password is not None):
        password = unquote(urlparts.password)
    else:
        password = None
    # Rebuild URL without username and password
    netloc = urlparts.hostname or ''
    if urlparts.port:
        netloc += ':' + str(urlparts.port)
    rebuilt_url = urlunparse((urlparts.scheme, netloc, urlparts.path,
                              urlparts.params, urlparts.query, urlparts.fragment))

    # Create a temporary file object
    httpfile = MkTempFile()

    # 1) Requests branch
    if usehttp == 'requests' and haverequests:
        if username and password:
            response = requests.get(
                rebuilt_url, headers=headers, auth=(username, password), timeout=(5, 30), stream=True
            )
        else:
            response = requests.get(rebuilt_url, headers=headers, timeout=(5, 30), stream=True)
        response.raw.decode_content = True
        shutil.copyfileobj(response.raw, httpfile, length=__filebuff_size__)

    # 2) HTTPX branch
    elif usehttp == 'httpx' and havehttpx:
        with httpx.Client(follow_redirects=True) as client:
            if username and password:
                response = client.get(
                    rebuilt_url, headers=headers, auth=(username, password)
                )
            else:
                response = client.get(rebuilt_url, headers=headers)
            raw_wrapper = RawIteratorWrapper(response.iter_bytes())
            shutil.copyfileobj(raw_wrapper, httpfile, length=__filebuff_size__)

    # 3) Mechanize branch
    elif usehttp == 'mechanize' and havemechanize:
        # Create a mechanize browser
        br = mechanize.Browser()
        # Optional: configure mechanize (disable robots.txt, handle redirects, etc.)
        br.set_handle_robots(False)
        # If you need custom headers, add them as a list of (header_name, header_value)
        if headers:
            br.addheaders = list(headers.items())

        # If you need to handle basic auth:
        if username and password:
            # Mechanize has its own password manager; this is one way to do it:
            br.add_password(rebuilt_url, username, password)

        # Open the URL and copy the response to httpfile
        response = br.open(rebuilt_url)
        shutil.copyfileobj(response, httpfile, length=__filebuff_size__)

    # 4) Fallback to urllib
    else:
        request = Request(rebuilt_url, headers=headers)
        if username and password:
            password_mgr = HTTPPasswordMgrWithDefaultRealm()
            password_mgr.add_password(None, rebuilt_url, username, password)
            auth_handler = HTTPBasicAuthHandler(password_mgr)
            opener = build_opener(auth_handler)
        else:
            opener = build_opener()
        response = opener.open(request)
        shutil.copyfileobj(response, httpfile, length=__filebuff_size__)

    # Reset file pointer to the start before returning
    httpfile.seek(0, 0)
    return httpfile


def upload_file_to_http_file(
    fileobj,
    url,
    method="POST",                 # "POST" or "PUT"
    headers=None,
    form=None,                     # dict of extra form fields → triggers multipart/form-data
    field_name="file",             # form field name for the file content
    filename=None,                 # defaults to basename of URL path
    content_type="application/octet-stream",
    usehttp=__use_http_lib__,      # 'requests' | 'httpx' | 'mechanize' | anything → urllib fallback
):
    """
    Py2+Py3 compatible HTTP/HTTPS upload.

    - If `form` is provided (dict), uses multipart/form-data:
        * text fields from `form`
        * file part named by `field_name` with given `filename` and `content_type`
    - If `form` is None, uploads raw body as POST/PUT with Content-Type.
    - Returns True on HTTP 2xx, else False.
    """
    if headers is None:
        headers = {}
    method = (method or "POST").upper()

    rebuilt_url, username, password = _rewrite_url_without_auth(url)
    filename = _guess_filename(url, filename)

    # rewind if possible
    try:
        fileobj.seek(0)
    except Exception:
        pass

    # ========== 1) requests (Py2+Py3) ==========
    if usehttp == 'requests' and haverequests:
        import requests

        auth = (username, password) if (username or password) else None

        if form is not None:
            # multipart/form-data
            files = {field_name: (filename, fileobj, content_type)}
            data = form or {}
            resp = requests.request(method, rebuilt_url, headers=headers, auth=auth,
                                    files=files, data=data, timeout=(5, 120))
        else:
            # raw body
            hdrs = {'Content-Type': content_type}
            hdrs.update(headers)
            # best-effort content-length (helps some servers)
            if hasattr(fileobj, 'seek') and hasattr(fileobj, 'tell'):
                try:
                    cur = fileobj.tell()
                    fileobj.seek(0, io.SEEK_END if hasattr(io, 'SEEK_END') else 2)
                    size = fileobj.tell() - cur
                    fileobj.seek(cur)
                    hdrs.setdefault('Content-Length', str(size))
                except Exception:
                    pass
            resp = requests.request(method, rebuilt_url, headers=hdrs, auth=auth,
                                    data=fileobj, timeout=(5, 300))

        return (200 <= resp.status_code < 300)

    # ========== 2) httpx (Py3 only) ==========
    if usehttp == 'httpx' and havehttpx and not PY2:
        import httpx
        auth = (username, password) if (username or password) else None

        with httpx.Client(follow_redirects=True, timeout=60) as client:
            if form is not None:
                files = {field_name: (filename, fileobj, content_type)}
                data  = form or {}
                resp = client.request(method, rebuilt_url, headers=headers, auth=auth,
                                      files=files, data=data)
            else:
                hdrs = {'Content-Type': content_type}
                hdrs.update(headers)
                resp = client.request(method, rebuilt_url, headers=hdrs, auth=auth,
                                      content=fileobj)
        return (200 <= resp.status_code < 300)

    # ========== 3) mechanize (forms) → prefer requests if available ==========
    if usehttp == 'mechanize' and havemechanize:
        # mechanize is great for HTML forms, but file upload requires form discovery.
        # For a generic upload helper, prefer requests. If not available, fall through.
        try:
            import requests  # noqa
            # delegate to requests path to ensure robust multipart handling
            return upload_file_to_http_file(
                fileobj, url, method=method, headers=headers,
                form=(form or {}), field_name=field_name,
                filename=filename, content_type=content_type,
                usehttp='requests'
            )
        except Exception:
            pass  # fall through to urllib

    # ========== 4) urllib fallback (Py2+Py3) ==========
    # multipart builder (no f-strings)
    boundary = ('----pyuploader-%s' % uuid.uuid4().hex)

    if form is not None:
        # Build multipart body to a temp file-like (your MkTempFile())
        buf = MkTempFile()

        def _w(s):
            buf.write(_to_bytes(s))

        # text fields
        if form:
            for k, v in form.items():
                _w('--' + boundary + '\r\n')
                _w('Content-Disposition: form-data; name="%s"\r\n\r\n' % k)
                _w('' if v is None else (v if isinstance(v, (str, bytes)) else str(v)))
                _w('\r\n')

        # file field
        _w('--' + boundary + '\r\n')
        _w('Content-Disposition: form-data; name="%s"; filename="%s"\r\n' % (field_name, filename))
        _w('Content-Type: %s\r\n\r\n' % content_type)

        try:
            fileobj.seek(0)
        except Exception:
            pass
        shutil.copyfileobj(fileobj, buf, length=__filebuff_size__)

        _w('\r\n')
        _w('--' + boundary + '--\r\n')

        buf.seek(0)
        data = buf.read()
        hdrs = {'Content-Type': 'multipart/form-data; boundary=%s' % boundary}
        hdrs.update(headers)
        req = Request(rebuilt_url, data=data)
        # method override for Py3; Py2 Request ignores 'method' kw
        if not PY2:
            req.method = method  # type: ignore[attr-defined]
    else:
        # raw body
        try:
            fileobj.seek(0)
        except Exception:
            pass
        data = fileobj.read()
        hdrs = {'Content-Type': content_type}
        hdrs.update(headers)
        req = Request(rebuilt_url, data=data)
        if not PY2:
            req.method = method  # type: ignore[attr-defined]

    for k, v in hdrs.items():
        req.add_header(k, v)

    # Basic auth if present
    if username or password:
        pwd_mgr = HTTPPasswordMgrWithDefaultRealm()
        pwd_mgr.add_password(None, rebuilt_url, username, password)
        opener = build_opener(HTTPBasicAuthHandler(pwd_mgr))
    else:
        opener = build_opener()

    # Py2 OpenerDirector.open takes timeout since 2.6; to be safe, avoid passing if it explodes
    try:
        resp = opener.open(req, timeout=60)
    except TypeError:
        resp = opener.open(req)

    # Status code compat
    code = getattr(resp, 'status', None) or getattr(resp, 'code', None) or 0
    try:
        resp.close()
    except Exception:
        pass
    return (200 <= int(code) < 300)


def download_file_from_http_string(url, headers=geturls_headers_pywwwget_python_alt, usehttp=__use_http_lib__):
    httpfile = download_file_from_http_file(url, headers, usehttp)
    httpout = httpfile.read()
    httpfile.close()
    return httpout


if(haveparamiko):
    def download_file_from_sftp_file(url):
        urlparts = urlparse(url)
        file_name = os.path.basename(unquote(urlparts.path))
        file_dir = os.path.dirname(unquote(urlparts.path))
        sftp_port = urlparts.port
        if(urlparts.port is None):
            sftp_port = 22
        else:
            sftp_port = urlparts.port
        if(urlparts.username is not None):
            sftp_username = unquote(urlparts.username)
        else:
            sftp_username = "anonymous"
        if(urlparts.password is not None):
            sftp_password = unquote(urlparts.password)
        elif(urlparts.password is None and urlparts.username == "anonymous"):
            sftp_password = "anonymous"
        else:
            sftp_password = ""
        if(urlparts.scheme != "sftp" and urlparts.scheme != "scp"):
            return False
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(urlparts.hostname, port=sftp_port,
                        username=sftp_username, password=sftp_password)
        except paramiko.ssh_exception.SSHException:
            return False
        except (socket.gaierror, socket.timeout):
            log.info("Error With URL "+url)
            return False
        sftp = ssh.open_sftp()
        sftpfile = MkTempFile()
        sftp.getfo(unquote(urlparts.path), sftpfile)
        sftp.close()
        ssh.close()
        sftpfile.seek(0, 0)
        return sftpfile
else:
    def download_file_from_sftp_file(url):
        return False

if(haveparamiko):
    def download_file_from_sftp_string(url):
        sftpfile = download_file_from_sftp_file(url)
        sftpout = sftpfile.read()
        sftpfile.close()
        return sftpout
else:
    def download_file_from_sftp_string(url):
        return False

if(haveparamiko):
    def upload_file_to_sftp_file(sftpfile, url):
        urlparts = urlparse(url)
        file_name = os.path.basename(unquote(urlparts.path))
        file_dir = os.path.dirname(unquote(urlparts.path))
        sftp_port = urlparts.port
        if(urlparts.port is None):
            sftp_port = 22
        else:
            sftp_port = urlparts.port
        if(urlparts.username is not None):
            sftp_username = unquote(urlparts.username)
        else:
            sftp_username = "anonymous"
        if(urlparts.password is not None):
            sftp_password = unquote(urlparts.password)
        elif(urlparts.password is None and urlparts.username == "anonymous"):
            sftp_password = "anonymous"
        else:
            sftp_password = ""
        if(urlparts.scheme != "sftp" and urlparts.scheme != "scp"):
            return False
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(urlparts.hostname, port=sftp_port,
                        username=sftp_username, password=sftp_password)
        except paramiko.ssh_exception.SSHException:
            return False
        except (socket.gaierror, socket.timeout):
            log.info("Error With URL "+url)
            return False
        sftp = ssh.open_sftp()
        sftpfile.seek(0, 0)
        sftp.putfo(sftpfile, unquote(urlparts.path))
        sftp.close()
        ssh.close()
        sftpfile.seek(0, 0)
        return sftpfile
else:
    def upload_file_to_sftp_file(sftpfile, url):
        return False

if(haveparamiko):
    def upload_file_to_sftp_string(sftpstring, url):
        sftpfileo = MkTempFile(sftpstring)
        sftpfile = upload_file_to_sftp_files(sftpfileo, url)
        sftpfileo.close()
        return sftpfile
else:
    def upload_file_to_sftp_string(url):
        return False

if(havepysftp):
    def download_file_from_pysftp_file(url):
        urlparts = urlparse(url)
        file_name = os.path.basename(unquote(urlparts.path))
        file_dir = os.path.dirname(unquote(urlparts.path))
        sftp_port = urlparts.port
        if(urlparts.port is None):
            sftp_port = 22
        else:
            sftp_port = urlparts.port
        if(urlparts.username is not None):
            sftp_username = unquote(urlparts.username)
        else:
            sftp_username = "anonymous"
        if(urlparts.password is not None):
            sftp_password = unquote(urlparts.password)
        elif(urlparts.password is None and urlparts.username == "anonymous"):
            sftp_password = "anonymous"
        else:
            sftp_password = ""
        if(urlparts.scheme != "sftp" and urlparts.scheme != "scp"):
            return False
        try:
            sftp = pysftp.Connection(urlparts.hostname, port=sftp_port,
                              username=sftp_username, password=sftp_password)
        except paramiko.ssh_exception.SSHException:
            return False
        except (socket.gaierror, socket.timeout):
            log.info("Error With URL "+url)
            return False
        sftpfile = MkTempFile()
        sftp.getfo(unquote(urlparts.path), sftpfile)
        sftp.close()
        ssh.close()
        sftpfile.seek(0, 0)
        return sftpfile
else:
    def download_file_from_pysftp_file(url):
        return False

if(havepysftp):
    def download_file_from_pysftp_string(url):
        sftpfile = download_file_from_pysftp_file(url)
        sftpout = sftpfile.read()
        sftpfile.close()
        return sftpout
else:
    def download_file_from_pysftp_string(url):
        return False

if(havepysftp):
    def upload_file_to_pysftp_file(sftpfile, url):
        urlparts = urlparse(url)
        file_name = os.path.basename(unquote(urlparts.path))
        file_dir = os.path.dirname(unquote(urlparts.path))
        sftp_port = urlparts.port
        if(urlparts.port is None):
            sftp_port = 22
        else:
            sftp_port = urlparts.port
        if(urlparts.username is not None):
            sftp_username = unquote(urlparts.username)
        else:
            sftp_username = "anonymous"
        if(urlparts.password is not None):
            sftp_password = unquote(urlparts.password)
        elif(urlparts.password is None and urlparts.username == "anonymous"):
            sftp_password = "anonymous"
        else:
            sftp_password = ""
        if(urlparts.scheme != "sftp" and urlparts.scheme != "scp"):
            return False
        try:
            sftp = pysftp.Connection(urlparts.hostname, port=sftp_port,
                              username=sftp_username, password=sftp_password)
        except paramiko.ssh_exception.SSHException:
            return False
        except (socket.gaierror, socket.timeout):
            log.info("Error With URL "+url)
            return False
        sftpfile.seek(0, 0)
        sftp.putfo(sftpfile, unquote(urlparts.path))
        sftp.close()
        ssh.close()
        sftpfile.seek(0, 0)
        return sftpfile
else:
    def upload_file_to_pysftp_file(sftpfile, url):
        return False

if(havepysftp):
    def upload_file_to_pysftp_string(sftpstring, url):
        sftpfileo = MkTempFile(sftpstring)
        sftpfile = upload_file_to_pysftp_file(ftpfileo, url)
        sftpfileo.close()
        return sftpfile
else:
    def upload_file_to_pysftp_string(sftpstring, url):
        return False


def download_file_from_internet_file(url, headers=geturls_headers_pywwwget_python_alt, usehttp=__use_http_lib__):
    urlparts = urlparse(url)
    if(urlparts.scheme == "http" or urlparts.scheme == "https"):
        return download_file_from_http_file(url, headers, usehttp)
    elif(urlparts.scheme == "ftp" or urlparts.scheme == "ftps"):
        return download_file_from_ftp_file(url)
    elif(urlparts.scheme == "sftp" or urlparts.scheme == "scp"):
        if(__use_pysftp__ and havepysftp):
            return download_file_from_pysftp_file(url)
        else:
            return download_file_from_sftp_file(url)
    elif(urlparts.scheme == "tcp" or urlparts.scheme == "udp"):
    outfile = MkTempFile()
    returnval = recv_via_url(outfile, url, recv_to_fileobj)
    if(not returnval):
        return False
    # Optional autosave (works for UDP seq meta and TCP/UDP in general)
    try:
        parts, o = _parse_net_url(url)
    except Exception:
        parts, o = (None, {})
    if o and o.get("save"):
        # prefer meta filename if available
        fname = None
        try:
            meta = getattr(outfile, "_pywwwget_meta", None)
            if meta and isinstance(meta, dict):
                fname = meta.get("filename") or None
        except Exception:
            fname = None
        if not fname:
            try:
                fname = _guess_filename(url) or None
            except Exception:
                fname = None
        out_path = _choose_output_path(fname, overwrite=bool(o.get("overwrite")), save_dir=o.get("save_dir"))
        try:
            _autosave_fileobj(outfile, out_path)
            try:
                sys.stdout.write("Saved: %s\n" % out_path)
                sys.stdout.flush()
            except Exception:
                pass
        except Exception:
            pass
    outfile.seek(0, 0)
    return outfile

    else:
        return False
    return False

def download_file_from_http_file_alt(url, headers=None, usehttp=__use_http_lib__):
    """
    Stream a URL to a temp file with optional auth (from URL) and
    optional integrity checks based on headers.

    Query flags:
      verify_len=1|0  (default: 1 if length header present)
      verify_sha=1|0  (default: 1 if X-File-SHA256 or strong ETag present)
    """
    if headers is None:
        headers = {}

    # Parse URL, extract user/pass, and rebuild without auth
    urlparts = urlparse(url)
    username = unquote(urlparts.username) if urlparts.username else None
    password = unquote(urlparts.password) if urlparts.password else None

    # verification controls from query string
    q = parse_qs(urlparts.query or "")
    want_verify_len = _qflag(q, "verify_len", None)  # None = auto
    want_verify_sha = _qflag(q, "verify_sha", None)

    # Rebuild netloc without userinfo
    netloc = urlparts.hostname or ''
    if urlparts.port:
        netloc += ':' + str(urlparts.port)
    rebuilt_url = urlunparse((urlparts.scheme, netloc, urlparts.path,
                              urlparts.params, urlparts.query, urlparts.fragment))

    # Allocate destination
    httpfile = MkTempFile()

    # Common chunk size (safe default even for chunked)
    CHUNK = 64 * 1024

    # --- Branch 1: requests ---
    if usehttp == 'requests' and haverequests:
        # build auth
        auth = (username, password) if (username and password) else None
        resp = requests.get(rebuilt_url, headers=headers, auth=auth, timeout=(5, 30), stream=True)
        resp.raise_for_status()

        # headers & expectations
        hdrs = _headers_dict_from_response(resp, 'requests')
        expected_len = _pick_expected_len(hdrs)
        expected_sha = _pick_expected_sha(hdrs)

        # auto-verify defaults
        verify_len = want_verify_len if want_verify_len is not None else (expected_len is not None)
        verify_sha = want_verify_sha if want_verify_sha is not None else (expected_sha is not None)

        # iter bytes
        resp.raw.decode_content = True  # allow gzip transparently if server used it
        if verify_len or verify_sha:
            it = resp.iter_content(chunk_size=CHUNK)
            _stream_copy_and_verify(
                it, httpfile,
                expected_len=(expected_len if verify_len else None),
                expected_sha=(expected_sha if verify_sha else None),
                chunk_size=CHUNK
            )
        else:
            # Fast path: no verify; still stream to avoid large memory
            for chunk in resp.iter_content(chunk_size=CHUNK):
                if chunk:
                    httpfile.write(_to_bytes(chunk))

    # --- Branch 2: httpx ---
    elif usehttp == 'httpx' and havehttpx:
        auth = (username, password) if (username and password) else None
        with httpx.Client(follow_redirects=True, timeout=30.0, auth=auth) as client:
            r = client.get(rebuilt_url)
            r.raise_for_status()
            hdrs = _headers_dict_from_response(r, 'httpx')
            expected_len = _pick_expected_len(hdrs)
            expected_sha = _pick_expected_sha(hdrs)
            verify_len = want_verify_len if want_verify_len is not None else (expected_len is not None)
            verify_sha = want_verify_sha if want_verify_sha is not None else (expected_sha is not None)

            if verify_len or verify_sha:
                it = r.iter_bytes()
                _stream_copy_and_verify(
                    it, httpfile,
                    expected_len=(expected_len if verify_len else None),
                    expected_sha=(expected_sha if verify_sha else None),
                    chunk_size=CHUNK
                )
            else:
                for chunk in r.iter_bytes():
                    if chunk:
                        httpfile.write(_to_bytes(chunk))

    # --- Branch 3: mechanize ---
    elif usehttp == 'mechanize' and havemechanize:
        br = mechanize.Browser()
        br.set_handle_robots(False)
        if headers:
            br.addheaders = list(headers.items())
        # mechanize basic-auth: add_password(url, user, pass)
        if username and password:
            br.add_password(rebuilt_url, username, password)

        response = br.open(rebuilt_url, timeout=30.0 if hasattr(br, 'timeout') else None)
        hdrs = _headers_dict_from_response(response, 'mechanize')
        expected_len = _pick_expected_len(hdrs)
        expected_sha = _pick_expected_sha(hdrs)
        verify_len = want_verify_len if want_verify_len is not None else (expected_len is not None)
        verify_sha = want_verify_sha if want_verify_sha is not None else (expected_sha is not None)

        if verify_len or verify_sha:
            def _iter_mech(resp, sz):
                while True:
                    chunk = resp.read(sz)
                    if not chunk:
                        break
                    yield chunk
            _stream_copy_and_verify(
                _iter_mech(response, CHUNK), httpfile,
                expected_len=(expected_len if verify_len else None),
                expected_sha=(expected_sha if verify_sha else None),
                chunk_size=CHUNK
            )
        else:
            # simple stream copy
            while True:
                chunk = response.read(CHUNK)
                if not chunk:
                    break
                httpfile.write(_to_bytes(chunk))

    # --- Branch 4: urllib fallback ---
    else:
        request = Request(rebuilt_url, headers=headers)
        opener = None
        if username and password:
            password_mgr = HTTPPasswordMgrWithDefaultRealm()
            password_mgr.add_password(None, rebuilt_url, username, password)
            auth_handler = HTTPBasicAuthHandler(password_mgr)
            opener = build_opener(auth_handler)
        else:
            opener = build_opener()

        response = opener.open(request, timeout=30)
        hdrs = _headers_dict_from_response(response, 'urllib')
        expected_len = _pick_expected_len(hdrs)
        expected_sha = _pick_expected_sha(hdrs)
        verify_len = want_verify_len if want_verify_len is not None else (expected_len is not None)
        verify_sha = want_verify_sha if want_verify_sha is not None else (expected_sha is not None)

        if verify_len or verify_sha:
            def _iter_urllib(resp, sz):
                while True:
                    chunk = resp.read(sz)
                    if not chunk:
                        break
                    yield chunk
            _stream_copy_and_verify(
                _iter_urllib(response, CHUNK), httpfile,
                expected_len=(expected_len if verify_len else None),
                expected_sha=(expected_sha if verify_sha else None),
                chunk_size=CHUNK
            )
        else:
            while True:
                chunk = response.read(CHUNK)
                if not chunk:
                    break
                httpfile.write(_to_bytes(chunk))

    # Rewind before returning
    try:
        httpfile.seek(0, 0)
    except Exception:
        pass
    return httpfile


def download_file_from_internet_string(url, headers=geturls_headers_pywwwget_python_alt):
    urlparts = urlparse(url)
    if(urlparts.scheme == "http" or urlparts.scheme == "https"):
        return download_file_from_http_string(url, headers)
    elif(urlparts.scheme == "ftp" or urlparts.scheme == "ftps"):
        return download_file_from_ftp_string(url)
    elif(urlparts.scheme == "sftp" or urlparts.scheme == "scp"):
        if(__use_pysftp__ and havepysftp):
            return download_file_from_pysftp_string(url)
        else:
            return download_file_from_sftp_string(url)
    else:
        return False
    return False


def upload_file_to_internet_file(ifp, url):
    urlparts = urlparse(url)
    if(urlparts.scheme == "ftp" or urlparts.scheme == "ftps"):
        return upload_file_to_ftp_file(ifp, url)
    elif(urlparts.scheme == "sftp" or urlparts.scheme == "scp"):
        if(__use_pysftp__ and havepysftp):
            return upload_file_to_pysftp_file(ifp, url)
        else:
            return upload_file_to_sftp_file(ifp, url)
    elif(urlparts.scheme == "tcp" or urlparts.scheme == "udp"):
        ifp.seek(0, 0)
        returnval = send_via_url(ifp, url, send_from_fileobj)
        if(not returnval):
            return False
        return returnval
    elif(urlparts.scheme == "http" or urlparts.scheme == "https"):
        ifp.seek(0, 0)
        returnval = send_via_http(ifp, url, run_http_file_server)
        if(not returnval):
            return False
        return returnval
    else:
        return False
    return False


def upload_file_to_internet_string(ifp, url):
    urlparts = urlparse(url)
    if(urlparts.scheme == "http" or urlparts.scheme == "https"):
        return False
    elif(urlparts.scheme == "ftp" or urlparts.scheme == "ftps"):
        return upload_file_to_ftp_string(ifp, url)
    elif(urlparts.scheme == "sftp" or urlparts.scheme == "scp"):
        if(__use_pysftp__ and havepysftp):
            return upload_file_to_pysftp_string(ifp, url)
        else:
            return upload_file_to_sftp_string(ifp, url)
    else:
        return False
    return False


# ---------- Core: send / recv ----------
def send_from_fileobj(fileobj, host, port=3124, proto="tcp", timeout=None,
                      chunk_size=65536,
                      use_ssl=False, ssl_verify=True, ssl_ca_file=None,
                      ssl_certfile=None, ssl_keyfile=None, server_hostname=None,
                      auth_user=None, auth_pass=None, auth_scope=u"",
                      on_progress=None, rate_limit_bps=None, want_sha=True,
                      enforce_path=True, path_text=u""):
    """
    Send fileobj over TCP/UDP with control prefaces.

    Control frames order (UDP):
      PATH <pct-encoded-path>\n           (if enforce_path)
      [AF1 auth blob or legacy AUTH\0u\0p\0, expect OK]
      [LEN <n> [sha]\n]                   (if total length known)
      [payload...]
      [HASH <sha>\n] + DONE\n             (if length unknown)

    TCP:
      PATH line + auth (if requested), then raw payload stream.
    """
    proto = (proto or "tcp").lower()
    total = 0
    port = int(port)
    if proto not in ("tcp", "udp"):
        raise ValueError("proto must be 'tcp' or 'udp'")

    # ---------------- UDP ----------------
    if proto == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if timeout is not None:
                sock.settimeout(timeout)
            try:
                sock.connect((host, port))
                connected = True
            except Exception:
                connected = False

            # (0) PATH preface
            if enforce_path:
                p = _quote_path_for_wire(_to_text(path_text))
                line = b"PATH " + p.encode('ascii') + b"\n"
                (sock.send(line) if connected else sock.sendto(line, (host, port)))

            # (1) Length and optional sha precompute
            total_bytes, start_pos = _discover_len_and_reset(fileobj)
            sha_hex = None
            if want_sha and total_bytes is not None:
                import hashlib
                h = hashlib.sha256()
                try: cur = fileobj.tell()
                except Exception: cur = None
                if start_pos is not None:
                    try: fileobj.seek(start_pos, os.SEEK_SET)
                    except Exception: pass
                _HSZ = 1024 * 1024
                while True:
                    blk = fileobj.read(_HSZ)
                    if not blk: break
                    h.update(_to_bytes(blk))
                sha_hex = h.hexdigest()
                # restore
                if start_pos is not None:
                    try: fileobj.seek(start_pos, os.SEEK_SET)
                    except Exception: pass
                elif cur is not None:
                    try: fileobj.seek(cur, os.SEEK_SET)
                    except Exception: pass

            # (2) AF1 auth (preferred) else legacy
            if auth_user is not None or auth_pass is not None:
                try:
                    blob = build_auth_blob_v1(
                        auth_user or u"", auth_pass or u"",
                        scope=auth_scope, length=total_bytes, sha_hex=(sha_hex if want_sha else None)
                    )
                except Exception:
                    blob = _build_auth_blob_legacy(auth_user or b"", auth_pass or b"")
                if connected:
                    sock.send(blob)
                    try:
                        resp = sock.recv(16)
                        if resp != _OK:
                            raise RuntimeError("UDP auth failed")
                    except Exception:
                        pass
                else:
                    sock.sendto(blob, (host, port))
                    try:
                        resp, _ = sock.recvfrom(16)
                        if resp != _OK:
                            raise RuntimeError("UDP auth failed")
                    except Exception:
                        pass

            # (3) Known-length preface
            if total_bytes is not None:
                pre = b"LEN " + str(int(total_bytes)).encode('ascii')
                if want_sha and sha_hex:
                    pre += b" " + sha_hex.encode('ascii')
                pre += b"\n"
                (sock.send(pre) if connected else sock.sendto(pre, (host, port)))

            # (4) Payload (cap datagram size)
            UDP_PAYLOAD_MAX = 1200  # keep well below typical MTU
            effective_chunk = min(int(chunk_size or 65536), UDP_PAYLOAD_MAX)

            sent_so_far = 0
            last_cb_ts = monotonic()
            rl_ts = last_cb_ts
            rl_bytes = 0

            rolling_h = None
            if want_sha and total_bytes is None:
                try:
                    import hashlib
                    rolling_h = hashlib.sha256()
                except Exception:
                    rolling_h = None

            while True:
                chunk = fileobj.read(effective_chunk)
                if not chunk:
                    break
                b = _to_bytes(chunk)
                if rolling_h is not None:
                    rolling_h.update(b)
                n = (sock.send(b) if connected else sock.sendto(b, (host, port)))
                total += n
                sent_so_far += n

                if rate_limit_bps:
                    sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, rate_limit_bps, n)
                    if sleep_s > 0.0:
                        time.sleep(min(sleep_s, 0.25))
                if on_progress and (monotonic() - last_cb_ts) >= 0.1:
                    try: on_progress(sent_so_far, total_bytes)
                    except Exception: pass
                    last_cb_ts = monotonic()

            # (5) Unknown-length trailers
            if total_bytes is None:
                if rolling_h is not None:
                    try:
                        th = rolling_h.hexdigest().encode('ascii')
                        frame = b"HASH " + th + b"\n"
                        (sock.send(frame) if connected else sock.sendto(frame, (host, port)))
                    except Exception:
                        pass
                try:
                    (sock.send(b"DONE\n") if connected else sock.sendto(b"DONE\n", (host, port)))
                except Exception:
                    pass

        finally:
            try: sock.close()
            except Exception: pass
        return total

    # ---------------- TCP ----------------
    sock = _connect_stream(host, port, timeout)
    try:
        if use_ssl:
            if not _ssl_available():
                raise RuntimeError("SSL requested but 'ssl' module unavailable.")
            sock = _ssl_wrap_socket(sock, server_side=False,
                                    server_hostname=(server_hostname or host),
                                    verify=ssl_verify, ca_file=ssl_ca_file,
                                    certfile=ssl_certfile, keyfile=ssl_keyfile)

        # (0) PATH preface first
        if enforce_path:
            p = _quote_path_for_wire(_to_text(path_text))
            line = b"PATH " + p.encode('ascii') + b"\n"
            sock.sendall(line)

        # (1) Length + optional sha (for AF1 metadata/logging)
        total_bytes, start_pos = _discover_len_and_reset(fileobj)
        sha_hex = None
        if want_sha and total_bytes is not None:
            try:
                import hashlib
                h = hashlib.sha256()
                cur = fileobj.tell()
                if start_pos is not None:
                    fileobj.seek(start_pos, os.SEEK_SET)
                _HSZ = 1024 * 1024
                while True:
                    blk = fileobj.read(_HSZ)
                    if not blk: break
                    h.update(_to_bytes(blk))
                sha_hex = h.hexdigest()
                fileobj.seek(cur, os.SEEK_SET)
            except Exception:
                sha_hex = None

        # (2) Auth preface
        if auth_user is not None or auth_pass is not None:
            try:
                blob = build_auth_blob_v1(
                    auth_user or u"", auth_pass or u"",
                    scope=auth_scope, length=total_bytes, sha_hex=(sha_hex if want_sha else None)
                )
            except Exception:
                blob = _build_auth_blob_legacy(auth_user or b"", auth_pass or b"")
            sock.sendall(blob)
            try:
                resp = sock.recv(16)
                if resp != _OK:
                    raise RuntimeError("TCP auth failed")
            except Exception:
                pass

        # (3) Payload
        sent_so_far = 0
        last_cb_ts = monotonic()
        rl_ts = last_cb_ts
        rl_bytes = 0

        use_sendfile = hasattr(sock, "sendfile") and hasattr(fileobj, "read")
        if use_sendfile:
            try:
                sent = sock.sendfile(fileobj)
                if isinstance(sent, int):
                    total += sent; sent_so_far += sent
                    if on_progress:
                        try: on_progress(sent_so_far, total_bytes)
                        except Exception: pass
                else:
                    raise RuntimeError("sendfile returned unexpected type")
            except Exception:
                # fallback chunk loop
                while True:
                    chunk = fileobj.read(chunk_size)
                    if not chunk: break
                    view = memoryview(_to_bytes(chunk))
                    while view:
                        n = sock.send(view); total += n; sent_so_far += n; view = view[n:]
                        if rate_limit_bps:
                            sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, rate_limit_bps, n)
                            if sleep_s > 0.0: time.sleep(min(sleep_s, 0.25))
                    if on_progress and (monotonic() - last_cb_ts) >= 0.1:
                        try: on_progress(sent_so_far, total_bytes)
                        except Exception: pass
                        last_cb_ts = monotonic()
        else:
            while True:
                chunk = fileobj.read(chunk_size)
                if not chunk: break
                view = memoryview(_to_bytes(chunk))
                while view:
                    n = sock.send(view); total += n; sent_so_far += n; view = view[n:]
                    if rate_limit_bps:
                        sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, rate_limit_bps, n)
                        if sleep_s > 0.0: time.sleep(min(sleep_s, 0.25))
                if on_progress and (monotonic() - last_cb_ts) >= 0.1:
                    try: on_progress(sent_so_far, total_bytes)
                    except Exception: pass
                    last_cb_ts = monotonic()
    finally:
        try: sock.shutdown(socket.SHUT_WR)
        except Exception: pass
        try: sock.close()
        except Exception: pass
    return total


def recv_to_fileobj(fileobj, host="", port=3124, proto="tcp", timeout=None,
                    max_bytes=None, chunk_size=65536, backlog=1,
                    use_ssl=False, ssl_verify=True, ssl_ca_file=None,
                    ssl_certfile=None, ssl_keyfile=None,
                    require_auth=False, expected_user=None, expected_pass=None,
                    total_timeout=None, expect_scope=None,
                    on_progress=None, rate_limit_bps=None,
                    enforce_path=True, wait_seconds=None):
    """
    Receive bytes into fileobj over TCP/UDP.

    Path enforcement:
      - UDP: expects 'PATH <...>\\n' control frame first (if enforce_path).
      - TCP: reads first line 'PATH <...>\\n' before auth/payload (if enforce_path).

    UDP control frames understood: PATH, LEN, HASH, DONE (+ AF1 auth blob).

    wait_seconds (TCP only): overall accept window to wait for a client
      (mirrors the HTTP server behavior). None = previous behavior (single accept
      with 'timeout' as the accept timeout).
    """
    proto = (proto or "tcp").lower()
    port = int(port)
    total = 0

    start_ts = time.time()
    def _time_left():
        if total_timeout is None:
            return None
        left = total_timeout - (time.time() - start_ts)
        return 0.0 if left <= 0 else left

    def _set_effective_timeout(socklike, base_timeout):
        left = _time_left()
        if left == 0.0:
            return False
        eff = base_timeout
        if left is not None:
            eff = left if eff is None else min(eff, left)
        if eff is not None:
            try:
                socklike.settimeout(eff)
            except Exception:
                pass
        return True

    if proto not in ("tcp", "udp"):
        raise ValueError("proto must be 'tcp' or 'udp'")

    # ---------------- UDP server ----------------
    if proto == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        authed_addr = None
        expected_len = None
        expected_sha = None
        path_checked = (not enforce_path)

        try:
            sock.bind(("", port))
            if timeout is None:
                try: sock.settimeout(10.0)
                except Exception: pass

            recvd_so_far = 0
            last_cb_ts = monotonic()
            rl_ts = last_cb_ts
            rl_bytes = 0

            while True:
                if _time_left() == 0.0:
                    if expected_len is not None and total < expected_len:
                        raise RuntimeError("UDP receive aborted by total_timeout before full payload received")
                    break
                if (max_bytes is not None) and (total >= max_bytes):
                    break

                if not _set_effective_timeout(sock, timeout):
                    if expected_len is not None and total < expected_len:
                        raise RuntimeError("UDP receive timed out before full payload received")
                    if expected_len is None and total > 0:
                        raise RuntimeError("UDP receive timed out with unknown length; partial data")
                    if expected_len is None and total == 0:
                        raise RuntimeError("UDP receive: no packets received before timeout (is the sender running?)")
                    break

                try:
                    data, addr = sock.recvfrom(chunk_size)
                except socket.timeout:
                    if expected_len is not None and total < expected_len:
                        raise RuntimeError("UDP receive idle-timeout before full payload received")
                    if expected_len is None and total > 0:
                        raise RuntimeError("UDP receive idle-timeout with unknown length; partial data")
                    if expected_len is None and total == 0:
                        raise RuntimeError("UDP receive: no packets received before timeout (is the sender running?)")
                    break

                if not data:
                    continue

                # (0) PATH first (strict)
                if not path_checked and data.startswith(b"PATH "):
                    got_path = _unquote_path_from_wire(data[5:].strip())
                    if _to_text(got_path) != _to_text(expect_scope or u""):
                        raise RuntimeError("UDP path mismatch: got %r expected %r"
                                           % (got_path, expect_scope))
                    path_checked = True
                    continue
                if enforce_path and not path_checked:
                    if not data.startswith(b"PATH "):
                        continue  # ignore until PATH arrives

                # (0b) Control frames
                if data.startswith(b"LEN ") and expected_len is None:
                    try:
                        parts = data.strip().split()
                        n = int(parts[1])
                        expected_len = (None if n < 0 else n)
                        if len(parts) >= 3:
                            expected_sha = parts[2].decode("ascii")
                    except Exception:
                        expected_len = None; expected_sha = None
                    continue

                if data.startswith(b"HASH "):
                    try:
                        expected_sha = data.strip().split()[1].decode("ascii")
                    except Exception:
                        expected_sha = None
                    continue

                if data == b"DONE\n":
                    # Treat DONE as end-of-transfer. If we know the expected length,
                    # ignore early DONE until we have all bytes (reduces truncation risk).
                    if expected_len is None or total_received >= expected_len:
                        break
                    else:
                        continue
                # (1) Auth (if required)
                if authed_addr is None and require_auth:
                    ok = False
                    v_ok, v_user, v_scope, _r, v_len, v_sha = verify_auth_blob_v1(
                        data, expected_user=expected_user, secret=expected_pass,
                        max_skew=600, expect_scope=expect_scope
                    )
                    if v_ok:
                        ok = True
                        if expected_len is None:
                            expected_len = v_len
                        if expected_sha is None:
                            expected_sha = v_sha
                    else:
                        user, pw = _parse_auth_blob_legacy(data)
                        ok = (user is not None and
                              (expected_user is None or user == _to_bytes(expected_user)) and
                              (expected_pass is None or pw == _to_bytes(expected_pass)))
                    try:
                        sock.sendto((_OK if ok else _NO), addr)
                    except Exception:
                        pass
                    if ok:
                        authed_addr = addr
                    continue

                if require_auth and addr != authed_addr:
                    continue

                # (2) Payload
                fileobj.write(data)
                try: fileobj.flush()
                except Exception: pass
                total += len(data)
                recvd_so_far += len(data)

                if rate_limit_bps:
                    sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, rate_limit_bps, len(data))
                    if sleep_s > 0.0:
                        time.sleep(min(sleep_s, 0.25))

                if on_progress and (monotonic() - last_cb_ts) >= 0.1:
                    try: on_progress(recvd_so_far, expected_len)
                    except Exception: pass
                    last_cb_ts = monotonic()

                if expected_len is not None and total >= expected_len:
                    break

            # Post-conditions
            if expected_len is not None and total != expected_len:
                raise RuntimeError("UDP receive incomplete: got %d of %s bytes" % (total, expected_len))

            if expected_sha:
                import hashlib
                try:
                    cur = fileobj.tell(); fileobj.seek(0)
                except Exception:
                    cur = None
                h = hashlib.sha256(); _HSZ = 1024 * 1024
                while True:
                    blk = fileobj.read(_HSZ)
                    if not blk: break
                    h.update(_to_bytes(blk))
                got = h.hexdigest()
                if cur is not None:
                    try: fileobj.seek(cur)
                    except Exception: pass
                if got != expected_sha:
                    raise RuntimeError("UDP checksum mismatch: got %s expected %s" % (got, expected_sha))

        finally:
            try: sock.close()
            except Exception: pass
        return total

    # ---------------- TCP server (one-shot with optional wait window) ----------------
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try: srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception: pass
        srv.bind((host or "", port))
        srv.listen(int(backlog) if backlog else 1)

        bytes_written = 0
        started = time.time()

        # per-accept wait
        per_accept = float(timeout) if timeout is not None else 1.0
        try: srv.settimeout(per_accept)
        except Exception: pass

        while True:
            if bytes_written > 0:
                break
            if wait_seconds is not None and (time.time() - started) >= wait_seconds:
                break

            try:
                conn, _peer = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            # TLS
            if use_ssl:
                if not _ssl_available():
                    try: conn.close()
                    except Exception: pass
                    break
                if not ssl_certfile:
                    try: conn.close()
                    except Exception: pass
                    raise ValueError("TLS server requires ssl_certfile (and usually ssl_keyfile).")
                conn = _ssl_wrap_socket(conn, server_side=True, server_hostname=None,
                                        verify=ssl_verify, ca_file=ssl_ca_file,
                                        certfile=ssl_certfile, keyfile=ssl_keyfile)

            recvd_so_far = 0
            last_cb_ts = monotonic()
            rl_ts = last_cb_ts
            rl_bytes = 0

            try:
                # (0) PATH line (if enforced)
                if enforce_path:
                    line = _recv_line(conn, maxlen=4096, timeout=timeout)
                    if not line or not line.startswith(b"PATH "):
                        try: conn.close()
                        except Exception: pass
                        continue
                    got_path = _unquote_path_from_wire(line[5:].strip())
                    if _to_text(got_path) != _to_text(expect_scope or u""):
                        try: conn.close()
                        except Exception: pass
                        raise RuntimeError("TCP path mismatch: got %r expected %r"
                                           % (got_path, expect_scope))

                # (1) Auth preface
                if require_auth:
                    if not _set_effective_timeout(conn, timeout):
                        try: conn.close()
                        except Exception: pass
                        continue
                    try:
                        preface = conn.recv(2048)
                    except socket.timeout:
                        try: conn.sendall(_NO)
                        except Exception: pass
                        try: conn.close()
                        except Exception: pass
                        continue

                    ok = False
                    v_ok, v_user, v_scope, _r, v_len, v_sha = verify_auth_blob_v1(
                        preface or b"", expected_user=expected_user, secret=expected_pass,
                        max_skew=600, expect_scope=expect_scope
                    )
                    if v_ok:
                        ok = True
                    else:
                        user, pw = _parse_auth_blob_legacy(preface or b"")
                        ok = (user is not None and
                              (expected_user is None or user == _to_bytes(expected_user)) and
                              (expected_pass is None or pw == _to_bytes(expected_pass)))
                    try: conn.sendall(_OK if ok else _NO)
                    except Exception: pass
                    if not ok:
                        try: conn.close()
                        except Exception: pass
                        continue

                # (2) Payload loop
                while True:
                    if _time_left() == 0.0: break
                    if (max_bytes is not None) and (bytes_written >= max_bytes): break

                    if not _set_effective_timeout(conn, timeout):
                        break
                    try:
                        data = conn.recv(chunk_size)
                    except socket.timeout:
                        break
                    if not data:
                        break

                    fileobj.write(data)
                    try: fileobj.flush()
                    except Exception: pass
                    total += len(data)
                    bytes_written += len(data)
                    recvd_so_far += len(data)

                    if rate_limit_bps:
                        sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, rate_limit_bps, len(data))
                        if sleep_s > 0.0:
                            time.sleep(min(sleep_s, 0.25))

                    if on_progress and (monotonic() - last_cb_ts) >= 0.1:
                        try: on_progress(recvd_so_far, max_bytes)
                        except Exception: pass
                        last_cb_ts = monotonic()

            finally:
                try: conn.shutdown(socket.SHUT_RD)
                except Exception: pass
                try: conn.close()
                except Exception: pass

        return total

    finally:
        try: srv.close()
        except Exception: pass

def run_tcp_file_server(fileobj, url, on_progress=None):
    """
    One-shot TCP uploader: wait for a client, authenticate (optional),
    then send control preface (LEN...), followed by the file bytes.
    Ends after serving exactly one client or wait window elapses.

    URL example:
      tcp://user:pass@0.0.0.0:5000/path/my.cat?
          auth=1&enforce_path=1&rate=200000&timeout=5&wait=30&ssl=0
    """
    parts, o = _parse_net_url(url)  # already returns proto/host/port/timeout/ssl/etc.
    if o["proto"] != "tcp":
        raise ValueError("run_tcp_file_server requires tcp:// URL")

    # Pull extras from the query string (enforce_path, want_sha, rate, wait)
    qs = parse_qs(parts.query or "")
    enforce_path = _qflag(qs, "enforce_path", True)
    want_sha      = _qflag(qs, "sha", True)
    rate_limit    = _qnum(qs, "rate", None, float)
    wait_seconds  = _qnum(qs, "wait", None, float)  # None = wait forever

    # Discover length (and precompute sha if requested & length known)
    total_bytes, start_pos = _discover_len_and_reset(fileobj)
    sha_hex = None
    if want_sha and total_bytes is not None:
        try:
            import hashlib
            h = hashlib.sha256()
            # hash current stream content
            cur = None
            try: cur = fileobj.tell()
            except Exception: pass
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            _HSZ = 1024 * 1024
            while True:
                blk = fileobj.read(_HSZ)
                if not blk: break
                h.update(_to_bytes(blk))
            sha_hex = h.hexdigest()
            # restore
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            elif cur is not None:
                try: fileobj.seek(cur, os.SEEK_SET)
                except Exception: pass
        except Exception:
            sha_hex = None

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try: srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception: pass
        srv.bind((o["host"], o["port"]))
        srv.listen(1)

        # Wait loop: keep accepting until a client is served or wait expires
        started = time.time()
        per_accept = float(o["timeout"]) if o["timeout"] is not None else 1.0
        try: srv.settimeout(per_accept)
        except Exception: pass

        bytes_sent = 0

        while True:
            # stop conditions
            if bytes_sent > 0:
                break
            if (wait_seconds is not None) and ((time.time() - started) >= wait_seconds):
                break

            try:
                conn, peer = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            # Optional TLS
            if o["use_ssl"]:
                if not _ssl_available():
                    try: conn.close()
                    except Exception: pass
                    break
                conn = _ssl_wrap_socket(conn, server_side=True,
                                        server_hostname=None,
                                        verify=o["ssl_verify"],
                                        ca_file=o["ssl_ca_file"],
                                        certfile=o["ssl_certfile"],
                                        keyfile=o["ssl_keyfile"])
            # Per-connection timeout
            if o["timeout"] is not None:
                try: conn.settimeout(float(o["timeout"]))
                except Exception: pass

            try:
                # --------- AUTH handshake (AF1 preferred, legacy fallback) ---------
                ok = True
                if (o["user"] is not None) or (o["pw"] is not None) or o.get("force_auth", False):
                    # Expect an auth preface from client
                    try:
                        preface = conn.recv(4096)
                    except socket.timeout:
                        ok = False
                        preface = b""

                    if ok:
                        v_ok, v_user, v_scope, _r, _len, _sha = verify_auth_blob_v1(
                            preface or b"", expected_user=o["user"], secret=o["pw"],
                            max_skew=600, expect_scope=(parts.path or u"")
                        )
                        if v_ok:
                            ok = True
                        else:
                            u, p = _parse_auth_blob_legacy(preface or b"")
                            ok = (u is not None and
                                  (o["user"] is None or u == _to_bytes(o["user"])) and
                                  (o["pw"] is None or p == _to_bytes(o["pw"])))
                            # if enforcing path with legacy, optionally let the client
                            # send a second line with PATH <text> (best-effort)
                            if ok and enforce_path:
                                try:
                                    line = conn.recv(1024)
                                    if line and line.startswith(b"PATH "):
                                        want_path = _to_text(line[5:].strip())
                                        ok = (want_path == (parts.path or u""))
                                except Exception:
                                    pass

                    # Respond OK/NO then proceed/close
                    try: conn.sendall(_OK if ok else _NO)
                    except Exception: pass
                    if not ok:
                        try: conn.close()
                        except Exception: pass
                        continue

                # --------- Control preface: LEN ---------
                if total_bytes is not None:
                    # "LEN <bytes> <sha?>\n"
                    line = "LEN %d%s\n" % (
                        int(total_bytes),
                        ((" " + sha_hex) if sha_hex else "")
                    )
                else:
                    line = "LEN -1\n"
                try: conn.sendall(_to_bytes(line))
                except Exception:
                    try: conn.close()
                    except Exception: pass
                    continue

                # --------- Stream payload ---------
                if start_pos is not None:
                    try: fileobj.seek(start_pos, os.SEEK_SET)
                    except Exception: pass

                last_cb = time.time()
                rl_ts   = time.time()
                rl_bytes= 0
                CS = int(o["chunk_size"] or 65536)

                while True:
                    buf = fileobj.read(CS)
                    if not buf:
                        break
                    b = _to_bytes(buf)
                    try:
                        conn.sendall(b)
                    except Exception:
                        break
                    bytes_sent += len(b)

                    if on_progress and (time.time() - last_cb) >= 0.1:
                        try: on_progress(bytes_sent, total_bytes)
                        except Exception: pass
                        last_cb = time.time()

                    if rate_limit:
                        sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, int(rate_limit), len(b))
                        if sleep_s > 0.0:
                            time.sleep(sleep_s)

                # Unknown-length: send DONE marker so clients can stop cleanly
                if total_bytes is None:
                    try: conn.sendall(b"DONE\n")
                    except Exception: pass

            finally:
                try: conn.shutdown(socket.SHUT_RDWR)
                except Exception: pass
                try: conn.close()
                except Exception: pass

        return bytes_sent

    finally:
        try: srv.close()
        except Exception: pass

def run_udp_file_server(fileobj, url, on_progress=None):
    """
    One-shot UDP uploader: wait for a client auth/hello, reply OK, then
    send LEN + payload as datagrams (and DONE if unknown length).
    Ends after serving exactly one client or wait window elapses.

    URL example:
      udp://user:pass@0.0.0.0:5001/path/my.cat?
          auth=1&enforce_path=1&rate=250000&timeout=5&wait=30
    """
    parts, o = _parse_net_url(url)
    if o["proto"] != "udp":
        raise ValueError("run_udp_file_server requires udp:// URL")

    qs = parse_qs(parts.query or "")
    enforce_path = _qflag(qs, "enforce_path", True)
    want_sha      = _qflag(qs, "sha", True)
    rate_limit    = _qnum(qs, "rate", None, float)
    wait_seconds  = _qnum(qs, "wait", None, float)

    total_bytes, start_pos = _discover_len_and_reset(fileobj)
    sha_hex = None
    if want_sha and total_bytes is not None:
        try:
            import hashlib
            h = hashlib.sha256()
            cur = None
            try: cur = fileobj.tell()
            except Exception: pass
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            _HSZ = 1024 * 1024
            while True:
                blk = fileobj.read(_HSZ)
                if not blk: break
                h.update(_to_bytes(blk))
            sha_hex = h.hexdigest()
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            elif cur is not None:
                try: fileobj.seek(cur, os.SEEK_SET)
                except Exception: pass
        except Exception:
            sha_hex = None

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((o["host"], o["port"]))
        if o["timeout"] is not None:
            try: sock.settimeout(float(o["timeout"]))
            except Exception: pass

        started = time.time()
        CS = int(o["chunk_size"] or 65536)
        bytes_sent = 0
        client = None

        # ---------- wait for client hello/auth ----------
        while True:
            # overall wait window
            if (wait_seconds is not None) and ((time.time() - started) >= wait_seconds):
                break
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except Exception:
                break

            ok = True
            # Require auth if creds configured or ?auth=1
            force_auth = o.get("force_auth", False) or (o["user"] is not None) or (o["pw"] is not None)
            if force_auth:
                v_ok, v_user, v_scope, _r, _len, _sha = verify_auth_blob_v1(
                    data or b"", expected_user=o["user"], secret=o["pw"],
                    max_skew=600, expect_scope=(parts.path or u"")
                )
                if v_ok:
                    ok = True
                else:
                    u, p = _parse_auth_blob_legacy(data or b"")
                    ok = (u is not None and
                          (o["user"] is None or u == _to_bytes(o["user"])) and
                          (o["pw"] is None or p == _to_bytes(o["pw"])))
                    # optional legacy PATH check (best effort)
                    if ok and enforce_path:
                        try:
                            line, addr2 = sock.recvfrom(1024)
                            if addr2 == addr and line and line.startswith(b"PATH "):
                                want_path = _to_text(line[5:].strip())
                                ok = (want_path == (parts.path or u""))
                        except Exception:
                            pass

            try: sock.sendto((_OK if ok else _NO), addr)
            except Exception:
                ok = False

            if ok:
                client = addr
                break

        if not client:
            return 0

        # ---------- send LEN preface ----------
        if total_bytes is not None:
            line = "LEN %d%s\n" % (int(total_bytes), ((" " + sha_hex) if sha_hex else ""))
        else:
            line = "LEN -1\n"
        try:
            sock.sendto(_to_bytes(line), client)
        except Exception:
            return 0

        # ---------- stream payload ----------
        if start_pos is not None:
            try: fileobj.seek(start_pos, os.SEEK_SET)
            except Exception: pass

        last_cb = time.time()
        rl_ts   = time.time()
        rl_bytes= 0

        while True:
            buf = fileobj.read(CS)
            if not buf:
                break
            b = _to_bytes(buf)
            try:
                sock.sendto(b, client)
            except Exception:
                break
            bytes_sent += len(b)

            if on_progress and (time.time() - last_cb) >= 0.1:
                try: on_progress(bytes_sent, total_bytes)
                except Exception: pass
                last_cb = time.time()

            if rate_limit:
                sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, int(rate_limit), len(b))
                if sleep_s > 0.0:
                    time.sleep(sleep_s)

        # Send explicit DONE marker so the receiver can finish immediately.
        # Repeat a few times to reduce the chance the final UDP packet is lost.
        try:
            done_retries = int(opts.get('done_retries', 2))
        except Exception:
            done_retries = 2
        done_retries = max(1, min(10, done_retries))
        for _ in range(done_retries):
            try:
                sock.sendto(b"DONE\n", client)
            except Exception:
                pass
        return bytes_sent

    finally:
        try: sock.close()
        except Exception: pass


class _OneShotHTTPServer(HTTPServer):
    allow_reuse_address = True


# ======================================
# One-shot HTTP/HTTPS file upload server
# ======================================
def run_http_file_server(fileobj, url, on_progress=None, backlog=5):
    # --- parse & precompute (unchanged) ---
    parts, o = _parse_http_url(url)
    
    total_bytes, start_pos = _discover_len_and_reset(fileobj)
    sha_hex = None
    if o["want_sha"] and total_bytes is not None:
        try:
            import hashlib, os
            h = hashlib.sha256()
            try: cur = fileobj.tell()
            except Exception: cur = None
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            _HSZ = 1024 * 1024
            while True:
                blk = fileobj.read(_HSZ)
                if not blk: break
                h.update(_to_bytes(blk))
            sha_hex = h.hexdigest()
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            elif cur is not None:
                try: fileobj.seek(cur, os.SEEK_SET)
                except Exception: pass
        except Exception:
            sha_hex = None

    expected_path = _to_text(o["path"] or u"/")

    state = dict(
        fileobj=fileobj,
        total=total_bytes,
        sha=sha_hex,
        chunk_size=int(o["chunk_size"] or 65536),
        mime=_to_text(o["mime"]),
        enforce_path=bool(o["enforce_path"]),
        require_auth=bool(o["require_auth"]),
        expected_path=expected_path,
        expected_user=o["user"],
        expected_pass=o["pw"],
        timeout=o["timeout"],
        on_progress=on_progress,
        bytes_sent=0,
        extra_headers=o.get("extra_headers") or {},
        rate_limit_bps=o.get("rate_limit_bps") or None
    )

    class Handler(BaseHTTPRequestHandler):
        # def log_message(self, fmt, *args): pass

        def _fail_401(self):
            self.send_response(401, "Unauthorized")
            self.send_header("WWW-Authenticate", 'Basic realm="file"')
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            try: self.wfile.write(_to_bytes("Unauthorized\n"))
            except Exception: pass

        def _fail_404(self):
            self.send_response(404, "Not Found")
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            try: self.wfile.write(_to_bytes("Not Found\n"))
            except Exception: pass

        def _ok_headers(self, length_known):
            self.send_response(200, "OK")
            self.send_header("Content-Type", state["mime"])
            if length_known and state["total"] is not None:
                self.send_header("Content-Length", str(int(state["total"])))
            else:
                self.send_header("Transfer-Encoding", "chunked")
            if state["sha"]:
                self.send_header("ETag", '"%s"' % state["sha"])
                self.send_header("X-File-SHA256", state["sha"])
            if state["total"] is not None:
                self.send_header("X-File-Length", str(int(state["total"])))
            for k, v in (state["extra_headers"] or {}).items():
                try: self.send_header(_to_text(k), _to_text(v))
                except Exception: pass
            self.end_headers()

        def _path_only(self):
            p = urlparse(self.path or "/")
            try:
                from urllib.parse import unquote
            except ImportError:
                from urllib import unquote
            return _to_text(unquote(p.path or "/"))

        def _check_basic_auth(self):
            if not state["require_auth"]:
                return True
            ah = self.headers.get("Authorization")
            if not ah or not ah.strip().lower().startswith("basic "):
                return False
            try:
                b64 = ah.strip().split(" ", 1)[1]
                raw = base64.b64decode(_to_bytes(b64))
                try: raw_txt = raw.decode("utf-8")
                except Exception: raw_txt = raw.decode("latin-1", "replace")
                if ":" not in raw_txt: return False
                u, p = raw_txt.split(":", 1)
                if state["expected_user"] is not None and u != _to_text(state["expected_user"]): return False
                if state["expected_pass"] is not None and p != _to_text(state["expected_pass"]): return False
                return True
            except Exception:
                return False

        def _serve_body(self, method):
            if state["timeout"] is not None:
                try: self.connection.settimeout(state["timeout"])
                except Exception: pass

            if method == "HEAD":
                self._ok_headers(length_known=(state["total"] is not None))
                return

            # GET body
            if state["total"] is not None:
                self._ok_headers(length_known=True)
                if start_pos is not None:
                    try: state["fileobj"].seek(start_pos, os.SEEK_SET)
                    except Exception: pass

                cs = state["chunk_size"]
                last_cb = time.time()
                rl_ts = time.time()
                rl_bytes = 0

                while True:
                    buf = state["fileobj"].read(cs)
                    if not buf: break
                    b = _to_bytes(buf)
                    try: self.wfile.write(b)
                    except Exception: break
                    state["bytes_sent"] += len(b)

                    if state["on_progress"] and (time.time() - last_cb) >= 0.1:
                        try: state["on_progress"](state["bytes_sent"], state["total"])
                        except Exception: pass
                        last_cb = time.time()

                    if state["rate_limit_bps"]:
                        sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, state["rate_limit_bps"], add_bytes=len(b))
                        if sleep_s > 0.0: time.sleep(sleep_s)
            else:
                # unknown length → chunked
                self._ok_headers(length_known=False)
                cs = state["chunk_size"]
                last_cb = time.time()
                rl_ts = time.time()
                rl_bytes = 0

                while True:
                    buf = state["fileobj"].read(cs)
                    if not buf:
                        try: self.wfile.write(b"0\r\n\r\n")
                        except Exception: pass
                        break
                    b = _to_bytes(buf)
                    try:
                        self.wfile.write(("%x\r\n" % len(b)).encode("ascii"))
                        self.wfile.write(b)
                        self.wfile.write(b"\r\n")
                    except Exception: break
                    state["bytes_sent"] += len(b)

                    if state["on_progress"] and (time.time() - last_cb) >= 0.1:
                        try: state["on_progress"](state["bytes_sent"], None)
                        except Exception: pass
                        last_cb = time.time()

                    if state["rate_limit_bps"]:
                        sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, state["rate_limit_bps"], add_bytes=len(b))
                        if sleep_s > 0.0: time.sleep(sleep_s)

        def _handle(self, method):
            req_path = self._path_only()
            if state["enforce_path"] and (req_path != state["expected_path"]):
                return self._fail_404()
            if not self._check_basic_auth():
                return self._fail_401()
            return self._serve_body(method)

        def do_GET(self):  return self._handle("GET")
        def do_HEAD(self): return self._handle("HEAD")

    # HTTP server with reuse + explicit select-based wait
    class _OneShotHTTPServer(HTTPServer):
        allow_reuse_address = True

    server_address = (o["host"], o["port"])
    httpd = _OneShotHTTPServer(server_address, Handler)

    # TLS if https
    if o["scheme"] == "https":
        import ssl
        if not o["certfile"]:
            httpd.server_close()
            raise ValueError("HTTPS requires ?cert=/path/cert.pem (and optionally &key=...)")
        try:
            httpd.socket = ssl.wrap_socket(
                httpd.socket, certfile=o["certfile"], keyfile=o["keyfile"], server_side=True
            )
        except Exception:
            httpd.server_close()
            raise

    # ---------- WAIT LOOP (select + handle_request) ----------
    wait_seconds = o.get("wait_seconds", None)  # None = wait indefinitely
    started = time.time()

    # set both socket and server timeouts
    per_accept = 1.0 if o["timeout"] is None else float(o["timeout"])
    try: httpd.socket.settimeout(per_accept)
    except Exception: pass
    try: httpd.timeout = per_accept
    except Exception: pass

    try:
        import select
        while True:
            if state["bytes_sent"] > 0:
                break
            if wait_seconds is not None and (time.time() - started) >= wait_seconds:
                break

            # poll the listening socket; only call handle_request if ready
            try:
                rlist, _, _ = select.select([httpd.socket], [], [], per_accept)
            except Exception:
                rlist = []

            if not rlist:
                continue

            try:
                httpd.handle_request()
            except socket.timeout:
                # keep looping
                continue
            except Exception:
                # unexpected error; exit loop
                break
    finally:
        try: httpd.server_close()
        except Exception: pass

    return state["bytes_sent"]



def run_tcp_file_server(fileobj, url, on_progress=None):
    """
    One-shot TCP uploader: wait for a client, authenticate (optional),
    then send control preface (LEN...), followed by the file bytes.
    Ends after serving exactly one client or wait window elapses.

    URL example:
      tcp://user:pass@0.0.0.0:5000/path/my.cat?
          auth=1&enforce_path=1&rate=200000&timeout=5&wait=30&ssl=0
    """
    parts, o = _parse_net_url(url)  # already returns proto/host/port/timeout/ssl/etc.
    if o["proto"] != "tcp":
        raise ValueError("run_tcp_file_server requires tcp:// URL")

    # Pull extras from the query string (enforce_path, want_sha, rate, wait)
    qs = parse_qs(parts.query or "")
    enforce_path = _qflag(qs, "enforce_path", True)
    want_sha      = _qflag(qs, "sha", True)
    rate_limit    = _qnum(qs, "rate", None, float)
    wait_seconds  = _qnum(qs, "wait", None, float)  # None = wait forever

    # Discover length (and precompute sha if requested & length known)
    total_bytes, start_pos = _discover_len_and_reset(fileobj)
    sha_hex = None
    if want_sha and total_bytes is not None:
        try:
            import hashlib
            h = hashlib.sha256()
            # hash current stream content
            cur = None
            try: cur = fileobj.tell()
            except Exception: pass
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            _HSZ = 1024 * 1024
            while True:
                blk = fileobj.read(_HSZ)
                if not blk: break
                h.update(_to_bytes(blk))
            sha_hex = h.hexdigest()
            # restore
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            elif cur is not None:
                try: fileobj.seek(cur, os.SEEK_SET)
                except Exception: pass
        except Exception:
            sha_hex = None

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try: srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception: pass
        srv.bind((o["host"], o["port"]))
        srv.listen(1)

        # Wait loop: keep accepting until a client is served or wait expires
        started = time.time()
        per_accept = float(o["timeout"]) if o["timeout"] is not None else 1.0
        try: srv.settimeout(per_accept)
        except Exception: pass

        bytes_sent = 0

        while True:
            # stop conditions
            if bytes_sent > 0:
                break
            if (wait_seconds is not None) and ((time.time() - started) >= wait_seconds):
                break

            try:
                conn, peer = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            # Optional TLS
            if o["use_ssl"]:
                if not _ssl_available():
                    try: conn.close()
                    except Exception: pass
                    break
                conn = _ssl_wrap_socket(conn, server_side=True,
                                        server_hostname=None,
                                        verify=o["ssl_verify"],
                                        ca_file=o["ssl_ca_file"],
                                        certfile=o["ssl_certfile"],
                                        keyfile=o["ssl_keyfile"])
            # Per-connection timeout
            if o["timeout"] is not None:
                try: conn.settimeout(float(o["timeout"]))
                except Exception: pass

            try:
                # --------- AUTH handshake (AF1 preferred, legacy fallback) ---------
                ok = True
                if (o["user"] is not None) or (o["pw"] is not None) or o.get("force_auth", False):
                    # Expect an auth preface from client
                    try:
                        preface = conn.recv(4096)
                    except socket.timeout:
                        ok = False
                        preface = b""

                    if ok:
                        v_ok, v_user, v_scope, _r, _len, _sha = verify_auth_blob_v1(
                            preface or b"", expected_user=o["user"], secret=o["pw"],
                            max_skew=600, expect_scope=(parts.path or u"")
                        )
                        if v_ok:
                            ok = True
                        else:
                            u, p = _parse_auth_blob_legacy(preface or b"")
                            ok = (u is not None and
                                  (o["user"] is None or u == _to_bytes(o["user"])) and
                                  (o["pw"] is None or p == _to_bytes(o["pw"])))
                            # if enforcing path with legacy, optionally let the client
                            # send a second line with PATH <text> (best-effort)
                            if ok and enforce_path:
                                try:
                                    line = conn.recv(1024)
                                    if line and line.startswith(b"PATH "):
                                        want_path = _to_text(line[5:].strip())
                                        ok = (want_path == (parts.path or u""))
                                except Exception:
                                    pass

                    # Respond OK/NO then proceed/close
                    try: conn.sendall(_OK if ok else _NO)
                    except Exception: pass
                    if not ok:
                        try: conn.close()
                        except Exception: pass
                        continue

                # --------- Control preface: LEN ---------
                if total_bytes is not None:
                    # "LEN <bytes> <sha?>\n"
                    line = "LEN %d%s\n" % (
                        int(total_bytes),
                        ((" " + sha_hex) if sha_hex else "")
                    )
                else:
                    line = "LEN -1\n"
                try: conn.sendall(_to_bytes(line))
                except Exception:
                    try: conn.close()
                    except Exception: pass
                    continue

                # --------- Stream payload ---------
                if start_pos is not None:
                    try: fileobj.seek(start_pos, os.SEEK_SET)
                    except Exception: pass

                last_cb = time.time()
                rl_ts   = time.time()
                rl_bytes= 0
                CS = int(o["chunk_size"] or 65536)

                while True:
                    buf = fileobj.read(CS)
                    if not buf:
                        break
                    b = _to_bytes(buf)
                    try:
                        conn.sendall(b)
                    except Exception:
                        break
                    bytes_sent += len(b)

                    if on_progress and (time.time() - last_cb) >= 0.1:
                        try: on_progress(bytes_sent, total_bytes)
                        except Exception: pass
                        last_cb = time.time()

                    if rate_limit:
                        sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, int(rate_limit), len(b))
                        if sleep_s > 0.0:
                            time.sleep(sleep_s)

                # Unknown-length: send DONE marker so clients can stop cleanly
                if total_bytes is None:
                    try: conn.sendall(b"DONE\n")
                    except Exception: pass

            finally:
                try: conn.shutdown(socket.SHUT_RDWR)
                except Exception: pass
                try: conn.close()
                except Exception: pass

        return bytes_sent

    finally:
        try: srv.close()
        except Exception: pass

def recv_to_fileobj(fileobj, host="", port=0, proto="tcp", timeout=None,
                    max_bytes=None, chunk_size=65536, backlog=1,
                    use_ssl=False, ssl_verify=True, ssl_ca_file=None,
                    ssl_certfile=None, ssl_keyfile=None,
                    require_auth=False, expected_user=None, expected_pass=None,
                    total_timeout=None, expect_scope=None,
                    on_progress=None, rate_limit_bps=None,
                    enforce_path=True, wait_seconds=None):
    """
    Receive bytes into fileobj over TCP/UDP.

    Path enforcement:
      - UDP: expects 'PATH <...>\\n' control frame first (if enforce_path).
      - TCP: reads first line 'PATH <...>\\n' before auth/payload (if enforce_path).

    UDP control frames understood: PATH, LEN, HASH, DONE (+ AF1 auth blob).

    wait_seconds (TCP only): overall accept window to wait for a client
      (mirrors the HTTP server behavior). None = previous behavior (single accept
      with 'timeout' as the accept timeout).
    """
    proto = (proto or "tcp").lower()
    port = int(port)
    total = 0

    start_ts = time.time()
    def _time_left():
        if total_timeout is None:
            return None
        left = total_timeout - (time.time() - start_ts)
        return 0.0 if left <= 0 else left

    def _set_effective_timeout(socklike, base_timeout):
        left = _time_left()
        if left == 0.0:
            return False
        eff = base_timeout
        if left is not None:
            eff = left if eff is None else min(eff, left)
        if eff is not None:
            try:
                socklike.settimeout(eff)
            except Exception:
                pass
        return True

    if proto not in ("tcp", "udp"):
        raise ValueError("proto must be 'tcp' or 'udp'")

    # ---------------- UDP server ----------------
    if proto == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        authed_addr = None
        expected_len = None
        expected_sha = None
        path_checked = (not enforce_path)

        try:
            sock.bind(("", port))
            if timeout is None:
                try: sock.settimeout(10.0)
                except Exception: pass

            recvd_so_far = 0
            last_cb_ts = monotonic()
            rl_ts = last_cb_ts
            rl_bytes = 0

            while True:
                if _time_left() == 0.0:
                    if expected_len is not None and total < expected_len:
                        raise RuntimeError("UDP receive aborted by total_timeout before full payload received")
                    break
                if (max_bytes is not None) and (total >= max_bytes):
                    break

                if not _set_effective_timeout(sock, timeout):
                    if expected_len is not None and total < expected_len:
                        raise RuntimeError("UDP receive timed out before full payload received")
                    if expected_len is None and total > 0:
                        raise RuntimeError("UDP receive timed out with unknown length; partial data")
                    if expected_len is None and total == 0:
                        raise RuntimeError("UDP receive: no packets received before timeout (is the sender running?)")
                    break

                try:
                    data, addr = sock.recvfrom(chunk_size)
                except socket.timeout:
                    if expected_len is not None and total < expected_len:
                        raise RuntimeError("UDP receive idle-timeout before full payload received")
                    if expected_len is None and total > 0:
                        raise RuntimeError("UDP receive idle-timeout with unknown length; partial data")
                    if expected_len is None and total == 0:
                        raise RuntimeError("UDP receive: no packets received before timeout (is the sender running?)")
                    break

                if not data:
                    continue

                # (0) PATH first (strict)
                if not path_checked and data.startswith(b"PATH "):
                    got_path = _unquote_path_from_wire(data[5:].strip())
                    if _to_text(got_path) != _to_text(expect_scope or u""):
                        raise RuntimeError("UDP path mismatch: got %r expected %r"
                                           % (got_path, expect_scope))
                    path_checked = True
                    continue
                if enforce_path and not path_checked:
                    if not data.startswith(b"PATH "):
                        continue  # ignore until PATH arrives

                # (0b) Control frames
                if data.startswith(b"LEN ") and expected_len is None:
                    try:
                        parts = data.strip().split()
                        n = int(parts[1])
                        expected_len = (None if n < 0 else n)
                        if len(parts) >= 3:
                            expected_sha = parts[2].decode("ascii")
                    except Exception:
                        expected_len = None; expected_sha = None
                    continue

                if data.startswith(b"HASH "):
                    try:
                        expected_sha = data.strip().split()[1].decode("ascii")
                    except Exception:
                        expected_sha = None
                    continue

                if data == b"DONE\n":
                    break

                # (1) Auth (if required)
                if authed_addr is None and require_auth:
                    ok = False
                    v_ok, v_user, v_scope, _r, v_len, v_sha = verify_auth_blob_v1(
                        data, expected_user=expected_user, secret=expected_pass,
                        max_skew=600, expect_scope=expect_scope
                    )
                    if v_ok:
                        ok = True
                        if expected_len is None:
                            expected_len = v_len
                        if expected_sha is None:
                            expected_sha = v_sha
                    else:
                        user, pw = _parse_auth_blob_legacy(data)
                        ok = (user is not None and
                              (expected_user is None or user == _to_bytes(expected_user)) and
                              (expected_pass is None or pw == _to_bytes(expected_pass)))
                    try:
                        sock.sendto((_OK if ok else _NO), addr)
                    except Exception:
                        pass
                    if ok:
                        authed_addr = addr
                    continue

                if require_auth and addr != authed_addr:
                    continue

                # (2) Payload
                fileobj.write(data)
                try: fileobj.flush()
                except Exception: pass
                total += len(data)
                recvd_so_far += len(data)

                if rate_limit_bps:
                    sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, rate_limit_bps, len(data))
                    if sleep_s > 0.0:
                        time.sleep(min(sleep_s, 0.25))

                if on_progress and (monotonic() - last_cb_ts) >= 0.1:
                    try: on_progress(recvd_so_far, expected_len)
                    except Exception: pass
                    last_cb_ts = monotonic()

                if expected_len is not None and total >= expected_len:
                    break

            # Post-conditions
            if expected_len is not None and total != expected_len:
                raise RuntimeError("UDP receive incomplete: got %d of %s bytes" % (total, expected_len))

            if expected_sha:
                import hashlib
                try:
                    cur = fileobj.tell(); fileobj.seek(0)
                except Exception:
                    cur = None
                h = hashlib.sha256(); _HSZ = 1024 * 1024
                while True:
                    blk = fileobj.read(_HSZ)
                    if not blk: break
                    h.update(_to_bytes(blk))
                got = h.hexdigest()
                if cur is not None:
                    try: fileobj.seek(cur)
                    except Exception: pass
                if got != expected_sha:
                    raise RuntimeError("UDP checksum mismatch: got %s expected %s" % (got, expected_sha))

        finally:
            try: sock.close()
            except Exception: pass
        return total

    # ---------------- TCP server (one-shot with optional wait window) ----------------
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try: srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception: pass
        srv.bind((host or "", port))
        srv.listen(int(backlog) if backlog else 1)

        bytes_written = 0
        started = time.time()

        # per-accept wait
        per_accept = float(timeout) if timeout is not None else 1.0
        try: srv.settimeout(per_accept)
        except Exception: pass

        while True:
            if bytes_written > 0:
                break
            if wait_seconds is not None and (time.time() - started) >= wait_seconds:
                break

            try:
                conn, _peer = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            # TLS
            if use_ssl:
                if not _ssl_available():
                    try: conn.close()
                    except Exception: pass
                    break
                if not ssl_certfile:
                    try: conn.close()
                    except Exception: pass
                    raise ValueError("TLS server requires ssl_certfile (and usually ssl_keyfile).")
                conn = _ssl_wrap_socket(conn, server_side=True, server_hostname=None,
                                        verify=ssl_verify, ca_file=ssl_ca_file,
                                        certfile=ssl_certfile, keyfile=ssl_keyfile)

            recvd_so_far = 0
            last_cb_ts = monotonic()
            rl_ts = last_cb_ts
            rl_bytes = 0

            try:
                # (0) PATH line (if enforced)
                if enforce_path:
                    line = _recv_line(conn, maxlen=4096, timeout=timeout)
                    if not line or not line.startswith(b"PATH "):
                        try: conn.close()
                        except Exception: pass
                        continue
                    got_path = _unquote_path_from_wire(line[5:].strip())
                    if _to_text(got_path) != _to_text(expect_scope or u""):
                        try: conn.close()
                        except Exception: pass
                        raise RuntimeError("TCP path mismatch: got %r expected %r"
                                           % (got_path, expect_scope))

                # (1) Auth preface
                if require_auth:
                    if not _set_effective_timeout(conn, timeout):
                        try: conn.close()
                        except Exception: pass
                        continue
                    try:
                        preface = conn.recv(2048)
                    except socket.timeout:
                        try: conn.sendall(_NO)
                        except Exception: pass
                        try: conn.close()
                        except Exception: pass
                        continue

                    ok = False
                    v_ok, v_user, v_scope, _r, v_len, v_sha = verify_auth_blob_v1(
                        preface or b"", expected_user=expected_user, secret=expected_pass,
                        max_skew=600, expect_scope=expect_scope
                    )
                    if v_ok:
                        ok = True
                    else:
                        user, pw = _parse_auth_blob_legacy(preface or b"")
                        ok = (user is not None and
                              (expected_user is None or user == _to_bytes(expected_user)) and
                              (expected_pass is None or pw == _to_bytes(expected_pass)))
                    try: conn.sendall(_OK if ok else _NO)
                    except Exception: pass
                    if not ok:
                        try: conn.close()
                        except Exception: pass
                        continue

                # (2) Payload loop
                while True:
                    if _time_left() == 0.0: break
                    if (max_bytes is not None) and (bytes_written >= max_bytes): break

                    if not _set_effective_timeout(conn, timeout):
                        break
                    try:
                        data = conn.recv(chunk_size)
                    except socket.timeout:
                        break
                    if not data:
                        break

                    fileobj.write(data)
                    try: fileobj.flush()
                    except Exception: pass
                    total += len(data)
                    bytes_written += len(data)
                    recvd_so_far += len(data)

                    if rate_limit_bps:
                        sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, rate_limit_bps, len(data))
                        if sleep_s > 0.0:
                            time.sleep(min(sleep_s, 0.25))

                    if on_progress and (monotonic() - last_cb_ts) >= 0.1:
                        try: on_progress(recvd_so_far, max_bytes)
                        except Exception: pass
                        last_cb_ts = monotonic()

            finally:
                try: conn.shutdown(socket.SHUT_RD)
                except Exception: pass
                try: conn.close()
                except Exception: pass

        return total

    finally:
        try: srv.close()
        except Exception: pass


def run_udp_file_server(fileobj, url, on_progress=None):
    """
    One-shot UDP uploader: wait for a client auth/hello, reply OK, then
    send LEN + payload as datagrams (and DONE if unknown length).
    Ends after serving exactly one client or wait window elapses.

    URL example:
      udp://user:pass@0.0.0.0:5001/path/my.cat?
          auth=1&enforce_path=1&rate=250000&timeout=5&wait=30
    """
    parts, o = _parse_net_url(url)
    if o["proto"] != "udp":
        raise ValueError("run_udp_file_server requires udp:// URL")

    qs = parse_qs(parts.query or "")
    enforce_path = _qflag(qs, "enforce_path", True)
    want_sha      = _qflag(qs, "sha", True)
    rate_limit    = _qnum(qs, "rate", None, float)
    wait_seconds  = _qnum(qs, "wait", None, float)

    total_bytes, start_pos = _discover_len_and_reset(fileobj)
    sha_hex = None
    if want_sha and total_bytes is not None:
        try:
            import hashlib
            h = hashlib.sha256()
            cur = None
            try: cur = fileobj.tell()
            except Exception: pass
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            _HSZ = 1024 * 1024
            while True:
                blk = fileobj.read(_HSZ)
                if not blk: break
                h.update(_to_bytes(blk))
            sha_hex = h.hexdigest()
            if start_pos is not None:
                try: fileobj.seek(start_pos, os.SEEK_SET)
                except Exception: pass
            elif cur is not None:
                try: fileobj.seek(cur, os.SEEK_SET)
                except Exception: pass
        except Exception:
            sha_hex = None

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((o["host"], o["port"]))
        if o["timeout"] is not None:
            try: sock.settimeout(float(o["timeout"]))
            except Exception: pass

        started = time.time()
        CS = int(o["chunk_size"] or 65536)
        bytes_sent = 0
        client = None

        # ---------- wait for client hello/auth ----------
        while True:
            # overall wait window
            if (wait_seconds is not None) and ((time.time() - started) >= wait_seconds):
                break
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except Exception:
                break

            ok = True
            # Require auth if creds configured or ?auth=1
            force_auth = o.get("force_auth", False) or (o["user"] is not None) or (o["pw"] is not None)
            if force_auth:
                v_ok, v_user, v_scope, _r, _len, _sha = verify_auth_blob_v1(
                    data or b"", expected_user=o["user"], secret=o["pw"],
                    max_skew=600, expect_scope=(parts.path or u"")
                )
                if v_ok:
                    ok = True
                else:
                    u, p = _parse_auth_blob_legacy(data or b"")
                    ok = (u is not None and
                          (o["user"] is None or u == _to_bytes(o["user"])) and
                          (o["pw"] is None or p == _to_bytes(o["pw"])))
                    # optional legacy PATH check (best effort)
                    if ok and enforce_path:
                        try:
                            line, addr2 = sock.recvfrom(1024)
                            if addr2 == addr and line and line.startswith(b"PATH "):
                                want_path = _to_text(line[5:].strip())
                                ok = (want_path == (parts.path or u""))
                        except Exception:
                            pass

            try: sock.sendto((_OK if ok else _NO), addr)
            except Exception:
                ok = False

            if ok:
                client = addr
                break

        if not client:
            return 0

        # ---------- send LEN preface ----------
        if total_bytes is not None:
            line = "LEN %d%s\n" % (int(total_bytes), ((" " + sha_hex) if sha_hex else ""))
        else:
            line = "LEN -1\n"
        try:
            sock.sendto(_to_bytes(line), client)
        except Exception:
            return 0

        # ---------- stream payload ----------
        if start_pos is not None:
            try: fileobj.seek(start_pos, os.SEEK_SET)
            except Exception: pass

        last_cb = time.time()
        rl_ts   = time.time()
        rl_bytes= 0

        while True:
            buf = fileobj.read(CS)
            if not buf:
                break
            b = _to_bytes(buf)
            try:
                sock.sendto(b, client)
            except Exception:
                break
            bytes_sent += len(b)

            if on_progress and (time.time() - last_cb) >= 0.1:
                try: on_progress(bytes_sent, total_bytes)
                except Exception: pass
                last_cb = time.time()

            if rate_limit:
                sleep_s, rl_ts, rl_bytes = _pace_rate(rl_ts, rl_bytes, int(rate_limit), len(b))
                if sleep_s > 0.0:
                    time.sleep(sleep_s)

        # Unknown length: send DONE marker to signal end to the client
        if total_bytes is None:
            try: sock.sendto(b"DONE\n", client)
            except Exception:
                pass

        return bytes_sent

    finally:
        try: sock.close()
        except Exception: pass


# ---------- URL drivers ----------

# ------------------------------
# Reliable UDP (seq/ack) helpers
# ------------------------------
_UDPSEQ_MAGIC = b"PWGS"
_UDPSEQ_VER = 1
# Header: magic(4) ver(1) flags(1) seq(u32) total_bytes(u32)
_UDPSEQ_HDR = "!4sBBII"
_UDPSEQ_HDR_LEN = struct.calcsize(_UDPSEQ_HDR)
_UDPSEQ_FLAG_DATA = 0x01
_UDPSEQ_FLAG_DONE = 0x02
_UDPSEQ_FLAG_ACK  = 0x04
_UDPSEQ_FLAG_META = 0x08

def _udpseq_now():
    try:
        return monotonic()
    except Exception:
        return time.time()

def _udpseq_send_pkt(sock, pkt, addr, connected):
    if connected:
        sock.send(pkt)
    else:
        sock.sendto(pkt, addr)


def _best_lan_ip():
    # Best-effort LAN IP guess (works on Android/Termux/Linux)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ip
    except Exception:
        return None


def _format_listen_urls(proto, bind_host, port, path, query):
    # Returns list[str] of helpful URLs
    if not path:
        path = "/"
    if not path.startswith("/"):
        path = "/" + path
    q = ""
    if query:
        q = "?" + query.lstrip("?")
    urls = []
    if bind_host in ("0.0.0.0", "", None):
        urls.append("%s://127.0.0.1:%d%s%s" % (proto, port, path, q))
        ip = _best_lan_ip()
        if ip and ip != "127.0.0.1":
            urls.append("%s://%s:%d%s%s" % (proto, ip, port, path, q))
    else:
        urls.append("%s://%s:%d%s%s" % (proto, bind_host, port, path, q))
    return urls



def _udpseq_send_from_fileobj(fileobj, host, port,
                              chunk_size=1024, window=8, retries=10,
                              timeout=0.5, total_timeout=0,
                              on_progress=None,
                              meta=False, name=None,
                              sha256=False, done_retries=2):
    """
    Send fileobj over UDP with sequence numbers + ACKs + retransmit.

    Enhancements (backward compatible):
      - meta=True: send a META frame containing filename (for autosave on receiver)
      - sha256=True: include SHA-256 digest in DONE frame payload (receiver can verify)
      - done_retries: send DONE this many times (1..10)

    Returns bytes_sent (payload bytes).
    """
    # keep payload small-ish to avoid fragmentation
    if chunk_size < 256:
        chunk_size = 256
    payload_max = int(chunk_size)

    addr = (host, int(port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(float(timeout) if timeout else 0.5)

    # Try to "connect" for convenience, but keep working even if it fails.
    connected = False
    try:
        sock.connect(addr)
        connected = True
    except Exception:
        connected = False

    inflight = {}  # seq -> [last_sent_ts, pkt, retry_count, payload_len]
    seq = 0
    eof = False
    sent_bytes = 0
    start_ts = _udpseq_now()
    last_activity = start_ts

    h = hashlib.sha256() if sha256 else None

    # Determine name (best-effort)
    if name is None:
        try:
            name = os.path.basename(_to_text(getattr(fileobj, "name", "") or "")) or ""
        except Exception:
            name = ""
    try:
        name_b = name.encode("utf-8") if (name and isinstance(name, str)) else (name if isinstance(name, bytes) else b"")
    except Exception:
        try:
            name_b = _to_text(name).encode("utf-8", "ignore")
        except Exception:
            name_b = b""
    if len(name_b) > 255:
        name_b = name_b[:255]

    # Send META frame first (optional)
    if meta:
        try:
            # total_bytes field left 0 (unknown); receiver primarily needs the name
            meta_payload = struct.pack("!H", len(name_b)) + name_b
            meta_hdr = struct.pack(_UDPSEQ_HDR, _UDPSEQ_MAGIC, _UDPSEQ_VER, _UDPSEQ_FLAG_META, 0xFFFFFFFF, 0)
            _udpseq_send_pkt(sock, meta_hdr + meta_payload, addr, connected)
        except Exception:
            pass

    try:
        while True:
            now = _udpseq_now()
            if total_timeout and (now - start_ts) > float(total_timeout):
                raise IOError("udp seq send total_timeout")

            # fill window
            while (not eof) and (len(inflight) < int(window)):
                data = fileobj.read(payload_max)
                if not data:
                    eof = True
                    break
                if h is not None:
                    try:
                        h.update(data)
                    except Exception:
                        pass
                hdr = struct.pack(_UDPSEQ_HDR, _UDPSEQ_MAGIC, _UDPSEQ_VER, _UDPSEQ_FLAG_DATA, int(seq), 0)
                pkt = hdr + data
                _udpseq_send_pkt(sock, pkt, addr, connected)
                inflight[int(seq)] = [now, pkt, 0, len(data)]
                sent_bytes += len(data)
                seq += 1
                last_activity = now
                if on_progress:
                    try: on_progress(sent_bytes, None)
                    except Exception: pass

            # if eof and no inflight, send DONE and finish
            if eof and not inflight:
                done_hdr = struct.pack(_UDPSEQ_HDR, _UDPSEQ_MAGIC, _UDPSEQ_VER, _UDPSEQ_FLAG_DONE, int(seq), int(sent_bytes))
                done_payload = b""
                if h is not None:
                    try:
                        done_payload = b"SHA256:" + h.hexdigest().encode("ascii")
                    except Exception:
                        done_payload = b""
                done_pkt = done_hdr + done_payload
                try:
                    dr = int(done_retries)
                except Exception:
                    dr = 2
                dr = max(1, min(10, dr))
                for _ in range(dr):
                    _udpseq_send_pkt(sock, done_pkt, addr, connected)
                return sent_bytes

            # wait for ACK or retransmit
            try:
                pkt = None
                if connected:
                    pkt = sock.recv(1024)
                    addr2 = addr
                else:
                    pkt, addr2 = sock.recvfrom(1024)
                if not pkt or len(pkt) < _UDPSEQ_HDR_LEN:
                    continue
                magic, ver, flags, aseq, _t = struct.unpack(_UDPSEQ_HDR, pkt[:_UDPSEQ_HDR_LEN])
                if magic == _UDPSEQ_MAGIC and ver == _UDPSEQ_VER and (flags & _UDPSEQ_FLAG_ACK):
                    if int(aseq) in inflight:
                        inflight.pop(int(aseq), None)
                        last_activity = _udpseq_now()
            except socket.timeout:
                # retransmit timed-out packets
                now = _udpseq_now()
                for s in list(inflight.keys()):
                    t, p, c, plen = inflight.get(s, [0, None, 0, 0])
                    if (now - t) >= float(timeout if timeout else 0.5):
                        if c < int(retries):
                            _udpseq_send_pkt(sock, p, addr, connected)
                            inflight[s] = [now, p, c + 1, plen]
                        else:
                            raise IOError("udp seq retransmit limit reached")
                continue

    finally:
        try: sock.close()
        except Exception: pass

def _udpseq_recv_to_fileobj(fileobj, host, port,
                            chunk_size=2048, timeout=1.0, total_timeout=0,
                            on_progress=None,
                            meta=False, sha256=False,
                            print_url=False, url_path="", url_query=""):
    """
    Receive UDP seq/ack stream into fileobj. Returns True/False.

    Enhancements (backward compatible):
      - meta=True: capture META frame (filename) into fileobj._pywwwget_meta
      - sha256=True: if DONE carries SHA256:<hex>, verify against received bytes
    """
    bind_addr = (host, int(port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(float(timeout) if timeout else 1.0)
    try:
        sock.bind(bind_addr)
    except Exception:
        # if host isn't bindable, bind on all interfaces
        sock.bind(("0.0.0.0", int(port)))

# If port=0 was used, the OS will pick a free port. Capture actual bound addr/port.
try:
    bound_host, bound_port = sock.getsockname()[0], sock.getsockname()[1]
except Exception:
    bound_host, bound_port = (host, int(port))

if print_url:
    for u in _format_listen_urls("udp", bound_host if bound_host else host, bound_port, url_path, url_query):
        try:
            sys.stdout.write("Listening: %s\n" % u)
        except Exception:
            # Python 2 fallback
            try:
                print("Listening: %s" % u)
            except Exception:
                pass
    try:
        sys.stdout.flush()
    except Exception:
        pass


    expected = 0
    received = {}  # seq -> payload
    done_seen = False
    total_bytes = None
    done_sha = None
    start_ts = _udpseq_now()
    last_activity = start_ts
    peer = None

    # meta/verify state
    meta_name = ""
    h = hashlib.sha256() if sha256 else None
    bytes_written = 0

    try:
        while True:
            now = _udpseq_now()
            if total_timeout and (now - start_ts) > float(total_timeout):
                return False

            try:
                pkt, addr = sock.recvfrom(65535)
            except socket.timeout:
                if done_seen:
                    # done seen: if we have no gaps left, finish
                    if expected in received:
                        continue
                    # gaps resolved (or none)
                    break
                continue
            except Exception:
                return False

            if not pkt or len(pkt) < _UDPSEQ_HDR_LEN:
                continue

            peer = addr
            last_activity = _udpseq_now()

            try:
                magic, ver, flags, seq, totalb = struct.unpack(_UDPSEQ_HDR, pkt[:_UDPSEQ_HDR_LEN])
            except Exception:
                continue
            if magic != _UDPSEQ_MAGIC or ver != _UDPSEQ_VER:
                continue

            if flags & _UDPSEQ_FLAG_META:
                if meta:
                    payload = pkt[_UDPSEQ_HDR_LEN:]
                    try:
                        if payload and len(payload) >= 2:
                            nlen = struct.unpack("!H", payload[:2])[0]
                            name_b = payload[2:2+int(nlen)]
                            try:
                                meta_name = name_b.decode("utf-8") if hasattr(name_b, "decode") else _to_text(name_b)
                            except Exception:
                                try:
                                    meta_name = name_b.decode("utf-8", "ignore")
                                except Exception:
                                    meta_name = ""
                            try:
                                fileobj._pywwwget_meta = {"filename": meta_name, "size": None, "peer": peer}
                            except Exception:
                                pass
                    except Exception:
                        pass
                continue

            if flags & _UDPSEQ_FLAG_DATA:
                payload = pkt[_UDPSEQ_HDR_LEN:]
                if payload is None:
                    payload = b""
                # store if new
                if int(seq) not in received and int(seq) >= expected:
                    received[int(seq)] = payload
                # ACK always
                if peer:
                    ack = struct.pack(_UDPSEQ_HDR, _UDPSEQ_MAGIC, _UDPSEQ_VER, _UDPSEQ_FLAG_ACK, int(seq), 0)
                    try:
                        sock.sendto(ack, peer)
                    except Exception:
                        pass
                # write contiguous
                while expected in received:
                    data = received.pop(expected)
                    try:
                        fileobj.write(data)
                    except Exception:
                        # ensure bytes
                        try:
                            fileobj.write(_to_bytes(data))
                        except Exception:
                            return False
                    bytes_written += len(data)
                    if h is not None:
                        try:
                            h.update(data)
                        except Exception:
                            pass
                    expected += 1
                    if on_progress:
                        try: on_progress(bytes_written, total_bytes)
                        except Exception: pass

                # If done already seen and no pending gaps, finish
                if done_seen and not received:
                    break

            elif flags & _UDPSEQ_FLAG_DONE:
                done_seen = True
                total_bytes = int(totalb) if totalb else None
                payload = pkt[_UDPSEQ_HDR_LEN:]
                if payload and payload.startswith(b"SHA256:"):
                    try:
                        done_sha = _to_text(payload[len(b"SHA256:"):]).strip()
                    except Exception:
                        done_sha = None
                # Update meta size if we have it
                if meta and meta_name:
                    try:
                        fileobj._pywwwget_meta = {"filename": meta_name, "size": total_bytes, "peer": peer, "sha256": done_sha}
                    except Exception:
                        pass
                # If no pending packets, finish
                if not received:
                    break
                # else keep receiving until gaps filled

        # Finished loop: verify sha if requested and available
        if h is not None and done_sha:
            try:
                got = h.hexdigest()
                if got.lower() != str(done_sha).lower():
                    raise IOError("UDP SHA256 mismatch")
            except Exception:
                # propagate mismatch as failure
                return False

        return True

    finally:
        try: sock.close()
        except Exception: pass

def send_via_url(fileobj, url, send_from_fileobj_func=send_from_fileobj):
    parts, o = _parse_net_url(url)

    # Reliable UDP mode (?seq=1 on udp://)
    if o.get("proto") == "udp" and o.get("udp_seq"):
        ack_to = o.get("udp_ack_timeout")
        if ack_to is None:
            ack_to = o.get("timeout", 0.5) or 0.5
        return _udpseq_send_from_fileobj(
            fileobj,
            o["host"], o["port"],
            chunk_size=o.get("chunk_size", 1024),
            window=o.get("udp_window", 8),
            retries=o.get("udp_retries", 10),
            timeout=ack_to,
            total_timeout=o.get("total_timeout", 0),
            meta=o.get("udp_meta", False),
            name=os.path.basename(o.get("path") or "") or None,
            sha256=o.get("udp_sha256", False),
            done_retries=o.get("done_retries", 2),
        )

    use_auth = (o["user"] is not None and o["pw"] is not None) or o["force_auth"]
    return send_from_fileobj_func(
        fileobj,
        o["host"], o["port"], proto=o["proto"],
        timeout=o["timeout"], chunk_size=o["chunk_size"],
        use_ssl=o["use_ssl"], ssl_verify=o["ssl_verify"],
        ssl_ca_file=o["ssl_ca_file"], ssl_certfile=o["ssl_certfile"], ssl_keyfile=o["ssl_keyfile"],
        server_hostname=o["server_hostname"],
        auth_user=(o["user"] if use_auth else None),
        auth_pass=(o["pw"]   if use_auth else None),
        auth_scope=o["path"],
        want_sha=o["want_sha"],
        enforce_path=o["enforce_path"],
        path_text=o["path"],
    )


def recv_via_url(fileobj, url, recv_to_fileobj_func=recv_to_fileobj):
    parts, o = _parse_net_url(url)

    # Reliable UDP mode (?seq=1 on udp://)
    if o.get("proto") == "udp" and o.get("udp_seq"):
        ack_to = o.get("udp_ack_timeout")
        if ack_to is None:
            ack_to = o.get("timeout", 1.0) or 1.0
        return _udpseq_recv_to_fileobj(
            fileobj,
            (o.get("bind") or o["host"]), o["port"],
            chunk_size=o.get("chunk_size", 2048),
            timeout=ack_to,
            total_timeout=o.get("total_timeout", 0),
            meta=o.get("udp_meta", False),
            sha256=o.get("udp_sha256", False),
            print_url=o.get("print_url", False),
            url_path=(parts.path if parts else ""),
            url_query=(parts.query if parts else ""),
        )

    require_auth = (o["user"] is not None and o["pw"] is not None) or o["force_auth"]
    return recv_to_fileobj_func(
        fileobj,
        o["host"], o["port"], proto=o["proto"],
        timeout=o["timeout"], total_timeout=o["total_timeout"],
        chunk_size=o["chunk_size"],
        use_ssl=o["use_ssl"], ssl_verify=o["ssl_verify"],
        ssl_ca_file=o["ssl_ca_file"], ssl_certfile=o["ssl_certfile"], ssl_keyfile=o["ssl_keyfile"],
        require_auth=require_auth,
        expected_user=(o["user"] if require_auth else None),
        expected_pass=(o["pw"]   if require_auth else None),
        auth_scope=o["path"],
        want_sha=o["want_sha"],
        enforce_path=o["enforce_path"],
        expected_path=o["path"],
    )


def send_via_http(fileobj, url, send_server_func=None, on_progress=None, backlog=5):
    """
    SERVER SIDE (uploader): serve 'fileobj' once via HTTP/HTTPS according to URL.
    Equivalent to send_via_url but for http(s)://
    
    Args:
        fileobj: readable file-like object positioned at the start of the data to serve
        url (str): http(s)://[user:pass@]host:port/path?query...
        send_server_func: optional override (defaults to run_http_file_server)
        on_progress: optional callback(bytes_sent, total_or_None)
        backlog (int): listen backlog (for the one accepted request)
    Returns:
        int: total bytes sent to the client (0 if none)
    """
    if send_server_func is None:
        # Provided earlier; tiny HTTP/HTTPS one-shot server with path/auth/sha support
        send_server_func = run_http_file_server
    return send_server_func(fileobj, url, on_progress=on_progress, backlog=backlog)


def recv_via_http(fileobj, url, http_download_func=None, copy_chunk_size=65536):
    """
    CLIENT SIDE (downloader): fetch via HTTP/HTTPS and copy into fileobj.
    Supports ?h=/headers=…/hjson=… for outbound request headers,
    and ?rate=… to throttle local write rate (bytes/sec).
    """
    if http_download_func is None:
        http_download_func = download_file_from_http_file

    # Extract client-side extras: headers + optional write rate
    u = urlparse(url)
    qs = parse_qs(u.query or "")
    client_headers = _parse_headers_from_qs(qs)
    rate_limit_bps = _qnum(qs, "rate", None, float)  # client write pacing

    # Use your downloader (it accepts headers=)
    tmpfp = http_download_func(url, headers=client_headers)
    total = 0
    try:
        try: tmpfp.seek(0)
        except Exception: pass

        last_ts = time.time()
        bytes_since = 0

        while True:
            chunk = tmpfp.read(copy_chunk_size)
            if not chunk:
                break
            b = _to_bytes(chunk)
            fileobj.write(b)
            total += len(b)

            # client-side pacing (write throttling)
            if rate_limit_bps:
                sleep_s, last_ts, bytes_since = _pace_rate(last_ts, bytes_since, int(rate_limit_bps), len(b))
                if sleep_s > 0.0:
                    time.sleep(sleep_s)

        try: fileobj.flush()
        except Exception: pass
    finally:
        try: tmpfp.close()
        except Exception: pass
    return total
