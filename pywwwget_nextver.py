#!/usr/bin/env python
# -*- coding: utf-8 -*-
# NOTE: This is a merged build based on the more feature-rich v35 ('clean') module,
# with targeted improvements from the v36 'opt' variant (notably improved LAN IP detection
# for print_url and other small robustness tweaks), while keeping the richer URL query options.
"""
pywwwgetadv_clean.py

A small, self-contained subset of PyNeoWWW-Get style helpers that keeps the same
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
import io
import re
import sys
import platform
import socket
import shutil
import time
import struct
import hashlib
import tempfile
import gzip
import ssl
import mimetypes

# Initialize mimetypes
try:
    mimetypes.init()
except Exception:
    pass
import base64
import threading

try:
    from io import BytesIO
except ImportError:
    try:
        from cStringIO import StringIO as BytesIO  # py2 fallback
    except Exception:
        from StringIO import StringIO as BytesIO

try:
    # Py3
    from urllib.parse import quote_from_bytes, unquote_to_bytes
except ImportError:
    # Py2
    from urllib import quote as _quote
    from urllib import unquote as _unquote

    def quote_from_bytes(b, safe=''):
        # Py2 urllib.quote expects "str" (bytes)
        return _quote(b, safe=safe)

    def unquote_to_bytes(s):
        # Returns "str" (bytes) in Py2
        return _unquote(s)


_TEXT_MIME_DEFAULT = 'text/plain; charset=utf-8'
_BIN_MIME_DEFAULT = 'application/octet-stream'


def _is_probably_text(data_bytes):
    """
    Heuristic: treat as text if it decodes as UTF-8 and does not contain many
    control bytes (except common whitespace).
    """
    if not data_bytes:
        return True
    # Fast path: NUL strongly suggests binary
    if b'\x00' in data_bytes:
        return False
    try:
        decoded = data_bytes.decode('utf-8')
    except Exception:
        return False

    # Count "control" chars excluding common whitespace
    control = 0
    for ch in decoded:
        o = ord(ch)
        if (o < 32 and ch not in u'\t\n\r') or o == 127:
            control += 1
    # Allow a small fraction of control chars
    return control <= max(1, len(decoded) // 200)


def data_url_encode(fileobj,
                    mime=None,
                    is_text=None,
                    charset='utf-8',
                    base64_encode=None):
    """
    Read all bytes from a file-like object and return a data: URL string.

    Args:
        fileobj: file-like (must support read()) returning bytes/str.
        mime: optional MIME type (e.g. 'image/png', 'text/plain').
              If not provided, defaults to text/plain; charset=utf-8 for text
              or application/octet-stream for binary.
        is_text: force text/binary decision (True/False). If None, auto-detect.
        charset: charset used when defaulting to text/* or when mime starts with text/
                 and mime doesn't already declare a charset.
        base64_encode: if True, always base64. If False, always percent-encode.
                       If None, choose percent-encode for text and base64 for binary.

    Returns:
        A unicode/text string containing the full data URL.
    """
    raw = fileobj.read()
    # Normalize to bytes
    if isinstance(raw, text_type):
        # If someone passed a text stream, encode it as utf-8 bytes
        raw_bytes = raw.encode(charset)
        detected_text = True
    else:
        raw_bytes = raw
        detected_text = _is_probably_text(raw_bytes)

    if is_text is None:
        is_text = detected_text

    if mime is None:
        mime = _TEXT_MIME_DEFAULT if is_text else _BIN_MIME_DEFAULT
    else:
        # If it's a text/* mime and no charset declared, append one
        mlow = mime.lower()
        if mlow.startswith('text/') and 'charset=' not in mlow:
            mime = mime + '; charset=' + charset

    if base64_encode is None:
        base64_encode = not is_text  # text => percent, binary => base64

    if base64_encode:
        b64 = base64.b64encode(raw_bytes)
        if not isinstance(b64, text_type):
            b64 = b64.decode('ascii')
        return u'data:{0};base64,{1}'.format(mime, b64)
    else:
        # Percent-encode bytes
        encoded = quote_from_bytes(raw_bytes, safe="!$&'()*+,;=:@-._~")
        if not isinstance(encoded, text_type):
            # Py2 quote returns bytes-str; ensure unicode
            encoded = encoded.decode('ascii')
        return u'data:{0},{1}'.format(mime, encoded)


_DATA_URL_RE = re.compile(r'^data:(?P<meta>[^,]*?),(?P<data>.*)$', re.DOTALL)


def data_url_decode(data_url):
    """
    Parse a data: URL and return (bytes_io, mime, is_base64).

    Returns:
        (MkTempFile(data_bytes), mime_string_or_None, is_base64_bool)

    Notes:
        - If no MIME is provided in the URL, mime will be None (per RFC 2397 default is text/plain;charset=US-ASCII).
        - This function does not attempt charset transcoding; it returns raw bytes.
    """
    if not isinstance(data_url, text_type):
        # Accept bytes input too
        try:
            data_url = data_url.decode('utf-8')
        except Exception:
            data_url = data_url.decode('ascii')

    m = _DATA_URL_RE.match(data_url)
    if not m:
        raise ValueError('Not a valid data: URL')

    meta = m.group('meta')
    data_part = m.group('data')

    meta_parts = [p for p in meta.split(';') if p] if meta else []
    is_base64 = False
    mime = None

    if meta_parts:
        # First part may be mime if it contains '/' or looks like type/subtype
        if '/' in meta_parts[0]:
            mime = meta_parts[0]
            rest = meta_parts[1:]
        else:
            rest = meta_parts

        for p in rest:
            if p.lower() == 'base64':
                is_base64 = True
            else:
                # keep parameters on mime if present (e.g. charset)
                if mime is None:
                    mime = p
                else:
                    mime = mime + ';' + p

    if is_base64:
        # data_part is base64 ascii text
        try:
            decoded_bytes = base64.b64decode(data_part.encode('ascii'))
        except Exception:
            # some inputs may include whitespace/newlines
            cleaned = ''.join(data_part.split())
            decoded_bytes = base64.b64decode(cleaned.encode('ascii'))
    else:
        # Percent-decoding; must operate on str, returns bytes in both py2/py3 wrapper
        decoded_bytes = unquote_to_bytes(data_part)

        # Py3 wrapper returns bytes; Py2 returns "str" bytes already.
        if isinstance(decoded_bytes, text_type):
            decoded_bytes = decoded_bytes.encode('latin-1')

    return MkTempFile(decoded_bytes), mime, is_base64


try:
    from urllib.parse import urlparse, urlunparse, parse_qs, unquote
    from urllib.request import Request, build_opener, HTTPBasicAuthHandler
    from urllib.error import URLError, HTTPError
    from urllib.request import HTTPPasswordMgrWithDefaultRealm
    try:
        from http.client import HTTPException
    except Exception:
        HTTPException = Exception
except Exception:
    from urlparse import urlparse, urlunparse, parse_qs  # type: ignore
    from urllib2 import Request, build_opener, HTTPBasicAuthHandler, URLError, HTTPError  # type: ignore
    from urllib2 import HTTPPasswordMgrWithDefaultRealm  # type: ignore
    try:
        from httplib import HTTPException  # type: ignore
    except Exception:
        HTTPException = Exception
    try:
        from urllib import unquote  # py2
    except Exception:
        def unquote(x):  # very small fallback
            return x


# HTTP server (for send-file mode)
try:
    # py3
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import socketserver as _socketserver
except Exception:
    # py2
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer  # type: ignore
    import SocketServer as _socketserver  # type: ignore



# Optional deps
haverequests = False
try:
    import requests  # noqa
    haverequests = True
except Exception:
    pass

haveurllib3 = False
try:
    import urllib3  # noqa
    haveurllib3 = True
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


# --- Configuration ---
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

__program_name__ = "PyNeoWWW-Get"
__program_alt_name__ = "PyWWWGet"
__program_small_name__ = "wwwget"
__project__ = __program_name__
__project_url__ = "https://github.com/GameMaker2k/PyNeoWWW-Get"
__version_info__ = (2, 2, 0, "RC 1", 1)
__version_date_info__ = (2026, 1, 23, "RC 1", 1)
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
geturls_ua_pywwwget_python_alt = "Mozilla/5.0 ({osver}; {archtype}; +{prourl}) {pyimp}/{pyver} (KHTML, like Gecko) {proname}/{prover}".format(osver=platform.system(
)+" "+platform.release(), archtype=platform.machine(), prourl=__project_url__, pyimp=py_implementation, pyver=platform.python_version(), proname=__project__, prover=__version__)
geturls_ua_googlebot_google = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
geturls_ua_googlebot_google_old = "Googlebot/2.1 (+http://www.google.com/bot.html)"
geturls_headers_pywwwget_python = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_pywwwget_python, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close",
                                    'SEC-CH-UA': "\""+__project__+"\";v=\""+str(__version__)+"\", \"Not;A=Brand\";v=\"8\", \""+py_implementation+"\";v=\""+str(platform.release())+"\"", 'SEC-CH-UA-FULL-VERSION': str(__version__), 'SEC-CH-UA-PLATFORM': ""+py_implementation+"", 'SEC-CH-UA-ARCH': ""+platform.machine()+"", 'SEC-CH-UA-PLATFORM-VERSION': str(__version__), 'SEC-CH-UA-BITNESS': str(PyBitness)}
geturls_headers_pywwwget_python_alt = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_pywwwget_python_alt, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close",
                                        'SEC-CH-UA': "\""+__project__+"\";v=\""+str(__version__)+"\", \"Not;A=Brand\";v=\"8\", \""+py_implementation+"\";v=\""+str(platform.release())+"\"", 'SEC-CH-UA-FULL-VERSION': str(__version__), 'SEC-CH-UA-PLATFORM': ""+py_implementation+"", 'SEC-CH-UA-ARCH': ""+platform.machine()+"", 'SEC-CH-UA-PLATFORM-VERSION': str(__version__), 'SEC-CH-UA-BITNESS': str(PyBitness)}
geturls_headers_googlebot_google = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_googlebot_google, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6",
                                    'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close"}
geturls_headers_googlebot_google_old = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_googlebot_google_old, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6",
                                        'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close"}

__use_inmem__ = True
__use_memfd__ = True
__use_spoolfile__ = False
__use_spooldir__ = tempfile.gettempdir()

BYTES_PER_KiB = 1024
BYTES_PER_MiB = 1024 * BYTES_PER_KiB

DEFAULT_SPOOL_MAX = 4 * BYTES_PER_MiB      # 4 MiB per spooled temp file
__spoolfile_size__ = DEFAULT_SPOOL_MAX

DEFAULT_BUFFER_MAX = 256 * BYTES_PER_KiB   # 256 KiB copy buffer
__filebuff_size__ = DEFAULT_BUFFER_MAX

# ---- Py2/Py3 type helpers ----
try:
    text_type = unicode  # noqa: F821  (Py2)
except NameError:
    text_type = str      # Py3

binary_types = (bytes, bytearray)
try:
    binary_types = (bytes, bytearray, memoryview)  # Py3 has memoryview; Py2 does too, but keep safe
except NameError:
    pass

# --------------------------
# Small helpers
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
    if not path:
        path = "/"
    if not path.startswith("/"):
        path = "/" + path
    q = ""
    if query:
        q = "?" + query.lstrip("?")
    urls = []
    if not bind_host or bind_host == "0.0.0.0":
        urls.append("%s://127.0.0.1:%d%s%s" % (scheme, port, path, q))
        ip = _best_lan_ip()
        if ip and ip != "127.0.0.1":
            urls.append("%s://%s:%d%s%s" % (scheme, ip, port, path, q))
    else:
        urls.append("%s://%s:%d%s%s" % (scheme, bind_host, port, path, q))
    return urls

def _parse_kv_headers(qs, prefix="hdr_"):
    out = {}
    for k in qs.keys():
        if k.startswith(prefix):
            hk = k[len(prefix):].replace("_", "-")
            try:
                out[hk] = qs.get(k)[0]
            except Exception:
                try:
                    out[hk] = qs[k][0]
                except Exception:
                    pass
    return out


def _throttle_bps(rate_bps, sent, started):
    """Sleep to enforce approximate bytes/sec rate."""
    try:
        rate_bps = float(rate_bps)
    except Exception:
        return
    if rate_bps <= 0:
        return
    elapsed = time.time() - started
    if elapsed <= 0:
        return
    should = float(sent) / rate_bps
    if should > elapsed:
        time.sleep(should - elapsed)





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
      - isbytes=True  -> file expects bytes; 'data' must be bytes-like (or str which will be encoded)
      - isbytes=False -> file expects text; 'data' must be text (or bytes which will be decoded)

    Notes:
      - On Windows, NamedTemporaryFile(delete=True) keeps the file open and cannot be reopened by
        other processes. Use delete=False if you need to pass the path elsewhere.
      - For text: in-memory StringIO ignores 'newline' and 'text_errors' (as usual).
      - When available, and if usememfd=True, memfd is used only for inmem=True and isbytes=True
        (Linux-only).
      - If autoswitch_spool=True and initial data size exceeds spool_max, in-memory storage is
        skipped and a spooled file is used instead (if use_spool=True).
      - If on_create is not None, it is called as on_create(fp, kind) where kind is one of:
        "memfd", "bytesio", "stringio", "spool", "disk".
    """

    # ---- sanitize params (avoid None surprises) ----
    prefix = prefix or ""
    suffix = suffix or ""
    # dir/spool_dir may be None (allowed)

    # ---- normalize initial data to the right type early ----
    init = None
    if data is not None:
        if isbytes:
            # Require bytes-like; allow common safe conversions
            if isinstance(data, binary_types):
                # bytes / bytearray / memoryview
                init = bytes(data) if not isinstance(data, bytes) else data
            elif isinstance(data, text_type):
                init = data.encode(encoding)
            else:
                raise TypeError("data must be bytes-like for isbytes=True")
        else:
            # Require text; allow decoding from bytes-like
            if isinstance(data, binary_types):
                # NOTE: preserve original behavior: STRICT decode here (not text_errors)
                init = bytes(data).decode(encoding, errors="strict")
            elif isinstance(data, text_type):
                init = data
            else:
                raise TypeError("data must be text (str/unicode) for isbytes=False")

    init_len = len(init) if (init is not None and isbytes) else None

    # ---- helper: callback ----
    def _created(fp, kind):
        if on_create is not None:
            on_create(fp, kind)

    # ---- helper: wrap binary handle as text with encoding/newline/errors ----
    def _wrap_text(binary_handle):
        # Prefer TextIOWrapper when available/usable.
        # In Py2, io.TextIOWrapper exists and works with binary handles.
        return io.TextIOWrapper(binary_handle, encoding=encoding,
                                newline=newline, errors=text_errors)

    # =========================
    # In-memory branch
    # =========================
    if inmem:
        # optional autoswitch to spool for large initial bytes payload
        if autoswitch_spool and use_spool and init_len is not None and init_len > spool_max:
            # fall through to spool/disk branches below
            pass
        else:
            # memfd only for bytes and only where available (Linux + Python that exposes it)
            memfd_create = getattr(os, "memfd_create", None)
            if usememfd and isbytes and callable(memfd_create):
                name = memfd_name or prefix or "MkTempFile"
                flags = 0
                # Close-on-exec is almost always what you want for temps
                if hasattr(os, "MFD_CLOEXEC"):
                    flags |= os.MFD_CLOEXEC
                # Optional sealing support
                if memfd_allow_sealing and hasattr(os, "MFD_ALLOW_SEALING"):
                    flags |= os.MFD_ALLOW_SEALING
                if memfd_flags_extra:
                    flags |= int(memfd_flags_extra)

                fd = memfd_create(name, flags)
                f = os.fdopen(fd, "w+b")
                if init is not None:
                    f.write(init)
                if reset_to_start:
                    f.seek(0)
                _created(f, "memfd")
                return f

            # Fallback: pure-Python in-memory objects
            if isbytes:
                f = io.MkTempFile(init if init is not None else b"")
                if reset_to_start:
                    f.seek(0)
                _created(f, "bytesio")
                return f
            else:
                # StringIO ignores newline/text_errors by design
                f = io.StringIO(init if init is not None else u"")
                if reset_to_start:
                    f.seek(0)
                _created(f, "stringio")
                return f

    # =========================
    # Spooled (RAM then disk)
    # =========================
    if use_spool:
        # Always create binary spooled file; wrap for text if needed
        b = tempfile.SpooledTemporaryFile(max_size=spool_max, mode="w+b", dir=spool_dir)
        f = b if isbytes else _wrap_text(b)
        if init is not None:
            f.write(init)
        if reset_to_start:
            f.seek(0)
        _created(f, "spool")
        return f

    # =========================
    # On-disk temp (NamedTemporaryFile)
    # =========================
    b = tempfile.NamedTemporaryFile(mode="w+b", prefix=prefix, suffix=suffix, dir=dir, delete=delete)
    f = b if isbytes else _wrap_text(b)
    if init is not None:
        f.write(init)
    if reset_to_start:
        f.seek(0)
    _created(f, "disk")
    return f



def _hs_token():
    # short ascii token for handshake correlation
    try:
        import random
        return ('%x' % random.getrandbits(64)).encode('ascii')
    except Exception:
        try:
            return ('%x' % (int(time.time()*1000000) ^ os.getpid())).encode('ascii')
        except Exception:
            return ('%x' % int(time.time()*1000000)).encode('ascii')

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

def _set_query_param(url, key, value):
    """Return url with query param key set to value (string)."""
    try:
        up = urlparse(url)
        qs = up.query or ""
        parts = []
        if qs:
            for kv in qs.split("&"):
                if not kv:
                    continue
                if kv.split("=", 1)[0] != key:
                    parts.append(kv)
        parts.append("%s=%s" % (key, value))
        newq = "&".join(parts)
        return urlunparse((up.scheme, up.netloc, up.path, up.params, newq, up.fragment))
    except Exception:
        return url

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
    if not file_dir:
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

        bio = MkTempFile()
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
    bio = MkTempFile(_to_bytes(data))
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
        bio = MkTempFile()
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
    bio = MkTempFile(_to_bytes(data))
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

    # URLLib3
    elif usehttp == "urllib3" and haveurllib3:
        http = urllib3.PoolManager()
        if username and password:
            auth_headers = urllib3.make_headers(basic_auth="{}:{}".format(username, password))
            headers.update(auth_headers)
        # Request with preload_content=False to get a file-like object
        resp = http.request("GET", rebuilt_url, headers=headers, preload_content=False)
        shutil.copyfileobj(resp, httpfile)
        resp.release_conn()

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

def _net_log(verbose, msg):
    """Lightweight network debug logging (stderr)."""
    if not verbose:
        return
    try:
        sys.stderr.write(str(msg).rstrip() + "\n")
        sys.stderr.flush()
    except Exception:
        pass

def _resolve_wait_timeout(scheme, mode, o):
    """Resolve effective wait timeout for sender-side wait/handshake.

    Priority:
      1) explicit wait_timeout
      2) wait_forever -> None
      3) positive total_timeout
      4) UDP raw -> None (wait indefinitely by default)
      5) fallback to timeout
    """
    wt = o.get("wait_timeout", None)
    if wt is not None:
        try:
            return float(wt)
        except Exception:
            return wt
    if o.get("wait_forever"):
        return None
    tt = o.get("total_timeout", 0.0)
    try:
        if tt not in (None, 0, 0.0) and float(tt) > 0.0:
            return float(tt)
    except Exception:
        pass
    if scheme == "udp" and (mode or "seq") == "raw":
        return None
    return o.get("timeout", None)

def _parse_net_url(url):
    p = urlparse(url)
    qs = parse_qs(p.query or "")
    mode = _qstr(qs, "mode", "seq" if p.scheme == "udp" else "raw").lower()

    # Timeouts:
    # - For TCP listener, legacy behavior is to wait indefinitely for a connection unless user asks otherwise.
    # - For UDP (especially seq mode), timeouts are needed to drive retransmit/finish behavior.
    has_timeout = "timeout" in qs
    if p.scheme == "tcp" and not has_timeout:
        timeout = None
    else:
        timeout = float(_qnum(qs, "timeout", 1.0 if p.scheme == "udp" else 30.0, cast=float))
    accept_timeout = float(_qnum(qs, "accept_timeout", 0.0 if p.scheme == "tcp" else (timeout or 0.0), cast=float))
    total_timeout = float(_qnum(qs, "total_timeout", 0.0, cast=float))
    window = int(_qnum(qs, "window", 32, cast=int))
    retries = int(_qnum(qs, "retries", 20, cast=int))
    chunk = int(_qnum(qs, "chunk", 1200 if p.scheme == "udp" else 65536, cast=int))
    print_url = _qflag(qs, "print_url", False)
    # Sender-side wait/retry options (tcp connect retry; udp raw-meta READY handshake)
    if "wait" in qs:
        wait = _qflag(qs, "wait", False)
    else:
        # Default ON for udp raw so sender waits for receiver like udp seq.
        wait = (p.scheme == "udp" and mode == "raw")
    if "connect_wait" in qs:
        connect_wait = _qflag(qs, "connect_wait", False)
    else:
        # Default ON for tcp so sender waits for receiver.
        connect_wait = (p.scheme == "tcp")
    handshake = _qflag(qs, "handshake", True if p.scheme in ("tcp","udp") else False)
    hello_interval = float(_qnum(qs, "hello_interval", 0.1, cast=float))
    wait_timeout = _qnum(qs, "wait_timeout", None, cast=float)
    wait_forever = _qflag(qs, "wait_forever", False)
    verbose = _qflag(qs, "verbose", False) or _qflag(qs, "debug", False)
    bind = _qstr(qs, "bind", None)
    resume = _qflag(qs, "resume", False)
    resume_to = _qstr(qs, "resume_to", None)
    save = _qflag(qs, "save", False)
    overwrite = _qflag(qs, "overwrite", False)
    save_dir = _qstr(qs, "save_dir", None)
    done = _qflag(qs, "done", False)
    done_token = _qstr(qs, "done_token", None)
    framing = _qstr(qs, "framing", None)
    sha256 = _qflag(qs, "sha256", False) or _qflag(qs, "sha", False)
    raw_meta = _qflag(qs, "raw_meta", True)
    raw_ack = _qflag(qs, "raw_ack", False)
    raw_ack_timeout = _qnum(qs, "raw_ack_timeout", 0.5, cast=float)
    raw_ack_retries = int(_qnum(qs, "raw_ack_retries", 40, cast=int))
    raw_ack_window = int(_qnum(qs, "raw_ack_window", 1, cast=int))
    if raw_ack_window < 1:
        raw_ack_window = 1
    raw_sha = _qflag(qs, "raw_sha", False)
    raw_hash = _qstr(qs, "raw_hash", "sha256")

    return p, {
        "mode": mode,
        "timeout": timeout,
        "accept_timeout": accept_timeout,
        "total_timeout": total_timeout,
        "window": window,
        "retries": retries,
        "chunk": chunk,
        "print_url": print_url,
        "wait": wait,
        "connect_wait": connect_wait,
        "wait_timeout": wait_timeout,
        "wait_forever": wait_forever,
        "verbose": verbose,
        "handshake": handshake,
        "hello_interval": hello_interval,
        "bind": bind,
        "resume": resume,
        "resume_to": resume_to,
        "save": save,
        "overwrite": overwrite,
        "save_dir": save_dir,
        "done": done,
        "done_token": done_token,
        "framing": framing,
        "sha256": sha256,
        "raw_meta": raw_meta,
        "raw_ack": raw_ack,
        "raw_ack_timeout": raw_ack_timeout,
        "raw_ack_retries": raw_ack_retries,
        "raw_ack_window": raw_ack_window,
        "raw_sha": raw_sha,
        "raw_hash": raw_hash,
    }

def recv_to_fileobj(fileobj, host, port, proto="tcp", path_text=None, **kwargs):
    """
    Receive bytes into fileobj.
    - TCP:
        * default: stream until FIN
        * framing=len: read a fixed header that declares payload length, then read exactly N bytes (safe)
        * optional sha256=1 with framing=len: reads a trailing sha256 digest and verifies
        * optional resume=1: receiver sends OFFSET <n>\n and sender seeks before streaming
    - UDP raw: receive until DONE frame (best effort) or end_timeout silence.
    - UDP seq: reliable with ACK/DONE and optional RESUME handshake.
        * framing=len: stop immediately when total length is reached (uses sender META length)
        * sha256=1: verify digest sent in DONE control packet (no token collision risk)
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

        chosen_port = srv.getsockname()[1]
        if kwargs.get("print_url"):
            path = path_text or "/"
            bind_host = host or "0.0.0.0"
            for u in _listen_urls("tcp", bind_host, chosen_port, path, ""):
                sys.stdout.write("Listening: %s\n" % u)
            try:
                sys.stdout.flush()
            except Exception:
                pass

        idle_to = kwargs.get("idle_timeout", None)
        acc_to = kwargs.get("accept_timeout", None)
        to = kwargs.get("timeout", None)
        try:
            if idle_to is not None and float(idle_to) > 0:
                srv.settimeout(float(idle_to))
            elif acc_to is not None and float(acc_to) > 0:
                srv.settimeout(float(acc_to))
            elif to is not None and float(to) > 0:
                srv.settimeout(float(to))
            else:
                srv.settimeout(None)  # legacy behavior
        except Exception:
            pass

        try:
            conn, _addr = srv.accept()
        except socket.timeout:
            try:
                srv.close()
            except Exception:
                pass
            return False
        except KeyboardInterrupt:
            try:
                srv.close()
            except Exception:
                pass
            raise
        except Exception:
            try:
                srv.close()
            except Exception:
                pass
            return False

        # Connection read timeout (separate from accept)
                # Optional handshake: if first line is HELLO <token>, reply READY <token>.
        # Uses MSG_PEEK so we only consume when HELLO is present.
        if kwargs.get("handshake", True):
            try:
                conn.settimeout(0.25)
                if hasattr(socket, "MSG_PEEK"):
                    peekh = conn.recv(6, socket.MSG_PEEK)
                else:
                    peekh = b""
            except Exception:
                peekh = b""
            try:
                if to is not None and float(to) > 0:
                    conn.settimeout(float(to))
                else:
                    conn.settimeout(None)
            except Exception:
                pass
            if peekh == b"HELLO ":
                line = b""
                while True:
                    b = conn.recv(1)
                    if not b:
                        break
                    line += b
                    if line.endswith(b"\n") or len(line) > 4096:
                        break
                tok = b""
                try:
                    parts = line.strip().split(None, 1)
                    if len(parts) == 2:
                        tok = parts[1]
                except Exception:
                    tok = b""
                try:
                    conn.sendall(b"READY " + tok + b"\n")
                except Exception:
                    pass

        try:
            if to is not None and float(to) > 0:
                conn.settimeout(float(to))
        except Exception:
            pass

        # Optional: consume "PATH ..." line (best effort)
        try:
            conn.settimeout(0.25)
            if hasattr(socket, "MSG_PEEK"):
                peek = conn.recv(5, socket.MSG_PEEK)
            else:
                peek = b""
        except Exception:
            peek = b""
        try:
            if to is not None and float(to) > 0:
                conn.settimeout(float(to))
            else:
                conn.settimeout(None)
        except Exception:
            pass

        if peek == b"PATH ":
            line = b""
            while True:
                b = conn.recv(1)
                if not b:
                    break
                line += b
                if line.endswith(b"\n") or len(line) > 4096:
                    break

        # Resume handshake: receiver tells sender where to start
        if kwargs.get("resume"):
            try:
                cur = fileobj.tell()
            except Exception:
                cur = 0
            msg = ("OFFSET %d\n" % int(cur)).encode("utf-8")
            try:
                conn.sendall(msg)
            except Exception:
                pass

        framing = (kwargs.get("framing") or "").lower()
        want_sha = bool(kwargs.get("sha256") or kwargs.get("sha") or kwargs.get("want_sha"))
        h = hashlib.sha256() if want_sha else None

        if framing == "len":
            # Header: b"PWG4" + uint64 size + uint32 flags (bit0=sha256)
            # Then payload bytes. If sha256 flag set, sender appends 32-byte digest after payload.
            try:
                header = b""
                while len(header) < 16:
                    chunk = conn.recv(16 - len(header))
                    if not chunk:
                        break
                    header += _to_bytes(chunk)
                if len(header) != 16 or not header.startswith(b"PWG4"):
                    # unknown framing header
                    try:
                        conn.close()
                    except Exception:
                        pass
                    try:
                        srv.close()
                    except Exception:
                        pass
                    return False
                size = struct.unpack("!Q", header[4:12])[0]
                flags = struct.unpack("!I", header[12:16])[0]
                sha_in_stream = bool(flags & 1)
                remaining = int(size)

                while remaining > 0:
                    chunk = conn.recv(min(65536, remaining))
                    if not chunk:
                        break
                    chunk = _to_bytes(chunk)
                    fileobj.write(chunk)
                    if h is not None:
                        h.update(chunk)
                    remaining -= len(chunk)

                if remaining != 0:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    try:
                        srv.close()
                    except Exception:
                        pass
                    return False

                if sha_in_stream:
                    digest = b""
                    while len(digest) < 32:
                        part = conn.recv(32 - len(digest))
                        if not part:
                            break
                        digest += _to_bytes(part)
                    if len(digest) != 32:
                        try:
                            conn.close()
                        except Exception:
                            pass
                        try:
                            srv.close()
                        except Exception:
                            pass
                        return False
                    if h is not None:
                        if h.digest() != digest:
                            try:
                                conn.close()
                            except Exception:
                                pass
                            try:
                                srv.close()
                            except Exception:
                                pass
                            return False
                else:
                    # If user asked for sha but sender didn't provide it, treat as failure.
                    if want_sha:
                        try:
                            conn.close()
                        except Exception:
                            pass
                        try:
                            srv.close()
                        except Exception:
                            pass
                        return False

            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
                try:
                    srv.close()
                except Exception:
                    pass
                return False
        else:
            # DONE token mode (unsafe for binary unless token unlikely) OR plain FIN
            done = bool(kwargs.get("done"))
            tok = kwargs.get("done_token") or "\nDONE\n"
            tokb = _to_bytes(tok)
            tlen = len(tokb)
            tail = b""

            while True:
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    continue
                except Exception:
                    break
                if not chunk:
                    break
                chunk = _to_bytes(chunk)

                if not done:
                    fileobj.write(chunk)
                    continue

                buf = tail + chunk
                if tlen and buf.endswith(tokb):
                    if len(buf) > tlen:
                        fileobj.write(buf[:-tlen])
                    tail = b""
                    break

                if tlen and len(buf) > tlen:
                    fileobj.write(buf[:-tlen])
                    tail = buf[-tlen:]
                else:
                    tail = buf

            if done and tail:
                fileobj.write(tail)

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

def send_from_fileobj(fileobj, host, port, proto="tcp", path_text=None, **kwargs):
    """
    Send bytes from fileobj to a listening receiver.
    - TCP:
        * default: stream and close (FIN)
        * framing=len: send fixed header declaring remaining byte length; optional sha256=1 appends digest after payload
        * resume=1: wait for OFFSET <n>\n from receiver, then seek before sending
    - UDP raw: send chunks then DONE.
    - UDP seq: reliable with ACK/DONE and optional RESUME handshake.
        * sha256=1: include digest bytes in DONE control packet
    """
    proto = (proto or "tcp").lower()
    port = int(port)

    if proto == "tcp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            to = kwargs.get("timeout", None)
            if to is not None and float(to) > 0:
                sock.settimeout(float(to))
        except Exception:
            pass

        if "wait" not in kwargs and "connect_wait" not in kwargs:
            # Default ON: behave like udp seq (wait for receiver)
            kwargs["connect_wait"] = True
        wait = bool(kwargs.get("wait", False) or kwargs.get("connect_wait", False))
        wait_timeout = kwargs.get("wait_timeout", None)
        if wait_timeout is not None:
            try:
                wait_timeout = float(wait_timeout)
            except Exception:
                wait_timeout = None
        start_t = time.time()
        while True:
            try:
                sock.connect((host, port))
                break
            except Exception:
                if not wait:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    return False
                if wait_timeout is not None and wait_timeout >= 0 and (time.time() - start_t) >= wait_timeout:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    return False
                try:
                    _net_log(kwargs.get("verbose"), "TCP: waiting for receiver (connect refused), retrying...")

                    time.sleep(0.1)
                except Exception:
                    pass
                continue

        # App-level handshake (default ON): sender sends HELLO <token>, receiver replies READY <token>.
        if kwargs.get("handshake", True):
            tok = kwargs.get("token")
            if tok is None:
                tok = _hs_token()
            else:
                tok = _to_bytes(tok)
            try:
                sock.sendall(b"HELLO " + tok + b"\n")
            except Exception:
                try:
                    sock.close()
                except Exception:
                    pass
                return False
            # Wait for READY (bounded by wait_timeout if provided)
            wt = kwargs.get("wait_timeout", None)
            try:
                sock.settimeout(float(wt) if wt is not None else None)
            except Exception:
                pass
            buf = b""
            while b"\n" not in buf and len(buf) < 4096:
                try:
                    b = sock.recv(1024)
                except Exception:
                    b = b""
                if not b:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    return False
                buf += b
            line = buf.split(b"\n", 1)[0].strip()
            if not line.startswith(b"READY"):
                try:
                    sock.close()
                except Exception:
                    pass
                return False
            if b" " in line:
                rt = line.split(None, 1)[1].strip()
                if rt and rt != tok:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    return False
            # restore user timeout if any
            try:
                to = kwargs.get("timeout", None)
                if to is not None and float(to) > 0:
                    sock.settimeout(float(to))
                else:
                    sock.settimeout(None)
            except Exception:
                pass

        if path_text:
            try:
                line = ("PATH %s\n" % (path_text or "/")).encode("utf-8")
                sock.sendall(line)
            except Exception:
                pass

        if kwargs.get("resume"):
            try:
                buf = b""
                while not buf.endswith(b"\n") and len(buf) < 128:
                    b = sock.recv(1)
                    if not b:
                        break
                    buf += b
                if buf.startswith(b"OFFSET "):
                    off = int(buf.split()[1])
                    try:
                        fileobj.seek(off, 0)
                    except Exception:
                        pass
            except Exception:
                pass

        framing = (kwargs.get("framing") or "").lower()
        want_sha = bool(kwargs.get("sha256") or kwargs.get("sha") or kwargs.get("want_sha"))
        h = hashlib.sha256() if want_sha else None

        if framing == "len":
            # Compute remaining size
            size = None
            try:
                cur = fileobj.tell()
                fileobj.seek(0, os.SEEK_END)
                end = fileobj.tell()
                fileobj.seek(cur, os.SEEK_SET)
                size = int(end - cur)
            except Exception:
                size = None
            if size is None or size < 0:
                try:
                    sock.close()
                except Exception:
                    pass
                return False
            flags = 1 if want_sha else 0
            header = b"PWG4" + struct.pack("!Q", int(size)) + struct.pack("!I", int(flags))
            try:
                sock.sendall(header)
            except Exception:
                try:
                    sock.close()
                except Exception:
                    pass
                return False

        try:
            while True:
                data = fileobj.read(65536)
                if not data:
                    break
                data = _to_bytes(data)
                sock.sendall(data)
                if h is not None:
                    h.update(data)

            if framing == "len" and want_sha:
                # append digest after payload
                sock.sendall(h.digest())

            elif kwargs.get("done"):
                # token mode (legacy)
                tok = kwargs.get("done_token") or "\nDONE\n"
                sock.sendall(_to_bytes(tok))
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return False

        try:
            sock.shutdown(socket.SHUT_WR)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
        return True

    mode = (kwargs.get("mode") or "seq").lower()
    if mode == "raw":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        addr = (host, int(port))
        chunk = int(kwargs.get("chunk", 1200))

        # META length for raw UDP (default on): helps receiver finish immediately after N bytes.
        raw_meta = kwargs.get("raw_meta", True)
        raw_sha = kwargs.get("raw_sha", False)
        raw_hash = (kwargs.get("raw_hash", "sha256") or "sha256").lower()

        # Determine remaining length if seekable
        total_len = None
        pos = None
        if raw_meta or raw_sha:
            try:
                pos = fileobj.tell()
                fileobj.seek(0, os.SEEK_END)
                end = fileobj.tell()
                fileobj.seek(pos, os.SEEK_SET)
                total_len = int(end - pos)
                if total_len < 0:
                    total_len = None
            except Exception:
                total_len = None
                try:
                    if pos is not None:
                        fileobj.seek(pos, os.SEEK_SET)
                except Exception:
                    pass

        if raw_meta and total_len is not None:
            if raw_meta and total_len is not None:
                try:
                    sock.sendto(b"META " + str(total_len).encode("ascii") + b"\n", addr)
                except Exception:
                    pass

        if "wait" not in kwargs and "connect_wait" not in kwargs:
            # Default ON for udp raw: behave like udp seq (wait for receiver)
            kwargs["wait"] = True
        # If requested, wait for receiver readiness (handshake).
# Default handshake=1 makes udp raw behave like tcp/udp-seq: sender will not start until receiver replies READY.
        if (kwargs.get("wait") or kwargs.get("connect_wait")):
            wt = kwargs.get("wait_timeout", None)
            try:
                wt = float(wt) if wt is not None else None
            except Exception:
                wt = None
            hello_iv = kwargs.get("hello_interval", 0.1)
            try:
                hello_iv = float(hello_iv)
            except Exception:
                hello_iv = 0.1
            if hello_iv <= 0:
                hello_iv = 0.1
            start_t = time.time()
            tok = kwargs.get("token")
            if tok is None:
                tok = _hs_token()
            else:
                tok = _to_bytes(tok)
            # For legacy receivers (no token), accept READY\n as well.
            while True:
                if wt is not None and wt >= 0 and (time.time() - start_t) >= wt:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    return False
                if kwargs.get("handshake", True):
                    try:
                        sock.sendto(b"HELLO " + tok + b"\n", addr)
                    except Exception:
                        pass
                # also send META periodically so old receivers can respond READY
                if raw_meta and total_len is not None:
                    try:
                        sock.sendto(b"META " + str(total_len).encode("ascii") + b"\n", addr)
                    except Exception:
                        pass
                try:
                    sock.settimeout(hello_iv)
                except Exception:
                    pass
                try:
                    pkt, _a = sock.recvfrom(1024)
                    if pkt.startswith(b"READY"):
                        _net_log(kwargs.get("verbose"), "UDP raw: received READY from receiver")
                        # READY or READY <token>
                        if b" " in pkt:
                            rt = pkt.split(None, 1)[1].strip()
                            if rt and rt != tok:
                                continue
                        break
                except Exception:
                    pass

        # Optional checksum advertisement (for raw UDP). Receiver will verify after full payload.
        expected_hex = None
        if raw_sha and total_len is not None:
            try:
                h = hashlib.sha256() if raw_hash != "md5" else hashlib.md5()
                cur = fileobj.tell()
                while True:
                    b = fileobj.read(65536)
                    if not b:
                        break
                    h.update(_to_bytes(b))
                expected_hex = h.hexdigest()
                fileobj.seek(cur, os.SEEK_SET)
            except Exception:
                expected_hex = None
                try:
                    if pos is not None:
                        fileobj.seek(pos, os.SEEK_SET)
                except Exception:
                    pass

        if raw_sha and expected_hex:
            try:
                sock.sendto(b"HASH " + raw_hash.encode("ascii") + b" " + expected_hex.encode("ascii") + b"\n", addr)
            except Exception:
                pass

        # Send payload
        if kwargs.get("raw_ack"):
            # Reliable UDP (Go-Back-N) using PKT/ACK framing.
            # PKT: b"PKT <seq> <data...>"
            # ACK: b"ACK <last_in_order>" (receiver sends exp_seq-1)
            ack_to = kwargs.get("raw_ack_timeout", 0.5)
            try:
                ack_to = float(ack_to)
            except Exception:
                ack_to = 0.5
            retries_max = kwargs.get("raw_ack_retries", 40)
            try:
                retries_max = int(retries_max)
            except Exception:
                retries_max = 40
            win = kwargs.get("raw_ack_window", 1)
            try:
                win = int(win)
            except Exception:
                win = 1
            if win < 1:
                win = 1

            base_seq = 0
            next_seq = 0
            pkts = {}
            eof = False
            timeout_tries = 0
            try:
                sock.settimeout(ack_to)
            except Exception:
                pass

            def _make_pkt(_seq, _data):
                return b"PKT " + str(_seq).encode("ascii") + b" " + _to_bytes(_data)

            while True:
                # Fill window
                while (not eof) and next_seq < base_seq + win:
                    data = fileobj.read(chunk)
                    if not data:
                        eof = True
                        break
                    pkt = _make_pkt(next_seq, data)
                    pkts[next_seq] = pkt
                    try:
                        sock.sendto(pkt, addr)
                    except Exception:
                        pass
                    next_seq += 1

                if eof and base_seq == next_seq:
                    break

                try:
                    apkt, _a = sock.recvfrom(1024)
                    if apkt.startswith(b"ACK "):
                        try:
                            aseq = int(apkt.split()[1])
                        except Exception:
                            aseq = -1
                        new_base = aseq + 1
                        if new_base > base_seq:
                            for s in list(pkts.keys()):
                                if s < new_base:
                                    try:
                                        del pkts[s]
                                    except Exception:
                                        pass
                            base_seq = new_base
                            timeout_tries = 0
                except Exception:
                    timeout_tries += 1
                    if retries_max >= 0 and timeout_tries >= retries_max:
                        try:
                            sock.close()
                        except Exception:
                            pass
                        return False
                    for s in range(base_seq, next_seq):
                        pkt = pkts.get(s)
                        if pkt is None:
                            continue
                        try:
                            sock.sendto(pkt, addr)
                        except Exception:
                            pass
        else:
            while True:
                data = fileobj.read(chunk)
                if not data:
                    break
                sock.sendto(_to_bytes(data), addr)

        # DONE for compatibility / receivers without META
        try:
            sock.sendto(b"DONE", addr)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
        return True

    return _udp_seq_send(fileobj, host, port, **kwargs)

def _udp_raw_recv(fileobj, host, port, **kwargs):
    """
    Raw UDP receive.

    Backwards compatible behavior:
      - If a META <len>
 packet is received first, read until exactly len bytes are written (fast finish).
      - Otherwise, fall back to legacy: read until DONE packet or end_timeout seconds of silence.

    Optional integrity check:
      - If raw_sha=1 and a HASH <algo> <hex> packet is received, verify digest and return True/False.
      - If raw_sha=1 but no HASH is received, returns False (since verification was requested).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host or "", int(port)))

    if kwargs.get("print_url"):
        sys.stdout.write("Listening: udp://%s:%d/\n" % (host or "0.0.0.0", sock.getsockname()[1]))
        try:
            sys.stdout.flush()
        except Exception:
            pass

    sock.settimeout(float(kwargs.get("timeout", 1.0)))
    end_timeout = float(kwargs.get("end_timeout", 0.25))

    want_sha = bool(kwargs.get("raw_sha", False))
    raw_hash = (kwargs.get("raw_hash", "sha256") or "sha256").lower()
    hasher = None
    expected_hex = None
    if want_sha:
        hasher = hashlib.sha256() if raw_hash != "md5" else hashlib.md5()

    # --- FIX: initialize raw-ack state (prevent NameError in raw_ack mode) ---
    want_ack = bool(kwargs.get("raw_ack") or kwargs.get("want_ack"))
    exp_seq = 0
    bytes_written = 0

    expected = None
    received = 0
    last = time.time()
    saw_any = False

    while True:
        try:
            pkt, _addr = sock.recvfrom(65536)
            # Handshake: sender announces itself; reply READY <token>.
            if kwargs.get("handshake", True) and pkt.startswith(b"HELLO "):
                tok = pkt.split(None, 1)[1].strip() if b" " in pkt else b""
                try:
                    sock.sendto(b"READY " + tok + b"\n", _addr)
                except Exception:
                    pass
                continue

        except socket.timeout:
            if expected is not None:
                continue
            if saw_any and (time.time() - last) >= end_timeout:
                break
            continue
        except KeyboardInterrupt:
            try:
                sock.close()
            except Exception:
                pass
            raise
        except Exception:
            break

        if not pkt:
            continue

        saw_any = True
        last = time.time()

        if expected is None and pkt.startswith(b"META "):
            try:
                line = pkt.split(b"\n", 1)[0]
                expected = int(line.split()[1])
                try:
                    sock.sendto(b"READY\n", _addr)
                except Exception:
                    pass
                if expected < 0:
                    expected = None
            except Exception:
                expected = None
            continue

        if pkt.startswith(b"HASH "):
            try:
                line = pkt.split(b"\n", 1)[0]
                parts = line.split()
                algo = parts[1].decode("ascii", "ignore").lower()
                hx = parts[2].decode("ascii", "ignore")
                expected_hex = hx
                if not want_sha:
                    want_sha = True
                raw_hash = algo or raw_hash
                hasher = hashlib.sha256() if raw_hash != "md5" else hashlib.md5()
            except Exception:
                pass
            continue

        if pkt == b"DONE":
            break

        if expected is None:
            if want_ack and pkt.startswith(b"PKT "):
                # Go-Back-N receiver: accept only in-order seq, ACK exp_seq-1
                try:
                    parts = pkt.split(b" ", 2)
                    seq = int(parts[1])
                    payload = parts[2] if len(parts) > 2 else b""
                except Exception:
                    seq = -1
                    payload = b""
                if seq == exp_seq:
                    try:
                        fileobj.write(payload)
                    except Exception:
                        try:
                            fileobj.write(_to_bytes(payload))
                        except Exception:
                            pass
                    if hasher is not None:
                        try:
                            hasher.update(payload)
                        except Exception:
                            pass
                    bytes_written += len(payload)
                    exp_seq += 1
                try:
                    sock.sendto(b"ACK " + str(exp_seq - 1).encode("ascii") + b"\n", _addr)
                except Exception:
                    pass
                continue
            fileobj.write(pkt)
            if hasher is not None:
                hasher.update(pkt)
        else:
            remain = expected - received
            if remain <= 0:
                break
            if len(pkt) <= remain:
                fileobj.write(pkt)
                if hasher is not None:
                    hasher.update(pkt)
                received += len(pkt)
            else:
                piece = pkt[:remain]
                fileobj.write(piece)
                if hasher is not None:
                    hasher.update(piece)
                received += remain
                break

        if expected is not None and received >= expected:
            break

    try:
        sock.close()
    except Exception:
        pass
    try:
        fileobj.seek(0, 0)
    except Exception:
        pass

    if want_sha:
        if expected_hex is None:
            return False
        try:
            return (hasher.hexdigest().lower() == expected_hex.strip().lower())
        except Exception:
            return False

    return True
def _udp_seq_send(fileobj, host, port, resume=False, path_text=None, **kwargs):
    addr = (host, int(port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(float(kwargs.get("timeout", 1.0)))

    chunk = int(kwargs.get("chunk", 1200))
    window = int(kwargs.get("window", 32))
    retries = int(kwargs.get("retries", 20))
    total_timeout = float(kwargs.get("total_timeout", 0.0))

    want_sha = bool(kwargs.get("sha256") or kwargs.get("sha") or kwargs.get("want_sha"))
    _h = hashlib.sha256() if want_sha else None

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
                _net_log(kwargs.get("verbose"), "UDP seq: received packet from receiver")
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
        if _h is not None:
            _h.update(data)
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
                if flags & _UF_ACK and len(payload) >= 4:
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
            if _h is not None:
                _h.update(data)
            _send_pkt(next_seq, data)
            in_flight[next_seq] = (data, time.time(), 0)
            next_seq += 1

    # DONE (explicit end marker). If sha requested, attach digest bytes.
    payload = b"DONE"
    if _h is not None:
        payload += _h.digest()
    for _i in range(3):
        sock.sendto(_u_pack(_UF_DONE, 0xFFFFFFFE, total) + payload, addr)
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
        try:
            sys.stdout.flush()
        except Exception:
            pass
    sock.settimeout(float(kwargs.get("timeout", 1.0)))

    chunk = int(kwargs.get("chunk", 1200))
    window = int(kwargs.get("window", 32))
    total_timeout = float(kwargs.get("total_timeout", 0.0))

    framing = (kwargs.get("framing") or "").lower()
    want_sha = bool(kwargs.get("sha256") or kwargs.get("sha") or kwargs.get("want_sha"))
    _h = hashlib.sha256() if want_sha else None

    total_len = None
    bytes_written = 0
    got_digest = None

    # resume offset
    resume_off = 0
    try:
        resume_off = int(kwargs.get("resume_offset", 0) or 0)
    except Exception:
        resume_off = 0
    expected = int(resume_off // chunk)

    received = {}
    done = False
    t0 = time.time()

    def _ack(addr, seq):
        sock.sendto(_u_pack(_UF_ACK, 0, 0) + struct.pack("!I", int(seq) & 0xFFFFFFFF), addr)

    resume_sent = False
    complete = False

    while True:
        if total_timeout and (time.time() - t0) > total_timeout:
            break
        try:
            pkt, addr = sock.recvfrom(65536)
        except socket.timeout:
            if complete and want_sha:
                continue
            if done and not received:
                break
            continue
        except Exception:
            break

        up = _u_unpack(pkt)
        if not up:
            continue
        flags, seq, total, payload = up

        if total_len is None and total:
            try:
                total_len = int(total)
            except Exception:
                total_len = None

        if not resume_sent:
            try:
                sock.sendto(_u_pack(_UF_RESUME, 0xFFFFFFFE, 0) + struct.pack("!Q", int(resume_off)), addr)
            except Exception:
                pass
            resume_sent = True

        if flags & _UF_META:
            try:
                sock.sendto(_u_pack(_UF_RESUME, 0xFFFFFFFE, 0) + struct.pack("!Q", int(resume_off)), addr)
            except Exception:
                pass
            continue

        if flags & _UF_DONE:
            done = True
            if payload.startswith(b"DONE") and len(payload) >= 4 + 32:
                got_digest = payload[4:4+32]
            if (framing == "len") and complete:
                break
            if not received and not want_sha:
                break
            continue

        if not (flags & _UF_DATA):
            continue

        _ack(addr, seq)

        if complete:
            continue

        if seq < expected:
            continue
        if seq >= expected + window * 8:
            continue

        if seq == expected:
            fileobj.write(payload)
            bytes_written += len(payload)
            if _h is not None:
                _h.update(_to_bytes(payload))
            expected += 1
            while expected in received:
                bufp = received.pop(expected)
                fileobj.write(bufp)
                bytes_written += len(bufp)
                if _h is not None:
                    _h.update(_to_bytes(bufp))
                expected += 1
        else:
            if seq not in received:
                received[seq] = payload

        if (framing == "len") and (total_len is not None) and (bytes_written >= total_len):
            complete = True
            if not want_sha:
                break
            if got_digest is not None:
                break

        if done and not received:
            break

    if want_sha:
        if got_digest is None:
            try:
                sock.close()
            except Exception:
                pass
            return False
        if _h is None or _h.digest() != got_digest:
            try:
                sock.close()
            except Exception:
                pass
            return False

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

def send_path(path, url, fmt="tar", compression=None, **kwargs):
    """
    Convenience helper: package a directory (or single file) and send it using upload_file_to_internet_file.

    - path: file or directory path.
    - url: destination URL (tcp://, udp://, ftp://, etc.)
    - fmt: "tar" or "zip"
    - compression: for tar: "gz" or None; for zip: ignored (zip uses deflate by default)
    Extra kwargs are forwarded to upload_file_to_internet_file via query params or directly.
    Returns whatever upload_file_to_internet_file returns.
    """
    try:
        import tempfile, tarfile, zipfile
    except Exception:
        return False

    p = os.path.abspath(path)

    # Use spooled temp file so small archives stay in memory, large spill to disk.
    tmp = None
    try:
        tmp = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b")
        if fmt.lower() == "zip":
            zf = zipfile.ZipFile(tmp, mode="w", compression=zipfile.ZIP_DEFLATED)
            try:
                if os.path.isdir(p):
                    for root, dirs, files in os.walk(p):
                        for fn in files:
                            full = os.path.join(root, fn)
                            rel = os.path.relpath(full, os.path.dirname(p))
                            zf.write(full, rel)
                else:
                    zf.write(p, os.path.basename(p))
            finally:
                zf.close()
        else:
            mode = "w"
            if compression in ("gz", "gzip"):
                mode = "w:gz"
            tf = tarfile.open(fileobj=tmp, mode=mode)
            try:
                arcname = os.path.basename(p.rstrip(os.sep))
                if os.path.isdir(p):
                    tf.add(p, arcname=arcname)
                else:
                    tf.add(p, arcname=os.path.basename(p))
            finally:
                tf.close()

        tmp.seek(0, 0)
        return upload_file_to_internet_file(tmp, url, **kwargs)
    finally:
        try:
            if tmp is not None:
                tmp.close()
        except Exception:
            pass

def recv_to_path(url, out_path, auto_extract=False, extract_dir=None, keep_archive=True, **kwargs):
    """
    Convenience helper: download into a real file path.
    Returns out_path on success, False on failure.
    """
    # listen-mode HTTP/HTTPS can stream straight to disk (avoid BytesIO)
    try:
        up = urlparse(url)
        if (up.scheme or "").lower() in ("http", "https"):
            qs = parse_qs(up.query or "")
            if _qflag(qs, "listen", False) or _qflag(qs, "recv", False):
                url2 = url
                if "out" not in qs:
                    url2 = _set_query_param(url2, "out", out_path)
                if "mkdir" not in qs:
                    url2 = _set_query_param(url2, "mkdir", "1")
                if "overwrite" not in qs:
                    url2 = _set_query_param(url2, "overwrite", "1")
                ok = download_file_from_internet_file(url2, **kwargs)
                return out_path if ok is not False else False
    except Exception:
        pass

    f = download_file_from_internet_file(url, **kwargs)
    if f is False:
        return False
    try:
        parent = os.path.dirname(os.path.abspath(out_path))
        if parent and not os.path.isdir(parent):
            try:
                os.makedirs(parent)
            except Exception:
                pass
        outfp = open(out_path, "wb")
        try:
            shutil.copyfileobj(f, outfp)
        finally:
            try:
                outfp.close()
            except Exception:
                pass
    except Exception:
        return False

    if auto_extract:
        try:
            import tarfile, zipfile
            ext = out_path.lower()
            if extract_dir is None:
                extract_dir = os.path.dirname(os.path.abspath(out_path)) or "."
            if ext.endswith(".zip"):
                zf = zipfile.ZipFile(out_path, "r")
                try:
                    zf.extractall(extract_dir)
                finally:
                    zf.close()
            elif ext.endswith(".tar") or ext.endswith(".tar.gz") or ext.endswith(".tgz") or ext.endswith(".tar.bz2") or ext.endswith(".tbz2") or ext.endswith(".tar.xz") or ext.endswith(".txz"):
                tf = tarfile.open(out_path, "r:*")
                try:
                    tf.extractall(extract_dir)
                finally:
                    tf.close()
            if not keep_archive:
                try:
                    os.unlink(out_path)
                except Exception:
                    pass
        except Exception:
            pass
    return out_path

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

    if p.scheme in ("data"):
        return data_url_decode(url)[0]

    if p.scheme in ("file"):
        return io.open(unquote(p.path), "rb")

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


def _serve_file_over_http(fileobj, url):
    """Serve the given file-like object via a tiny HTTP server.

    Usage:
        upload_file_to_internet_file(open("x.bin","rb"),
            "http://0.0.0.0:0/x.bin?print_url=1&max_clients=1&range=1&download=1")

    Flags (query params):
      - bind=IP            : bind address (default from host in URL, or 0.0.0.0)
      - port=0             : auto-pick free port (use :0 in URL)
      - print_url=1        : print reachable URLs
      - max_clients=N      : stop after N successful GETs (default 1)
      - idle_timeout=SEC   : stop if no request within SEC (default 0 = wait forever)
      - range=1            : support Range requests (resume) (default 1)
      - download=1|name    : set Content-Disposition attachment; optional filename
      - content_type=TYPE  : override Content-Type (default guessed)
      - gzip=1             : gzip encode if client accepts (best for text)
      - auth=user:pass     : enable Basic Auth
      - cors=1             : add Access-Control-Allow-Origin: *
      - hdr_X=Y            : add custom headers (hdr_Cache_Control=no-cache)
    Returns:
      bound_port (int) on success, False on failure.
    """
    p = urlparse(url)
    qs = parse_qs(p.query or "")

    bind = _qstr(qs, "bind", None) or (p.hostname or "0.0.0.0")
    port = p.port if (p.port is not None) else int(_qnum(qs, "port", 0, cast=int))
    path = p.path or "/"
    print_url = _qflag(qs, "print_url", False)
    max_clients = int(_qnum(qs, "max_clients", 1, cast=int))
    idle_timeout = float(_qnum(qs, "idle_timeout", 0.0, cast=float))
    allow_range = _qflag(qs, "range", True)
    gzip_on = _qflag(qs, "gzip", False)
    cors = _qflag(qs, "cors", False)
    content_type = _qstr(qs, "content_type", None)
    download = _qstr(qs, "download", None)
    auth = _qstr(qs, "auth", None)
    extra_headers = _parse_kv_headers(qs, prefix="hdr_")

    # Try to serve from an on-disk filename if available (better for big files)
    file_path = getattr(fileobj, "name", None)
    can_reopen = False
    if file_path and isinstance(file_path, (str,)):
        try:
            can_reopen = os.path.isfile(file_path)
        except Exception:
            can_reopen = False

    # Otherwise snapshot into memory once (still file-like, but avoids racing file pointers)
    use_direct = (not can_reopen) and (max_clients == 1)
    data_bytes = None
    if (not can_reopen) and (not use_direct):
        try:
            pos = fileobj.tell()
        except Exception:
            pos = None
        try:
            try:
                fileobj.seek(0, 0)
            except Exception:
                pass
            data_bytes = fileobj.read()
        finally:
            if pos is not None:
                try:
                    fileobj.seek(pos, 0)
                except Exception:
                    pass
        data_bytes = _to_bytes(data_bytes)

    # Determine filename for disposition
    default_name = os.path.basename(path.strip("/")) or "download.bin"
    if download and download not in ("1", "true", "yes"):
        disp_name = download
    else:
        disp_name = default_name

    # Determine type
    if not content_type:
        try:
            content_type = mimetypes.guess_type(default_name)[0] or "application/octet-stream"
        except Exception:
            content_type = "application/octet-stream"

    # Auth header
    auth_user = auth_pass = None
    if auth:
        if ":" in auth:
            auth_user, auth_pass = auth.split(":", 1)
        else:
            auth_user, auth_pass = auth, ""

    # A little mutable state owned by handler closure
    state = {"served": 0, "stop": False}

    def _open_reader():
        if use_direct:
            try:
                fileobj.seek(0, 0)
            except Exception:
                pass
            return fileobj
        if can_reopen:
            return open(file_path, "rb")
        return MkTempFile(data_bytes)

    class _Handler(BaseHTTPRequestHandler):
        server_version = "PyWWWGetCleanHTTP/1.0"

        def log_message(self, fmt, *args):
            # quiet by default
            return

        def _unauth(self):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="pywwwget"')
            self.send_header("Connection", "close")
            self.end_headers()

        def _check_auth(self):
            if not auth_user:
                return True
            h = self.headers.get("Authorization")
            if not h or not h.startswith("Basic "):
                return False
            try:
                raw = base64.b64decode(h.split(" ", 1)[1].strip().encode("utf-8"))
                if not isinstance(raw, bytes):
                    raw = _to_bytes(raw)
                pair = raw.decode("utf-8", "ignore")
            except Exception:
                return False
            if ":" in pair:
                u, pw = pair.split(":", 1)
            else:
                u, pw = pair, ""
            return (u == auth_user and pw == auth_pass)

        def do_HEAD(self):
            # Treat HEAD like GET without body
            self._do_send(body=False)

        def do_GET(self):
            self._do_send(body=True)

        def _do_send(self, body=True):
            # Only serve on exact path (ignore query)
            req_path = self.path.split("?", 1)[0]
            if req_path != path:
                self.send_response(404)
                self.send_header("Connection", "close")
                self.end_headers()
                return

            if not self._check_auth():
                self._unauth()
                return

            # Open data source
            f = _open_reader()
            try:
                # Compute total size
                try:
                    f.seek(0, 2)
                    total = f.tell()
                    f.seek(0, 0)
                except Exception:
                    total = None
                    try:
                        f.seek(0, 0)
                    except Exception:
                        pass

                # Range support
                start = 0
                end = None
                status = 200
                if allow_range and total is not None:
                    rng = self.headers.get("Range")
                    if rng and rng.startswith("bytes="):
                        try:
                            spec = rng.split("=", 1)[1].strip()
                            a, b = spec.split("-", 1)
                            if a:
                                start = int(a)
                            if b:
                                end = int(b)
                            status = 206
                        except Exception:
                            start = 0
                            end = None
                            status = 200

                if total is not None and start < 0:
                    start = 0
                if total is not None and start > total:
                    start = total

                if total is not None:
                    f.seek(start, 0)
                    remain = total - start
                    if end is not None and end >= start:
                        remain = min(remain, (end - start + 1))
                else:
                    remain = None

                # Maybe gzip (only if not ranged and client accepts)
                use_gzip = False
                if gzip_on and status == 200:
                    ae = self.headers.get("Accept-Encoding", "") or ""
                    if "gzip" in ae.lower():
                        # heuristic: only gzip text/* or small-ish unknown
                        if content_type.startswith("text/") or content_type in ("application/json", "application/xml"):
                            use_gzip = True

                self.send_response(status)
                self.send_header("Content-Type", content_type)
                if cors:
                    self.send_header("Access-Control-Allow-Origin", "*")

                if download:
                    self.send_header("Content-Disposition", 'attachment; filename="%s"' % disp_name)

                # Custom headers
                for hk, hv in extra_headers.items():
                    try:
                        self.send_header(hk, hv)
                    except Exception:
                        pass

                if total is not None:
                    if status == 206:
                        last = start + (remain - 1 if remain is not None else 0)
                        self.send_header("Content-Range", "bytes %d-%d/%d" % (start, last, total))
                    self.send_header("Accept-Ranges", "bytes")

                if use_gzip:
                    self.send_header("Content-Encoding", "gzip")

                # Body
                if not body:
                    self.send_header("Connection", "close")
                    self.end_headers()
                    return

                if use_gzip:
                    # stream gzip
                    self.send_header("Connection", "close")
                    self.end_headers()
                    gz = gzip.GzipFile(fileobj=self.wfile, mode="wb")
                    try:
                        shutil.copyfileobj(f, gz)
                    finally:
                        try:
                            gz.close()
                        except Exception:
                            pass
                else:
                    if remain is not None:
                        self.send_header("Content-Length", str(int(remain)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    if remain is None:
                        shutil.copyfileobj(f, self.wfile)
                    else:
                        # bounded copy
                        left = int(remain)
                        buf = 64 * 1024
                        while left > 0:
                            chunk = f.read(min(buf, left))
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            left -= len(chunk)

                # Count successful serves
                state["served"] += 1
                if state["served"] >= max_clients:
                    state["stop"] = True
            finally:
                try:
                    if not use_direct: f.close()
                except Exception:
                    pass

    # Threading server
    class _ThreadingHTTPServer(_socketserver.ThreadingMixIn, HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    try:
        httpd = _ThreadingHTTPServer((bind, int(port)), _Handler)
    except Exception:
        return False

    bound_port = httpd.server_address[1]
    if print_url:
        for u in _listen_urls(("https" if tls_on else p.scheme), bind, bound_port, path, p.query):
            try:
                sys.stdout.write("Listening: %s\n" % u)
            except Exception:
                pass
        try:
            sys.stdout.flush()
        except Exception:
            pass

    # Serve loop: handle_request() so we can stop after max_clients or idle_timeout
    if idle_timeout and idle_timeout > 0:
        try:
            httpd.timeout = float(idle_timeout)
        except Exception:
            pass

    try:
        sidecar_start = None
        while not state["stop"]:
            httpd.handle_request()

            if idle_timeout and idle_timeout > 0:
                # If handle_request times out, it returns; stop if nothing served yet and idle passed.
                if state["served"] == 0:
                    break

            if expect_sidecar and state.get("upload_done") and (not state.get("sidecar_done")):
                if sidecar_start is None:
                    sidecar_start = time.time()
                if sidecar_timeout is not None and sidecar_timeout >= 0:
                    if (time.time() - sidecar_start) >= float(sidecar_timeout):
                        try:
                            if print_hash:
                                sys.stdout.write("Sidecar timeout (%.3fs); continuing without enforcement.\\n" % float(sidecar_timeout))
                                sys.stdout.flush()
                                # Optional cleanup on timeout
                                if sidecar_timeout_mode == "delete":
                                    try:
                                        sp = state.get("saved_path")
                                        if sp and os.path.exists(sp):
                                            os.unlink(sp)
                                            try:
                                                sys.stdout.write("Deleted (sidecar timeout): %s\n" % sp)
                                                sys.stdout.flush()
                                            except Exception:
                                                pass
                                    except Exception:
                                        pass
                        except Exception:
                            pass
                        break
    finally:
        try:
            httpd.server_close()
        except Exception:
            pass

    return bound_port


def _recv_file_over_http(url):
    """Receive bytes via a tiny HTTP server (PUT/POST) and return a BytesIO.

    Usage:
        download_file_from_internet_file("http://0.0.0.0:8000/upload.bin?listen=1&print_url=1")
        download_file_from_internet_file("http://0.0.0.0:0/x.bin?listen=1&print_url=1&auth=user:pass")

    Flags (query params):
      - bind=IP            : bind address (default from host in URL, or 0.0.0.0)
      - port=0             : auto-pick free port (use :0 in URL)
      - print_url=1        : print reachable URLs
      - max_clients=N      : stop after N successful uploads (default 1)
      - idle_timeout=SEC   : stop if no request within SEC (default 0 = wait forever)
      - method=PUT|POST    : accept only this method (default PUT and POST)
      - auth=user:pass     : enable Basic Auth
      - cors=1             : add Access-Control-Allow-Origin: *
      - hdr_X=Y            : add custom headers to response
    Returns: BytesIO on success, False on failure.
    """
    p = urlparse(url)
    qs = parse_qs(p.query or "")

    bind = _qstr(qs, "bind", None) or (p.hostname or "0.0.0.0")
    port = p.port if (p.port is not None) else int(_qnum(qs, "port", 0, cast=int))
    want_path = p.path or "/"
    print_url = _qflag(qs, "print_url", False)
    max_clients = int(_qnum(qs, "max_clients", 1, cast=int))
    idle_timeout = float(_qnum(qs, "idle_timeout", 0.0, cast=float))
    cors = _qflag(qs, "cors", False)
    auth = _qstr(qs, "auth", None)
    out_path = _qstr(qs, "out", None)
    use_tmp = _qflag(qs, "tmp", False)
    overwrite = _qflag(qs, "overwrite", False)
    mkdir = _qflag(qs, "mkdir", False)
    max_size = _qnum(qs, "max_size", None, cast=int)
    print_save = _qflag(qs, "print_save", False)
    hash_algo = (_qstr(qs, "hash", None) or "").lower().strip() or None
    expect_hash = (_qstr(qs, "expect_hash", None) or _qstr(qs, "want_hash", None) or "").strip() or None
    print_hash = _qflag(qs, "print_hash", True)
    expect_sidecar = _qflag(qs, "expect_sidecar", False) or (_qstr(qs, "stream_hash", "") or "").lower().strip() == "sidecar"
    sidecar_suffix = _qstr(qs, "sidecar_suffix", ".hash")
    sidecar_timeout = _qnum(qs, "sidecar_timeout", None, cast=float)
    sidecar_timeout_mode = (_qstr(qs, "sidecar_timeout_mode", "keep") or "keep").lower().strip()
    if sidecar_timeout_mode not in ("keep", "delete"):
        sidecar_timeout_mode = "keep"
    if sidecar_timeout is None and expect_sidecar and idle_timeout and float(idle_timeout) > 0:
        sidecar_timeout = float(idle_timeout)
    extra_headers = _parse_kv_headers(qs, prefix="hdr_")
    method_only = (_qstr(qs, "method", "") or "").upper().strip()

    state = {
        "served": 0,
        "stop": False,
        "out": None,
        "upload_digest": None,
        "sidecar_digest": None,
        "saved_path": None,
        "upload_done": False,
        "sidecar_done": False,
    }

    userpass = None
    if auth:
        if ":" in auth:
            userpass = auth.split(":", 1)
        else:
            userpass = [auth, ""]

    class Handler(BaseHTTPRequestHandler):
        server_version = "PyWWWGetHTTPRecv/1.0"
        def _unauth(self):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="PyWWWGet"')
            self.end_headers()

        def _check_auth(self):
            if not userpass:
                return True
            ah = self.headers.get("Authorization")
            if not ah or not ah.lower().startswith("basic "):
                return False
            try:
                import base64
                raw = base64.b64decode(ah.split(None, 1)[1].strip().encode("ascii"))
                u, pw = raw.decode("utf-8", "ignore").split(":", 1)
                return (u == userpass[0] and pw == userpass[1])
            except Exception:
                return False

        def log_message(self, *args):
            # quiet
            return

        def _common_headers(self):
            if cors:
                self.send_header("Access-Control-Allow-Origin", "*")
            for k, v in extra_headers.items():
                self.send_header(k, v)

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Methods", "PUT, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, Content-Length")
            self._common_headers()
            self.end_headers()
def _handle_sidecar(self):
    # Accept hash sidecar at /path + suffix
    want_sidecar = (want_path or "/") + (sidecar_suffix or ".hash")
    if self.path.split("?", 1)[0] != want_sidecar:
        self.send_response(404)
        self._common_headers()
        self.end_headers()
        return
    if not self._check_auth():
        self._unauth()
        return

    length = self.headers.get("Content-Length")
    data = b""
    try:
        if length is not None:
            data = self.rfile.read(int(length))
        else:
            data = self.rfile.read(65536)
    except Exception:
        data = b""

    try:
        txt = data.decode("utf-8", "ignore").strip()
    except Exception:
        txt = ""
    # Accept "<hex>" or "<algo> <hex>"
    dig = ""
    parts = txt.split()
    if len(parts) == 1:
        dig = parts[0]
    elif len(parts) >= 2:
        if parts[0].lower() == (hash_algo or "").lower():
            dig = parts[1]
        else:
            dig = parts[-1]
    state["sidecar_digest"] = dig
    state["sidecar_done"] = True

    # If upload digest already known, verify now
    ud = state.get("upload_digest")
    if ud and dig and ud.lower() != dig.lower():
        # delete saved file if any
        try:
            sp = state.get("saved_path")
            if sp and os.path.exists(sp):
                os.unlink(sp)
        except Exception:
            pass
        self.send_response(422)
        self._common_headers()
        self.end_headers()
        state["stop"] = True
        return

    # If upload already done and matches, we can stop.
    if state.get("upload_done") and ud and dig and ud.lower() == dig.lower():
        state["stop"] = True

    self.send_response(200)
    self._common_headers()
    self.send_header("Content-Type", "text/plain")
    self.end_headers()
    try:
        self.wfile.write(b"OK\n")
    except Exception:
        pass



def _handle_upload(self):
    if method_only and self.command != method_only:
        self.send_response(405)
        self._common_headers()
        self.end_headers()
        return
    if self.path.split("?", 1)[0] != want_path:
        self.send_response(404)
        self._common_headers()
        self.end_headers()
        return
    if not self._check_auth():
        self._unauth()
        return

    length = self.headers.get("Content-Length")

    # Choose output target: memory (default), explicit out path, or temp file
    out = None
    outfp = None
    outname = None

    try:
        if out_path:
            outname = out_path
            if mkdir:
                try:
                    parent = os.path.dirname(os.path.abspath(outname))
                    if parent and not os.path.isdir(parent):
                        os.makedirs(parent)
                except Exception:
                    pass
            if (not overwrite) and os.path.exists(outname):
                self.send_response(409)
                self._common_headers()
                self.end_headers()
                return
            outfp = open(outname, "wb")
        elif use_tmp:
            import tempfile
            tf = tempfile.NamedTemporaryFile(delete=False)
            outname = tf.name
            outfp = tf
        else:
            out = MkTempFile()

        total = 0
        if length is not None:
            to_read = int(length)
            while to_read > 0:
                chunk = self.rfile.read(min(65536, to_read))
                if not chunk:
                    break
                total += len(chunk)
                if max_size is not None and max_size >= 0 and total > int(max_size):
                    raise ValueError("max_size exceeded")
                if outfp is not None:
                    outfp.write(chunk)
                else:
                    out.write(chunk)
                to_read -= len(chunk)
        else:
            while True:
                chunk = self.rfile.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if max_size is not None and max_size >= 0 and total > int(max_size):
                    raise ValueError("max_size exceeded")
                if outfp is not None:
                    outfp.write(chunk)
                else:
                    out.write(chunk)

        if outfp is not None:
            try:
                outfp.close()
            except Exception:
                pass
            if print_save and outname:
                try:
                    sys.stdout.write("Saved: %s\n" % outname)
                    sys.stdout.flush()
                except Exception:
                    pass
            try:
                out = open(outname, "rb")
            except Exception:
                out = False
        else:
            out.seek(0, 0)

    except Exception:
        try:
            if outfp is not None:
                outfp.close()
        except Exception:
            pass
        try:
            if outname and os.path.exists(outname) and (use_tmp or out_path):
                os.unlink(outname)
        except Exception:
            pass
        self.send_response(413)
        self._common_headers()
        self.end_headers()
        return

    state["out"] = out
    state["served"] += 1
    if state["served"] >= max_clients:
        state["stop"] = True

    self.send_response(200)
    self._common_headers()
    self.send_header("Content-Type", "text/plain")
    self.end_headers()
    try:
        self.wfile.write(b"OK\n")
    except Exception:
        pass

        def do_PUT(self):

            self._handle_upload()

        def do_POST(self):
            self._handle_upload()

    try:
        from http.server import HTTPServer, BaseHTTPRequestHandler
    except Exception:
        from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

    try:
        httpd = HTTPServer((bind, int(port)), Handler)
    except Exception:
        return False

    bound_port = httpd.server_address[1]

    if print_url:
        bind_host = bind or "0.0.0.0"
        for u in _listen_urls("http", bind_host, bound_port, want_path, p.query):
            sys.stdout.write("Listening: %s\n" % u)
        try:
            sys.stdout.flush()
        except Exception:
            pass

    if idle_timeout and idle_timeout > 0:
        try:
            httpd.timeout = float(idle_timeout)
        except Exception:
            pass

    try:
        while not state["stop"]:
            httpd.handle_request()
            if idle_timeout and idle_timeout > 0 and state["served"] == 0:
                # timed out waiting for first upload
                break
    finally:
        try:
            httpd.server_close()
        except Exception:
            pass

    return state["out"] if state["out"] is not None else False



def upload_file_to_internet_file(fileobj, url):
    p = urlparse(url)
    if p.scheme in ("http", "https"):
        return _serve_file_over_http(fileobj, url)
    if p.scheme in ("ftp", "ftps"):
        return upload_file_to_ftp_file(fileobj, url)
    if p.scheme in ("sftp", "scp"):
        if __use_pysftp__ and havepysftp:
            return upload_file_to_pysftp_file(fileobj, url)
        return upload_file_to_sftp_file(fileobj, url)
    if p.scheme in ("data"):
        return data_url_encode(fileobj)
    if p.scheme in ("file"):
        outfile = io.open(unquote(p.path), "wb")
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        with io.open(unquote(p.path), "wb") as fdst:
            shutil.copyfileobj(fileobj, fdst)
        return fileobj
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
            wait=o.get("wait"), connect_wait=o.get("connect_wait"), wait_timeout=(o.get("wait_timeout") if o.get("wait_timeout") is not None else (None if (p.scheme == "udp" and (o.get("mode") or "seq") == "raw") else o.get("timeout"))),
            window=o.get("window"), retries=o.get("retries"), chunk=o.get("chunk"),
            resume=o.get("resume"), path_text=path_text,
            done=o.get("done"), done_token=o.get("done_token"), framing=o.get("framing"), sha256=o.get("sha256")
        )
        return fileobj if ok else False

    return False

def upload_file_to_internet_string(data, url):
    bio = MkTempFile(_to_bytes(data))
    out = upload_file_to_internet_file(bio, url)
    try:
        bio.close()
    except Exception:
        pass
    return out
# --------------------------
# Public exports
# --------------------------

__all__ = [
    'download_file_from_internet_file',
    'download_file_from_internet_string',
    'upload_file_to_internet_file',
    'upload_file_to_internet_string',
    'send_path',
    'recv_to_path',
    'detect_cwd',
    'MkTempFile',
    '__version__',
    '__program_name__',
    '__project__',
    '__project_url__',
]

# --------------------------
# Simple CLI (optional)
# --------------------------

if __name__ == "__main__":
    # Minimal command-line interface (kept intentionally simple for portability).
    # Examples:
    #   python pywwwget.py download <url> [output_path]
    #   python pywwwget.py upload <file_or_dir> <url>
    #   python pywwwget.py help
    try:
        argv = sys.argv
    except Exception:
        argv = []

    if len(argv) > 1:
        cmd = (argv[1] or "").lower()

        if cmd in ("download", "dl", "get"):
            if len(argv) > 2:
                url = argv[2]
                out = argv[3] if len(argv) > 3 else _guess_filename(url)
                res = recv_to_path(url, out, print_url=True)
                if res:
                    sys.stdout.write("Downloaded to: %s\n" % res)
                else:
                    sys.stdout.write("Download failed\n")
                    try:
                        sys.exit(1)
                    except Exception:
                        pass

        elif cmd in ("upload", "up", "send"):
            if len(argv) > 3:
                path = argv[2]
                url = argv[3]
                if os.path.isdir(path):
                    res = send_path(path, url, print_url=True)
                else:
                    with open(path, "rb") as f:
                        res = upload_file_to_internet_file(f, url)
                if res:
                    sys.stdout.write("Upload successful\n")
                else:
                    sys.stdout.write("Upload failed\n")
                    try:
                        sys.exit(1)
                    except Exception:
                        pass

        else:
            sys.stdout.write(
                "PyNeoWWW-Get v%s\n\n"
                "Usage:\n"
                "  %s download <url> [output_path]\n"
                "  %s upload <file_or_dir> <url>\n"
                "  %s help\n"
                % (__version__, argv[0] if argv else "python", argv[0] if argv else "python", argv[0] if argv else "python")
            )
    else:
        sys.stdout.write("PyNeoWWW-Get Library %s loaded.\n" % __version__)
