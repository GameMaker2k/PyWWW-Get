#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
pywwwgetadv_clean.py - Optimized and Bug-Fixed Version

Optimizations:
1. Fixed broken imports and missing variables
2. Added missing functions and variables
3. Improved error handling
4. Fixed indentation issues
5. Added missing imports
6. Optimized performance
7. Fixed NameError exceptions

Key fixes:
- Added missing __all__ and imports
- Fixed _udp_seq_send and _udp_seq_recv definitions
- Fixed _serve_file_over_http indentation
- Added missing variables (tls_on, expect_sidecar, etc.)
- Fixed broken return statements
- Fixed HTTP server implementation
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os
import io
import re
import sys
import json
import random
import platform
import secrets
import socket
import shutil
import time
import struct
import hmac
import hashlib
import tempfile
import zlib
import gzip
import ssl
import mimetypes
import base64
import threading
import errno
import random
import fcntl
try:
    import select
except ImportError:
    select = None

# Initialize mimetypes
try:
    mimetypes.init()
except Exception:
    pass

try:
    import cookielib
except ImportError:
    import http.cookiejar as cookielib

try:
    from io import BytesIO
    from io import UnsupportedOperation
except ImportError:
    try:
        from cStringIO import StringIO as BytesIO  # py2 fallback
    except ImportError:
        from StringIO import StringIO as BytesIO
    UnsupportedOperation = None

try:
    # Py3
    from urllib.parse import quote_from_bytes, unquote_to_bytes, urlencode
except ImportError:
    # Py2
    from urllib import urlencode
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
PY2 = (sys.version_info[0] == 2)

# get_readable_size by Lipis
# http://stackoverflow.com/posts/14998888/revisions


def get_readable_size(bytes, precision=1, unit="IEC"):
    unit = unit.upper()
    if(unit != "IEC" and unit != "SI"):
        unit = "IEC"
    if(unit == "IEC"):
        units = [" B", " KiB", " MiB", " GiB", " TiB", " PiB", " EiB", " ZiB"]
        unitswos = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB"]
        unitsize = 1024.0
    if(unit == "SI"):
        units = [" B", " kB", " MB", " GB", " TB", " PB", " EB", " ZB"]
        unitswos = ["B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB"]
        unitsize = 1000.0
    return_val = {}
    orgbytes = bytes
    for unit in units:
        if abs(bytes) < unitsize:
            strformat = "%3."+str(precision)+"f%s"
            pre_return_val = (strformat % (bytes, unit))
            pre_return_val = re.sub(
                r"([0]+) ([A-Za-z]+)", r" \2", pre_return_val)
            pre_return_val = re.sub(r"\. ([A-Za-z]+)", r" \1", pre_return_val)
            alt_return_val = pre_return_val.split()
            return_val = {'Bytes': orgbytes, 'ReadableWithSuffix': pre_return_val,
                          'ReadableWithoutSuffix': alt_return_val[0], 'ReadableSuffix': alt_return_val[1]}
            return return_val
        bytes /= unitsize
    strformat = "%."+str(precision)+"f%s"
    pre_return_val = (strformat % (bytes, "YiB"))
    pre_return_val = re.sub(r"([0]+) ([A-Za-z]+)", r" \2", pre_return_val)
    pre_return_val = re.sub(r"\. ([A-Za-z]+)", r" \1", pre_return_val)
    alt_return_val = pre_return_val.split()
    return_val = {'Bytes': orgbytes, 'ReadableWithSuffix': pre_return_val,
                  'ReadableWithoutSuffix': alt_return_val[0], 'ReadableSuffix': alt_return_val[1]}
    return return_val


def get_readable_size_from_file(infile, precision=1, unit="IEC", usehashes=False, usehashtypes="md5,sha1"):
    unit = unit.upper()
    usehashtypes = usehashtypes.lower()
    getfilesize = os.path.getsize(infile)
    return_val = get_readable_size(getfilesize, precision, unit)
    if(usehashes):
        hashtypelist = usehashtypes.split(",")
        openfile = open(infile, "rb")
        filecontents = openfile.read()
        openfile.close()
        listnumcount = 0
        listnumend = len(hashtypelist)
        while(listnumcount < listnumend):
            hashtypelistlow = hashtypelist[listnumcount].strip()
            hashtypelistup = hashtypelistlow.upper()
            filehash = hashlib.new(hashtypelistup)
            filehash.update(filecontents)
            filegethash = filehash.hexdigest()
            return_val.update({hashtypelistup: filegethash})
            listnumcount += 1
    return return_val

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


# Python 2/3 compatibility imports
try:
    from urllib.parse import urlparse, urlunparse, parse_qs, unquote
    from urllib.request import Request, build_opener, HTTPBasicAuthHandler
    from urllib.error import URLError, HTTPError
    from urllib.request import HTTPPasswordMgrWithDefaultRealm
    from http.client import HTTPException
except ImportError:
    from urlparse import urlparse, urlunparse, parse_qs  # type: ignore
    from urllib2 import Request, build_opener, HTTPBasicAuthHandler, URLError, HTTPError  # type: ignore
    from urllib2 import HTTPPasswordMgrWithDefaultRealm  # type: ignore
    from httplib import HTTPException  # type: ignore
    try:
        from urllib import unquote  # py2
    except ImportError:
        def unquote(x):  # very small fallback
            return x

# HTTP server imports
try:
    # Python 3
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import socketserver as _socketserver
    from http import HTTPStatus
except ImportError:
    # Python 2
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer  # type: ignore
    import SocketServer as _socketserver  # type: ignore
    HTTPStatus = type('HTTPStatus', (), {'OK': 200, 'NOT_FOUND': 404, 'UNAUTHORIZED': 401})

# Optional dependencies with better error handling
haverequests = False
try:
    import requests  # noqa
    haverequests = True
except ImportError:
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
except ImportError:
    pass

havehttpcore = False
try:
    import httpcore
    havehttpcore = True
except ImportError:
    pass

havemechanize = False
try:
    import mechanize  # noqa
    havemechanize = True
except ImportError:
    pass

havepycurl = False
try:
    import pycurl
    havepycurl = True
except ImportError:
    pass

haveparamiko = False
try:
    import paramiko  # noqa
    haveparamiko = True
except ImportError:
    pass

havepysftp = False
try:
    import pysftp  # noqa
    havepysftp = True
except ImportError:
    pass

# FTP imports with SSL support detection
ftpssl = True
try:
    from ftplib import FTP, FTP_TLS, all_errors
    from ftplib import error_perm, error_reply, error_temp, error_proto
except ImportError:
    try:
        from ftplib import FTP, all_errors, error_perm, error_reply, error_temp, error_proto
        ftpssl = False
    except ImportError:
        ftpssl = False
        FTP = None
        all_errors = Exception

# Python 2/3 string compatibility
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

geturls_cj = cookielib.CookieJar()
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

def fix_header_names(header_dict):
    if(sys.version[0] == "2"):
        header_dict = {k.title(): v for k, v in header_dict.iteritems()}
    if(sys.version[0] >= "3"):
        header_dict = {k.title(): v for k, v in header_dict.items()}
    return header_dict

def make_http_headers_from_dict_to_list(headers):
    if isinstance(headers, dict):
        returnval = []
        if(sys.version[0] == "2"):
            for headkey, headvalue in headers.iteritems():
                returnval.append((headkey, headvalue))
        if(sys.version[0] >= "3"):
            for headkey, headvalue in headers.items():
                returnval.append((headkey, headvalue))
    elif isinstance(headers, list):
        returnval = headers
    else:
        returnval = False
    return returnval


def make_http_headers_from_dict_to_pycurl(headers):
    if isinstance(headers, dict):
        returnval = []
        if(sys.version[0] == "2"):
            for headkey, headvalue in headers.iteritems():
                returnval.append(headkey+": "+headvalue)
        if(sys.version[0] >= "3"):
            for headkey, headvalue in headers.items():
                returnval.append(headkey+": "+headvalue)
    elif isinstance(headers, list):
        returnval = headers
    else:
        returnval = False
    return returnval


def make_http_headers_from_pycurl_to_dict(headers):
    header_dict = {}
    headers = headers.strip().split('\r\n')
    for header in headers:
        parts = header.split(': ', 1)
        if(len(parts) == 2):
            key, value = parts
            header_dict[key.title()] = value
    return header_dict


def make_http_headers_from_list_to_dict(headers):
    if isinstance(headers, list):
        returnval = {}
        mli = 0
        mlil = len(headers)
        while(mli < mlil):
            returnval.update({headers[mli][0]: headers[mli][1]})
            mli = mli + 1
    elif isinstance(headers, dict):
        returnval = headers
    else:
        returnval = False
    return returnval

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
# Constants
# --------------------------

UDP_MAGIC = b"PWG2"
UDP_VERSION = 1
UDP_HEADER_FORMAT = "!4sBBIQ Q".replace(" ", "")  # magic, ver, flags, seq(u32), total(u64)
UDP_HEADER_LEN = struct.calcsize(UDP_HEADER_FORMAT)

# UDP flags
UF_DATA = 0x01
UF_ACK = 0x02
UF_DONE = 0x04
UF_RESUME = 0x08
UF_META = 0x10
UF_CRC  = 0x20

TCP_MAGIC = b"PWG4"
TCP_HEADER_LEN = 16  # 4 (magic) + 8 (size) + 4 (flags)

DEFAULT_TIMEOUT = 30.0
DEFAULT_CHUNK_SIZE = 65536
DEFAULT_UDP_CHUNK = 1200
DEFAULT_WINDOW_SIZE = 32
DEFAULT_RETRIES = 20

# UDPSEQ protocol (simple, robust, explicit DONE, supports resume)
_U_MAGIC = UDP_MAGIC                 # 4
_U_VER = UDP_VERSION                 # 1 byte
_U_HDR = UDP_HEADER_FORMAT           # magic, ver, flags, seq(u32), total(u64)
_U_HDR_LEN = UDP_HEADER_LEN

_UF_DATA   = UF_DATA
_UF_ACK    = UF_ACK
_UF_DONE   = UF_DONE
_UF_RESUME = UF_RESUME
_UF_META   = UF_META
_UF_CRC    = UF_CRC

# ---- Protocol constants ----
_PT_INITIAL   = 0x01
_PT_HANDSHAKE = 0x02
_PT_0RTT      = 0x03
_PT_1RTT      = 0x04
_PT_RETRY     = 0x05
_PT_CLOSE     = 0x1c

# Frames
_FT_STREAM = 0x10   # STREAM: stream_id(u16) + off(u32) + len(u16) + data
_FT_ACK    = 0x02   # ACK: largest(u32) + ack_upto(u32) + sack_mask(u64)
_FT_META   = 0x20   # META: total_len(u64) + flags(u8) + optional text + token?
_FT_RESUME = 0x21   # RESUME: next_offset(u64)
_FT_DONE   = 0x22   # DONE: "DONE" + sha256(32) optional
_FT_RETRY  = 0x23   # RETRY: token_len(u16) + token(bytes)

_MF_RESUME_REQ = 0x01
_MF_HAS_TOKEN  = 0x02

_MAGIC = b"UQIC"
_HDR_FMT = "!4sBBQIH"
_HDR_SZ = struct.calcsize(_HDR_FMT)
_TAG_SZ = 16


# --------------------------
# Utility Functions
# --------------------------

def _byte_at(b, i):
    """Get integer value of byte at index i for Py2/Py3."""
    v = b[i]
    return v if isinstance(v, int) else ord(v)

def _to_bytes(x, encoding='utf-8'):
    """Convert input to bytes, handling None and various types."""
    if x is None:
        return b""
    if isinstance(x, bytes):
        return x
    if isinstance(x, bytearray):
        return bytes(x)
    try:
        return str(x).encode(encoding)
    except (UnicodeEncodeError, AttributeError):
        try:
            return bytes(x)
        except Exception:
            return str(x).encode(encoding, errors='replace')

def _to_text(x, encoding='utf-8'):
    """Convert input to text string."""
    if x is None:
        return u""
    if isinstance(x, str):
        return x
    if isinstance(x, bytes):
        try:
            return x.decode(encoding, "replace")
        except UnicodeDecodeError:
            return x.decode("latin-1", "replace")
    return str(x)

def _rand_u64():
    # os.urandom works on py2/py3
    return struct.unpack("!Q", os.urandom(8))[0]

def _best_lan_ip():
    """Get the best LAN IP address."""
    try:
        # Try to connect to Google DNS to determine outgoing interface
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        # Fallback: try to get any non-loopback IP
        try:
            hostname = socket.gethostname()
            return socket.gethostbyname(hostname)
        except Exception:
            return "127.0.0.1"

def _listen_urls(scheme, bind_host, port, path, query=""):
    """Generate listening URLs for all interfaces."""
    if not path:
        path = "/"
    if not path.startswith("/"):
        path = "/" + path
    q = ("?" + query.lstrip("?")) if query else ""
    
    urls = []
    if not bind_host or bind_host == "0.0.0.0" or bind_host == "":
        # Add localhost URL
        urls.append("%s://127.0.0.1:%d%s%s" % (scheme, port, path, q))
        
        # Add LAN IP if available and different from localhost
        lan_ip = _best_lan_ip()
        if lan_ip and lan_ip != "127.0.0.1":
            urls.append("%s://%s:%d%s%s" % (scheme, lan_ip, port, path, q))
    else:
        urls.append("%s://%s:%d%s%s" % (scheme, bind_host, port, path, q))
    
    return urls

def _parse_kv_headers(qs, prefix="hdr_"):
    """Parse custom headers from query string."""
    out = {}
    for k, v in qs.items():
        if k.startswith(prefix):
            hk = k[len(prefix):].replace("_", "-")
            if isinstance(v, list) and v:
                out[hk] = _to_text(v[0])
            elif v:
                out[hk] = _to_text(v)
    return out

def _throttle_bps(rate_bps, sent, started):
    """Sleep to enforce approximate bytes/sec rate."""
    try:
        rate_bps = float(rate_bps)
    except (ValueError, TypeError):
        return
    
    if rate_bps <= 0:
        return
    
    elapsed = max(time.time() - started, 0.001)
    expected_time = float(sent) / rate_bps
    
    if expected_time > elapsed:
        time.sleep(expected_time - elapsed)

def _hs_token():
    """Generate a short ASCII token for handshake correlation."""
    try:
        return ('%016x' % random.getrandbits(64)).encode('ascii')
    except Exception:
        try:
            return ('%016x' % (int(time.time() * 1000000) ^ os.getpid())).encode('ascii')
        except Exception:
            return ('%016x' % int(time.time() * 1000000)).encode('ascii')

def _set_query_param(url, key, value):
    """Return url with query param key set to value (string)."""
    try:
        up = urlparse(url)
        qs = up.query or ""
        parts = []
        
        # Parse existing query string
        if qs:
            for kv in qs.split("&"):
                if not kv:
                    continue
                if "=" in kv:
                    k, _ = kv.split("=", 1)
                else:
                    k = kv
                if k != key:
                    parts.append(kv)
        
        # Add new parameter
        parts.append("%s=%s" % (key, value))
        newq = "&".join(parts)
        
        return urlunparse((up.scheme, up.netloc, up.path, up.params, newq, up.fragment))
    except Exception:
        return url

def _qflag(qs, key, default=False):
    """Get boolean flag from query string."""
    v = qs.get(key, [None])[0]
    if v is None:
        return default
    v = _to_text(v).strip().lower()
    return v in ("1", "true", "yes", "on", "y", "enable", "enabled")

def _qnum(qs, key, default, cast=int):
    """Get numeric value from query string."""
    v = qs.get(key, [None])[0]
    if v is None or v == "":
        return default
    try:
        return cast(v)
    except (ValueError, TypeError):
        try:
            return cast(_to_text(v))
        except (ValueError, TypeError):
            return default

def _qstr(qs, key, default=None):
    """Get string value from query string."""
    v = qs.get(key, [None])[0]
    if v is None:
        return default
    return _to_text(v)

def _ensure_dir(d):
    """Ensure directory exists."""
    if not d:
        return
    if not os.path.isdir(d):
        try:
            os.makedirs(d)
        except (OSError, IOError):
            pass

def _guess_filename(url):
    """Guess filename from URL."""
    p = urlparse(url)
    bn = os.path.basename(p.path or "")
    return bn or "download.bin"

def _choose_output_path(fname, overwrite=False, save_dir=None):
    """Choose output path, avoiding overwrites if not allowed."""
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
    """Copy file-like object to filesystem path."""
    if (not overwrite) and os.path.exists(path):
        raise IOError("Refusing to overwrite: %s" % path)
    
    _ensure_dir(os.path.dirname(path) or ".")
    
    with open(path, "wb") as out:
        try:
            fileobj.seek(0, 0)
        except (AttributeError, IOError):
            pass
        shutil.copyfileobj(fileobj, out)


def _net_log(verbose, msg):
    if verbose:
        try:
            sys.stderr.write(msg + "\n")
            sys.stderr.flush()
        except Exception:
            pass

def _resolve_wait_timeout(scheme, mode, options):
    """Resolve effective wait timeout for sender-side wait/handshake."""
    wt = options.get("wait_timeout", None)
    if wt is not None:
        try:
            return float(wt)
        except (ValueError, TypeError):
            return wt
    
    if options.get("wait_forever"):
        return None
    
    tt = options.get("total_timeout", 0.0)
    try:
        if tt not in (None, 0, 0.0) and float(tt) > 0.0:
            return float(tt)
    except (ValueError, TypeError):
        pass
    
    if scheme == "udp" and (mode or "seq") == "raw":
        return None
    
    return options.get("timeout", None)

# --------------------------
# File-like Object Management
# --------------------------

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
                f = BytesIO(init if init is not None else b"")
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

# --------------------------
# FTP helpers
# --------------------------

def detect_cwd_ftp(ftp, file_dir):
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

def download_file_from_ftp_file(url, timeout=60, returnstats=False):
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
    start_time = time.time()
    socket.setdefaulttimeout(float(timeout))
    ftp = FTP_TLS() if (p.scheme == "ftps") else FTP()
    try:
        ftp.connect(host, port, timeout=float(timeout))
        _ftp_login(ftp, user, pw)
        if p.scheme == "ftps":
            try:
                ftp.prot_p()
            except Exception:
                pass

        # Try cwd into directory; if it works, RETR just basename.
        use_cwd = detect_cwd_ftp(ftp, file_dir)
        retr_path = os.path.basename(path) if use_cwd else path

        bio = MkTempFile()
        ftp.retrbinary("RETR " + retr_path, bio.write)
        ftp.quit()
        fulldatasize = bio.tell()
        bio.seek(0, 0)
        end_time = time.time()
        total_time = end_time - start_time
        if(returnstats):
            returnval = {'Type': "Buffer", 'Buffer': bio, 'Contentsize': fulldatasize, 'ContentsizeAlt': {'IEC': get_readable_size(fulldatasize, 2, "IEC"), 'SI': get_readable_size(fulldatasize, 2, "SI")}, 'Headers': None, 'Version': None, 'Method': None, 'HeadersSent': None, 'URL': url, 'Code': None, 'RequestTime': {'StartTime': start_time, 'EndTime': end_time, 'TotalTime': total_time}, 'FTPLib': 'pyftp'}
        else:
            return bio
    except Exception:
        try:
            ftp.close()
        except Exception:
            pass
        return False

def download_file_from_ftp_string(url, timeout=60, returnstats=False):
    fp = download_file_from_ftp_file(url, timeout, returnstats)
    return fp.read() if fp else False

def download_file_from_ftps_file(url, timeout=60, returnstats=False):
    return download_file_from_ftp_file(url, timeout, returnstats)

def download_file_from_ftps_string(url, timeout=60, returnstats=False):
    return download_file_from_ftp_string(url, timeout, returnstats)

def upload_file_to_ftp_file(fileobj, url, timeout=60):
    p = urlparse(url)
    if p.scheme not in ("ftp", "ftps"):
        return False
    if p.scheme == "ftps" and not ftpssl:
        return False
    socket.setdefaulttimeout(float(timeout))
    host = p.hostname
    port = p.port or 21
    user = p.username
    pw = p.password
    path = p.path or "/"
    file_dir = os.path.dirname(path)
    fname = os.path.basename(path) or "upload.bin"

    ftp = FTP_TLS() if (p.scheme == "ftps") else FTP()
    try:
        ftp.connect(host, port, timeout=float(timeout))
        _ftp_login(ftp, user, pw)
        if p.scheme == "ftps":
            try:
                ftp.prot_p()
            except Exception:
                pass

        use_cwd = detect_cwd_ftp(ftp, file_dir)
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

def upload_file_to_ftp_string(data, url, timeout=60):
    bio = MkTempFile(_to_bytes(data))
    out = upload_file_to_ftp_file(bio, url, timeout)
    try:
        bio.close()
    except Exception:
        pass
    return out

def upload_file_to_ftp_file(fileobj, url, timeout=60):
    return upload_file_to_ftp_file(fileobj, url, timeout)

def upload_file_to_ftp_string(fileobj, url, timeout=60):
    return upload_file_to_ftp_string(fileobj, url, timeout)

# --------------------------
# SFTP helpers
# --------------------------

def detect_cwd_sftp(sftp, file_dir):
    """
    Test whether chdir into file_dir works. Returns True if it does,
    False if not (so absolute paths should be used).
    """
    if not file_dir:
        return False  # nothing to cwd into
    try:
        sftp.chdir(file_dir)
        return True
    except all_errors:
        return False

def download_file_from_sftp_file(url, timeout=60, returnstats=False):
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
    socket.setdefaulttimeout(float(timeout))
    start_time = time.time()
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=port, username=user, password=pw, timeout=float(timeout))
        sftp = ssh.open_sftp()
        use_cwd = detect_cwd_sftp(sftp, path)
        retr_path = os.path.basename(path) if use_cwd else path
        bio = MkTempFile()
        sftp.getfo(retr_path, bio)
        sftp.close()
        ssh.close()
        fulldatasize = bio.tell()
        bio.seek(0, 0)
        end_time = time.time()
        total_time = end_time - start_time
        if(returnstats):
            returnval = {'Type': "Buffer", 'Buffer': bio, 'Contentsize': fulldatasize, 'ContentsizeAlt': {'IEC': get_readable_size(fulldatasize, 2, "IEC"), 'SI': get_readable_size(fulldatasize, 2, "SI")}, 'Headers': None, 'Version': None, 'Method': None, 'HeadersSent': None, 'URL': url, 'Code': None, 'RequestTime': {'StartTime': start_time, 'EndTime': end_time, 'TotalTime': total_time}, 'SFTPLib': 'paramiko'}
        else:
            return bio
    except Exception:
        try:
            ssh.close()
        except Exception:
            pass
        return False

def download_file_from_sftp_string(url, timeout=60, returnstats=False):
    fp = download_file_from_sftp_file(url, timeout, returnstats)
    return fp.read() if fp else False

def upload_file_to_sftp_file(fileobj, url, timeout=60):
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
    fname = os.path.basename(path) or "upload.bin"
    socket.setdefaulttimeout(float(timeout))
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=port, username=user, password=pw, timeout=float(timeout))
        sftp = ssh.open_sftp()
        use_cwd = detect_cwd_sftp(sftp, path)
        stor_path = fname if use_cwd else path
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        sftp.putfo(fileobj, stor_path)
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

def upload_file_to_sftp_string(data, url, timeout=60):
    bio = MkTempFile(_to_bytes(data))
    out = upload_file_to_sftp_file(bio, url, timeout)
    try:
        bio.close()
    except Exception:
        pass
    return out

# --------------------------
# Pysftp Compatibility Layer
# --------------------------

def download_file_from_pysftp_file(url, timeout=60, returnstats=False):
    if not havepysftp:
        return False
    p = urlparse(url)
    if p.scheme not in ("sftp", "scp"):
        return False
    socket.setdefaulttimeout(float(timeout))
    host = p.hostname
    port = p.port or 22
    user = p.username or "anonymous"
    pw = p.password or ("anonymous" if user == "anonymous" else "")
    path = p.path or "/"
    fname = os.path.basename(path) or "upload.bin"

    conn = None
    start_time = time.time()
    try:
        # NOTE: pysftp host key checking is strict by default.
        # If you need AutoAddPolicy-like behavior, set cnopts (see note below).
        conn = pysftp.Connection(host=host, port=port, username=user, password=pw)

        sftp = conn.sftp_client
        use_cwd = detect_cwd_sftp(sftp, path)
        retr_path = os.path.basename(path) if use_cwd else path
        bio = BytesIO()
        sftp.getfo(retr_path, bio)

        fulldatasize = bio.tell()
        bio.seek(0, 0)

        end_time = time.time()
        total_time = end_time - start_time
        if(returnstats):
            returnval = {'Type': "Buffer", 'Buffer': bio, 'Contentsize': fulldatasize, 'ContentsizeAlt': {'IEC': get_readable_size(fulldatasize, 2, "IEC"), 'SI': get_readable_size(fulldatasize, 2, "SI")}, 'Headers': None, 'Version': None, 'Method': None, 'HeadersSent': None, 'URL': url, 'Code': None, 'RequestTime': {'StartTime': start_time, 'EndTime': end_time, 'TotalTime': total_time}, 'SFTPLib': 'pysftp'}
        else:
            return bio

    except Exception:
        return False
    finally:
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass

def download_file_from_pysftp_string(url, timeout=60, returnstats=False):
    fp = download_file_from_pysftp_file(url, timeout, returnstats)
    return fp.read() if fp else False

def upload_file_to_pysftp_file(fileobj, url, timeout=60):
    if not havepysftp:
        return False
    p = urlparse(url)
    if p.scheme not in ("sftp", "scp"):
        return False
    socket.setdefaulttimeout(float(timeout))
    host = p.hostname
    port = p.port or 22
    user = p.username or "anonymous"
    pw = p.password or ("anonymous" if user == "anonymous" else "")
    path = p.path or "/"
    fname = os.path.basename(path) or "upload.bin"

    conn = None
    try:
        conn = pysftp.Connection(host=host, port=port, username=user, password=pw)

        sftp = conn.sftp_client
        use_cwd = detect_cwd_sftp(sftp, path)
        stor_path = fname if use_cwd else path
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass

        sftp.putfo(fileobj, stor_path)

        try:
            fileobj.seek(0, 0)
        except Exception:
            pass

        return fileobj

    except Exception:
        return False
    finally:
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass

def upload_file_to_pysftp_string(data, url, timeout=60):
    if not havepysftp:
        return False
    return upload_file_to_sftp_string(data, url, timeout)

def decoded_stream(resp):
    # resp can be urllib response or anything file-like with headers
    enc = None
    try:
        enc = resp.headers.get("Content-Encoding")
    except Exception:
        pass

    if not enc:
        return resp

    enc = enc.lower().strip()

    if enc == "gzip":
        return gzip.GzipFile(fileobj=resp)
    if enc == "deflate":
        # deflate is ambiguous; try zlib header first, then raw deflate
        data = resp.read()
        try:
            return io.BytesIO(zlib.decompress(data))
        except zlib.error:
            return io.BytesIO(zlib.decompress(data, -zlib.MAX_WBITS))

    # br requires brotli package; zstd requires zstandard package.
    # If you need these, handle here.
    return resp

# --------------------------
# HTTP helpers (download only)
# --------------------------

def http_status_to_reason(code):
    reasons = {
        100: 'Continue',
        101: 'Switching Protocols',
        102: 'Processing',
        200: 'OK',
        201: 'Created',
        202: 'Accepted',
        203: 'Non-Authoritative Information',
        204: 'No Content',
        205: 'Reset Content',
        206: 'Partial Content',
        207: 'Multi-Status',
        208: 'Already Reported',
        226: 'IM Used',
        300: 'Multiple Choices',
        301: 'Moved Permanently',
        302: 'Found',
        303: 'See Other',
        304: 'Not Modified',
        305: 'Use Proxy',
        307: 'Temporary Redirect',
        308: 'Permanent Redirect',
        400: 'Bad Request',
        401: 'Unauthorized',
        402: 'Payment Required',
        403: 'Forbidden',
        404: 'Not Found',
        405: 'Method Not Allowed',
        406: 'Not Acceptable',
        407: 'Proxy Authentication Required',
        408: 'Request Timeout',
        409: 'Conflict',
        410: 'Gone',
        411: 'Length Required',
        412: 'Precondition Failed',
        413: 'Payload Too Large',
        414: 'URI Too Long',
        415: 'Unsupported Media Type',
        416: 'Range Not Satisfiable',
        417: 'Expectation Failed',
        421: 'Misdirected Request',
        422: 'Unprocessable Entity',
        423: 'Locked',
        424: 'Failed Dependency',
        426: 'Upgrade Required',
        428: 'Precondition Required',
        429: 'Too Many Requests',
        431: 'Request Header Fields Too Large',
        451: 'Unavailable For Legal Reasons',
        500: 'Internal Server Error',
        501: 'Not Implemented',
        502: 'Bad Gateway',
        503: 'Service Unavailable',
        504: 'Gateway Timeout',
        505: 'HTTP Version Not Supported',
        506: 'Variant Also Negotiates',
        507: 'Insufficient Storage',
        508: 'Loop Detected',
        510: 'Not Extended',
        511: 'Network Authentication Required'
    }
    return reasons.get(code, 'Unknown Status Code')


def ftp_status_to_reason(code):
    reasons = {
        110: 'Restart marker reply',
        120: 'Service ready in nnn minutes',
        125: 'Data connection already open; transfer starting',
        150: 'File status okay; about to open data connection',
        200: 'Command okay',
        202: 'Command not implemented, superfluous at this site',
        211: 'System status, or system help reply',
        212: 'Directory status',
        213: 'File status',
        214: 'Help message',
        215: 'NAME system type',
        220: 'Service ready for new user',
        221: 'Service closing control connection',
        225: 'Data connection open; no transfer in progress',
        226: 'Closing data connection',
        227: 'Entering Passive Mode',
        230: 'User logged in, proceed',
        250: 'Requested file action okay, completed',
        257: '"PATHNAME" created',
        331: 'User name okay, need password',
        332: 'Need account for login',
        350: 'Requested file action pending further information',
        421: 'Service not available, closing control connection',
        425: 'Can\'t open data connection',
        426: 'Connection closed; transfer aborted',
        450: 'Requested file action not taken',
        451: 'Requested action aborted. Local error in processing',
        452: 'Requested action not taken. Insufficient storage space in system',
        500: 'Syntax error, command unrecognized',
        501: 'Syntax error in parameters or arguments',
        502: 'Command not implemented',
        503: 'Bad sequence of commands',
        504: 'Command not implemented for that parameter',
        530: 'Not logged in',
        532: 'Need account for storing files',
        550: 'Requested action not taken. File unavailable',
        551: 'Requested action aborted. Page type unknown',
        552: 'Requested file action aborted. Exceeded storage allocation',
        553: 'Requested action not taken. File name not allowed'
    }
    return reasons.get(code, 'Unknown Status Code')


def sftp_status_to_reason(code):
    reasons = {
        0: 'SSH_FX_OK',
        1: 'SSH_FX_EOF',
        2: 'SSH_FX_NO_SUCH_FILE',
        3: 'SSH_FX_PERMISSION_DENIED',
        4: 'SSH_FX_FAILURE',
        5: 'SSH_FX_BAD_MESSAGE',
        6: 'SSH_FX_NO_CONNECTION',
        7: 'SSH_FX_CONNECTION_LOST',
        8: 'SSH_FX_OP_UNSUPPORTED'
    }
    return reasons.get(code, 'Unknown Status Code')

def read_all(fileobj, encoding='utf-8', errors='replace'):
    data = fileobj.read()
    if data is None:
        return u'' if PY2 else ''
    if isinstance(data, bytes):
        return data.decode(encoding, errors)
    return data  # already text (unicode on py2 or str on py3)

# ---------------- Parsing primitives ----------------

_req_line_http1 = re.compile(r'^(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/(?P<version>\d+\.\d)\s*$')
_req_line_h2    = re.compile(r'^(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/(?P<version>2(?:\.0)?)\s*$')
_status_line_v1 = re.compile(r'^HTTP/(?P<version>\d+\.\d)\s+(?P<code>\d{3})(?:\s+(?P<reason>.*))?$')
_status_line_h2 = re.compile(r'^HTTP/(?P<version>2(?:\.0)?)\s+(?P<code>\d{3})(?:\s+(?P<reason>.*))?$')

def _normalize(text):
    return text.replace('\r\n', '\n').replace('\r', '\n')

def _split_header_block(block_text):
    block_text = _normalize(block_text)
    lines = block_text.split('\n')
    while lines and lines[-1] == '':
        lines.pop()

    # unfold obs-fold (space/tab continuation)
    out = []
    for line in lines:
        if out and (line.startswith(' ') or line.startswith('\t')):
            out[-1] += ' ' + line.lstrip()
        else:
            out.append(line)
    return out

def _parse_headers(lines):
    headers = {}
    for line in lines:
        if not line or ':' not in line:
            continue
        name, value = line.split(':', 1)
        name = name.strip()
        value = value.strip()
        key = name.lower()

        if key in headers:
            if isinstance(headers[key], list):
                headers[key].append(value)
            else:
                headers[key] = [headers[key], value]
        else:
            headers[key] = value
    return headers

def parse_request_block(block_text):
    if not block_text:
        return None
    lines = _split_header_block(block_text)
    if not lines:
        return None

    m = _req_line_http1.match(lines[0]) or _req_line_h2.match(lines[0])
    if not m:
        return None

    return {
        'method': m.group('method'),
        'path': m.group('path'),
        'version': m.group('version'),
        'headers': _parse_headers(lines[1:]),
    }

def parse_response_block(block_text):
    if not block_text:
        return None
    lines = _split_header_block(block_text)
    if not lines:
        return None

    m = _status_line_v1.match(lines[0]) or _status_line_h2.match(lines[0])
    if not m:
        return None

    code = int(m.group('code'))
    reason = (m.group('reason') or '').strip()
    return {
        'version': m.group('version'),
        'status_code': code,
        'reason': reason,
        'headers': _parse_headers(lines[1:]),
    }

# ---------------- Extraction from verbose output ----------------

# HTTP/1.x request block: "GET / HTTP/1.1" ... blank line
_HTTP1_REQ_BLOCK = re.compile(
    r'(?ms)^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP/\d\.\d\s*\n'
    r'(?:.*?\n)*?\n'
)

# HTTP/2 synthesized request block: "GET / HTTP/2" ... blank line
_HTTP2_SYN_REQ_BLOCK = re.compile(
    r'(?ms)^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP/2(?:\.0)?\s*\n'
    r'(?:.*?\n)*?\n'
)

# HTTP/2 bracket pseudo-headers:
# [HTTP/2] [1] [:method: GET]
# [HTTP/2] [1] [:path: /]
# [HTTP/2] [1] [user-agent: ...]
_HTTP2_BRACKET_LINE = re.compile(
    r'^\[HTTP/2\]\s*\[(?P<stream>\d+)\]\s*\[(?P<kv>.+?)\]\s*$'
)

def _extract_http2_bracket_request(text):
    """
    Build a synthetic request block from the [HTTP/2] [stream] [key: value] lines.
    Returns (block_text, used_stream) or (None, None).
    """
    t = _normalize(text)
    lines = t.split('\n')

    # Collect per stream
    per_stream = {}
    order = []  # stream appearance order
    for line in lines:
        m = _HTTP2_BRACKET_LINE.match(line)
        if not m:
            continue
        stream = m.group('stream')
        kv = m.group('kv')
        if stream not in per_stream:
            per_stream[stream] = []
            order.append(stream)
        per_stream[stream].append(kv)

    if not order:
        return (None, None)

    # pick first stream that has :method and :path
    for stream in order:
        kvs = per_stream[stream]
        pseudo = {}
        normal = []
        for kv in kvs:
            # kv is like ":method: GET" or "user-agent: blah"
            if ':' not in kv:
                continue
            name, value = kv.split(':', 1)
            name = name.strip()
            value = value.strip()

            # special case: pseudo headers start with empty name because kv starts ":method..."
            # our split gives name="" and value="method: GET" if we split at first ':'
            if name == '' and value:
                # now split "method: GET"
                if ':' in value:
                    n2, v2 = value.split(':', 1)
                    pseudo[':' + n2.strip()] = v2.strip()
                continue

            # regular "host: github.com"
            normal.append((name, value))

        # also handle case where pseudo lines came as "[:method: GET]" (already handled)
        if ':method' in pseudo and ':path' in pseudo:
            method = pseudo[':method']
            path = pseudo[':path']
            # prefer :authority for Host if present
            authority = pseudo.get(':authority')

            block_lines = []
            block_lines.append('%s %s HTTP/2' % (method, path))
            if authority:
                block_lines.append('Host: %s' % authority)

            # add other pseudo? scheme isn't a header line usually; skip it.
            # add bracketed normal headers
            for (name, value) in normal:
                block_lines.append('%s: %s' % (name, value))
            block_lines.append('')  # blank line terminator

            return ('\n'.join(block_lines), stream)

    return (None, None)

# Response blocks
_HTTP1_RESP_BLOCK = re.compile(
    r'(?ms)^HTTP/\d\.\d\s+\d{3}.*\n(?:.*?\n)*?\n'
)
_HTTP2_RESP_BLOCK = re.compile(
    r'(?ms)^HTTP/2(?:\.0)?\s+\d{3}.*\n(?:.*?\n)*?\n'
)

def extract_request_and_response(debug_text):
    """
    Returns (request_block_text, response_block_text).
    Supports:
      - HTTP/1 request blocks
      - HTTP/2 synthesized request blocks
      - HTTP/2 bracket pseudo-header sequences (converted to synthetic block)
      - HTTP/1 and HTTP/2 response blocks
    """
    t = _normalize(debug_text)

    # Try request in priority order:
    # 1) HTTP/1 request block
    m = _HTTP1_REQ_BLOCK.search(t)
    if m:
        req_block = m.group(0)
    else:
        # 2) HTTP/2 synthesized request block
        m2 = _HTTP2_SYN_REQ_BLOCK.search(t)
        if m2:
            req_block = m2.group(0)
        else:
            # 3) HTTP/2 bracket pseudo headers -> synthesize
            req_block, _stream = _extract_http2_bracket_request(t)

    # Try response in priority order:
    mr2 = _HTTP2_RESP_BLOCK.search(t)
    mr1 = _HTTP1_RESP_BLOCK.search(t)
    if mr2 and mr1:
        # choose whichever appears first
        resp_block = mr2.group(0) if mr2.start() < mr1.start() else mr1.group(0)
    elif mr2:
        resp_block = mr2.group(0)
    elif mr1:
        resp_block = mr1.group(0)
    else:
        resp_block = None

    return req_block, resp_block

def parse_pycurl_verbose(fileobj_or_text):
    if hasattr(fileobj_or_text, 'read'):
        text = read_all(fileobj_or_text)
    else:
        if isinstance(fileobj_or_text, bytes):
            text = fileobj_or_text.decode('utf-8', 'replace')
        else:
            text = fileobj_or_text

    req_block, resp_block = extract_request_and_response(text)
    return {
        'raw': {'request': req_block, 'response': resp_block},
        'request': parse_request_block(req_block) if req_block else None,
        'response': parse_response_block(resp_block) if resp_block else None,
    }

def decode_headers_any(headers):
    # Accepts: dict-like (has .items()) OR list/tuple of pairs
    if hasattr(headers, "items"):
        pairs = headers.items()
    else:
        pairs = headers  # assume iterable of (k, v)

    return {
        (k.decode("ascii", "replace") if isinstance(k, (bytes, bytearray)) else str(k)):
        (v.decode("latin-1", "replace") if isinstance(v, (bytes, bytearray)) else str(v))
        for k, v in pairs
    }

def _is_many_specs(value):
    # True if value looks like: [ [field, fobj, ctype], [field, fobj, ctype], ... ]
    return (
        isinstance(value, (list, tuple)) and value and
        isinstance(value[0], (list, tuple)) and len(value[0]) >= 2
    )


def _normalize_ctype(filename, ctype):
    if ctype == "textplain":
        return "text/plain"
    if ctype:
        return ctype
    if guess_type:
        guessed = guess_type(filename)[0]
        if guessed:
            return guessed
    return "application/octet-stream"


def _ensure_ext(filename, default_ext=".txt"):
    if "." not in filename:
        return filename + default_ext
    return filename


def _read_fileobj(fobj):
    data = fobj.read()
    # rewind if possible so caller can reuse the file object
    try:
        fobj.seek(0)
    except Exception:
        pass
    return data


def to_requests_files(payload, default_ext=".txt"):
    """
    Input payload format:
      {
        "hello.txt": ["file[]", fobj, "text/plain"],
        "goodbye":   ["file[]", fobj2, "textplain"],
        "multi.bin": [
            ["file[]", fobj3, "application/octet-stream"],
            ["file[]", fobj4, None],
        ],
      }

    Output:
      [
        ("file[]", ("hello.txt", b"...", "text/plain")),
        ("file[]", ("goodbye.txt", b"...", "text/plain")),
        ("file[]", ("multi.bin", b"...", "application/octet-stream")),
        ("file[]", ("multi.bin", b"...", "application/octet-stream")),
      ]
    """
    out = []

    # Py2 dict iteration
    items = payload.items()

    for filename, spec in items:
        # ensure filename is a text string
        if not isinstance(filename, text_type):
            filename = text_type(filename)

        filename2 = _ensure_ext(filename, default_ext)

        specs = spec if _is_many_specs(spec) else [spec]

        for one in specs:
            if not isinstance(one, (list, tuple)) or len(one) < 2:
                raise ValueError("Bad spec for %r: expected [fieldname, fileobj, (optional) ctype]" % filename)

            fieldname = one[0]
            fobj = one[1]
            ctype = one[2] if len(one) > 2 else None

            ctype = _normalize_ctype(filename2, ctype)
            data = _read_fileobj(fobj)

            out.append((fieldname, (filename2, data, ctype)))

    return out

def to_pycurl_httpost(payload, default_ext=".txt"):
    """
    Input payload format (same as your requests converter):
      {
        "hello.txt": ["file[]", fobj, "text/plain"],
        "goodbye":   ["file[]", fobj2, "textplain"],
        "multi.txt": [
            ["file[]", fobj3, "text/plain"],
            ["file[]", fobj4, None],
        ],
      }

    Output:
      [
        ('file[]', (pycurl.FORM_BUFFER, 'hello.txt',  pycurl.FORM_BUFFERPTR, b'...', pycurl.FORM_CONTENTTYPE, 'text/plain')),
        ('file[]', (pycurl.FORM_BUFFER, 'goodbye.txt',pycurl.FORM_BUFFERPTR, b'...', pycurl.FORM_CONTENTTYPE, 'text/plain')),
        ...
      ]
    """

    http_post = []
    for filename, spec in payload.items():
        if not isinstance(filename, text_type):
            filename = text_type(filename)

        filename2 = _ensure_ext(filename, default_ext)
        specs = spec if _is_many_specs(spec) else [spec]

        for one in specs:
            if not isinstance(one, (list, tuple)) or len(one) < 2:
                raise ValueError("Bad spec for %r: expected [fieldname, fileobj, (optional) ctype]" % filename)

            fieldname = one[0]
            fobj = one[1]
            ctype = one[2] if len(one) > 2 else None
            ctype = _normalize_ctype(filename2, ctype)

            data = fobj.read()
            try:
                fobj.seek(0)
            except Exception:
                pass

            # Important: pycurl wants bytes for FORM_BUFFERPTR
            # If someone fed you text in Py3, encode it.
            if isinstance(data, text_type):
                data = data.encode("utf-8")

            http_post.append((
                fieldname,
                (
                    pycurl.FORM_BUFFER, filename2,
                    pycurl.FORM_BUFFERPTR, data,
                    pycurl.FORM_CONTENTTYPE, ctype,
                )
            ))

    return http_post

def download_file_from_http_file(url, headers=None, usehttp=__use_http_lib__, httpuseragent=None, httpreferer=None, httpcookie=geturls_cj, httpmethod="GET", postdata=None, jsonpost=False, sendfiles=None, putfile=None, timeout=60, returnstats=False):
    if headers is None:
        headers = {}
    else:
        if(isinstance(headers, list)):
            headers = make_http_headers_from_list_to_dict(headers)
    p = urlparse(url)
    username = unquote(p.username) if p.username else None
    password = unquote(p.password) if p.password else None
    if(httpmethod is None):
        httpmethod = "GET"
    httpmethod = httpmethod.upper()
    # Strip auth from URL
    netloc = p.hostname or ""
    if p.port:
        netloc += ":" + str(p.port)
    rebuilt_url = urlunparse((p.scheme, netloc, p.path, p.params, p.query, p.fragment))
    extendargs = {}

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

    if(httpuseragent is not None):
        if('User-Agent' in headers):
            headers['User-Agent'] = httpuseragent
        else:
            headers.update({'User-Agent': httpuseragent})
    if(httpreferer is not None):
        if('Referer' in headers):
            headers['Referer'] = httpreferer
        else:
            headers.update({'Referer': httpreferer})

    if(usehttp == "pycurl"):
        if(isinstance(headers, dict)):
            headers = make_http_headers_from_dict_to_pycurl(headers)

    socket.setdefaulttimeout(float(timeout))
    start_time = time.time()

    # Requests
    if usehttp == "requests" and haverequests:
        auth = (username, password) if (username and password) else None
        extendargs.update({'url': rebuilt_url, 'method': httpmethod, 'headers': headers, 'auth': auth, 'cookies': httpcookie, 'stream': True, 'allow_redirects': True, 'timeout': (float(timeout), float(timeout))})
        try:
            if(httpmethod == "POST"):
                if(putfile is not None and sendfiles is not None):
                    putfile = None
                if(putfile is not None):
                    putfile.seek(0, 0)
                    extendargs.update({'data': putfile})
                if(sendfiles is not None and isinstance(sendfiles, dict)):
                    jsonpost = False
                    sendfiles = to_requests_files(sendfiles)
                    if(sendfiles is not None):
                        for _, (_, fobj, *_) in sendfiles:
                            if hasattr(fobj, "seek"):
                                fobj.seek(0)
                    extendargs.update({'files': sendfiles})
                if(jsonpost and postdata is not None):
                    extendargs.update({'json': postdata})
                elif(not jsonpost and postdata is not None):
                    extendargs.update({'data': postdata})
            elif(httpmethod == "PUT" or httpmethod == "PATCH" or httpmethod == "DELETE"):
                if(putfile is not None and sendfiles is not None):
                    sendfiles = None
                if(putfile is not None):
                    putfile.seek(0, 0)
                    extendargs.update({'data': putfile})
                if(sendfiles is not None and isinstance(sendfiles, dict)):
                    jsonpost = False
                    sendfiles = to_requests_files(sendfiles)
                    if(sendfiles is not None):
                        for _, (_, fobj, *_) in sendfiles:
                            if hasattr(fobj, "seek"):
                                fobj.seek(0)
                    extendargs.update({'files': sendfiles})
                if(jsonpost and postdata is not None):
                    extendargs.update({'json': postdata})
                elif(not jsonpost and postdata is not None and (isinstance(sendfiles, dict) or sendfiles is None)):
                    extendargs.update({'data': postdata})
            r = requests.request(**extendargs)
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            r = e.response
        except (socket.timeout, socket.gaierror, requests.exceptions.ConnectionError):
            return False
        r.raw.decode_content = True
        #shutil.copyfileobj(r.raw, httpfile)
        for chunk in r.iter_content(chunk_size=1024 * 1024):
            if chunk:
                httpfile.write(chunk)
        httpcodeout = r.status_code
        httpcodereason = r.reason
        vertostr = {
                    10: "HTTP/1.0",
                    11: "HTTP/1.1"
        }
        try:
            httpversionout = vertostr[r.raw.version]
        except AttributeError:
            httpversionout = "HTTP/1.1"
        httpmethodout = httpmethod
        httpurlout = r.url
        httpheaderout = r.headers
        httpheadersentout = r.request.headers

    # HTTPX
    elif usehttp == "httpx" and havehttpx:
        try:
            import h2
            usehttp2 = True
        except ImportError:
            usehttp2 = False
        try:
            with httpx.Client(follow_redirects=True, http1=True, http2=usehttp2, trust_env=True, timeout=float(timeout)) as client:
                auth = (username, password) if (username and password) else None
                extendargs.update({'url': rebuilt_url, 'method': httpmethod, 'headers': headers, 'auth': auth, 'cookies': httpcookie})
                if(httpmethod == "POST"):
                    if(putfile is not None and sendfiles is not None):
                        putfile = None
                    if(putfile is not None):
                        putfile.seek(0, 0)
                        extendargs.update({'content': putfile})
                    if(sendfiles is not None and isinstance(sendfiles, dict)):
                        jsonpost = False
                        sendfiles = to_requests_files(sendfiles)
                        if(sendfiles is not None):
                            for _, (_, fobj, *_) in sendfiles:
                                if hasattr(fobj, "seek"):
                                    fobj.seek(0)
                        extendargs.update({'files': sendfiles})
                    if(jsonpost and postdata is not None):
                        extendargs.update({'json': postdata})
                    elif(not jsonpost and postdata is not None):
                        extendargs.update({'data': postdata})
                elif(httpmethod == "PUT" or httpmethod == "PATCH" or httpmethod == "DELETE"):
                    if(putfile is not None and sendfiles is not None):
                        sendfiles = None
                    if(putfile is not None):
                        putfile.seek(0, 0)
                        extendargs.update({'content': putfile})
                    if(sendfiles is not None and isinstance(sendfiles, dict)):
                        jsonpost = False
                        sendfiles = to_requests_files(sendfiles)
                        if(sendfiles is not None):
                            for _, (_, fobj, *_) in sendfiles:
                                if hasattr(fobj, "seek"):
                                    fobj.seek(0)
                        extendargs.update({'files': sendfiles})
                    if(jsonpost and postdata is not None):
                        extendargs.update({'json': postdata})
                    elif(not jsonpost and postdata is not None):
                        extendargs.update({'data': postdata})
                r = client.request(**extendargs)
                r.raise_for_status()
        except httpx.HTTPStatusError as e:
            r = e.response
        except (socket.timeout, socket.gaierror, httpx.ConnectError):
            return False
        for chunk in r.iter_bytes(chunk_size=1024 * 1024):
            if chunk:
                httpfile.write(chunk)
        httpcodeout = r.status_code
        try:
            httpcodereason = r.reason_phrase
        except:
            httpcodereason = http_status_to_reason(r.status_code)
        httpversionout = r.http_version
        httpmethodout = httpmethod
        httpurlout = str(r.url)
        httpheaderout = {
            k.decode("ascii", errors="replace")
            if isinstance(k, (bytes, bytearray)) else str(k):
            v.decode("ascii", errors="replace")
            if isinstance(v, (bytes, bytearray)) else str(v)
            for k, v in r.headers.items()
        }
        httpheadersentout = r.request.headers


    # HTTPCore
    elif usehttp == "httpcore" and havehttpcore:
        try:
            import h2
            usehttp2 = True
        except ImportError:
            usehttp2 = False
        with httpcore.ConnectionPool(http1=True, http2=usehttp2) as client:
            timeoutdict = {"connect": float(timeout), "read": float(timeout), "write": float(timeout), "pool": float(timeout)}
            extendargs.update({'url': rebuilt_url, 'method': httpmethod, 'extensions': {"timeout": timeoutdict}})
            if(httpmethod == "POST" or httpmethod == "PUT" or httpmethod == "PATCH" or httpmethod == "DELETE"):
                if(jsonpost and postdata is not None and putfile is None):
                    if('Content-Type' in headers):
                        headers['Content-Type'] = "application/json"
                    else:
                        headers.update({'Content-Type': "application/json"})
                    extendargs.update({'content': json.dumps(postdata).encode('UTF-8')})
                elif(not jsonpost and postdata is not None and putfile is None):
                    if('Content-Type' in headers):
                        headers['Content-Type'] = "application/x-www-form-urlencoded"
                    else:
                        headers.update({'Content-Type': "application/x-www-form-urlencoded"})
                    extendargs.update({'content': urlencode(postdata).encode('UTF-8')})
                elif(putfile is not None):
                    putfile.seek(0, 0)
                    extendargs.update({'content': putfile})
            extendargs.update({'headers': headers})
            try:
                with client.stream(**extendargs, ) as r:
                    for chunk in r.iter_stream():
                        if chunk:
                            httpfile.write(chunk)
            except (socket.timeout, socket.gaierror, httpcore.ConnectError):
                return False
        httpcodeout = r.status
        httpcodereason = http_status_to_reason(r.status)
        httpversionout = r.extensions.get("http_version")
        if isinstance(httpversionout, (bytes, bytearray)):
            httpversionout = httpversionout.decode("ascii", errors="replace")
        httpmethodout = httpmethod
        httpurlout = str(rebuilt_url)
        httpheaderout = decode_headers_any(r.headers)
        httpheadersentout = headers

    # Mechanize
    elif usehttp == "mechanize" and havemechanize:
        br = mechanize.Browser()
        br.set_cookiejar(httpcookie)
        br.set_handle_robots(False)
        if username and password:
            br.add_password(rebuilt_url, username, password)
        if(not jsonpost and postdata is not None and not isinstance(postdata, dict)):
            postdata = urlencode(postdata).encode('UTF-8')
        elif(jsonpost and postdata is not None and not isinstance(postdata, dict)):
            postdata = json.dumps(postdata).encode('UTF-8')
        try:
            if(httpmethod == "GET"):
                if headers:
                    br.addheaders = list(headers.items())
                resp = br.open(rebuilt_url, timeout=timeout)
            elif(httpmethod == "POST"):
                if(jsonpost and postdata is not None):
                    if('Content-Type' in headers):
                        headers['Content-Type'] = "application/json"
                    else:
                        headers.update({'Content-Type': "application/json"})
                if headers:
                    br.addheaders = list(headers.items())
                resp = br.open(rebuilt_url, data=postdata, timeout=float(timeout))
            else:
                if headers:
                    br.addheaders = list(headers.items())
                resp = br.open(rebuilt_url, timeout=timeout)
        except HTTPError as e:
            resp = e
        except (socket.timeout, socket.gaierror, URLError):
            return False
        shutil.copyfileobj(resp, httpfile, length=1024 * 1024)
        httpcodeout = resp.code
        httpcodereason = resp.msg
        vertostr = {
                    10: "HTTP/1.0",
                    11: "HTTP/1.1"
        }
        try:
            httpversionout = vertostr[br.version]
        except AttributeError:
            httpversionout = "HTTP/1.1"
        httpmethodout = httpmethod
        httpurlout = resp.geturl()
        httpheaderout = resp.info()
        reqhead = br.request
        httpheadersentout = reqhead.header_items()

    # URLLib3
    elif usehttp == "urllib3" and haveurllib3:
        http = urllib3.PoolManager(timeout=urllib3.Timeout(total=float(timeout)))
        if username and password:
            auth_headers = urllib3.make_headers(basic_auth="{}:{}".format(username, password))
            headers.update(auth_headers)
        # Request with preload_content=False to get a file-like object
        try:
            extendargs.update({'url': rebuilt_url, 'method': httpmethod, 'headers': headers, 'preload_content': False, 'decode_content': True})
            if(putfile is not None and sendfiles is not None):
                sendfiles = None
            if(httpmethod == "POST"):
                if(putfile is not None and sendfiles is not None):
                    putfile = None
                if(putfile is not None and not isinstance(putfile, dict)):
                    putfile.seek(0, 0)
                    extendargs.update({'body': putfile})
                if(sendfiles is not None and isinstance(sendfiles, dict)):
                    jsonpost = False
                    sendfiles = to_requests_files(sendfiles)
                    if(sendfiles is not None):
                        for _, (_, fobj, *_) in sendfiles:
                            if hasattr(fobj, "seek"):
                                fobj.seek(0)
                    extendargs.update({'fields': sendfiles})
                if(jsonpost and postdata is not None):
                    extendargs.update({'json': postdata})
                elif(not jsonpost and postdata is not None):
                    if('fields' in headers):
                        extendargs['fields'].update({postdata})
                    else:
                        extendargs.update({'fields': postdata})
            elif(httpmethod == "PUT" or httpmethod == "PATCH" or httpmethod == "DELETE"):
                if(putfile is not None and sendfiles is not None):
                    sendfiles = None
                if(putfile is not None and not isinstance(putfile, dict)):
                    putfile.seek(0, 0)
                    extendargs.update({'body': putfile})
                if(sendfiles is not None and isinstance(sendfiles, dict)):
                    jsonpost = False
                    sendfiles = to_requests_files(sendfiles)
                    if(sendfiles is not None):
                        for _, (_, fobj, *_) in sendfiles:
                            if hasattr(fobj, "seek"):
                                fobj.seek(0)
                    extendargs.update({'fields': sendfiles})
                if(jsonpost and postdata is not None):
                    extendargs.update({'json': postdata})
                elif(not jsonpost and postdata is not None):
                    if('fields' in headers):
                        extendargs['fields'].update({postdata})
                    else:
                        extendargs.update({'fields': postdata})
            resp = http.request(**extendargs)
        except (socket.timeout, socket.gaierror, urllib3.exceptions.MaxRetryError):
            return False
        shutil.copyfileobj(resp, httpfile, length=1024 * 1024)
        httpcodeout = resp.status
        httpcodereason = resp.reason
        vertostr = {
                    10: "HTTP/1.0",
                    11: "HTTP/1.1"
        }
        try:
            httpversionout = vertostr[resp.version]
        except AttributeError:
            httpversionout = "HTTP/1.1"
        httpmethodout = httpmethod
        httpurlout = resp.geturl()
        httpheaderout = resp.info()
        httpheadersentout = headers
        resp.release_conn()

    elif(usehttp == "pycurl"):
        retrieved_body = MkTempFile()
        retrieved_headers = MkTempFile()
        sentout_headers = MkTempFile()
        curlreq = pycurl.Curl()
        if(hasattr(pycurl, "CURL_HTTP_VERSION_3_0")):
            usehttpver = pycurl.CURL_HTTP_VERSION_3_0
        elif(hasattr(pycurl, "CURL_HTTP_VERSION_2_0")):
            usehttpver = pycurl.CURL_HTTP_VERSION_2_0
        else:
            usehttpver = pycurl.CURL_HTTP_VERSION_1_1
        curlreq.setopt(pycurl.URL, rebuilt_url)
        curlreq.setopt(pycurl.HTTP_VERSION, usehttpver)
        curlreq.setopt(pycurl.WRITEDATA, retrieved_body)
        curlreq.setopt(pycurl.WRITEHEADER, retrieved_headers)
        curlreq.setopt(pycurl.VERBOSE, 1)
        curlreq.setopt(pycurl.DEBUGFUNCTION, lambda t, m: sentout_headers.write(m))
        curlreq.setopt(pycurl.FOLLOWLOCATION, True)
        curlreq.setopt(pycurl.TIMEOUT, timeout)
        if(httpmethod == "GET"):
            curlreq.setopt(pycurl.HTTPGET, True)
        elif(httpmethod == "POST"):
            if(putfile is not None and sendfiles is not None):
                putfile = None
            curlreq.setopt(pycurl.POST, True)
            if(sendfiles is not None):
                jsonpost = False
                sendfiles = to_pycurl_httpost(sendfiles)
                curlreq.setopt(pycurl.HTTPPOST, sendfiles)
            if(jsonpost and postdata is not None):
                if('Content-Type' in headers):
                    headers['Content-Type'] = "application/json"
                else:
                    headers.update({'Content-Type': "application/json"})
                    curlreq.setopt(pycurl.POSTFIELDS, json.dumps(postdata).encode('UTF-8'))
            elif(not jsonpost and postdata is not None):
                curlreq.setopt(pycurl.POSTFIELDS, urlencode(postdata).encode('UTF-8'))
        elif(httpmethod == "PUT" or httpmethod == "PATCH" or httpmethod == "DELETE"):
            if(putfile is not None and sendfiles is not None):
                sendfiles = None
            curlreq.setopt(pycurl.CUSTOMREQUEST, httpmethod)
            if(putfile is not None):
                curlreq.setopt(pycurl.UPLOAD, True)
                putfile.seek(0, 0)
                curlreq.setopt(pycurl.READDATA, putfile)
            if(sendfiles is not None):
                jsonpost = False
                sendfiles = to_pycurl_httpost(sendfiles)
                curlreq.setopt(pycurl.HTTPPOST, sendfiles)
            if(jsonpost and postdata is not None):
                if('Content-Type' in headers):
                    headers['Content-Type'] = "application/json"
                else:
                    headers.update({'Content-Type': "application/json"})
                    curlreq.setopt(pycurl.POSTFIELDS, json.dumps(postdata).encode('UTF-8'))
            elif(not jsonpost and postdata is not None):
                curlreq.setopt(pycurl.POSTFIELDS, urlencode(postdata).encode('UTF-8'))
        else:
            curlreq.setopt(pycurl.HTTPGET, True)
        headers = make_http_headers_from_dict_to_pycurl(headers)
        curlreq.setopt(pycurl.HTTPHEADER, headers)
        try:
            curlreq.perform()
        except (socket.timeout, socket.gaierror, pycurl.error):
            curlreq.close()
            return False
        retrieved_headers.seek(0, 0)
        sentout_headers.seek(0, 0)
        httpheadersentpre = parse_pycurl_verbose(sentout_headers)
        sentout_headers.close()
        if(sys.version[0] == "2"):
            pycurlhead = retrieved_headers.read()
        if(sys.version[0] >= "3"):
            pycurlhead = retrieved_headers.read().decode('UTF-8')
        pycurlheadersout = make_http_headers_from_pycurl_to_dict(pycurlhead)
        retrieved_body.seek(0, 0)
        httpfile = retrieved_body
        retrieved_headers.close()
        HTTP_VERSION_MAP = {
            pycurl.CURL_HTTP_VERSION_1_0: "HTTP/1.0",
            pycurl.CURL_HTTP_VERSION_1_1: "HTTP/1.1",
        }
        # Optional HTTP/3 (only if compiled in)
        if hasattr(pycurl, "CURL_HTTP_VERSION_2"):
            HTTP_VERSION_MAP[pycurl.CURL_HTTP_VERSION_2] = "HTTP/2.0"
        # Optional HTTP/3 (only if compiled in)
        if hasattr(pycurl, "CURL_HTTP_VERSION_3"):
            HTTP_VERSION_MAP[pycurl.CURL_HTTP_VERSION_3] = "HTTP/3.0"
        ver_enum = curlreq.getinfo(pycurl.INFO_HTTP_VERSION)
        httpcodeout = curlreq.getinfo(pycurl.HTTP_CODE)
        httpcodereason = http_status_to_reason(curlreq.getinfo(pycurl.HTTP_CODE))
        httpversionout = HTTP_VERSION_MAP.get(ver_enum, "HTTP/1.1")
        httpmethodout = httpmethod
        httpurlout = curlreq.getinfo(pycurl.EFFECTIVE_URL)
        curlreq.close()
        httpheaderout = pycurlheadersout
        try:
            httpheadersentout = httpheadersentpre['request']['headers']
        except TypeError:
            httpheadersentout = headers

    # urllib fallback
    else:
        extendargs.update({'url': rebuilt_url})
        if(httpmethod == "GET"):
            extendargs.update({'method': "GET"})
        elif(httpmethod == "POST"):
            extendargs.update({'method': "POST"})
            if(jsonpost and postdata is not None):
                if('Content-Type' in headers):
                    headers['Content-Type'] = "application/json"
                else:
                    headers.update({'Content-Type': "application/json"})
                extendargs.update({'data': json.dumps(postdata).encode('UTF-8')})
            elif(not jsonpost and postdata is not None):
                extendargs.update({'data': urlencode(postdata).encode('UTF-8')})
        else:
            extendargs.update({'method': "GET"})
        extendargs.update({'headers': headers})
        req = Request(**extendargs)
        if username and password:
            mgr = HTTPPasswordMgrWithDefaultRealm()
            mgr.add_password(None, rebuilt_url, username, password)
            opener = build_opener(HTTPBasicAuthHandler(mgr), HTTPCookieProcessor(httpcookie))
        else:
            opener = build_opener()
        try:
            resp = opener.open(req, timeout=timeout)
        except HTTPError as e:
            resp = e;
        except (socket.timeout, socket.gaierror, URLError):
            return False
        resp2 = decoded_stream(resp)
        shutil.copyfileobj(resp2, httpfile, length=1024 * 1024)
        httpcodeout = resp.getcode()
        try:
            httpcodereason = resp.reason
        except AttributeError:
            httpcodereason = http_status_to_reason(geturls_text.getcode())
        vertostr = {
                    10: "HTTP/1.0",
                    11: "HTTP/1.1"
        }
        try:
            httpversionout = vertostr[resp.version]
        except AttributeError:
            httpversionout = "HTTP/1.1"
        try:
            httpmethodout = resp.get_method()
        except AttributeError:
            httpmethodout = resp._method
        httpurlout = resp.geturl()
        httpheaderout = resp.info()
        try:
            httpheadersentout =  req.unredirected_hdrs | req.headers
        except AttributeError:
            httpheadersentout = req.header_items()
    fulldatasize = httpfile.tell()
    try:
        httpfile.seek(0, 0)
    except Exception:
        pass
    end_time = time.time()
    total_time = end_time - start_time
    if(returnstats):
        if(isinstance(httpheaderout, list)):
            httpheaderout = make_http_headers_from_list_to_dict(httpheaderout)
        httpheaderout = fix_header_names(httpheaderout)
        returnval = {'Type': "Buffer", 'Buffer': httpfile, 'ContentSize': fulldatasize, 'ContentsizeAlt': {'IEC': get_readable_size(
            fulldatasize, 2, "IEC"), 'SI': get_readable_size(fulldatasize, 2, "SI")}, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout, 'Reason': httpcodereason, 'HTTPLib': usehttp, 'RequestTime': {'StartTime': start_time, 'EndTime': end_time, 'TotalTime': total_time}}
        return returnval
    else:
        if(httpmethod == "HEAD"):
            return httpheadersentout
        else:
            return httpfile

def download_file_from_http_string(url, headers=None, usehttp=__use_http_lib__, httpuseragent=None, httpreferer=None, httpcookie=geturls_cj, httpmethod="GET", postdata=None, jsonpost=False, sendfiles=None, putfile=None, timeout=60, returnstats=False):
    fp = download_file_from_http_file(url, headers, usehttp, httpuseragent, httpreferer, httpcookie, httpmethod, postdata, jsonpost, sendfiles, putfile, timeout, returnstats)
    return fp.read() if fp else False

def download_file_from_https_string(url, headers=None, usehttp=__use_http_lib__, httpuseragent=None, httpreferer=None, httpcookie=geturls_cj, httpmethod="GET", postdata=None, jsonpost=False, sendfiles=None, putfile=None, timeout=60, returnstats=False):
    return download_file_from_http_file(url, headers, usehttp, httpuseragent, httpreferer, httpcookie, httpmethod, postdata, jsonpost, sendfiles, putfile, timeout, returnstats)

def download_file_from_https_string(url, headers=None, usehttp=__use_http_lib__, httpuseragent=None, httpreferer=None, httpcookie=geturls_cj, httpmethod="GET", postdata=None, jsonpost=False, sendfiles=None, putfile=None, timeout=60, returnstats=False):
    return download_file_from_http_string(url, headers, usehttp, httpuseragent, httpreferer, httpcookie, httpmethod, postdata, jsonpost, sendfiles, putfile, timeout, returnstats)

# --------------------------
# UDP Packet Utilities
# --------------------------

def _u_pack(flags, seq, total, tid):
    return struct.pack(
        _U_HDR,
        _U_MAGIC,
        _U_VER,
        int(flags) & 0xFF,
        int(seq) & 0xFFFFFFFF,
        int(total) & 0xFFFFFFFFFFFFFFFF,
        int(tid) & 0xFFFFFFFFFFFFFFFF,
    )

def _u_unpack(pkt):
    if not pkt or len(pkt) < _U_HDR_LEN:
        return None
    magic, ver, flags, seq, total, tid = struct.unpack(_U_HDR, pkt[:_U_HDR_LEN])
    if magic != _U_MAGIC or ver != _U_VER:
        return None
    return (flags, seq, total, tid, pkt[_U_HDR_LEN:])

# --------------------------
# Network URL Parsing
# --------------------------

def _parse_net_url(url):
    """Parse network URL (TCP/UDP) with all options."""
    p = urlparse(url)
    qs = parse_qs(p.query or "")
    
    # Determine mode
    if p.scheme == "udp":
        mode = _qstr(qs, "mode", "seq").lower()
    else:
        mode = _qstr(qs, "mode", "raw").lower()
    
    # Timeout settings
    has_timeout = "timeout" in qs
    if p.scheme == "tcp" and not has_timeout:
        timeout = None
    else:
        timeout = float(_qnum(qs, "timeout", 
                            1.0 if p.scheme == "udp" else 30.0, cast=float))
    
    # Parse all options
    options = {
        "mode": mode,
        "timeout": timeout,
        "accept_timeout": float(_qnum(qs, "accept_timeout", 
                                    0.0 if p.scheme == "tcp" else (timeout or 0.0), 
                                    cast=float)),
        "total_timeout": float(_qnum(qs, "total_timeout", 0.0, cast=float)),
        "window": int(_qnum(qs, "window", DEFAULT_WINDOW_SIZE, cast=int)),
        "retries": int(_qnum(qs, "retries", DEFAULT_RETRIES, cast=int)),
        "chunk": int(_qnum(qs, "chunk", 
                          DEFAULT_UDP_CHUNK if p.scheme == "udp" else DEFAULT_CHUNK_SIZE, 
                          cast=int)),
        "print_url": _qflag(qs, "print_url", False),
        "wait": _qflag(qs, "wait", p.scheme == "udp" and mode == "raw"),
        "connect_wait": _qflag(qs, "connect_wait", p.scheme == "tcp"),
        "handshake": _qflag(qs, "handshake", p.scheme in ("tcp", "udp")),
        "hello_interval": float(_qnum(qs, "hello_interval", 0.1, cast=float)),
        "wait_timeout": _qnum(qs, "wait_timeout", None, cast=float),
        "wait_forever": _qflag(qs, "wait_forever", False),
        "verbose": _qflag(qs, "verbose", False) or _qflag(qs, "debug", False),
        "bind": _qstr(qs, "bind", None),
        "resume": _qflag(qs, "resume", False),
        "resume_to": _qstr(qs, "resume_to", None),
        "save": _qflag(qs, "save", False),
        "overwrite": _qflag(qs, "overwrite", False),
        "save_dir": _qstr(qs, "save_dir", None),
        "done": _qflag(qs, "done", False),
        "done_token": _qstr(qs, "done_token", None),
        "framing": _qstr(qs, "framing", None),
        "sha256": _qflag(qs, "sha256", False) or _qflag(qs, "sha", False),
        "raw_meta": _qflag(qs, "raw_meta", True),
        "raw_ack": _qflag(qs, "raw_ack", False),
        "raw_ack_timeout": _qnum(qs, "raw_ack_timeout", 0.5, cast=float),
        "raw_ack_retries": int(_qnum(qs, "raw_ack_retries", 40, cast=int)),
        "raw_ack_window": max(1, int(_qnum(qs, "raw_ack_window", 1, cast=int))),
        "raw_sha": _qflag(qs, "raw_sha", False),
        "raw_hash": _qstr(qs, "raw_hash", "sha256"),
        "idle_timeout": _qnum(qs, "idle_timeout", None, cast=float),
        "end_timeout": _qnum(qs, "end_timeout", 0.25, cast=float),
    }
    
    return p, options

# --------------------------
# TCP/UDP Receiver Implementation
# --------------------------

def recv_to_fileobj(fileobj, host, port, proto="tcp", path_text=None, **kwargs):
    """
    Receive bytes into fileobj.
    
    TCP modes:
      - Default: stream until FIN
      - framing=len: read length header then exactly N bytes
      - sha256=1 with framing=len: verify trailing digest
      - resume=1: send OFFSET <n> and sender seeks before streaming
    
    UDP modes:
      - raw: receive until DONE or timeout
      - seq: reliable with ACK/DONE and optional RESUME
    """
    proto = (proto or "tcp").lower()
    port = int(port)
    
    if proto == "tcp":
        return _tcp_recv(fileobj, host, port, path_text, **kwargs)
    else:
        mode = (kwargs.get("mode") or "seq").lower()
        if mode == "raw":
            return _udp_raw_recv(fileobj, host, port, **kwargs)
        elif mode == "quic":
            return _udp_quic_recv(fileobj, host, port, **kwargs)
        else:
            return _udp_seq_recv(fileobj, host, port, **kwargs)

def _tcp_recv(fileobj, host, port, path_text, **kwargs):
    """TCP receiver implementation."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # Set socket options
        try:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception:
            pass
        
        srv.bind((host or "", port))
        srv.listen(1)
        
        chosen_port = srv.getsockname()[1]
        
        # Print listening URLs if requested
        if kwargs.get("print_url"):
            path = path_text or "/"
            bind_host = host or "0.0.0.0"
            for u in _listen_urls("tcp", bind_host, chosen_port, path, ""):
                sys.stdout.write("Listening: %s\n" % u)
            sys.stdout.flush()
        
        # Set accept timeout
        timeout = kwargs.get("timeout")
        accept_timeout = kwargs.get("accept_timeout")
        idle_timeout = kwargs.get("idle_timeout")
        
        if idle_timeout is not None and float(idle_timeout) > 0:
            srv.settimeout(float(idle_timeout))
        elif accept_timeout is not None and float(accept_timeout) > 0:
            srv.settimeout(float(accept_timeout))
        elif timeout is not None and float(timeout) > 0:
            srv.settimeout(float(timeout))
        else:
            srv.settimeout(None)  # Wait forever
        
        # Accept connection
        try:
            conn, addr = srv.accept()
            _net_log(kwargs.get("verbose"), "TCP connection from %s:%d" % addr)
        except socket.timeout:
            _net_log(kwargs.get("verbose"), "TCP accept timeout")
            return False
        except KeyboardInterrupt:
            raise
        except Exception as e:
            _net_log(kwargs.get("verbose"), "TCP accept error: %s" % str(e))
            return False
        
        # Set connection timeout
        if timeout is not None and float(timeout) > 0:
            conn.settimeout(float(timeout))
        
        # Optional handshake
        if kwargs.get("handshake", True):
            _tcp_handshake(conn, kwargs.get("verbose"))
        
        # Consume PATH line if present
        _tcp_consume_path(conn, kwargs.get("verbose"))
        
        # Resume handshake
        if kwargs.get("resume"):
            _tcp_resume_handshake(fileobj, conn, kwargs.get("verbose"))
        
        # Receive data
        framing = (kwargs.get("framing") or "").lower()
        want_sha = bool(kwargs.get("sha256") or kwargs.get("sha"))
        
        if framing == "len":
            success = _tcp_receive_framed(fileobj, conn, want_sha, kwargs.get("verbose"))
        else:
            success = _tcp_receive_stream(fileobj, conn, kwargs, kwargs.get("verbose"))
        
        # Cleanup
        try:
            conn.close()
        except Exception:
            pass
        
        if success:
            try:
                fileobj.seek(0, 0)
            except Exception:
                pass
            return True
        else:
            return False
    
    finally:
        try:
            srv.close()
        except Exception:
            pass

def _tcp_handshake(conn, verbose):
    """Perform TCP handshake (HELLO/READY)."""
    try:
        conn.settimeout(0.25)
        
        # Peek to see if HELLO is present
        try:
            if hasattr(socket, "MSG_PEEK"):
                peekh = conn.recv(6, socket.MSG_PEEK)
            else:
                # No MSG_PEEK, just try to read
                conn.settimeout(0.1)
                peekh = conn.recv(6)
                if peekh == b"HELLO ":
                    # Put it back by sending to ourselves? Can't easily undo.
                    # For simplicity, we'll handle it differently.
                    pass
                else:
                    # Not HELLO, restore timeout and continue
                    return
        except socket.timeout:
            return
        except Exception:
            return
        
        if peekh == b"HELLO ":
            # Read the full HELLO line
            line = b""
            conn.settimeout(0.5)
            while True:
                b = conn.recv(1)
                if not b or b == b"\n" or len(line) > 4096:
                    break
                line += b
            
            # Parse token
            parts = line.strip().split(None, 1)
            token = parts[1] if len(parts) > 1 else b""
            
            # Send READY response
            try:
                conn.sendall(b"READY " + token + b"\n")
            except Exception:
                pass
    
    except Exception:
        pass

def _tcp_consume_path(conn, verbose):
    """Consume PATH line if present."""
    try:
        conn.settimeout(0.25)
        
        # Peek for PATH
        try:
            if hasattr(socket, "MSG_PEEK"):
                peek = conn.recv(5, socket.MSG_PEEK)
            else:
                peek = conn.recv(5)
                if peek != b"PATH ":
                    # Not PATH, put back (can't actually do this easily)
                    return
        except socket.timeout:
            return
        
        if peek == b"PATH ":
            # Read the PATH line
            line = b""
            while True:
                b = conn.recv(1)
                if not b or b == b"\n" or len(line) > 4096:
                    break
                line += b
    
    except Exception:
        pass

def _tcp_resume_handshake(fileobj, conn, verbose):
    """Perform resume handshake."""
    try:
        cur_pos = fileobj.tell()
    except Exception:
        cur_pos = 0
    
    try:
        msg = ("OFFSET %d\n" % cur_pos).encode("utf-8")
        conn.sendall(msg)
        _net_log(verbose, "Sent OFFSET %d" % cur_pos)
    except Exception:
        pass

def _tcp_receive_framed(fileobj, conn, want_sha, verbose):
    """Receive framed data with length header."""
    try:
        # Read header: b"PWG4" + uint64 size + uint32 flags
        header = b""
        while len(header) < TCP_HEADER_LEN:
            chunk = conn.recv(TCP_HEADER_LEN - len(header))
            if not chunk:
                break
            header += _to_bytes(chunk)
        
        if len(header) != TCP_HEADER_LEN or not header.startswith(TCP_MAGIC):
            _net_log(verbose, "Invalid framing header")
            return False
        
        # Parse header
        size = struct.unpack("!Q", header[4:12])[0]
        flags = struct.unpack("!I", header[12:16])[0]
        sha_in_stream = bool(flags & 1)
        remaining = int(size)
        
        # Initialize hash if needed
        h = hashlib.sha256() if (want_sha or sha_in_stream) else None
        
        # Receive payload
        while remaining > 0:
            chunk = conn.recv(min(DEFAULT_CHUNK_SIZE, remaining))
            if not chunk:
                break
            
            fileobj.write(chunk)
            if h is not None:
                h.update(chunk)
            
            remaining -= len(chunk)
        
        if remaining != 0:
            _net_log(verbose, "Incomplete framed transfer")
            return False
        
        # Verify SHA if present in stream
        if sha_in_stream:
            digest = b""
            while len(digest) < 32:
                part = conn.recv(32 - len(digest))
                if not part:
                    break
                digest += _to_bytes(part)
            
            if len(digest) != 32:
                _net_log(verbose, "Missing or incomplete SHA256 digest")
                return False
            
            if h is not None and h.digest() != digest:
                _net_log(verbose, "SHA256 verification failed")
                return False
        
        # If user wanted SHA but sender didn't provide it
        if want_sha and not sha_in_stream:
            _net_log(verbose, "SHA256 requested but not provided by sender")
            return False
        
        return True
    
    except Exception as e:
        _net_log(verbose, "Framed receive error: %s" % str(e))
        return False

def _tcp_receive_stream(fileobj, conn, kwargs, verbose):
    """Receive streaming data (plain or DONE-token mode)."""
    done = bool(kwargs.get("done"))
    tok = kwargs.get("done_token") or "\nDONE\n"
    tokb = _to_bytes(tok)
    tlen = len(tokb)
    tail = b""
    
    h = None
    if kwargs.get("sha256") or kwargs.get("sha"):
        h = hashlib.sha256()
    
    try:
        while True:
            try:
                chunk = conn.recv(DEFAULT_CHUNK_SIZE)
            except socket.timeout:
                continue
            except Exception:
                break
            
            if not chunk:
                break
            
            chunk = _to_bytes(chunk)
            
            if not done:
                fileobj.write(chunk)
                if h is not None:
                    h.update(chunk)
                continue
            
            # DONE token mode
            buf = tail + chunk
            
            if tlen and buf.endswith(tokb):
                # Found DONE token
                if len(buf) > tlen:
                    fileobj.write(buf[:-tlen])
                    if h is not None:
                        h.update(buf[:-tlen])
                tail = b""
                break
            
            if tlen and len(buf) > tlen:
                # Write all but last tlen bytes (could contain partial token)
                fileobj.write(buf[:-tlen])
                if h is not None:
                    h.update(buf[:-tlen])
                tail = buf[-tlen:]
            else:
                tail = buf
        
        # Write any remaining data
        if done and tail:
            fileobj.write(tail)
            if h is not None:
                h.update(tail)
        
        return True
    
    except Exception as e:
        _net_log(verbose, "Stream receive error: %s" % str(e))
        return False

# --------------------------
# UDP Raw Receiver
# --------------------------

def _udp_raw_recv(fileobj, host, port, **kwargs):
    """Raw UDP receiver implementation."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        sock.bind((host or "", int(port)))
        
        # Print listening URL
        if kwargs.get("print_url"):
            sys.stdout.write("Listening: udp://%s:%d/\n" % 
                           (host or "0.0.0.0", sock.getsockname()[1]))
            sys.stdout.flush()
        
        # Configure socket
        timeout = float(kwargs.get("timeout", 1.0))
        end_timeout = float(kwargs.get("end_timeout", 0.25))
        sock.settimeout(timeout)
        
        # Setup for optional features
        want_sha = bool(kwargs.get("raw_sha", False))
        raw_hash = (kwargs.get("raw_hash", "sha256") or "sha256").lower()
        
        hasher = None
        expected_hex = None
        if want_sha:
            if raw_hash == "md5":
                hasher = hashlib.md5()
            else:
                hasher = hashlib.sha256()
        
        want_ack = bool(kwargs.get("raw_ack") or kwargs.get("want_ack"))
        exp_seq = 0
        bytes_written = 0
        
        expected = None
        received = 0
        saw_any = False
        last = time.time()
        
        sender_addr = None
        
        while True:
            try:
                pkt, addr = sock.recvfrom(65536)
                sender_addr = addr  # Remember sender for replies
                saw_any = True
                last = time.time()
                
                # Handshake: HELLO
                if kwargs.get("handshake", True) and pkt.startswith(b"HELLO "):
                    parts = pkt.split(None, 1)
                    token = parts[1].strip() if len(parts) > 1 else b""
                    try:
                        sock.sendto(b"READY " + token + b"\n", addr)
                    except Exception:
                        pass
                    continue
                
                # META packet (length announcement)
                if expected is None and pkt.startswith(b"META "):
                    try:
                        line = pkt.split(b"\n", 1)[0]
                        expected = int(line.split()[1])
                        # Acknowledge META
                        try:
                            sock.sendto(b"READY\n", addr)
                        except Exception:
                            pass
                    except Exception:
                        pass
                    continue
                
                # HASH packet (checksum announcement)
                if pkt.startswith(b"HASH "):
                    try:
                        line = pkt.split(b"\n", 1)[0]
                        parts = line.split()
                        if len(parts) >= 3:
                            algo = parts[1].decode("ascii", "ignore").lower()
                            hx = parts[2].decode("ascii", "ignore")
                            expected_hex = hx
                            if not want_sha:
                                want_sha = True
                            raw_hash = algo or raw_hash
                            if raw_hash == "md5":
                                hasher = hashlib.md5()
                            else:
                                hasher = hashlib.sha256()
                    except Exception:
                        pass
                    continue
                
                # DONE packet
                if pkt == b"DONE":
                    break
                
                # Reliable mode (Go-Back-N)
                if want_ack and pkt.startswith(b"PKT "):
                    try:
                        parts = pkt.split(b" ", 2)
                        seq = int(parts[1])
                        payload = parts[2] if len(parts) > 2 else b""
                    except Exception:
                        seq = -1
                        payload = b""
                    
                    # Accept in-order packets only
                    if seq == exp_seq:
                        fileobj.write(payload)
                        if hasher is not None:
                            hasher.update(payload)
                        bytes_written += len(payload)
                        exp_seq += 1
                    
                    # Send ACK for last in-order packet
                    try:
                        sock.sendto(b"ACK " + str(exp_seq - 1).encode("ascii") + b"\n", addr)
                    except Exception:
                        pass
                    continue
                
                # Normal raw packet processing
                if expected is None:
                    # No expected length, just write everything
                    fileobj.write(pkt)
                    if hasher is not None:
                        hasher.update(pkt)
                else:
                    # Have expected length, write up to that amount
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
                
                # Check if we've received expected amount
                if expected is not None and received >= expected:
                    break
            
            except socket.timeout:
                if expected is not None:
                    continue
                if saw_any and (time.time() - last) >= end_timeout:
                    break
                continue
            
            except KeyboardInterrupt:
                raise
            except Exception as e:
                _net_log(kwargs.get("verbose"), "UDP raw recv error: %s" % str(e))
                break
        
        # Final DONE acknowledgment
        if sender_addr:
            try:
                sock.sendto(b"DONE_ACK\n", sender_addr)
            except Exception:
                pass
        
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        
        # Verify hash if requested
        if want_sha:
            if expected_hex is None or hasher is None:
                return False
            try:
                return (hasher.hexdigest().lower() == expected_hex.strip().lower())
            except Exception:
                return False
        
        return True
    
    finally:
        try:
            sock.close()
        except Exception:
            pass

# --------------------------
# UDP Seq Receiver
# --------------------------

def _udp_seq_recv(fileobj, host, port, **kwargs):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host or "", int(port)))

    if kwargs.get("print_url"):
        sys.stdout.write("Listening: udp://%s:%d/\n" % (host or "0.0.0.0", sock.getsockname()[1]))
        try:
            sys.stdout.flush()
        except Exception:
            pass

    timeout = float(kwargs.get("timeout", 1.0))
    sock.settimeout(timeout)

    chunk = int(kwargs.get("chunk", 1200))
    window = int(kwargs.get("window", 32))
    total_timeout = float(kwargs.get("total_timeout", 0.0))

    framing = (kwargs.get("framing") or "").lower()
    want_sha = bool(kwargs.get("sha256") or kwargs.get("sha") or kwargs.get("want_sha"))
    _h = hashlib.sha256() if want_sha else None

    # CRC option (must match sender)
    use_crc = bool(kwargs.get("crc32", False))

    total_len = None
    bytes_written = 0
    got_digest = None

    resume_off = 0
    try:
        resume_off = int(kwargs.get("resume_offset", 0) or 0)
    except Exception:
        resume_off = 0
    resume_seq = int(max(0, resume_off) // chunk)
    expected = resume_seq

    received = {}   # seq -> payload (data bytes only)
    done = False
    complete = False
    t0 = time.time()

    active_tid = None

    # stats
    crc_bad = 0

    def _ack(addr):
        # Payload: ack_upto(u32) + sack_mask(u64)
        ack_upto = int(expected - 1) & 0xFFFFFFFF
        sack_mask = 0
        base = int(expected)
        for s in received.keys():
            d = int(s) - base
            if 0 <= d < 64:
                sack_mask |= (1 << d)
        payload = struct.pack("!IQ", ack_upto, sack_mask)
        sock.sendto(_u_pack(_UF_ACK, 0, 0, active_tid) + payload, addr)

    def _send_resume(addr):
        sock.sendto(
            _u_pack(_UF_RESUME, 0xFFFFFFFE, 0, active_tid)
            + struct.pack("!I", int(resume_seq) & 0xFFFFFFFF),
            addr,
        )

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
        flags, seq, total, tid, payload = up

        if active_tid is None:
            active_tid = tid
        if tid != active_tid:
            continue

        if total_len is None and total:
            try:
                total_len = int(total)
            except Exception:
                total_len = None

        if flags & _UF_META:
            try:
                _send_resume(addr)
            except Exception:
                pass
            continue

        if flags & _UF_DONE:
            done = True
            if payload.startswith(b"DONE") and len(payload) >= 4 + 32:
                got_digest = payload[4:4 + 32]
            if complete and ((not want_sha) or (got_digest is not None)):
                break
            if not received and not want_sha:
                break
            continue

        if not (flags & _UF_DATA):
            continue

        if complete:
            try:
                _ack(addr)
            except Exception:
                pass
            continue

        # window sanity
        if seq < expected:
            try:
                _ack(addr)
            except Exception:
                pass
            continue
        if seq >= expected + window * 8:
            continue

        # CRC verify if enabled + flagged
        if use_crc and (flags & _UF_CRC):
            if len(payload) < 4:
                crc_bad += 1
                try:
                    _ack(addr)
                except Exception:
                    pass
                continue
            want = struct.unpack("!I", payload[:4])[0]
            data = payload[4:]
            got = zlib.crc32(data) & 0xFFFFFFFF
            if got != want:
                crc_bad += 1
                # drop packet, do not buffer/write; ACK current state
                try:
                    _ack(addr)
                except Exception:
                    pass
                continue
            payload = data  # strip CRC, keep data only

        # store/write in order
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

        try:
            _ack(addr)
        except Exception:
            pass

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

    # (optional) expose receiver CRC stats
    so = kwargs.get("stats_obj")
    if isinstance(so, dict):
        so["crc_bad"] = crc_bad

    return True

# --------------------------
# TCP/UDP Sender Implementation
# --------------------------

def send_from_fileobj(fileobj, host, port, proto="tcp", path_text=None, **kwargs):
    """
    Send bytes from fileobj to a listening receiver.
    
    TCP modes:
      - Default: stream and close (FIN)
      - framing=len: send length header
      - sha256=1: append digest after payload
      - resume=1: wait for OFFSET from receiver
    
    UDP modes:
      - raw: send chunks then DONE
      - seq: reliable with ACK/DONE and optional RESUME
    """
    proto = (proto or "tcp").lower()
    port = int(port)
    
    if proto == "tcp":
        return _tcp_send(fileobj, host, port, path_text, **kwargs)
    else:
        mode = (kwargs.get("mode") or "seq").lower()
        if mode == "raw":
            return _udp_raw_send(fileobj, host, port, **kwargs)
        elif mode == "quic":
            return _udp_quic_send(fileobj, host, port, **kwargs)
        else:
            return _udp_seq_send(fileobj, host, port, **kwargs)

def _tcp_send(fileobj, host, port, path_text, **kwargs):
    """TCP sender implementation."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # Set timeout
        timeout = kwargs.get("timeout")
        if timeout is not None and float(timeout) > 0:
            sock.settimeout(float(timeout))
        
        # Wait for receiver (connect with retries)
        wait = bool(kwargs.get("wait", False) or kwargs.get("connect_wait", True))
        wait_timeout = kwargs.get("wait_timeout", None)
        
        if wait_timeout is not None:
            try:
                wait_timeout = float(wait_timeout)
            except (ValueError, TypeError):
                wait_timeout = None
        
        start_t = time.time()
        connected = False
        
        while not connected:
            try:
                sock.connect((host, port))
                connected = True
                _net_log(kwargs.get("verbose"), "TCP connected to %s:%d" % (host, port))
            except Exception as e:
                if not wait:
                    _net_log(kwargs.get("verbose"), "TCP connect failed: %s" % str(e))
                    return False
                
                if wait_timeout is not None and wait_timeout >= 0:
                    if (time.time() - start_t) >= wait_timeout:
                        _net_log(kwargs.get("verbose"), "TCP connect timeout")
                        return False
                
                _net_log(kwargs.get("verbose"), "TCP waiting for receiver, retrying...")
                time.sleep(0.1)
        
        # Handshake
        if kwargs.get("handshake", True):
            if not _tcp_send_handshake(sock, kwargs):
                return False
        
        # Send PATH
        if path_text:
            try:
                line = ("PATH %s\n" % (path_text or "/")).encode("utf-8")
                sock.sendall(line)
            except Exception:
                pass
        
        # Resume handshake
        if kwargs.get("resume"):
            if not _tcp_send_resume(sock, fileobj, kwargs.get("verbose")):
                return False
        
        # Send data
        framing = (kwargs.get("framing") or "").lower()
        want_sha = bool(kwargs.get("sha256") or kwargs.get("sha") or kwargs.get("want_sha"))
        
        if framing == "len":
            success = _tcp_send_framed(sock, fileobj, want_sha, kwargs.get("verbose"))
        else:
            success = _tcp_send_stream(sock, fileobj, kwargs, kwargs.get("verbose"))
        
        return success
    
    finally:
        try:
            sock.close()
        except Exception:
            pass

def _tcp_send_handshake(sock, kwargs):
    """Perform TCP sender handshake."""
    tok = kwargs.get("token")
    if tok is None:
        tok = _hs_token()
    else:
        tok = _to_bytes(tok)
    
    try:
        sock.sendall(b"HELLO " + tok + b"\n")
    except Exception:
        return False
    
    # Wait for READY response
    wt = kwargs.get("wait_timeout", None)
    try:
        sock.settimeout(float(wt) if wt is not None else None)
    except Exception:
        pass
    
    buf = b""
    try:
        while b"\n" not in buf and len(buf) < 4096:
            b = sock.recv(1024)
            if not b:
                return False
            buf += b
    except Exception:
        return False
    
    line = buf.split(b"\n", 1)[0].strip()
    if not line.startswith(b"READY"):
        return False
    
    if b" " in line:
        rt = line.split(None, 1)[1].strip()
        if rt and rt != tok:
            return False
    
    # Restore timeout
    timeout = kwargs.get("timeout")
    try:
        if timeout is not None and float(timeout) > 0:
            sock.settimeout(float(timeout))
        else:
            sock.settimeout(None)
    except Exception:
        pass
    
    return True

def _tcp_send_resume(sock, fileobj, verbose):
    """Handle resume request from receiver."""
    try:
        buf = b""
        sock.settimeout(1.0)
        
        while not buf.endswith(b"\n") and len(buf) < 128:
            try:
                b = sock.recv(1)
                if not b:
                    break
                buf += b
            except socket.timeout:
                break
        
        if buf.startswith(b"OFFSET "):
            try:
                off = int(buf.split()[1])
                fileobj.seek(off, 0)
                _net_log(verbose, "Resuming from offset %d" % off)
            except Exception:
                pass
    except Exception:
        pass
    
    return True

def _tcp_send_framed(sock, fileobj, want_sha, verbose):
    """Send framed data with length header."""
    try:
        # Determine size
        size = None
        try:
            cur = fileobj.tell()
            fileobj.seek(0, os.SEEK_END)
            end = fileobj.tell()
            fileobj.seek(cur, os.SEEK_SET)
            size = int(end - cur)
        except Exception:
            _net_log(verbose, "Cannot determine file size")
            return False
        
        if size < 0:
            return False
        
        # Prepare header
        flags = 1 if want_sha else 0
        header = TCP_MAGIC + struct.pack("!Q", int(size)) + struct.pack("!I", int(flags))
        
        # Send header
        sock.sendall(header)
        
        # Initialize hash
        h = hashlib.sha256() if want_sha else None
        
        # Send data
        sent = 0
        while sent < size:
            remaining = size - sent
            chunk_size = min(DEFAULT_CHUNK_SIZE, remaining)
            data = fileobj.read(chunk_size)
            if not data:
                break
            
            sock.sendall(data)
            if h is not None:
                h.update(data)
            sent += len(data)
        
        # Send hash if requested
        if want_sha and h is not None:
            sock.sendall(h.digest())
        
        return True
    
    except Exception as e:
        _net_log(verbose, "Framed send error: %s" % str(e))
        return False

def _tcp_send_stream(sock, fileobj, kwargs, verbose):
    """Send streaming data."""
    done = bool(kwargs.get("done"))
    
    try:
        # Send data
        while True:
            data = fileobj.read(DEFAULT_CHUNK_SIZE)
            if not data:
                break
            sock.sendall(data)
        
        # Send DONE token if requested
        if done:
            tok = kwargs.get("done_token") or "\nDONE\n"
            sock.sendall(_to_bytes(tok))
        
        # Graceful shutdown
        try:
            sock.shutdown(socket.SHUT_WR)
        except Exception:
            pass
        
        return True
    
    except Exception as e:
        _net_log(verbose, "Stream send error: %s" % str(e))
        return False

# --------------------------
# UDP Raw Sender
# --------------------------

def _udp_raw_send(fileobj, host, port, **kwargs):
    """UDP raw sender implementation."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = (host, int(port))
    
    try:
        # Configure socket
        timeout = float(kwargs.get("timeout", 1.0))
        sock.settimeout(timeout)
        
        chunk = int(kwargs.get("chunk", DEFAULT_UDP_CHUNK))
        
        # Get file info for META
        total_len = None
        pos = None
        
        raw_meta = kwargs.get("raw_meta", True)
        raw_sha = kwargs.get("raw_sha", False)
        raw_hash = (kwargs.get("raw_hash", "sha256") or "sha256").lower()
        
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
        
        # Send META if available
        if raw_meta and total_len is not None:
            try:
                sock.sendto(b"META " + str(total_len).encode("ascii") + b"\n", addr)
            except Exception:
                pass
        
        # Wait for receiver (handshake)
        wait = bool(kwargs.get("wait", True) or kwargs.get("connect_wait", False))
        if wait:
            if not _udp_raw_wait_for_receiver(sock, addr, total_len, kwargs):
                return False
        
        # Send HASH if requested
        expected_hex = None
        if raw_sha and total_len is not None:
            expected_hex = _udp_raw_compute_hash(fileobj, raw_hash, pos)
            if expected_hex:
                try:
                    sock.sendto(b"HASH " + raw_hash.encode("ascii") + b" " + 
                              expected_hex.encode("ascii") + b"\n", addr)
                except Exception:
                    pass
        
        # Send data (reliable or best-effort)
        if kwargs.get("raw_ack"):
            success = _udp_raw_send_reliable(sock, fileobj, addr, chunk, kwargs)
        else:
            success = _udp_raw_send_best_effort(sock, fileobj, addr, chunk)
        
        # Send DONE
        if success:
            try:
                sock.sendto(b"DONE", addr)
            except Exception:
                pass
        
        return success
    
    finally:
        try:
            sock.close()
        except Exception:
            pass

def _udp_raw_wait_for_receiver(sock, addr, total_len, kwargs):
    """Wait for receiver to be ready."""
    wt = kwargs.get("wait_timeout", None)
    try:
        wt = float(wt) if wt is not None else None
    except (ValueError, TypeError):
        wt = None
    
    hello_iv = float(kwargs.get("hello_interval", 0.1))
    if hello_iv <= 0:
        hello_iv = 0.1
    
    start_t = time.time()
    tok = kwargs.get("token")
    if tok is None:
        tok = _hs_token()
    else:
        tok = _to_bytes(tok)
    
    while True:
        # Check timeout
        if wt is not None and wt >= 0:
            if (time.time() - start_t) >= wt:
                return False
        
        # Send HELLO
        if kwargs.get("handshake", True):
            try:
                sock.sendto(b"HELLO " + tok + b"\n", addr)
            except Exception:
                pass
        
        # Send META periodically for legacy receivers
        if total_len is not None:
            try:
                sock.sendto(b"META " + str(total_len).encode("ascii") + b"\n", addr)
            except Exception:
                pass
        
        # Wait for READY
        try:
            sock.settimeout(hello_iv)
        except Exception:
            pass
        
        try:
            pkt, _ = sock.recvfrom(1024)
            if pkt.startswith(b"READY"):
                _net_log(kwargs.get("verbose"), "UDP raw: received READY from receiver")
                
                # Verify token if present
                if b" " in pkt:
                    rt = pkt.split(None, 1)[1].strip()
                    if rt and rt != tok:
                        continue
                return True
        except socket.timeout:
            pass
        except Exception:
            pass

def _udp_raw_compute_hash(fileobj, algo, start_pos):
    """Compute hash of file data."""
    try:
        if algo == "md5":
            h = hashlib.md5()
        else:
            h = hashlib.sha256()
        
        cur = fileobj.tell()
        if start_pos is not None:
            fileobj.seek(start_pos, os.SEEK_SET)
        
        while True:
            b = fileobj.read(65536)
            if not b:
                break
            h.update(b)
        
        if start_pos is not None:
            fileobj.seek(start_pos, os.SEEK_SET)
        
        return h.hexdigest()
    except Exception:
        return None

def _udp_raw_send_reliable(sock, fileobj, addr, chunk, kwargs):
    """Send data using Go-Back-N reliable protocol."""
    ack_to = float(kwargs.get("raw_ack_timeout", 0.5))
    retries_max = int(kwargs.get("raw_ack_retries", 40))
    win = max(1, int(kwargs.get("raw_ack_window", 1)))
    
    base_seq = 0
    next_seq = 0
    pkts = {}
    eof = False
    timeout_tries = 0
    
    try:
        sock.settimeout(ack_to)
    except Exception:
        pass
    
    def _make_pkt(seq, data):
        return b"PKT " + str(seq).encode("ascii") + b" " + _to_bytes(data)
    
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
        
        # Wait for ACK
        try:
            apkt, _ = sock.recvfrom(1024)
            if apkt.startswith(b"ACK "):
                try:
                    aseq = int(apkt.split()[1])
                except Exception:
                    aseq = -1
                
                new_base = aseq + 1
                if new_base > base_seq:
                    # Remove acknowledged packets
                    for s in list(pkts.keys()):
                        if s < new_base:
                            try:
                                del pkts[s]
                            except Exception:
                                pass
                    base_seq = new_base
                    timeout_tries = 0
        except socket.timeout:
            timeout_tries += 1
            if retries_max >= 0 and timeout_tries >= retries_max:
                return False
            
            # Retransmit all unacknowledged packets in window
            for s in range(base_seq, next_seq):
                pkt = pkts.get(s)
                if pkt is None:
                    continue
                try:
                    sock.sendto(pkt, addr)
                except Exception:
                    pass
        except Exception:
            return False
    
    return True

def _udp_raw_send_best_effort(sock, fileobj, addr, chunk):
    """Send data using best-effort (no ACKs)."""
    try:
        while True:
            data = fileobj.read(chunk)
            if not data:
                break
            sock.sendto(_to_bytes(data), addr)
        return True
    except Exception:
        return False

# --------------------------
# UDP Seq Sender
# --------------------------

def _udp_seq_send(fileobj, host, port, resume=False, path_text=None, **kwargs):
    addr = (host, int(port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # --- RTT-based timeout params ---
    base_timeout = float(kwargs.get("timeout", 1.0))
    min_to = float(kwargs.get("min_timeout", 0.05))
    max_to = float(kwargs.get("max_timeout", 3.0))

    # Start with base timeout; will adapt
    timeout = max(min_to, min(max_to, base_timeout))
    sock.settimeout(timeout)

    chunk = int(kwargs.get("chunk", 1200))
    max_window = int(kwargs.get("window", 32))          # cap
    init_window = int(kwargs.get("init_window", max(1, min(4, max_window))))
    retries = int(kwargs.get("retries", 20))
    total_timeout = float(kwargs.get("total_timeout", 0.0))

    enable_fast_retx = bool(kwargs.get("fast_retx", True))

    # CRC option
    use_crc = bool(kwargs.get("crc32", False))

    want_sha = bool(kwargs.get("sha256") or kwargs.get("sha") or kwargs.get("want_sha"))
    _h = hashlib.sha256() if want_sha else None

    tid = int(kwargs.get("tid", 0) or 0)
    if tid == 0:
        tid = secrets.randbits(64)

    # stats
    stats = {
        "tid": tid,
        "bytes_sent_payload": 0,
        "pkts_sent": 0,
        "pkts_retx": 0,
        "pkts_acked": 0,
        "pkts_sacked": 0,
        "loss_events": 0,
        "duration_s": 0.0,
        "throughput_Bps": 0.0,
        "srtt": None,
        "rttvar": None,
        "timeout": timeout,
        "cwnd_start": init_window,
        "cwnd_end": init_window,
    }

    # discover total length if possible
    total = 0
    try:
        start_pos = fileobj.tell()
        fileobj.seek(0, os.SEEK_END)
        total = int(fileobj.tell())
        fileobj.seek(start_pos, os.SEEK_SET)
    except Exception:
        total = 0

    # Resume handshake
    start_seq = 0
    if resume:
        sock.sendto(_u_pack(_UF_META, 0xFFFFFFFF, total, tid) + b"RESUME", addr)
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
            flags, _seq, _t, r_tid, payload = up
            if r_tid != tid:
                continue
            if (flags & _UF_RESUME) and len(payload) >= 4:
                resume_seq = struct.unpack("!I", payload[:4])[0]
                try:
                    fileobj.seek(int(resume_seq) * chunk, os.SEEK_SET)
                    start_seq = int(resume_seq)
                except Exception:
                    start_seq = 0
                break

    # Congestion window (AIMD)
    cwnd = max(1, min(max_window, init_window))
    cwnd_float = float(cwnd)  # for additive increase smoothing

    next_seq = start_seq
    in_flight = {}  # seq -> (wire_payload, ts_sent, tries, data_len)

    # RTT estimator (EWMA, TCP-like)
    srtt = None
    rttvar = None

    def _update_rtt(sample):
        nonlocal srtt, rttvar, timeout
        if sample <= 0:
            return
        if srtt is None:
            srtt = sample
            rttvar = sample / 2.0
        else:
            # RFC6298-ish
            alpha = 1 / 8
            beta = 1 / 4
            rttvar = (1 - beta) * rttvar + beta * abs(srtt - sample)
            srtt = (1 - alpha) * srtt + alpha * sample
        timeout = srtt + 4.0 * rttvar
        timeout = max(min_to, min(max_to, timeout))
        try:
            sock.settimeout(timeout)
        except Exception:
            pass

    def _loss_event():
        nonlocal cwnd, cwnd_float
        stats["loss_events"] += 1
        cwnd = max(1, cwnd // 2)
        cwnd_float = float(cwnd)

    def _ai_increase(acked_count):
        # additive increase: cwnd += acked/cwnd (smoothed)
        nonlocal cwnd, cwnd_float
        if acked_count <= 0:
            return
        cwnd_float += float(acked_count) / max(1.0, float(cwnd))
        new_cwnd = int(cwnd_float)
        if new_cwnd > cwnd:
            cwnd = min(max_window, new_cwnd)
            cwnd_float = float(cwnd)

    def _send_pkt(seq, wire_payload, flags):
        sock.sendto(_u_pack(flags, seq, total, tid) + wire_payload, addr)
        stats["pkts_sent"] += 1

    t_start = time.time()
    failed = False

    def _read_chunk():
        data = fileobj.read(chunk)
        if not data:
            return None
        data = _to_bytes(data)
        if _h is not None:
            _h.update(data)
        return data

    # Prime window
    eof = False
    while not eof and len(in_flight) < cwnd:
        data = _read_chunk()
        if data is None:
            eof = True
            break
        flags = _UF_DATA | (_UF_CRC if use_crc else 0)
        wire = struct.pack("!I", zlib.crc32(data) & 0xFFFFFFFF) + data if use_crc else data
        _send_pkt(next_seq, wire, flags)
        in_flight[next_seq] = (wire, time.time(), 0, len(data))
        stats["bytes_sent_payload"] += len(data)
        next_seq += 1

    while in_flight or not eof:
        if total_timeout and (time.time() - t_start) > total_timeout:
            failed = True
            break

        # Receive ACKs + SACK
        try:
            pkt, _peer = sock.recvfrom(2048)
            up = _u_unpack(pkt)
            if up:
                flags, _seq, _t, r_tid, payload = up
                if r_tid == tid and (flags & _UF_ACK) and len(payload) >= 4:
                    ack_upto = None
                    sack_mask = 0
                    if len(payload) >= 12:
                        ack_upto, sack_mask = struct.unpack("!IQ", payload[:12])
                    else:
                        (ack_upto,) = struct.unpack("!I", payload[:4])

                    newly_acked = 0
                    now = time.time()

                    # Cumulative ACK: drop all <= ack_upto
                    for s in [s for s in list(in_flight.keys()) if s <= ack_upto]:
                        wire, ts, _tries, _dlen = in_flight[s]
                        # RTT sample from original send timestamp (works best if not retransmitted)
                        sample = now - ts
                        _update_rtt(sample)
                        del in_flight[s]
                        stats["pkts_acked"] += 1
                        newly_acked += 1

                    # SACK: drop indicated packets after base=(ack_upto+1)
                    if sack_mask:
                        base = (ack_upto + 1) & 0xFFFFFFFF
                        for i in range(64):
                            if (sack_mask >> i) & 1:
                                s = (base + i) & 0xFFFFFFFF
                                if s in in_flight:
                                    wire, ts, _tries, _dlen = in_flight[s]
                                    sample = now - ts
                                    _update_rtt(sample)
                                    del in_flight[s]
                                    stats["pkts_sacked"] += 1
                                    newly_acked += 1

                        # Optional fast retransmit: resend base if still outstanding
                        if enable_fast_retx:
                            missing = base
                            if missing in in_flight:
                                wire, _ts, tries, _dlen = in_flight[missing]
                                if tries < retries:
                                    _send_pkt(missing, wire, _UF_DATA | (_UF_CRC if use_crc else 0))
                                    in_flight[missing] = (wire, time.time(), tries + 1, _dlen)
                                    stats["pkts_retx"] += 1
                                    _loss_event()

                    _ai_increase(newly_acked)
        except socket.timeout:
            pass
        except Exception:
            pass

        # Retransmit timed-out packets
        now = time.time()
        for seq in list(in_flight.keys()):
            wire, ts, tries, dlen = in_flight[seq]
            if (now - ts) >= timeout:
                if tries >= retries:
                    failed = True
                    in_flight.clear()
                    break
                _send_pkt(seq, wire, _UF_DATA | (_UF_CRC if use_crc else 0))
                in_flight[seq] = (wire, now, tries + 1, dlen)
                stats["pkts_retx"] += 1
                _loss_event()

        if failed:
            break

        # Fill window based on cwnd
        while not eof and len(in_flight) < cwnd:
            data = _read_chunk()
            if data is None:
                eof = True
                break
            flags = _UF_DATA | (_UF_CRC if use_crc else 0)
            wire = struct.pack("!I", zlib.crc32(data) & 0xFFFFFFFF) + data if use_crc else data
            _send_pkt(next_seq, wire, flags)
            in_flight[next_seq] = (wire, time.time(), 0, len(data))
            stats["bytes_sent_payload"] += len(data)
            next_seq += 1

    # finalize stats
    dur = max(1e-9, time.time() - t_start)
    stats["duration_s"] = dur
    stats["throughput_Bps"] = float(stats["bytes_sent_payload"]) / dur
    stats["timeout"] = timeout
    stats["srtt"] = srtt
    stats["rttvar"] = rttvar
    stats["cwnd_end"] = cwnd

    if failed:
        try:
            sock.close()
        except Exception:
            pass
        if kwargs.get("return_stats"):
            return (False, stats)
        so = kwargs.get("stats_obj")
        if isinstance(so, dict):
            so.update(stats)
        return False

    # DONE marker
    payload = b"DONE"
    if _h is not None:
        payload += _h.digest()

    for _i in range(3):
        sock.sendto(_u_pack(_UF_DONE, 0xFFFFFFFE, total, tid) + payload, addr)
        time.sleep(0.02)

    try:
        sock.close()
    except Exception:
        pass

    so = kwargs.get("stats_obj")
    if isinstance(so, dict):
        so.update(stats)

    if kwargs.get("return_stats"):
        return (True, stats)
    return True

def _make_tag(psk, header_and_body):
    mac = hmac.new(_to_bytes(psk), header_and_body, hashlib.sha256).digest()
    return mac[:_TAG_SZ]

def _pack_pkt(pt, cid, pn, body, psk=None, flags=0):
    body = _to_bytes(body)
    if len(body) > 65535:
        body = body[:65535]
    hdr = struct.pack(_HDR_FMT, _MAGIC, int(pt) & 0xFF, int(flags) & 0xFF,
                      int(cid) & 0xFFFFFFFFFFFFFFFF, int(pn) & 0xFFFFFFFF, len(body))
    wire = hdr + body
    if psk:
        wire += _make_tag(psk, wire)
    return wire

def _unpack_pkt(wire, psk=None):
    wire = _to_bytes(wire)
    if len(wire) < _HDR_SZ:
        return None
    magic, pt, flags, cid, pn, blen = struct.unpack(_HDR_FMT, wire[:_HDR_SZ])
    if magic != _MAGIC:
        return None
    need = _HDR_SZ + int(blen)
    if len(wire) < need:
        return None
    body = wire[_HDR_SZ:need]
    if psk:
        if len(wire) < need + _TAG_SZ:
            return None
        tag = wire[need:need + _TAG_SZ]
        calc = _make_tag(psk, wire[:need])
        if tag != calc:
            return None
    return (pt, flags, cid, pn, body)

def _pack_frame(ft, payload):
    payload = _to_bytes(payload)
    if len(payload) > 65535:
        payload = payload[:65535]
    return struct.pack("!BH", int(ft) & 0xFF, len(payload)) + payload

def _iter_frames(body):
    body = _to_bytes(body)
    i = 0
    n = len(body)
    while i + 3 <= n:
        ft, flen = struct.unpack("!BH", body[i:i+3])
        i += 3
        if i + flen > n:
            return
        yield (ft, body[i:i+flen])
        i += flen

# ---- Stateless retry cookie ----
def _retry_token(retry_secret, addr, cid):
    # HMAC(secret, "ip:port" + cid) trunc16
    # NOTE: This is *authentication* of client address only; not encryption.
    secret = _to_bytes(retry_secret)
    ip = addr[0]
    port = int(addr[1])
    msg = _to_bytes("%s:%d|" % (ip, port)) + struct.pack("!Q", int(cid) & 0xFFFFFFFFFFFFFFFF)
    mac = hmac.new(secret, msg, hashlib.sha256).digest()
    return mac[:16]

def _token_valid(retry_secret, addr, cid, token):
    if not retry_secret:
        return True
    token = _to_bytes(token)
    return token == _retry_token(retry_secret, addr, cid)

# ---- Congestion control helpers (sender-side) ----
def _cc_init(cc, init_cwnd, max_cwnd):
    cc = (cc or "reno").lower()
    if cc == "fixed":
        cwnd = max_cwnd
        cwnd_f = float(cwnd)
    else:
        cwnd = max(1, min(max_cwnd, int(init_cwnd)))
        cwnd_f = float(cwnd)
    return cc, cwnd, cwnd_f

def _cc_on_ack(cc, cwnd, cwnd_f, acked, max_cwnd):
    if acked <= 0:
        return cwnd, cwnd_f
    if cc == "fixed":
        return max_cwnd, float(max_cwnd)
    if cc == "cubic":
        # Not real CUBIC; just a more aggressive growth curve.
        # Grow by ~acked * 0.4 + (acked/cwnd) to keep it bounded.
        cwnd_f += 0.4 * float(acked) + (float(acked) / max(1.0, float(cwnd)))
        new_cwnd = int(cwnd_f)
        if new_cwnd > cwnd:
            cwnd = min(max_cwnd, new_cwnd)
            cwnd_f = float(cwnd)
        return cwnd, cwnd_f

    # reno-ish additive increase: cwnd += acked/cwnd
    cwnd_f += float(acked) / max(1.0, float(cwnd))
    new_cwnd = int(cwnd_f)
    if new_cwnd > cwnd:
        cwnd = min(max_cwnd, new_cwnd)
        cwnd_f = float(cwnd)
    return cwnd, cwnd_f

def _cc_on_loss(cc, cwnd, cwnd_f, max_cwnd):
    if cc == "fixed":
        return max_cwnd, float(max_cwnd)
    if cc == "cubic":
        # more gentle reduction than reno
        cwnd = max(1, int(float(cwnd) * 0.7))
        return cwnd, float(cwnd)
    # reno
    cwnd = max(1, cwnd // 2)
    return cwnd, float(cwnd)

# =============================================================================
# Sender
# =============================================================================

def _udp_quic_send(fileobj, host, port, resume=False, path_text=None, **kwargs):
    addr = (host, int(port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    base_timeout = float(kwargs.get("timeout", 1.0))
    min_to = float(kwargs.get("min_timeout", 0.05))
    max_to = float(kwargs.get("max_timeout", 3.0))
    timeout = max(min_to, min(max_to, base_timeout))
    try:
        sock.settimeout(timeout)
    except Exception:
        pass

    chunk = int(kwargs.get("chunk", 1200))
    max_window = int(kwargs.get("window", 32))
    init_window = int(kwargs.get("init_window", max(1, min(4, max_window))))
    retries = int(kwargs.get("retries", 20))
    total_timeout = float(kwargs.get("total_timeout", 0.0))
    fast_retx = bool(kwargs.get("fast_retx", True))

    cc = kwargs.get("cc", "reno")

    want_sha = bool(kwargs.get("sha256") or kwargs.get("sha") or kwargs.get("want_sha"))
    _h = hashlib.sha256() if want_sha else None

    psk = kwargs.get("psk", None)
    if psk:
        psk = _to_bytes(psk)

    cid = int(kwargs.get("cid", 0) or 0)
    if cid == 0:
        cid = _rand_u64()

    stream_id = int(kwargs.get("stream_id", 0) or 0) & 0xFFFF

    enable_0rtt = bool(kwargs.get("enable_0rtt", True))
    token = kwargs.get("token", None)
    if token is not None:
        token = _to_bytes(token)

    # stats
    stats = {
        "cid": cid,
        "bytes_sent_payload": 0,
        "pkts_sent": 0,
        "pkts_retx": 0,
        "pkts_acked": 0,
        "pkts_sacked": 0,
        "loss_events": 0,
        "duration_s": 0.0,
        "throughput_Bps": 0.0,
        "srtt": None,
        "rttvar": None,
        "timeout": timeout,
        "cwnd_start": init_window,
        "cwnd_end": init_window,
        "cc": cc,
        "retry_used": False,
        "server_token": None,
        "start_offset": 0,
    }

    # total length if possible
    total_len = 0
    try:
        cur = fileobj.tell()
        fileobj.seek(0, os.SEEK_END)
        total_len = int(fileobj.tell())
        fileobj.seek(cur, os.SEEK_SET)
    except Exception:
        total_len = 0

    # RTT estimator
    rtt = {"srtt": None, "rttvar": None, "timeout": timeout}
    def _update_rtt(sample):
        if sample <= 0:
            return
        if rtt["srtt"] is None:
            rtt["srtt"] = sample
            rtt["rttvar"] = sample / 2.0
        else:
            alpha = 1.0 / 8.0
            beta = 1.0 / 4.0
            rtt["rttvar"] = (1 - beta) * rtt["rttvar"] + beta * abs(rtt["srtt"] - sample)
            rtt["srtt"] = (1 - alpha) * rtt["srtt"] + alpha * sample
        to = rtt["srtt"] + 4.0 * rtt["rttvar"]
        to = max(min_to, min(max_to, to))
        rtt["timeout"] = to
        try:
            sock.settimeout(to)
        except Exception:
            pass

    # congestion control init
    cc, cwnd, cwnd_f = _cc_init(cc, init_window, max_window)

    # pn space
    pn = 1

    # ---- Handshake (with retry support) ----
    start_offset = 0
    meta_flags = 0
    if resume:
        meta_flags |= _MF_RESUME_REQ
    if token is not None:
        meta_flags |= _MF_HAS_TOKEN

    meta_payload = struct.pack("!QB", int(total_len) & 0xFFFFFFFFFFFFFFFF, int(meta_flags) & 0xFF)
    if path_text:
        meta_payload += _to_bytes(path_text)[:512]
    if token is not None:
        # append token_len + token
        meta_payload += struct.pack("!H", len(token) & 0xFFFF) + token

    body = _pack_frame(_FT_META, meta_payload)
    sock.sendto(_pack_pkt(_PT_INITIAL, cid, pn, body, psk=psk), addr)
    stats["pkts_sent"] += 1
    pn = (pn + 1) & 0xFFFFFFFF

    # helper to send STREAM
    def _send_stream(pkt_pn, off, data, pt=_PT_1RTT):
        off32 = int(off) & 0xFFFFFFFF
        if len(data) > 65535:
            data = data[:65535]
        fp = struct.pack("!HIH", int(stream_id) & 0xFFFF, off32, len(data)) + data
        b = _pack_frame(_FT_STREAM, fp)
        sock.sendto(_pack_pkt(pt, cid, pkt_pn, b, psk=psk), addr)
        stats["pkts_sent"] += 1

    # If doing 0-RTT resume, we may start sending _PT_0RTT immediately,
    # but server can ignore until token validated.
    # We'll still listen for RETRY/RESUME and adapt.
    t_hand = time.time()
    server_allows_0rtt = bool(resume and enable_0rtt)
    pending_retry = False

    # Wait for RETRY/RESUME briefly (but don't block forever)
    # If RETRY arrives, resend INITIAL with token.
    while True:
        if total_timeout and (time.time() - t_hand) > total_timeout:
            break
        try:
            pkt, _ = sock.recvfrom(4096)
        except socket.timeout:
            break
        except Exception:
            break
        up = _unpack_pkt(pkt, psk=psk)
        if not up:
            continue
        rpt, _fl, rcid, _rpn, rbody = up
        if rcid != cid:
            continue

        if rpt == _PT_RETRY:
            # parse token
            for ft, fp in _iter_frames(rbody):
                if ft == _FT_RETRY and len(fp) >= 2:
                    (tlen,) = struct.unpack("!H", fp[:2])
                    tok = fp[2:2 + int(tlen)]
                    if tok:
                        stats["retry_used"] = True
                        stats["server_token"] = tok
                        token = tok
                        pending_retry = True
            break

        # RESUME is delivered in HANDSHAKE/1RTT; accept it anywhere
        for ft, fp in _iter_frames(rbody):
            if ft == _FT_RESUME and len(fp) >= 8:
                (start_offset,) = struct.unpack("!Q", fp[:8])
                try:
                    fileobj.seek(int(start_offset), os.SEEK_SET)
                except Exception:
                    start_offset = 0
                break
        if start_offset:
            break

    # If server requested RETRY, resend INITIAL with token and wait for RESUME again.
    if pending_retry and token is not None:
        pn_retry = pn
        pn = (pn + 1) & 0xFFFFFFFF

        meta_flags = 0
        if resume:
            meta_flags |= _MF_RESUME_REQ
        meta_flags |= _MF_HAS_TOKEN
        meta_payload = struct.pack("!QB", int(total_len) & 0xFFFFFFFFFFFFFFFF, int(meta_flags) & 0xFF)
        if path_text:
            meta_payload += _to_bytes(path_text)[:512]
        meta_payload += struct.pack("!H", len(token) & 0xFFFF) + token

        body = _pack_frame(_FT_META, meta_payload)
        sock.sendto(_pack_pkt(_PT_INITIAL, cid, pn_retry, body, psk=psk), addr)
        stats["pkts_sent"] += 1

        # wait a bit for RESUME (optional)
        t2 = time.time()
        while True:
            if total_timeout and (time.time() - t2) > total_timeout:
                break
            try:
                pkt, _ = sock.recvfrom(4096)
            except socket.timeout:
                break
            except Exception:
                break
            up = _unpack_pkt(pkt, psk=psk)
            if not up:
                continue
            _pt, _fl, rcid, _rpn, rbody = up
            if rcid != cid:
                continue
            for ft, fp in _iter_frames(rbody):
                if ft == _FT_RESUME and len(fp) >= 8:
                    (start_offset,) = struct.unpack("!Q", fp[:8])
                    try:
                        fileobj.seek(int(start_offset), os.SEEK_SET)
                    except Exception:
                        start_offset = 0
                    break
            if start_offset:
                break

    stats["start_offset"] = int(start_offset)

    # ---- Sender loop (offset-based) ----
    in_flight = {}  # pn -> (sent_ts, tries, offset, data, pt_used)

    next_off = int(start_offset)
    eof = False
    failed = False
    t_start = time.time()

    def _read_chunk():
        data = fileobj.read(chunk)
        if not data:
            return None
        data = _to_bytes(data)
        if _h is not None:
            _h.update(data)
        return data

    # ACK state
    # receiver sends: largest pn observed, ack_upto cumulative, sack_mask for next 64
    largest_acked = 0

    # prime window
    while not eof and len(in_flight) < cwnd:
        data = _read_chunk()
        if data is None:
            eof = True
            break
        pt_use = _PT_0RTT if server_allows_0rtt else _PT_1RTT
        _send_stream(pn, next_off, data, pt=pt_use)
        in_flight[pn] = (time.time(), 0, next_off, data, pt_use)
        stats["bytes_sent_payload"] += len(data)
        next_off += len(data)
        pn = (pn + 1) & 0xFFFFFFFF

    while in_flight or not eof:
        if total_timeout and (time.time() - t_start) > total_timeout:
            failed = True
            break

        # receive ACKs / possible late RETRY (rare but handle)
        try:
            pkt, _ = sock.recvfrom(4096)
            up = _unpack_pkt(pkt, psk=psk)
            if up:
                rpt, _fl, rcid, _rpn, rbody = up
                if rcid == cid:
                    if rpt == _PT_RETRY:
                        # server rejected token / address validation; stop 0-RTT and wait
                        server_allows_0rtt = False

                    for ft, fp in _iter_frames(rbody):
                        if ft != _FT_ACK:
                            continue
                        if len(fp) < 16:
                            continue
                        largest, ack_upto, sack_mask = struct.unpack("!IIQ", fp[:16])
                        largest_acked = max(largest_acked, int(largest))
                        now = time.time()
                        newly_acked = 0

                        # cumulative ack
                        for p in [p for p in list(in_flight.keys()) if p <= int(ack_upto)]:
                            ts, _tries, _off, _data, _pt_use = in_flight.pop(p)
                            _update_rtt(now - ts)
                            stats["pkts_acked"] += 1
                            newly_acked += 1

                        # sack beyond ack_upto
                        base = (int(ack_upto) + 1) & 0xFFFFFFFF
                        if sack_mask:
                            for i in range(64):
                                if (sack_mask >> i) & 1:
                                    p = (base + i) & 0xFFFFFFFF
                                    if p in in_flight:
                                        ts, _tries, _off, _data, _pt_use = in_flight.pop(p)
                                        _update_rtt(now - ts)
                                        stats["pkts_sacked"] += 1
                                        newly_acked += 1

                            # fast retransmit of base (if still outstanding)
                            if fast_retx and (base in in_flight):
                                ts, tries, off, data, pt_use = in_flight[base]
                                if tries < retries:
                                    _send_stream(base, off, data, pt=pt_use if pt_use != _PT_0RTT else _PT_1RTT)
                                    in_flight[base] = (time.time(), tries + 1, off, data, _PT_1RTT)
                                    stats["pkts_retx"] += 1
                                    stats["loss_events"] += 1
                                    cwnd, cwnd_f = _cc_on_loss(cc, cwnd, cwnd_f, max_window)

                        cwnd, cwnd_f = _cc_on_ack(cc, cwnd, cwnd_f, newly_acked, max_window)

        except socket.timeout:
            pass
        except Exception:
            pass

        # RTO retransmit
        now = time.time()
        to = float(rtt["timeout"]) if rtt["timeout"] else timeout
        for p in list(in_flight.keys()):
            ts, tries, off, data, pt_use = in_flight[p]
            if (now - ts) >= to:
                if tries >= retries:
                    failed = True
                    in_flight.clear()
                    break
                # retransmit as 1-RTT (safer)
                _send_stream(p, off, data, pt=_PT_1RTT)
                in_flight[p] = (now, tries + 1, off, data, _PT_1RTT)
                stats["pkts_retx"] += 1
                stats["loss_events"] += 1
                cwnd, cwnd_f = _cc_on_loss(cc, cwnd, cwnd_f, max_window)

        if failed:
            break

        # fill window
        while not eof and len(in_flight) < cwnd:
            data = _read_chunk()
            if data is None:
                eof = True
                break
            pt_use = _PT_0RTT if server_allows_0rtt else _PT_1RTT
            _send_stream(pn, next_off, data, pt=pt_use)
            in_flight[pn] = (time.time(), 0, next_off, data, pt_use)
            stats["bytes_sent_payload"] += len(data)
            next_off += len(data)
            pn = (pn + 1) & 0xFFFFFFFF

    dur = max(1e-9, time.time() - t_start)
    stats["duration_s"] = dur
    stats["throughput_Bps"] = float(stats["bytes_sent_payload"]) / dur
    stats["srtt"] = rtt["srtt"]
    stats["rttvar"] = rtt["rttvar"]
    stats["timeout"] = rtt["timeout"]
    stats["cwnd_end"] = cwnd

    if failed:
        try:
            sock.close()
        except Exception:
            pass
        so = kwargs.get("stats_obj")
        if isinstance(so, dict):
            so.update(stats)
        if kwargs.get("return_stats"):
            return (False, stats)
        return False

    # DONE
    done_payload = b"DONE"
    if _h is not None:
        done_payload += _h.digest()
    body = _pack_frame(_FT_DONE, done_payload)
    for _i in range(3):
        try:
            sock.sendto(_pack_pkt(_PT_1RTT, cid, pn, body, psk=psk), addr)
            stats["pkts_sent"] += 1
        except Exception:
            pass
        time.sleep(0.02)

    try:
        sock.close()
    except Exception:
        pass

    so = kwargs.get("stats_obj")
    if isinstance(so, dict):
        so.update(stats)
    if kwargs.get("return_stats"):
        return (True, stats)
    return True

# =============================================================================
# Receiver
# =============================================================================

def _udp_quic_recv(fileobj, host, port, **kwargs):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host or "", int(port)))

    if kwargs.get("print_url"):
        sys.stdout.write("Listening: udp://%s:%d/\n" % (host or "0.0.0.0", sock.getsockname()[1]))
        try:
            sys.stdout.flush()
        except Exception:
            pass

    timeout = float(kwargs.get("timeout", 1.0))
    try:
        sock.settimeout(timeout)
    except Exception:
        pass

    chunk = int(kwargs.get("chunk", 1200))
    window = int(kwargs.get("window", 32))
    total_timeout = float(kwargs.get("total_timeout", 0.0))

    framing = (kwargs.get("framing") or "").lower()
    want_sha = bool(kwargs.get("sha256") or kwargs.get("sha") or kwargs.get("want_sha"))
    _h = hashlib.sha256() if want_sha else None

    psk = kwargs.get("psk", None)
    if psk:
        psk = _to_bytes(psk)

    # multi-stream outputs
    stream_map = kwargs.get("stream_map", None)  # {stream_id:int -> fileobj}
    # default stream 0 -> provided fileobj
    if not isinstance(stream_map, dict):
        stream_map = {}
    if 0 not in stream_map:
        stream_map[0] = fileobj

    # retry
    stateless_retry = bool(kwargs.get("stateless_retry", False))
    retry_secret = kwargs.get("retry_secret", None)
    if retry_secret is not None:
        retry_secret = _to_bytes(retry_secret)

    total_len = None
    bytes_written = {}  # per stream_id -> bytes
    got_digest = None

    resume_off = 0
    try:
        resume_off = int(kwargs.get("resume_offset", 0) or 0)
    except Exception:
        resume_off = 0

    active_cid = None

    # per-stream reorder buffers: stream_id -> {offset->data}
    received = {}
    expected_off = {}  # stream_id -> expected offset
    # initialize stream 0 expected offset with resume_offset
    expected_off[0] = int(max(0, resume_off))

    # pn ACK state (much cleaner than v1):
    # ack_upto is the largest contiguous pn we've seen starting from 0.
    ack_upto = 0
    seen_pn = set([0])  # treat pn=0 as already "seen" to allow ack_upto to advance from 0
    largest_pn = 0

    done = False
    complete = False
    t0 = time.time()

    # whether 0-RTT is allowed for this connection (validated token or retry disabled)
    allow_0rtt = not stateless_retry  # if no retry, allow

    def _send_ack(addr, cid):
        # Build sack mask for pn in (ack_upto+1 .. ack_upto+64)
        base = (int(ack_upto) + 1) & 0xFFFFFFFF
        mask = 0
        for p in seen_pn:
            d = int(p) - int(base)
            if 0 <= d < 64:
                mask |= (1 << d)
        payload = struct.pack("!IIQ",
                              int(largest_pn) & 0xFFFFFFFF,
                              int(ack_upto) & 0xFFFFFFFF,
                              int(mask) & 0xFFFFFFFFFFFFFFFF)
        body = _pack_frame(_FT_ACK, payload)
        try:
            sock.sendto(_pack_pkt(_PT_1RTT, cid, 0, body, psk=psk), addr)
        except Exception:
            pass

    def _send_retry(addr, cid, token):
        token = _to_bytes(token)
        fp = struct.pack("!H", len(token) & 0xFFFF) + token
        body = _pack_frame(_FT_RETRY, fp)
        try:
            sock.sendto(_pack_pkt(_PT_RETRY, cid, 1, body, psk=psk), addr)
        except Exception:
            pass

    def _send_resume(addr, cid, stream_id, off):
        body = _pack_frame(_FT_RESUME, struct.pack("!Q", int(off) & 0xFFFFFFFFFFFFFFFF))
        try:
            sock.sendto(_pack_pkt(_PT_HANDSHAKE, cid, 2, body, psk=psk), addr)
        except Exception:
            pass

    while True:
        if total_timeout and (time.time() - t0) > total_timeout:
            break
        try:
            pkt, addr = sock.recvfrom(65536)
        except socket.timeout:
            # if receiver thinks complete, keep waiting for DONE/digest briefly
            if complete and want_sha:
                continue
            if done:
                break
            continue
        except Exception:
            break

        up = _unpack_pkt(pkt, psk=psk)
        if not up:
            continue
        pt, _flags, cid, pn, body = up

        if active_cid is None:
            active_cid = cid
        if cid != active_cid:
            continue

        # pn tracking
        pn_i = int(pn) & 0xFFFFFFFF
        largest_pn = max(largest_pn, pn_i)
        seen_pn.add(pn_i)
        # advance cumulative ack_upto
        while ((ack_upto + 1) & 0xFFFFFFFF) in seen_pn:
            ack_upto = (ack_upto + 1) & 0xFFFFFFFF

        # INITIAL handling (META + retry token + resume)
        if pt == _PT_INITIAL:
            for ft, fp in _iter_frames(body):
                if ft != _FT_META or len(fp) < 9:
                    continue
                (tlen, mflags) = struct.unpack("!QB", fp[:9])
                if tlen:
                    try:
                        total_len = int(tlen)
                    except Exception:
                        total_len = None

                # parse optional token
                token = None
                if int(mflags) & _MF_HAS_TOKEN:
                    # token_len + token, after optional text; we can't perfectly split text,
                    # so we search from the end: last 2 bytes before token could be len.
                    # BUT we encoded as: [text<=512][u16 len][token]. We'll decode that:
                    if len(fp) >= 9 + 2:
                        # token_len is at the end minus token bytes; so read len from (end - token_len - 2)
                        # can't know token_len; easiest: read u16 at last 2+N? not possible.
                        # So we adopt a simple rule: token_len is stored in the last 2 bytes BEFORE token,
                        # and token is at the end. We'll interpret the final u16 as token_len if plausible.
                        # Format we wrote: ... + u16 + token. So u16 is at position - (2+token_len).
                        # We guess token_len by reading last 2 bytes as len if token_len==0, else fail.
                        # To avoid ambiguity, we also accept "len then token at end" by scanning.
                        # We'll scan for a plausible token_len in the last 64 bytes.
                        buf = fp[9:]
                        found = None
                        scan_max = min(len(buf), 64)
                        # Try each possible split where u16 sits at i and token at i+2 to end.
                        for i in range(max(0, len(buf) - scan_max), len(buf) - 1):
                            if i + 2 > len(buf):
                                continue
                            (tl,) = struct.unpack("!H", buf[i:i+2])
                            if tl == (len(buf) - (i + 2)) and tl > 0:
                                found = buf[i+2:]
                                break
                        if found is not None:
                            token = found

                # stateless retry decision
                if stateless_retry and retry_secret:
                    if (token is None) or (not _token_valid(retry_secret, addr, cid, token)):
                        # send retry token and do not allow 0-RTT until valid token arrives
                        tok = _retry_token(retry_secret, addr, cid)
                        allow_0rtt = False
                        _send_retry(addr, cid, tok)
                        # still ACK so sender sees liveness
                        _send_ack(addr, cid)
                        continue
                    else:
                        allow_0rtt = True

                # resume response (stream 0 only for now)
                if int(mflags) & _MF_RESUME_REQ:
                    # tell client where to resume for stream 0
                    off0 = int(expected_off.get(0, 0))
                    _send_resume(addr, cid, 0, off0)

            _send_ack(addr, cid)
            continue

        # If 0-RTT not allowed, ignore 0-RTT packets (but ACK pns so sender can progress)
        if pt == _PT_0RTT and not allow_0rtt:
            _send_ack(addr, cid)
            continue

        # process frames
        for ft, fp in _iter_frames(body):
            if ft == _FT_DONE:
                done = True
                if fp.startswith(b"DONE") and len(fp) >= 4 + 32:
                    got_digest = fp[4:4+32]
                continue

            if ft != _FT_STREAM:
                continue
            if len(fp) < 2 + 4 + 2:
                continue

            sid, off32, dlen = struct.unpack("!HIH", fp[:8])
            sid = int(sid) & 0xFFFF
            data = fp[8:8+int(dlen)]

            # only write streams we have an output for
            out = stream_map.get(sid, None)
            if out is None:
                continue

            if sid not in received:
                received[sid] = {}
            if sid not in expected_off:
                expected_off[sid] = 0
            if sid not in bytes_written:
                bytes_written[sid] = 0

            # offset u32 is ambiguous for >4GiB; we accept within a "near window" of expected.
            exp = int(expected_off[sid])
            off = int(off32)
            if off + len(data) < exp:
                continue
            if off > exp + window * chunk * 8:
                continue

            if off == exp:
                out.write(data)
                bytes_written[sid] += len(data)
                if _h is not None and sid == 0:
                    # digest applies to stream 0 (common case); customize if you want per-stream digests
                    _h.update(_to_bytes(data))
                expected_off[sid] = exp + len(data)

                # flush contiguous buffered
                while int(expected_off[sid]) in received[sid]:
                    buf = received[sid].pop(int(expected_off[sid]))
                    out.write(buf)
                    bytes_written[sid] += len(buf)
                    if _h is not None and sid == 0:
                        _h.update(_to_bytes(buf))
                    expected_off[sid] = int(expected_off[sid]) + len(buf)
            else:
                if off not in received[sid]:
                    received[sid][off] = data

        _send_ack(addr, cid)

        # completion checks (stream 0 framing)
        bw0 = int(bytes_written.get(0, 0))
        if (framing == "len") and (total_len is not None) and (bw0 >= int(total_len)):
            complete = True
            if not want_sha:
                break
            if got_digest is not None:
                break

        if done:
            # if done and stream0 has no gaps, end (or wait for digest)
            if want_sha and got_digest is None:
                continue
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

    # rewind stream 0 output
    try:
        stream_map.get(0, fileobj).seek(0, 0)
    except Exception:
        pass

    return True

# --------------------------
# HTTP Server Implementation (for uploads)
# --------------------------

def _serve_file_over_http(fileobj, url):
    """Serve file via HTTP server."""
    p = urlparse(url)
    qs = parse_qs(p.query or "")
    
    # Parse options
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
    
    # TLS not implemented in original, setting to False
    tls_on = False
    
    # Check if we can reopen the file
    file_path = getattr(fileobj, "name", None)
    can_reopen = False
    if file_path and isinstance(file_path, (str, bytes)):
        try:
            can_reopen = os.path.isfile(file_path)
        except Exception:
            can_reopen = False
    
    # Determine if we need to buffer in memory
    use_direct = (not can_reopen) and (max_clients == 1)
    data_bytes = None
    
    if (not can_reopen) and (not use_direct):
        # Buffer data in memory for multiple clients
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
    
    # Determine filename for Content-Disposition
    default_name = os.path.basename(path.strip("/")) or "download.bin"
    if download and download not in ("1", "true", "yes"):
        disp_name = download
    else:
        disp_name = default_name
    
    # Determine Content-Type
    if not content_type:
        try:
            content_type = mimetypes.guess_type(default_name)[0] or "application/octet-stream"
        except Exception:
            content_type = "application/octet-stream"
    
    # Parse auth
    auth_user = auth_pass = None
    if auth:
        if ":" in auth:
            auth_user, auth_pass = auth.split(":", 1)
        else:
            auth_user, auth_pass = auth, ""
    
    # Shared state
    state = {"served": 0, "stop": False}
    
    def _open_reader():
        """Open appropriate reader for current request."""
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
        """HTTP request handler for serving files."""
        
        server_version = "PyWWWGetCleanHTTP/1.0"
        
        def log_message(self, fmt, *args):
            """Quiet logging."""
            if _qflag(qs, "verbose", False):
                super(_Handler, self).log_message(fmt, *args)
        
        def _unauth(self):
            """Send 401 Unauthorized response."""
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="pywwwget"')
            self.send_header("Connection", "close")
            self.end_headers()
        
        def _check_auth(self):
            """Check Basic Authentication."""
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
            """Handle HEAD request."""
            self._do_send(body=False)
        
        def do_GET(self):
            """Handle GET request."""
            self._do_send(body=True)
        
        def _do_send(self, body=True):
            """Send file data."""
            # Only serve exact path
            req_path = self.path.split("?", 1)[0]
            if req_path != path:
                self.send_response(404)
                self.send_header("Connection", "close")
                self.end_headers()
                return
            
            # Check auth
            if not self._check_auth():
                self._unauth()
                return
            
            # Open data source
            f = _open_reader()
            try:
                # Get file size
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
                
                # Handle Range requests
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
                
                if total is not None:
                    if start < 0:
                        start = 0
                    if start > total:
                        start = total
                    
                    f.seek(start, 0)
                    remain = total - start
                    if end is not None and end >= start:
                        remain = min(remain, (end - start + 1))
                else:
                    remain = None
                
                # Check for gzip support
                use_gzip = False
                if gzip_on and status == 200:
                    ae = self.headers.get("Accept-Encoding", "") or ""
                    if "gzip" in ae.lower():
                        # Only gzip text content or small files
                        if content_type.startswith("text/") or \
                           content_type in ("application/json", "application/xml"):
                            use_gzip = True
                
                # Send headers
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                
                if cors:
                    self.send_header("Access-Control-Allow-Origin", "*")
                
                if download:
                    self.send_header("Content-Disposition", 
                                   'attachment; filename="%s"' % disp_name)
                
                # Extra headers
                for hk, hv in extra_headers.items():
                    try:
                        self.send_header(hk, hv)
                    except Exception:
                        pass
                
                # Range headers
                if total is not None:
                    if status == 206:
                        last = start + (remain - 1 if remain is not None else 0)
                        self.send_header("Content-Range", 
                                       "bytes %d-%d/%d" % (start, last, total))
                    self.send_header("Accept-Ranges", "bytes")
                
                # Gzip header
                if use_gzip:
                    self.send_header("Content-Encoding", "gzip")
                
                # No body for HEAD
                if not body:
                    self.send_header("Connection", "close")
                    self.end_headers()
                    return
                
                # Send body
                if use_gzip:
                    # Stream gzip
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
                    # Plain send
                    if remain is not None:
                        self.send_header("Content-Length", str(int(remain)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    
                    if remain is None:
                        shutil.copyfileobj(f, self.wfile)
                    else:
                        # Bounded copy
                        left = int(remain)
                        buf_size = 64 * 1024
                        while left > 0:
                            chunk = f.read(min(buf_size, left))
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            left -= len(chunk)
                
                # Update state
                state["served"] += 1
                if state["served"] >= max_clients:
                    state["stop"] = True
            
            finally:
                try:
                    if not use_direct:
                        f.close()
                except Exception:
                    pass
    
    # Create server
    try:
        httpd = HTTPServer((bind, int(port)), _Handler)
    except Exception as e:
        _net_log(True, "HTTP server error: %s" % str(e))
        return False
    
    bound_port = httpd.server_address[1]
    
    # Print URLs
    if print_url:
        for u in _listen_urls(("https" if tls_on else p.scheme), 
                             bind, bound_port, path, p.query):
            sys.stdout.write("Listening: %s\n" % u)
        sys.stdout.flush()
    
    # Configure timeout
    if idle_timeout and idle_timeout > 0:
        try:
            httpd.timeout = float(idle_timeout)
        except Exception:
            pass
    
    # Serve requests
    try:
        while not state["stop"]:
            httpd.handle_request()
            
            if idle_timeout and idle_timeout > 0 and state["served"] == 0:
                # Timed out waiting for first request
                break
    except KeyboardInterrupt:
        pass
    finally:
        try:
            httpd.server_close()
        except Exception:
            pass
    
    return bound_port

# --------------------------
# Main Public API Functions
# --------------------------

def download_file_from_internet_file(url, **kwargs):
    p = urlparse(url)
    if p.scheme in ("http", "https"):
        return download_file_from_http_file(url, **kwargs)
    if p.scheme in ("ftp", "ftps"):
        return download_file_from_ftp_file(url, **kwargs)
    if p.scheme in ("sftp", "scp"):
        if __use_pysftp__ and havepysftp:
            return download_file_from_pysftp_file(url, **kwargs)
        return download_file_from_sftp_file(url, **kwargs)

    if p.scheme in ("data", ):
        return data_url_decode(url)[0]

    if p.scheme in ("file" or ""):
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

def download_file_from_internet_string(url, **kwargs):
    fp = download_file_from_internet_file(url, **kwargs)
    return fp.read() if fp else False

def upload_file_to_internet_file(fileobj, url):
    """
    Upload file to any supported protocol.
    
    Returns fileobj on success, False on failure.
    """
    p = urlparse(url)
    
    # HTTP/HTTPS (serve file)
    if p.scheme in ("http", "https"):
        return _serve_file_over_http(fileobj, url)
    
    # FTP/FTPS
    elif p.scheme in ("ftp", "ftps"):
        return upload_file_to_ftp_file(fileobj, url)
    
    # SFTP/SCP
    elif p.scheme in ("sftp", "scp"):
        if __use_pysftp__ and havepysftp:
            return upload_file_to_pysftp_file(fileobj, url)
        return upload_file_to_sftp_file(fileobj, url)

    elif p.scheme in ("data", ):
        return data_url_encode(fileobj)

    elif p.scheme in ("file" or ""):
        outfile = io.open(unquote(p.path), "wb")
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        with io.open(unquote(p.path), "wb") as fdst:
            shutil.copyfileobj(fileobj, fdst)
        return fileobj

    # TCP/UDP
    elif p.scheme in ("tcp", "udp"):
        parts, options = _parse_net_url(url)
        host = parts.hostname
        port = parts.port or 0
        path_text = parts.path or "/"
        
        try:
            fileobj.seek(0, 0)
        except Exception:
            pass
        
        # Send data
        ok = send_from_fileobj(
            fileobj, host=host, port=port, proto=p.scheme,
            mode=options.get("mode"), timeout=options.get("timeout"), 
            total_timeout=options.get("total_timeout"), wait=options.get("wait"), 
            connect_wait=options.get("connect_wait"), 
            wait_timeout=options.get("wait_timeout"),
            window=options.get("window"), retries=options.get("retries"), 
            chunk=options.get("chunk"), resume=options.get("resume"), 
            path_text=path_text, done=options.get("done"), 
            done_token=options.get("done_token"), framing=options.get("framing"), 
            sha256=options.get("sha256")
        )
        
        return fileobj if ok else False
    
    # Unsupported protocol
    else:
        return False

def upload_file_to_internet_string(data, url):
    """Upload string/bytes to any supported protocol."""
    bio = MkTempFile(_to_bytes(data))
    out = upload_file_to_internet_file(bio, url)
    try:
        bio.close()
    except Exception:
        pass
    return out

# --------------------------
# Convenience Functions
# --------------------------

def send_path(path, url, fmt="tar", compression=None, **kwargs):
    """
    Package a directory or file and send it.
    
    Args:
        path: File or directory path
        url: Destination URL
        fmt: "tar" or "zip"
        compression: For tar: "gz" or None
        **kwargs: Additional options passed to upload_file_to_internet_file
    
    Returns:
        Result from upload_file_to_internet_file
    """
    try:
        import tarfile
        import zipfile
    except ImportError:
        return False
    
    p = os.path.abspath(path)
    
    # Create archive in memory/temp file
    tmp = None
    try:
        # Use spooled file for memory efficiency
        tmp = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b")
        
        if fmt.lower() == "zip":
            zf = zipfile.ZipFile(tmp, mode="w", compression=zipfile.ZIP_DEFLATED)
            try:
                if os.path.isdir(p):
                    # Add directory contents
                    for root, dirs, files in os.walk(p):
                        for fn in files:
                            full = os.path.join(root, fn)
                            rel = os.path.relpath(full, os.path.dirname(p))
                            zf.write(full, rel)
                else:
                    # Add single file
                    zf.write(p, os.path.basename(p))
            finally:
                zf.close()
        else:
            # Tar format
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

def recv_to_path(url, out_path, auto_extract=False, extract_dir=None, 
                keep_archive=True, **kwargs):
    """
    Download directly to filesystem path.
    
    Args:
        url: Source URL
        out_path: Destination path
        auto_extract: Auto-extract archives
        extract_dir: Extraction directory (defaults to out_path parent)
        keep_archive: Keep archive after extraction
        **kwargs: Additional options
    
    Returns:
        out_path on success, False on failure
    """
    # Handle HTTP listen mode specially
    try:
        up = urlparse(url)
        if (up.scheme or "").lower() in ("http", "https"):
            qs = parse_qs(up.query or "")
            if _qflag(qs, "listen", False) or _qflag(qs, "recv", False):
                # Modify URL for direct save
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
    
    # General download
    f = download_file_from_internet_file(url, **kwargs)
    if f is False:
        return False
    
    try:
        # Ensure parent directory exists
        parent = os.path.dirname(os.path.abspath(out_path))
        if parent and not os.path.isdir(parent):
            try:
                os.makedirs(parent)
            except Exception:
                pass
        
        # Write to file
        with open(out_path, "wb") as outfp:
            try:
                shutil.copyfileobj(f, outfp)
            finally:
                try:
                    f.close()
                except Exception:
                    pass
    except Exception as e:
        _net_log(True, "recv_to_path error: %s" % str(e))
        return False
    
    # Auto-extract if requested
    if auto_extract:
        try:
            import tarfile
            import zipfile
            
            if extract_dir is None:
                extract_dir = os.path.dirname(os.path.abspath(out_path)) or "."
            
            ext = out_path.lower()
            if ext.endswith(".zip"):
                zf = zipfile.ZipFile(out_path, "r")
                try:
                    zf.extractall(extract_dir)
                finally:
                    zf.close()
            
            elif any(ext.endswith(x) for x in [".tar", ".tar.gz", ".tgz", 
                                             ".tar.bz2", ".tbz2", ".tar.xz", ".txz"]):
                tf = tarfile.open(out_path, "r:*")
                try:
                    tf.extractall(extract_dir)
                finally:
                    tf.close()
            
            # Remove archive if requested
            if not keep_archive:
                try:
                    os.unlink(out_path)
                except Exception:
                    pass
        
        except Exception as e:
            _net_log(True, "Auto-extract error: %s" % str(e))
    
    return out_path

# --------------------------
# Module Initialization
# --------------------------

# Initialize mimetypes
mimetypes.init()

# Export public API
__all__ = [
    'download_file_from_internet_file',
    'download_file_from_internet_string',
    'upload_file_to_internet_file',
    'upload_file_to_internet_string',
    'send_path',
    'recv_to_path',
    'detect_cwd_ftp',
    'MkTempFile',
    '__version__',
    '__program_name__',
    '__project__',
    '__project_url__',
]


# Main entry point for command-line usage
if __name__ == "__main__":
    # Simple command-line interface
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        
        if cmd in ("download", "dl", "get"):
            if len(sys.argv) > 2:
                url = sys.argv[2]
                out = sys.argv[3] if len(sys.argv) > 3 else _guess_filename(url)
                
                result = recv_to_path(url, out, print_url=True)
                if result:
                    print("Downloaded to: %s" % result)
                else:
                    print("Download failed")
                    sys.exit(1)
        
        elif cmd in ("upload", "up", "send"):
            if len(sys.argv) > 3:
                path = sys.argv[2]
                url = sys.argv[3]
                
                if os.path.isdir(path):
                    result = send_path(path, url, print_url=True)
                else:
                    with open(path, "rb") as f:
                        result = upload_file_to_internet_file(f, url)
                
                if result:
                    print("Upload successful")
                else:
                    print("Upload failed")
                    sys.exit(1)
        
        elif cmd in ("help", "-h", "--help"):
            print("""
PyNeoWWW-Get (Optimized) v%s
Usage:
  %s download <url> [output_path]
  %s upload <file_or_dir> <url>
  %s help

Examples:
  %s download http://example.com/file.zip
  %s upload backup.tar.gz tcp://192.168.1.100:8000/
  %s upload /photos/ udp://192.168.1.100:9000/?mode=seq
            """ % (__version__, sys.argv[0], sys.argv[0], sys.argv[0], 
                   sys.argv[0], sys.argv[0], sys.argv[0]))
        
        else:
            print("Unknown command. Use 'help' for usage.")
            sys.exit(1)
    else:
        print("PyNeoWWW-Get (Optimized) v%s" % __version__)
        print("Use '%s help' for usage." % sys.argv[0])
