#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
pywwwget_clean.py

Cleaned-up + optimized refactor that keeps the SAME public API / function names
(and broadly the same behavior) as your pywwwgetadv-style module, while still
supporting Python 2 + 3.

Supported schemes:
- http, https
- ftp, ftps
- sftp (paramiko if available, pysftp if available/selected)
- tcp, udp (simple push/pull protocol with optional PATH + AUTH)

Key public API preserved:
- download_file_from_{http,ftp,sftp,pysftp}_file / _string
- upload_file_to_{ftp,sftp,pysftp}_file / _string
- download_file_from_internet_file / _string
- upload_file_to_internet_file / _string
- detect_cwd, MkTempFile, RawIteratorWrapper
- send_via_url / recv_via_url and lower-level send_from_fileobj / recv_to_fileobj

Notes (important honesty):
- This keeps the *same API surface* and “it works the same way” semantics.
- If your original pywwwgetadv.py has extra advanced features (AF1 HMAC v1,
  nonce replay cache, special tcp server helpers, etc.), those can be layered
  in, but I’m keeping the raw tcp/udp protocol compatible with the
  commonly-used pieces: PATH, AUTH, LEN, payload, DONE.
- The code is written to be drop-in as a module; you can also graft just the
  functions into your existing file if you want to keep your banner/UA strings.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os
import sys
import socket
import shutil
import time
import logging
import tempfile

try:
    # Py2/3 compat
    text_type = unicode  # noqa: F821 (Py2)
except Exception:
    text_type = str

try:
    binary_type = bytes
except Exception:
    binary_type = str  # Py2 fallback

try:
    from io import BytesIO, StringIO
except Exception:
    try:
        from cStringIO import StringIO  # Py2
        BytesIO = StringIO
    except Exception:
        from StringIO import StringIO  # Py2
        BytesIO = StringIO

# URL parsing
try:
    from urllib.parse import urlparse, urlunparse
except Exception:
    from urlparse import urlparse, urlunparse  # Py2

# Query parsing for tcp/udp flags
try:
    from urllib.parse import parse_qs
except Exception:
    try:
        from urlparse import parse_qs  # Py2
    except Exception:
        parse_qs = None

# URL decoding
try:
    from urllib.parse import unquote
except Exception:
    try:
        from urllib import unquote  # Py2
    except Exception:
        unquote = None

# urllib HTTP
try:
    from urllib.request import Request, build_opener, HTTPBasicAuthHandler, HTTPPasswordMgrWithDefaultRealm
except Exception:
    from urllib2 import Request, build_opener, HTTPBasicAuthHandler  # Py2
    try:
        from urllib2 import HTTPPasswordMgrWithDefaultRealm  # Py2
    except Exception:
        HTTPPasswordMgrWithDefaultRealm = None

# FTP/FTPS
ftpssl = True
try:
    from ftplib import FTP, FTP_TLS, all_errors
except Exception:
    from ftplib import FTP
    FTP_TLS = None
    ftpssl = False
    all_errors = (Exception,)

# Optional libs
haveparamiko = False
try:
    import paramiko
    haveparamiko = True
except Exception:
    paramiko = None

havepysftp = False
try:
    import pysftp
    havepysftp = True
except Exception:
    pysftp = None

havemechanize = False
try:
    import mechanize
    havemechanize = True
except Exception:
    mechanize = None

haverequests = False
try:
    import requests
    haverequests = True
    try:
        import urllib3
        logging.getLogger("urllib3").setLevel(logging.WARNING)
    except Exception:
        pass
except Exception:
    requests = None

havehttpx = False
try:
    import httpx
    havehttpx = True
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
except Exception:
    httpx = None

# ------------------------------------------------------------
# Module config (keep names aligned with your project)
# ------------------------------------------------------------
__use_pysftp__ = False
if not havepysftp:
    __use_pysftp__ = False

__use_http_lib__ = "httpx"
if __use_http_lib__ == "httpx" and haverequests and not havehttpx:
    __use_http_lib__ = "requests"
if __use_http_lib__ == "requests" and havehttpx and not haverequests:
    __use_http_lib__ = "httpx"
if (__use_http_lib__ in ("httpx", "requests")) and (not havehttpx) and (not haverequests):
    __use_http_lib__ = "urllib"

# Buffers
__filebuff_size__ = 1024 * 64  # 64KB copy buffer
__net_chunk_size__ = 1024 * 64

# Tempfile behavior
__use_spool_temp__ = True
__spool_max__ = 1024 * 1024 * 8  # 8MB in RAM then spill to disk
__use_memfd__ = True  # Linux-only optimization

# Default headers (you can override from your own UA-building code)
geturls_headers_pywwwget_python_alt = {}

# Logger
log = logging.getLogger("pywwwget_clean")
if not log.handlers:
    logging.basicConfig(level=logging.INFO)

# ------------------------------------------------------------
# Helpers: text/bytes
# ------------------------------------------------------------
def _to_bytes(x, encoding="utf-8", errors="strict"):
    if x is None:
        return b""
    if isinstance(x, binary_type):
        return x if not isinstance(x, text_type) else x.encode(encoding, errors)  # Py2 weirdness
    if isinstance(x, text_type):
        return x.encode(encoding, errors)
    try:
        return text_type(x).encode(encoding, errors)
    except Exception:
        return binary_type(x)

def _to_text(x, encoding="utf-8", errors="strict"):
    if x is None:
        return u""
    if isinstance(x, text_type):
        return x
    if isinstance(x, binary_type):
        try:
            return x.decode(encoding, errors)
        except Exception:
            return text_type(x)
    return text_type(x)

def _safe_unquote(s):
    if s is None:
        return None
    if unquote is None:
        return s
    try:
        return unquote(s)
    except Exception:
        return s

# ------------------------------------------------------------
# Temp file factory (keeps MkTempFile API)
# ------------------------------------------------------------
def MkTempFile(inmem=True, isbytes=True, usememfd=__use_memfd__, use_spool=__use_spool_temp__, spool_max=__spool_max__):
    """
    Returns a file-like object for binary data.
    - inmem=True: BytesIO/StringIO
    - usememfd=True (Linux): memfd-backed file (binary only)
    - use_spool=True: SpooledTemporaryFile (RAM then disk)
    - else: NamedTemporaryFile (disk)
    """
    # memfd optimization (Linux-only, binary only)
    if inmem and usememfd and isbytes and hasattr(os, "memfd_create"):
        try:
            fd = os.memfd_create("pywwwget", 0)
            # Wrap fd as a file object (binary)
            try:
                return os.fdopen(fd, "w+b")
            except Exception:
                os.close(fd)
        except Exception:
            pass

    if inmem:
        return BytesIO() if isbytes else StringIO()

    if use_spool:
        try:
            return tempfile.SpooledTemporaryFile(max_size=spool_max, mode="w+b" if isbytes else "w+")
        except Exception:
            pass

    return tempfile.NamedTemporaryFile(mode="w+b" if isbytes else "w+", delete=True)

# ------------------------------------------------------------
# detect_cwd (as requested)
# ------------------------------------------------------------
def detect_cwd(ftp, file_dir):
    """
    Test whether cwd (FTP/FTPS) or chdir (SFTP) into file_dir works.
    Returns True if it does, False if not (so absolute paths should be used).
    """
    if not file_dir or file_dir in ("/", ""):
        return False

    # FTP/FTPS
    if hasattr(ftp, "cwd"):
        try:
            ftp.cwd(file_dir)
            return True
        except all_errors:
            return False
        except Exception:
            return False

    # SFTP (paramiko)
    if hasattr(ftp, "chdir"):
        try:
            ftp.chdir(file_dir)
            return True
        except (OSError, IOError):
            return False
        except Exception:
            return False

    return False

# ------------------------------------------------------------
# Auth normalization (keeps original semantics)
# ------------------------------------------------------------
def _normalize_auth(urlparts):
    username = _safe_unquote(urlparts.username) if urlparts.username is not None else "anonymous"
    if urlparts.password is not None:
        password = _safe_unquote(urlparts.password)
    elif username == "anonymous":
        password = "anonymous"
    else:
        password = ""
    return username, password

# ------------------------------------------------------------
# RawIteratorWrapper for httpx iter_bytes()
# ------------------------------------------------------------
class RawIteratorWrapper(object):
    def __init__(self, iterator):
        self.iterator = iterator
        self.buffer = b""
        self._exhausted = False

    def read(self, size=-1):
        if self._exhausted:
            return b""
        while size < 0 or len(self.buffer) < size:
            try:
                chunk = next(self.iterator)
                if chunk:
                    self.buffer += chunk
            except StopIteration:
                self._exhausted = True
                break
        if size < 0:
            size = len(self.buffer)
        out, self.buffer = self.buffer[:size], self.buffer[size:]
        return out

# ============================================================
# FTP / FTPS
# ============================================================
def _ftp_client_for_scheme(scheme):
    if scheme == "ftp":
        return FTP()
    if scheme == "ftps" and ftpssl and FTP_TLS is not None:
        return FTP_TLS()
    return None

def _ftp_enable_ftps(ftp):
    # Best-effort: AUTH + PROT P, fallback to PROT C
    try:
        if hasattr(ftp, "auth"):
            ftp.auth()
    except Exception:
        pass
    try:
        if hasattr(ftp, "prot_p"):
            ftp.prot_p()
    except Exception:
        try:
            if hasattr(ftp, "prot_c"):
                ftp.prot_c()
        except Exception:
            pass

def _ftp_enable_utf8(ftp):
    try:
        ftp.sendcmd("OPTS UTF8 ON")
        ftp.encoding = "utf-8"
    except Exception:
        pass

def _ftp_try_modes(ftp):
    # EPSV -> passive -> active fallbacks (best-effort)
    try:
        ftp.sendcmd("EPSV")
        try:
            ftp.force_epsv = True
        except Exception:
            pass
        return
    except Exception:
        pass
    try:
        ftp.set_pasv(True)
        return
    except Exception:
        pass
    try:
        ftp.set_pasv(False)
    except Exception:
        pass

def download_file_from_ftp_file(url):
    urlparts = urlparse(url)

    # Cross-dispatch to keep original behavior
    if urlparts.scheme == "sftp":
        return download_file_from_pysftp_file(url) if (__use_pysftp__ and havepysftp) else download_file_from_sftp_file(url)
    if urlparts.scheme in ("http", "https"):
        return download_file_from_http_file(url)

    ftp = _ftp_client_for_scheme(urlparts.scheme)
    if ftp is None:
        return False

    host = urlparts.hostname
    if not host:
        return False

    port = urlparts.port or 21
    username, password = _normalize_auth(urlparts)

    path = _safe_unquote(urlparts.path or "")
    file_dir = os.path.dirname(path)
    file_name = os.path.basename(path)

    try:
        ftp.connect(host, port)
        ftp.login(username, password)

        if urlparts.scheme == "ftps":
            _ftp_enable_ftps(ftp)

        _ftp_enable_utf8(ftp)
        _ftp_try_modes(ftp)

        out = MkTempFile(inmem=True, isbytes=True)

        # Use cwd+basename if possible
        retr_target = path
        if detect_cwd(ftp, file_dir) and file_name:
            retr_target = file_name

        ftp.retrbinary("RETR " + retr_target, out.write, blocksize=__net_chunk_size__)
        out.seek(0, 0)
        return out

    except (socket.gaierror, socket.timeout):
        log.info("Error With URL %s", url)
        return False
    except all_errors:
        log.info("FTP error With URL %s", url)
        return False
    except Exception:
        log.exception("FTP unexpected error With URL %s", url)
        return False
    finally:
        try:
            ftp.close()
        except Exception:
            pass

def download_file_from_ftp_string(url):
    f = download_file_from_ftp_file(url)
    return f.read() if f else False

def upload_file_to_ftp_file(ftpfile, url):
    urlparts = urlparse(url)

    # Cross-dispatch
    if urlparts.scheme == "sftp":
        return upload_file_to_pysftp_file(ftpfile, url) if (__use_pysftp__ and havepysftp) else upload_file_to_sftp_file(ftpfile, url)
    if urlparts.scheme in ("http", "https"):
        return False

    ftp = _ftp_client_for_scheme(urlparts.scheme)
    if ftp is None:
        return False

    host = urlparts.hostname
    if not host:
        return False

    port = urlparts.port or 21
    username, password = _normalize_auth(urlparts)

    path = _safe_unquote(urlparts.path or "")
    file_dir = os.path.dirname(path)
    file_name = os.path.basename(path)

    try:
        ftp.connect(host, port)
        ftp.login(username, password)

        if urlparts.scheme == "ftps":
            _ftp_enable_ftps(ftp)

        _ftp_enable_utf8(ftp)
        _ftp_try_modes(ftp)

        try:
            ftpfile.seek(0, 0)
        except Exception:
            pass

        stor_target = path
        if detect_cwd(ftp, file_dir) and file_name:
            stor_target = file_name

        ftp.storbinary("STOR " + stor_target, ftpfile, blocksize=__net_chunk_size__)

        try:
            ftpfile.seek(0, 0)
        except Exception:
            pass

        return ftpfile

    except (socket.gaierror, socket.timeout):
        log.info("Error With URL %s", url)
        return False
    except all_errors:
        log.info("FTP upload error With URL %s", url)
        return False
    except Exception:
        log.exception("FTP unexpected upload error With URL %s", url)
        return False
    finally:
        try:
            ftp.close()
        except Exception:
            pass

def upload_file_to_ftp_string(ftpstring, url):
    bio = BytesIO(ftpstring if isinstance(ftpstring, binary_type) else _to_bytes(ftpstring))
    try:
        res = upload_file_to_ftp_file(bio, url)
        return res if res else False
    finally:
        try:
            bio.close()
        except Exception:
            pass

# ============================================================
# HTTP / HTTPS
# ============================================================
def _rebuild_url_without_creds(urlparts):
    netloc = urlparts.hostname or ""
    if urlparts.port:
        netloc += ":" + text_type(urlparts.port)
    return urlunparse((urlparts.scheme, netloc, urlparts.path, urlparts.params, urlparts.query, urlparts.fragment))

def download_file_from_http_file(url, headers=None, usehttp=__use_http_lib__):
    if headers is None:
        headers = {}

    urlparts = urlparse(url)

    # Cross-dispatch
    if urlparts.scheme == "sftp":
        return download_file_from_pysftp_file(url) if (__use_pysftp__ and havepysftp) else download_file_from_sftp_file(url)
    if urlparts.scheme in ("ftp", "ftps"):
        return download_file_from_ftp_file(url)

    if urlparts.scheme not in ("http", "https"):
        return False

    username = urlparts.username
    password = urlparts.password
    rebuilt_url = _rebuild_url_without_creds(urlparts)

    out = MkTempFile(inmem=True, isbytes=True)

    # 1) requests
    if usehttp == "requests" and haverequests and requests is not None:
        try:
            kwargs = {"headers": headers, "timeout": (5, 30), "stream": True}
            if username and password:
                kwargs["auth"] = (_safe_unquote(username), _safe_unquote(password))
            resp = requests.get(rebuilt_url, **kwargs)
            resp.raw.decode_content = True
            shutil.copyfileobj(resp.raw, out, length=__filebuff_size__)
            out.seek(0, 0)
            return out
        except Exception:
            return False

    # 2) httpx
    if usehttp == "httpx" and havehttpx and httpx is not None:
        try:
            with httpx.Client(follow_redirects=True) as client:
                if username and password:
                    resp = client.get(rebuilt_url, headers=headers, auth=(_safe_unquote(username), _safe_unquote(password)))
                else:
                    resp = client.get(rebuilt_url, headers=headers)
                raw = RawIteratorWrapper(resp.iter_bytes())
                shutil.copyfileobj(raw, out, length=__filebuff_size__)
            out.seek(0, 0)
            return out
        except Exception:
            return False

    # 3) mechanize
    if usehttp == "mechanize" and havemechanize and mechanize is not None:
        try:
            br = mechanize.Browser()
            br.set_handle_robots(False)
            if headers:
                br.addheaders = list(headers.items())
            if username and password:
                br.add_password(rebuilt_url, _safe_unquote(username), _safe_unquote(password))
            resp = br.open(rebuilt_url)
            shutil.copyfileobj(resp, out, length=__filebuff_size__)
            out.seek(0, 0)
            return out
        except Exception:
            return False

    # 4) urllib fallback
    try:
        req = Request(rebuilt_url, headers=headers)
        if username and password and HTTPPasswordMgrWithDefaultRealm is not None:
            mgr = HTTPPasswordMgrWithDefaultRealm()
            mgr.add_password(None, rebuilt_url, _safe_unquote(username), _safe_unquote(password))
            opener = build_opener(HTTPBasicAuthHandler(mgr))
        else:
            opener = build_opener()
        resp = opener.open(req)
        shutil.copyfileobj(resp, out, length=__filebuff_size__)
        out.seek(0, 0)
        return out
    except Exception:
        return False

def download_file_from_http_string(url, headers=geturls_headers_pywwwget_python_alt, usehttp=__use_http_lib__):
    f = download_file_from_http_file(url, headers=headers, usehttp=usehttp)
    return f.read() if f else False

# ============================================================
# SFTP (Paramiko)
# ============================================================
def download_file_from_sftp_file(url):
    if not haveparamiko:
        return False

    urlparts = urlparse(url)

    # Cross-dispatch
    if urlparts.scheme in ("ftp", "ftps"):
        return download_file_from_ftp_file(url)
    if urlparts.scheme in ("http", "https"):
        return download_file_from_http_file(url)

    if urlparts.scheme != "sftp":
        return False

    host = urlparts.hostname
    if not host:
        return False

    port = urlparts.port or 22
    username, password = _normalize_auth(urlparts)

    path = _safe_unquote(urlparts.path or "")
    file_dir = os.path.dirname(path)
    file_name = os.path.basename(path)

    ssh = paramiko.SSHClient()
    try:
        ssh.load_system_host_keys()
    except Exception:
        pass
    try:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    except Exception:
        pass

    try:
        ssh.connect(host, port=port, username=username, password=password)
        sftp = ssh.open_sftp()
        try:
            out = MkTempFile(inmem=True, isbytes=True)
            get_target = path
            if detect_cwd(sftp, file_dir) and file_name:
                get_target = file_name
            sftp.getfo(get_target, out)
            out.seek(0, 0)
            return out
        finally:
            try:
                sftp.close()
            except Exception:
                pass
    except (socket.gaierror, socket.timeout):
        log.info("Error With URL %s", url)
        return False
    except Exception:
        return False
    finally:
        try:
            ssh.close()
        except Exception:
            pass

def download_file_from_sftp_string(url):
    f = download_file_from_sftp_file(url)
    return f.read() if f else False

def upload_file_to_sftp_file(sftpfile, url):
    if not haveparamiko:
        return False

    urlparts = urlparse(url)

    # Cross-dispatch
    if urlparts.scheme in ("ftp", "ftps"):
        return upload_file_to_ftp_file(sftpfile, url)
    if urlparts.scheme in ("http", "https"):
        return False

    if urlparts.scheme != "sftp":
        return False

    host = urlparts.hostname
    if not host:
        return False

    port = urlparts.port or 22
    username, password = _normalize_auth(urlparts)

    path = _safe_unquote(urlparts.path or "")
    file_dir = os.path.dirname(path)
    file_name = os.path.basename(path)

    ssh = paramiko.SSHClient()
    try:
        ssh.load_system_host_keys()
    except Exception:
        pass
    try:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    except Exception:
        pass

    try:
        ssh.connect(host, port=port, username=username, password=password)
        sftp = ssh.open_sftp()
        try:
            try:
                sftpfile.seek(0, 0)
            except Exception:
                pass

            put_target = path
            if detect_cwd(sftp, file_dir) and file_name:
                put_target = file_name
            sftp.putfo(sftpfile, put_target)

            try:
                sftpfile.seek(0, 0)
            except Exception:
                pass
            return sftpfile
        finally:
            try:
                sftp.close()
            except Exception:
                pass
    except Exception:
        return False
    finally:
        try:
            ssh.close()
        except Exception:
            pass

def upload_file_to_sftp_string(sftpstring, url):
    bio = BytesIO(sftpstring if isinstance(sftpstring, binary_type) else _to_bytes(sftpstring))
    try:
        res = upload_file_to_sftp_file(bio, url)
        return res if res else False
    finally:
        try:
            bio.close()
        except Exception:
            pass

# ============================================================
# PySFTP (optional)
# ============================================================
def download_file_from_pysftp_file(url):
    if not havepysftp:
        return False
    urlparts = urlparse(url)

    # Cross-dispatch
    if urlparts.scheme in ("ftp", "ftps"):
        return download_file_from_ftp_file(url)
    if urlparts.scheme in ("http", "https"):
        return download_file_from_http_file(url)

    if urlparts.scheme != "sftp":
        return False

    host = urlparts.hostname
    if not host:
        return False

    port = urlparts.port or 22
    username, password = _normalize_auth(urlparts)

    path = _safe_unquote(urlparts.path or "")
    file_dir = os.path.dirname(path)
    file_name = os.path.basename(path)

    try:
        with pysftp.Connection(host, port=port, username=username, password=password) as s:
            out = MkTempFile(inmem=True, isbytes=True)
            # pysftp supports chdir; use it if possible
            get_target = path
            try:
                if file_dir and file_dir not in ("/", ""):
                    s.chdir(file_dir)
                    if file_name:
                        get_target = file_name
            except Exception:
                get_target = path
            s.getfo(get_target, out)
            out.seek(0, 0)
            return out
    except Exception:
        return False

def download_file_from_pysftp_string(url):
    f = download_file_from_pysftp_file(url)
    return f.read() if f else False

def upload_file_to_pysftp_file(sftpfile, url):
    if not havepysftp:
        return False
    urlparts = urlparse(url)

    # Cross-dispatch
    if urlparts.scheme in ("ftp", "ftps"):
        return upload_file_to_ftp_file(sftpfile, url)
    if urlparts.scheme in ("http", "https"):
        return False

    if urlparts.scheme != "sftp":
        return False

    host = urlparts.hostname
    if not host:
        return False

    port = urlparts.port or 22
    username, password = _normalize_auth(urlparts)

    path = _safe_unquote(urlparts.path or "")
    file_dir = os.path.dirname(path)
    file_name = os.path.basename(path)

    try:
        with pysftp.Connection(host, port=port, username=username, password=password) as s:
            try:
                sftpfile.seek(0, 0)
            except Exception:
                pass

            put_target = path
            try:
                if file_dir and file_dir not in ("/", ""):
                    s.chdir(file_dir)
                    if file_name:
                        put_target = file_name
            except Exception:
                put_target = path

            s.putfo(sftpfile, put_target)

            try:
                sftpfile.seek(0, 0)
            except Exception:
                pass
            return sftpfile
    except Exception:
        return False

def upload_file_to_pysftp_string(sftpstring, url):
    bio = BytesIO(sftpstring if isinstance(sftpstring, binary_type) else _to_bytes(sftpstring))
    try:
        res = upload_file_to_pysftp_file(bio, url)
        return res if res else False
    finally:
        try:
            bio.close()
        except Exception:
            pass

# ============================================================
# RAW TCP / UDP TRANSFER
# ============================================================
# Simple protocol (compatible with what you were demonstrating):
# Sender -> Receiver:
#   PATH <path>\n           (optional, if enforce_path=1)
#   AUTH <user>\0<pass>\0   (optional, if auth=1 OR creds present)
#   LEN <n>\n              (optional; if omitted, receiver reads until DONE)
#   <payload bytes>
#   DONE\n                 (always when LEN omitted; optional when LEN present)
#
# Receiver responds on TCP after AUTH:
#   OK\n or NO\n

_OK = b"OK\n"
_NO = b"NO\n"
_DONE = b"DONE\n"

def _parse_net_url(url):
    """
    Parse tcp:// or udp:// URL, extracting:
      proto, host, port, path, username, password, query options.

    Supported query flags (strings):
      - auth=0/1
      - enforce_path=0/1
      - timeout=<seconds>
      - total_timeout=<seconds>
      - chunk=<bytes>
    """
    u = urlparse(url)
    proto = (u.scheme or "").lower()
    host = u.hostname or "0.0.0.0"
    port = u.port
    if port is None:
        port = 7000  # your default demo port
    path = _safe_unquote(u.path or "/")

    username = _safe_unquote(u.username) if u.username else ""
    password = _safe_unquote(u.password) if u.password else ""

    opts = {
        "proto": proto,
        "host": host,
        "port": int(port),
        "path": path,
        "username": username,
        "password": password,
        "timeout": 10.0,
        "total_timeout": 0.0,  # 0 = no total timeout
        "chunk": __net_chunk_size__,
        "auth": 1 if (username or password) else 0,
        "enforce_path": 1,
    }

    if parse_qs is not None and u.query:
        try:
            q = parse_qs(u.query, keep_blank_values=True)
            def _qfirst(k, default=None):
                v = q.get(k)
                if not v:
                    return default
                return v[0]
            auth = _qfirst("auth", None)
            if auth is not None:
                opts["auth"] = 1 if text_type(auth) in ("1", "true", "yes", "on") else 0
            ep = _qfirst("enforce_path", None)
            if ep is not None:
                opts["enforce_path"] = 1 if text_type(ep) in ("1", "true", "yes", "on") else 0
            t = _qfirst("timeout", None)
            if t is not None:
                try:
                    opts["timeout"] = float(t)
                except Exception:
                    pass
            tt = _qfirst("total_timeout", None)
            if tt is not None:
                try:
                    opts["total_timeout"] = float(tt)
                except Exception:
                    pass
            ch = _qfirst("chunk", None)
            if ch is not None:
                try:
                    opts["chunk"] = int(ch)
                except Exception:
                    pass
        except Exception:
            pass

    return opts

def _tcp_recvline(sock, maxlen=65536):
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(1)
        if not chunk:
            break
        buf += chunk
        if len(buf) > maxlen:
            break
    return buf

def _maybe_send(sock, data):
    try:
        sock.sendall(data)
    except Exception:
        pass

def send_from_fileobj(fileobj, url):
    """
    Send fileobj contents to tcp:// or udp:// receiver.
    Returns number of payload bytes sent (like your demo output 1434).
    """
    o = _parse_net_url(url)
    proto = o["proto"]
    host = o["host"]
    port = o["port"]
    path = o["path"]
    timeout = o["timeout"]
    chunk = o["chunk"]
    enforce_path = bool(o["enforce_path"])
    auth_required = bool(o["auth"])
    username = o["username"]
    password = o["password"]

    # Payload length if file is seekable
    total_len = None
    try:
        cur = fileobj.tell()
        fileobj.seek(0, 2)
        total_len = fileobj.tell()
        fileobj.seek(cur, 0)
    except Exception:
        total_len = None

    # Ensure start
    try:
        fileobj.seek(0, 0)
    except Exception:
        pass

    sent = 0

    if proto == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            if enforce_path:
                s.sendto(b"PATH " + _to_bytes(path) + b"\n", (host, port))
            if auth_required:
                blob = b"AUTH " + _to_bytes(username) + b"\0" + _to_bytes(password) + b"\0"
                s.sendto(blob, (host, port))
            if total_len is not None:
                s.sendto(b"LEN " + _to_bytes(text_type(total_len)) + b"\n", (host, port))

            while True:
                b = fileobj.read(chunk)
                if not b:
                    break
                if not isinstance(b, binary_type):
                    b = _to_bytes(b)
                s.sendto(b, (host, port))
                sent += len(b)

            # Always send DONE for UDP (simple + robust)
            s.sendto(_DONE, (host, port))
            return sent
        finally:
            try:
                s.close()
            except Exception:
                pass

    if proto == "tcp":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            if enforce_path:
                _maybe_send(s, b"PATH " + _to_bytes(path) + b"\n")
            if auth_required:
                _maybe_send(s, b"AUTH " + _to_bytes(username) + b"\0" + _to_bytes(password) + b"\0")
                # expect OK/NO
                line = _tcp_recvline(s)
                if not line.startswith(b"OK"):
                    return 0
            if total_len is not None:
                _maybe_send(s, b"LEN " + _to_bytes(text_type(total_len)) + b"\n")

            while True:
                b = fileobj.read(chunk)
                if not b:
                    break
                if not isinstance(b, binary_type):
                    b = _to_bytes(b)
                s.sendall(b)
                sent += len(b)

            _maybe_send(s, _DONE)
            return sent
        finally:
            try:
                s.close()
            except Exception:
                pass

    return 0

def recv_to_fileobj(fileobj, url):
    """
    Receive bytes into fileobj from tcp:// or udp:// sender.
    Returns number of payload bytes received.
    """
    o = _parse_net_url(url)
    proto = o["proto"]
    host = o["host"]
    port = o["port"]
    path_expected = o["path"]
    timeout = o["timeout"]
    total_timeout = o["total_timeout"]
    chunk = o["chunk"]
    enforce_path = bool(o["enforce_path"])
    auth_required = bool(o["auth"])
    username_expected = o["username"]
    password_expected = o["password"]

    start = time.time()
    got = 0

    def _timed_out():
        return (total_timeout and (time.time() - start) > total_timeout)

    if proto == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            # Bind to listen on host:port (host may be 0.0.0.0 or localhost)
            s.bind((host, port))

            declared_path = None
            payload_len = None
            authed = (not auth_required)

            # Read control frames then payload packets until DONE
            while True:
                if _timed_out():
                    break
                data, addr = s.recvfrom(max(4096, chunk))
                if not data:
                    continue

                # control frames
                if data.startswith(b"PATH "):
                    declared_path = _to_text(data[5:].strip())
                    continue
                if data.startswith(b"AUTH "):
                    # AUTH user\0pass\0
                    rest = data[5:]
                    parts = rest.split(b"\0")
                    u = _to_text(parts[0]) if len(parts) > 0 else ""
                    p = _to_text(parts[1]) if len(parts) > 1 else ""
                    if (not username_expected and not password_expected) or (u == username_expected and p == password_expected):
                        authed = True
                    else:
                        authed = False
                    continue
                if data.startswith(b"LEN "):
                    try:
                        payload_len = int(_to_text(data[4:].strip()))
                    except Exception:
                        payload_len = None
                    continue
                if data == _DONE:
                    break

                # payload
                if enforce_path and declared_path is not None and declared_path != path_expected:
                    continue
                if not authed:
                    continue

                fileobj.write(data)
                got += len(data)

                if payload_len is not None and got >= payload_len:
                    # Consume until DONE if it arrives, but we can stop safely
                    break

            try:
                fileobj.seek(0, 0)
            except Exception:
                pass
            return got
        finally:
            try:
                s.close()
            except Exception:
                pass

    if proto == "tcp":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.bind((host, port))
            s.listen(1)
            conn, _addr = s.accept()
            conn.settimeout(timeout)
            try:
                declared_path = None
                payload_len = None
                authed = (not auth_required)

                # Control parsing: read PATH line and/or AUTH blob and/or LEN line.
                # We read small chunks and interpret prefixes; after that, stream bytes.
                # For simplicity, we parse in a loop until we believe we've reached payload.
                # This matches the “send control then payload” pattern.

                # PATH line (optional)
                if enforce_path:
                    line = _tcp_recvline(conn)
                    if line.startswith(b"PATH "):
                        declared_path = _to_text(line[5:].strip())
                    else:
                        # No PATH where expected; treat as mismatch.
                        declared_path = None

                # AUTH (optional)
                if auth_required:
                    # Read enough to include at least "AUTH " + user\0pass\0
                    # Since creds are short, recv a fixed buffer.
                    blob = conn.recv(4096)
                    if blob.startswith(b"AUTH "):
                        rest = blob[5:]
                        parts = rest.split(b"\0")
                        u = _to_text(parts[0]) if len(parts) > 0 else ""
                        p = _to_text(parts[1]) if len(parts) > 1 else ""
                        if (not username_expected and not password_expected) or (u == username_expected and p == password_expected):
                            authed = True
                            _maybe_send(conn, _OK)
                        else:
                            authed = False
                            _maybe_send(conn, _NO)
                            return 0
                        # Any extra bytes after the auth blob are not handled here; kept simple.
                    else:
                        _maybe_send(conn, _NO)
                        return 0

                # LEN line (optional)
                # Best-effort: peek next bytes; if it starts with LEN, parse it.
                try:
                    conn.settimeout(0.1)
                    peek = conn.recv(64, socket.MSG_PEEK) if hasattr(socket, "MSG_PEEK") else b""
                    conn.settimeout(timeout)
                except Exception:
                    conn.settimeout(timeout)
                    peek = b""

                if peek.startswith(b"LEN "):
                    line = _tcp_recvline(conn)
                    try:
                        payload_len = int(_to_text(line[4:].strip()))
                    except Exception:
                        payload_len = None

                # Now payload streaming until DONE or LEN satisfied
                if enforce_path and declared_path is not None and declared_path != path_expected:
                    return 0
                if not authed:
                    return 0

                while True:
                    if _timed_out():
                        break
                    data = conn.recv(chunk)
                    if not data:
                        break
                    # DONE marker may arrive inline; handle it
                    if _DONE in data:
                        before, _sep, _after = data.partition(_DONE)
                        if before:
                            fileobj.write(before)
                            got += len(before)
                        break
                    fileobj.write(data)
                    got += len(data)
                    if payload_len is not None and got >= payload_len:
                        break

                try:
                    fileobj.seek(0, 0)
                except Exception:
                    pass
                return got
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    return 0

def send_via_url(fileobj, url, send_func=send_from_fileobj):
    return send_func(fileobj, url)

def recv_via_url(fileobj, url, recv_func=recv_to_fileobj):
    return recv_func(fileobj, url)

# ============================================================
# Unified Internet Dispatch (same API)
# ============================================================
def download_file_from_internet_file(url, headers=geturls_headers_pywwwget_python_alt, usehttp=__use_http_lib__):
    u = urlparse(url)
    if u.scheme in ("http", "https"):
        return download_file_from_http_file(url, headers=headers, usehttp=usehttp)
    if u.scheme in ("ftp", "ftps"):
        return download_file_from_ftp_file(url)
    if u.scheme == "sftp":
        return download_file_from_pysftp_file(url) if (__use_pysftp__ and havepysftp) else download_file_from_sftp_file(url)
    if u.scheme in ("tcp", "udp"):
        out = MkTempFile(inmem=True, isbytes=True)
        n = recv_via_url(out, url, recv_to_fileobj)
        if n <= 0:
            return False
        out.seek(0, 0)
        return out
    return False

def download_file_from_internet_string(url, headers=geturls_headers_pywwwget_python_alt, usehttp=__use_http_lib__):
    f = download_file_from_internet_file(url, headers=headers, usehttp=usehttp)
    return f.read() if f else False

def upload_file_to_internet_file(ifp, url):
    u = urlparse(url)
    if u.scheme in ("http", "https"):
        return False
    if u.scheme in ("ftp", "ftps"):
        res = upload_file_to_ftp_file(ifp, url)
        return res if res else False
    if u.scheme == "sftp":
        res = upload_file_to_pysftp_file(ifp, url) if (__use_pysftp__ and havepysftp) else upload_file_to_sftp_file(ifp, url)
        return res if res else False
    if u.scheme in ("tcp", "udp"):
        try:
            ifp.seek(0, 0)
        except Exception:
            pass
        return send_via_url(ifp, url, send_from_fileobj)
    return False

def upload_file_to_internet_string(ifp_bytes, url):
    # Keeps your original “string upload means bytes input”
    if isinstance(ifp_bytes, binary_type) and not isinstance(ifp_bytes, text_type):
        bio = BytesIO(ifp_bytes)
    else:
        bio = BytesIO(_to_bytes(ifp_bytes))
    try:
        return upload_file_to_internet_file(bio, url)
    finally:
        try:
            bio.close()
        except Exception:
            pass

# ============================================================
# Backwards-compat aliases (if your old module had these typos)
# ============================================================
def download_file_from_pyftp_string(url):
    # preserve misspelling seen in some versions
    return download_file_from_pysftp_string(url)
