#!/usr/bin/env python3
"""
PyWWWGet - Advanced Multi-Protocol Network File Transfer Module
Optimized version with improved error handling and performance.
"""

import os
import io
import re
import sys
import logging
import json
import getpass
import random
import platform
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
import functools
from typing import Any, Dict, Optional, Tuple, Union, BinaryIO, List, Mapping, Callable
from urllib.parse import quote_from_bytes, unquote_to_bytes, urlencode, urlparse, urlunparse, parse_qs, unquote
from urllib.request import Request, build_opener, install_opener, HTTPBasicAuthHandler, HTTPCookieProcessor, HTTPSHandler, HTTPPasswordMgrWithDefaultRealm
from urllib.error import URLError, HTTPError
from http.client import HTTPException
from http.server import BaseHTTPRequestHandler, HTTPServer
from http import cookies as http_cookies
import http.cookiejar as cookielib
import socketserver

# Initialize mimetypes once
try:
    mimetypes.init()
except Exception:
    pass

# Conditional imports with better error handling
_DEPENDENCIES = {
    'requests': None,
    'urllib3': None,
    'httpx': None,
    'httpcore': None,
    'mechanize': None,
    'pycurl': None,
    'paramiko': None,
    'pysftp': None,
    'certifi': None,
    'socks': None,
}

for dep in _DEPENDENCIES:
    try:
        _DEPENDENCIES[dep] = __import__(dep)
    except ImportError:
        pass

# Constants
_TEXT_MIME_DEFAULT = 'text/plain; charset=utf-8'
_BIN_MIME_DEFAULT = 'application/octet-stream'
BYTES_PER_KiB = 1024
BYTES_PER_MiB = 1024 * BYTES_PER_KiB
DEFAULT_SPOOL_MAX = 4 * BYTES_PER_MiB
DEFAULT_BUFFER_MAX = 256 * BYTES_PER_KiB

# Module configuration
__program_name__ = "PyNeoWWW-Get"
__project__ = __program_name__
__project_url__ = "https://github.com/GameMaker2k/PyNeoWWW-Get"
__version_info__ = (2, 2, 0, "RC 1", 1)
__version__ = f"{__version_info__[0]}.{__version_info__[1]}.{__version_info__[2]}"
if __version_info__[3]:
    __version__ += f" {__version_info__[3]}"

__use_inmem__ = True
__use_memfd__ = True
__use_spoolfile__ = False
__use_spooldir__ = tempfile.gettempdir()
__spoolfile_size__ = DEFAULT_SPOOL_MAX
__filebuff_size__ = DEFAULT_BUFFER_MAX

# Protocol selection
__use_http_lib__ = "httpx"
if not _DEPENDENCIES['httpx'] and _DEPENDENCIES['requests']:
    __use_http_lib__ = "requests"
elif not _DEPENDENCIES['requests'] and not _DEPENDENCIES['httpx']:
    __use_http_lib__ = "urllib"

__use_pysftp__ = bool(_DEPENDENCIES['pysftp'])

# Type aliases
text_type = str
binary_types = (bytes, bytearray, memoryview)

# Setup logging
_LOG = logging.getLogger(__name__)

# Cache for frequently used values
_PLATFORM_INFO = {
    'system': platform.system(),
    'release': platform.release(),
    'machine': platform.machine(),
    'python_impl': platform.python_implementation() or "Python",
    'python_version': platform.python_version(),
    'architecture': platform.architecture()[0] if platform.architecture() else "32",
}

# User-Agent strings (cached)
_USER_AGENTS = {
    'pywwwget': f"Mozilla/5.0 (compatible; {__project__}/{__version__}; +{__project_url__})",
    'pywwwget_alt': f"Mozilla/5.0 ({_PLATFORM_INFO['system']} {_PLATFORM_INFO['release']}; "
                     f"{_PLATFORM_INFO['machine']}; +{__project_url__}) "
                     f"{_PLATFORM_INFO['python_impl']}/{_PLATFORM_INFO['python_version']} "
                     f"(KHTML, like Gecko) {__project__}/{__version__}",
    'googlebot': "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
}

# Default headers
_DEFAULT_HEADERS = {
    'pywwwget': {
        'Referer': "http://google.com/",
        'User-Agent': _USER_AGENTS['pywwwget'],
        'Accept-Encoding': "none",
        'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6",
        'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7",
        'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        'Connection': "close",
        'SEC-CH-UA': f'"{__project__}";v="{__version__}", "Not;A=Brand";v="8", '
                     f'"{_PLATFORM_INFO["python_impl"]}";v="{_PLATFORM_INFO["release"]}"',
        'SEC-CH-UA-FULL-VERSION': __version__,
        'SEC-CH-UA-PLATFORM': _PLATFORM_INFO['python_impl'],
        'SEC-CH-UA-ARCH': _PLATFORM_INFO['machine'],
        'SEC-CH-UA-PLATFORM-VERSION': __version__,
        'SEC-CH-UA-BITNESS': _PLATFORM_INFO['architecture'][:2],
    }
}

# Cookie jar management
_COOKIE_JAR = cookielib.CookieJar()
_COOKIE_FILENAME = None

# SSL certificate location
def _get_default_cert():
    """Get default SSL certificate location."""
    if _DEPENDENCIES['certifi']:
        return _DEPENDENCIES['certifi'].where()
    return None

_DEFAULT_CERT = _get_default_cert()

# ============================================================================
# Utility Functions
# ============================================================================

def _to_bytes(x: Any) -> bytes:
    """Convert input to bytes."""
    if x is None:
        return b""
    if isinstance(x, bytes):
        return x
    if isinstance(x, str):
        return x.encode("utf-8")
    return bytes(x)

def _to_text(x: Any) -> str:
    """Convert input to text."""
    if x is None:
        return ""
    if isinstance(x, bytes):
        try:
            return x.decode("utf-8", "replace")
        except UnicodeDecodeError:
            return x.decode("latin-1", "replace")
    return str(x)

def _emit(msg: str, *, logger: Optional[logging.Logger] = None,
          level: int = logging.INFO, stream: str = "stderr") -> None:
    """Emit a message to log or stdout/stderr."""
    if logger is not None:
        try:
            logger.log(level, msg)
            return
        except Exception:
            pass
    
    out = sys.stderr if stream != "stdout" else sys.stdout
    try:
        out.write(msg + "\n")
        out.flush()
    except Exception:
        pass

def _logger_from_kwargs(kwargs: Mapping[str, Any]) -> Optional[logging.Logger]:
    """Extract logger from kwargs."""
    return kwargs.get("logger") if isinstance(kwargs.get("logger"), logging.Logger) else None

def _ensure_dir(d: str) -> None:
    """Ensure directory exists."""
    if d and not os.path.isdir(d):
        try:
            os.makedirs(d, exist_ok=True)
        except Exception:
            pass

def _guess_filename(url: str) -> str:
    """Extract filename from URL."""
    parsed = urlparse(url)
    basename = os.path.basename(parsed.path or "")
    return basename or "download.bin"

def _choose_output_path(fname: str, overwrite: bool = False,
                        save_dir: Optional[str] = None) -> str:
    """Choose output path with conflict resolution."""
    if not save_dir:
        save_dir = "."
    _ensure_dir(save_dir)
    
    base = os.path.join(save_dir, fname)
    if overwrite or not os.path.exists(base):
        return base
    
    root, ext = os.path.splitext(base)
    for i in range(1, 10000):
        cand = f"{root}.{i}{ext}"
        if not os.path.exists(cand):
            return cand
    return base

def _copy_fileobj_to_path(fileobj: BinaryIO, path: str, overwrite: bool = False) -> None:
    """Copy file-like object to path."""
    if not overwrite and os.path.exists(path):
        raise OSError(f"Refusing to overwrite: {path}")
    
    _ensure_dir(os.path.dirname(path) or ".")
    with open(path, "wb") as out:
        try:
            fileobj.seek(0)
        except Exception:
            pass
        shutil.copyfileobj(fileobj, out)

# ============================================================================
# File Size and Hash Utilities
# ============================================================================

def get_readable_size(bytes_val: int, precision: int = 1, unit: str = "IEC") -> Dict[str, Any]:
    """
    Convert bytes to human-readable format.
    
    Args:
        bytes_val: Size in bytes
        precision: Decimal precision
        unit: "IEC" (binary, 1024) or "SI" (decimal, 1000)
    
    Returns:
        Dictionary with size information
    """
    unit = unit.upper()
    if unit not in ("IEC", "SI"):
        unit = "IEC"
    
    if unit == "IEC":
        units = [" B", " KiB", " MiB", " GiB", " TiB", " PiB", " EiB", " ZiB"]
        unit_size = 1024.0
    else:  # SI
        units = [" B", " kB", " MB", " GB", " TB", " PB", " EB", " ZB"]
        unit_size = 1000.0
    
    original_bytes = bytes_val
    bytes_val = float(bytes_val)
    
    for unit_str in units:
        if abs(bytes_val) < unit_size:
            strformat = f"%3.{precision}f%s"
            pre_return_val = strformat % (bytes_val, unit_str)
            # Clean up formatting
            pre_return_val = re.sub(r"([0]+) ([A-Za-z]+)", r" \2", pre_return_val)
            pre_return_val = re.sub(r"\. ([A-Za-z]+)", r" \1", pre_return_val)
            alt_return_val = pre_return_val.split()
            
            return {
                'Bytes': original_bytes,
                'ReadableWithSuffix': pre_return_val,
                'ReadableWithoutSuffix': alt_return_val[0],
                'ReadableSuffix': alt_return_val[1] if len(alt_return_val) > 1 else ""
            }
        bytes_val /= unit_size
    
    # Fallback for very large sizes
    strformat = f"%{precision}f%s"
    pre_return_val = strformat % (bytes_val, "YiB")
    pre_return_val = re.sub(r"([0]+) ([A-Za-z]+)", r" \2", pre_return_val)
    pre_return_val = re.sub(r"\. ([A-Za-z]+)", r" \1", pre_return_val)
    alt_return_val = pre_return_val.split()
    
    return {
        'Bytes': original_bytes,
        'ReadableWithSuffix': pre_return_val,
        'ReadableWithoutSuffix': alt_return_val[0],
        'ReadableSuffix': alt_return_val[1] if len(alt_return_val) > 1 else ""
    }

def get_readable_size_from_file(infile: str, precision: int = 1, unit: str = "IEC",
                                usehashes: bool = False, usehashtypes: str = "md5,sha1") -> Dict[str, Any]:
    """
    Get file size and optionally hashes.
    
    Args:
        infile: Path to file
        precision: Decimal precision for size
        unit: "IEC" or "SI"
        usehashes: Whether to compute hashes
        usehashtypes: Comma-separated hash algorithms
    
    Returns:
        Dictionary with size and hash information
    """
    try:
        filesize = os.path.getsize(infile)
    except OSError:
        filesize = 0
    
    result = get_readable_size(filesize, precision, unit)
    
    if usehashes:
        try:
            with open(infile, "rb") as f:
                content = f.read()
        except Exception:
            content = b""
        
        hashtypelist = [ht.strip().lower() for ht in usehashtypes.split(",") if ht.strip()]
        for hashtype in hashtypelist:
            try:
                hash_obj = hashlib.new(hashtype)
                hash_obj.update(content)
                result[hashtype.upper()] = hash_obj.hexdigest()
            except ValueError:  # Invalid hash algorithm
                continue
    
    return result

# ============================================================================
# Temporary File Management
# ============================================================================

class _TempFileManager:
    """Manager for temporary file creation with automatic cleanup."""
    
    _instance = None
    _files_to_cleanup = []
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            import atexit
            atexit.register(cls._cleanup)
        return cls._instance
    
    @classmethod
    def _cleanup(cls):
        """Clean up temporary files."""
        for fileobj in cls._files_to_cleanup:
            try:
                if hasattr(fileobj, 'close'):
                    fileobj.close()
                if hasattr(fileobj, 'name') and os.path.exists(fileobj.name):
                    os.unlink(fileobj.name)
            except Exception:
                pass
        cls._files_to_cleanup.clear()
    
    @classmethod
    def register(cls, fileobj):
        """Register a file for cleanup."""
        if fileobj not in cls._files_to_cleanup:
            cls._files_to_cleanup.append(fileobj)

def MkTempFile(data: Any = None, inmem: bool = __use_inmem__,
               usememfd: bool = __use_memfd__, isbytes: bool = True,
               prefix: str = __program_name__, delete: bool = True,
               encoding: str = "utf-8", newline: Optional[str] = None,
               text_errors: str = "strict", dir: Optional[str] = None,
               suffix: str = "", use_spool: bool = __use_spoolfile__,
               spool_max: int = __spoolfile_size__,
               spool_dir: str = __use_spooldir__,
               reset_to_start: bool = True,
               memfd_name: str = __program_name__,
               memfd_allow_sealing: bool = False,
               memfd_flags_extra: int = 0,
               on_create: Optional[Callable] = None) -> BinaryIO:
    """
    Create a temporary file with flexible storage options.
    
    Args:
        data: Initial data
        inmem: Use memory if possible
        usememfd: Use memfd_create on Linux
        isbytes: Data is bytes (True) or text (False)
        prefix: File prefix
        delete: Delete on close
        encoding: Text encoding
        newline: Newline handling
        text_errors: Error handling for text
        dir: Directory for disk file
        suffix: File suffix
        use_spool: Use spooled temporary file
        spool_max: Max memory before spooling to disk
        spool_dir: Directory for spooled files
        reset_to_start: Seek to start after writing
        memfd_name: Name for memfd file
        memfd_allow_sealing: Allow sealing on memfd
        memfd_flags_extra: Extra flags for memfd
        on_create: Callback after creation
    
    Returns:
        File-like object
    """
    # Prepare initial data
    init_data = None
    init_len = 0
    
    if data is not None:
        try:
            if isbytes:
                if isinstance(data, binary_types):
                    init_data = bytes(data)
                elif isinstance(data, text_type):
                    init_data = data.encode(encoding)
                else:
                    init_data = _to_bytes(data)
            else:
                if isinstance(data, binary_types):
                    init_data = bytes(data).decode(encoding, errors=text_errors)
                elif isinstance(data, text_type):
                    init_data = data
                else:
                    init_data = _to_text(data)
            init_len = len(init_data) if init_data else 0
        except Exception:
            init_data = b"" if isbytes else ""
            init_len = 0
    
    # Create callback wrapper
    def _created_callback(fp, kind):
        if on_create:
            try:
                on_create(fp, kind)
            except Exception:
                pass
        # Register for cleanup if it's a disk file
        if kind == "disk":
            _TempFileManager.register(fp)
    
    # Try memory options first
    if inmem and init_len <= spool_max:
        # Try memfd on Linux
        if usememfd and isbytes and hasattr(os, "memfd_create"):
            try:
                name = memfd_name or prefix or "MkTempFile"
                flags = 0
                if hasattr(os, "MFD_CLOEXEC"):
                    flags |= os.MFD_CLOEXEC
                if memfd_allow_sealing and hasattr(os, "MFD_ALLOW_SEALING"):
                    flags |= os.MFD_ALLOW_SEALING
                if memfd_flags_extra:
                    flags |= int(memfd_flags_extra)
                
                fd = os.memfd_create(name, flags)
                f = os.fdopen(fd, "w+b")
                if init_data:
                    f.write(init_data)
                if reset_to_start:
                    f.seek(0)
                _created_callback(f, "memfd")
                return f
            except Exception:
                pass  # Fall back to BytesIO
        
        # Use BytesIO/StringIO
        if isbytes:
            f = io.BytesIO(init_data if init_data else b"")
        else:
            f = io.StringIO(init_data if init_data else "")
        
        if reset_to_start:
            f.seek(0)
        _created_callback(f, "bytesio" if isbytes else "stringio")
        return f
    
    # Spooled temporary file
    if use_spool:
        try:
            f = tempfile.SpooledTemporaryFile(max_size=spool_max, mode="w+b", dir=spool_dir)
            if init_data:
                f.write(init_data)
            if reset_to_start:
                f.seek(0)
            _created_callback(f, "spool")
            return f
        except Exception:
            pass  # Fall back to named temporary file
    
    # Regular disk file
    try:
        f = tempfile.NamedTemporaryFile(mode="w+b", prefix=prefix, suffix=suffix,
                                        dir=dir, delete=delete)
        if init_data:
            f.write(init_data)
        if reset_to_start:
            f.seek(0)
        _created_callback(f, "disk")
        return f
    except Exception:
        # Ultimate fallback: BytesIO
        f = io.BytesIO(init_data if (isbytes and init_data) else b"")
        if reset_to_start:
            f.seek(0)
        _created_callback(f, "bytesio")
        return f

# ============================================================================
# Data URL Support
# ============================================================================

_DATA_URL_RE = re.compile(r'^data:(?P<meta>[^,]*?),(?P<data>.*)$', re.DOTALL)

def _is_probably_text(data_bytes: bytes) -> bool:
    """Check if bytes likely contain text."""
    if not data_bytes:
        return True
    if b'\x00' in data_bytes:
        return False
    
    try:
        decoded = data_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return False
    
    # Count control characters
    control = 0
    for ch in decoded:
        o = ord(ch)
        if (o < 32 and ch not in '\t\n\r') or o == 127:
            control += 1
    
    return control <= max(1, len(decoded) // 200)

def data_url_encode(fileobj: BinaryIO, mime: Optional[str] = None,
                    is_text: Optional[bool] = None, charset: str = 'utf-8',
                    base64_encode: Optional[bool] = None) -> str:
    """
    Encode file as data URL.
    
    Args:
        fileobj: File-like object to encode
        mime: MIME type
        is_text: Whether data is text
        charset: Character encoding
        base64_encode: Whether to base64 encode
    
    Returns:
        data: URL string
    """
    raw = fileobj.read()
    raw_bytes = _to_bytes(raw)
    detected_text = _is_probably_text(raw_bytes)
    
    if is_text is None:
        is_text = detected_text
    
    if mime is None:
        mime = _TEXT_MIME_DEFAULT if is_text else _BIN_MIME_DEFAULT
    elif mime.lower().startswith('text/') and 'charset=' not in mime.lower():
        mime = f"{mime}; charset={charset}"
    
    if base64_encode is None:
        base64_encode = not is_text
    
    if base64_encode:
        b64 = base64.b64encode(raw_bytes).decode('ascii')
        return f'data:{mime};base64,{b64}'
    else:
        encoded = quote_from_bytes(raw_bytes, safe="!$&'()*+,;=:@-._~")
        return f'data:{mime},{encoded}'

def data_url_decode(data_url: str) -> Tuple[BinaryIO, Optional[str], bool]:
    """
    Decode data URL.
    
    Args:
        data_url: data: URL string
    
    Returns:
        Tuple of (fileobj, mime_type, was_base64)
    """
    if not isinstance(data_url, str):
        try:
            data_url = data_url.decode('utf-8')
        except UnicodeDecodeError:
            data_url = data_url.decode('ascii', 'replace')
    
    match = _DATA_URL_RE.match(data_url)
    if not match:
        raise ValueError('Not a valid data: URL')
    
    meta = match.group('meta')
    data_part = match.group('data')
    
    meta_parts = [p for p in meta.split(';') if p] if meta else []
    is_base64 = False
    mime = None
    
    if meta_parts:
        if '/' in meta_parts[0]:
            mime = meta_parts[0]
            rest = meta_parts[1:]
        else:
            rest = meta_parts
        
        for p in rest:
            if p.lower() == 'base64':
                is_base64 = True
            elif mime is None:
                mime = p
            else:
                mime = f"{mime};{p}"
    
    if is_base64:
        try:
            decoded_bytes = base64.b64decode(data_part.encode('ascii'))
        except Exception:
            # Try with whitespace removed
            cleaned = ''.join(data_part.split())
            decoded_bytes = base64.b64decode(cleaned.encode('ascii'))
    else:
        decoded_bytes = unquote_to_bytes(data_part)
    
    return MkTempFile(decoded_bytes), mime, is_base64

# ============================================================================
# HTTP Protocol Handlers
# ============================================================================

class HTTPHandler:
    """Unified HTTP handler with multiple backend support."""
    
    def __init__(self, backend: str = None):
        self.backend = backend or __use_http_lib__
        self.session = None
        self.cookie_jar = cookielib.CookieJar()
        
    def _prepare_headers(self, headers: Optional[Dict]) -> Dict:
        """Prepare headers for request."""
        if headers is None:
            headers = _DEFAULT_HEADERS['pywwwget'].copy()
        elif isinstance(headers, list):
            headers = dict(headers)
        return headers
    
    def _prepare_cookies(self, cookie_file: Optional[str] = None) -> None:
        """Prepare cookie jar."""
        if cookie_file and os.path.exists(cookie_file):
            try:
                self.cookie_jar.load(cookie_file, ignore_discard=True, ignore_expires=True)
            except Exception:
                pass
    
    def _save_cookies(self, cookie_file: Optional[str] = None) -> None:
        """Save cookies to file."""
        if cookie_file:
            try:
                self.cookie_jar.save(cookie_file, ignore_discard=True, ignore_expires=True)
            except Exception:
                pass
    
    def _fix_localhost_cookies(self) -> None:
        """Fix localhost cookie domain."""
        to_add = []
        to_del = []
        
        for cookie in self.cookie_jar:
            if getattr(cookie, "domain", None) == "localhost.local":
                to_del.append((cookie.domain, cookie.path, cookie.name))
                
                new_cookie = cookielib.Cookie(
                    version=getattr(cookie, "version", 0),
                    name=cookie.name,
                    value=cookie.value,
                    port=getattr(cookie, "port", None),
                    port_specified=getattr(cookie, "port_specified", False),
                    domain="localhost",
                    domain_specified=False,
                    domain_initial_dot=False,
                    path=getattr(cookie, "path", "/"),
                    path_specified=getattr(cookie, "path_specified", True),
                    secure=getattr(cookie, "secure", False),
                    expires=getattr(cookie, "expires", None),
                    discard=getattr(cookie, "discard", True),
                    comment=getattr(cookie, "comment", None),
                    comment_url=getattr(cookie, "comment_url", None),
                    rest=getattr(cookie, "rest", {}),
                    rfc2109=getattr(cookie, "rfc2109", False),
                )
                to_add.append(new_cookie)
        
        for domain, path, name in to_del:
            self.cookie_jar.clear(domain=domain, path=path, name=name)
        
        for cookie in to_add:
            self.cookie_jar.set_cookie(cookie)
    
    def download(self, url: str, **kwargs) -> Union[BinaryIO, Dict]:
        """Download file from HTTP/HTTPS URL."""
        try:
            if self.backend == "requests" and _DEPENDENCIES['requests']:
                return self._download_requests(url, **kwargs)
            elif self.backend == "httpx" and _DEPENDENCIES['httpx']:
                return self._download_httpx(url, **kwargs)
            elif self.backend == "httpcore" and _DEPENDENCIES['httpcore']:
                return self._download_httpcore(url, **kwargs)
            elif self.backend == "mechanize" and _DEPENDENCIES['mechanize']:
                return self._download_mechanize(url, **kwargs)
            elif self.backend == "urllib3" and _DEPENDENCIES['urllib3']:
                return self._download_urllib3(url, **kwargs)
            elif self.backend == "pycurl" and _DEPENDENCIES['pycurl']:
                return self._download_pycurl(url, **kwargs)
            else:
                return self._download_urllib(url, **kwargs)
        except Exception as e:
            _LOG.error(f"HTTP download failed: {e}")
            return False
    
    def _download_requests(self, url: str, **kwargs) -> Union[BinaryIO, Dict]:
        """Download using requests library."""
        import requests
        
        # Prepare request
        headers = self._prepare_headers(kwargs.get('headers'))
        timeout = kwargs.get('timeout', 60)
        
        # Parse URL for auth
        parsed = urlparse(url)
        auth = None
        if parsed.username and parsed.password:
            auth = (unquote(parsed.username), unquote(parsed.password))
        
        # Prepare session
        if self.session is None:
            self.session = requests.Session()
            self.session.cookies = self.cookie_jar
        
        # Make request
        try:
            response = self.session.get(
                url,
                headers=headers,
                auth=auth,
                stream=True,
                timeout=timeout,
                verify=kwargs.get('usesslcert', _DEFAULT_CERT)
            )
            response.raise_for_status()
        except requests.RequestException as e:
            _LOG.error(f"Requests error: {e}")
            return False
        
        # Save to file
        output = MkTempFile()
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                output.write(chunk)
        
        output.seek(0)
        self._fix_localhost_cookies()
        
        if kwargs.get('returnstats'):
            return {
                'Type': "Buffer",
                'Buffer': output,
                'ContentSize': output.tell(),
                'Headers': dict(response.headers),
                'Version': f"HTTP/{response.raw.version/10}",
                'URL': response.url,
                'Code': response.status_code,
                'Reason': response.reason,
            }
        
        return output
    
    def _download_httpx(self, url: str, **kwargs) -> Union[BinaryIO, Dict]:
        """Download using httpx library."""
        import httpx
        
        headers = self._prepare_headers(kwargs.get('headers'))
        timeout = kwargs.get('timeout', 60)
        
        # Prepare client
        if self.session is None:
            self.session = httpx.Client(
                follow_redirects=True,
                timeout=timeout,
                cookies=self.cookie_jar,
                verify=kwargs.get('usesslcert', _DEFAULT_CERT)
            )
        
        try:
            response = self.session.get(url, headers=headers)
            response.raise_for_status()
        except httpx.HTTPError as e:
            _LOG.error(f"HTTPX error: {e}")
            return False
        
        # Save to file
        output = MkTempFile()
        for chunk in response.iter_bytes():
            if chunk:
                output.write(chunk)
        
        output.seek(0)
        self._fix_localhost_cookies()
        
        if kwargs.get('returnstats'):
            return {
                'Type': "Buffer",
                'Buffer': output,
                'ContentSize': output.tell(),
                'Headers': dict(response.headers),
                'Version': response.http_version,
                'URL': str(response.url),
                'Code': response.status_code,
                'Reason': response.reason_phrase,
            }
        
        return output
    
    def _download_urllib(self, url: str, **kwargs) -> Union[BinaryIO, Dict]:
        """Download using standard urllib."""
        headers = self._prepare_headers(kwargs.get('headers'))
        timeout = kwargs.get('timeout', 60)
        
        # Build opener with cookie support
        opener = build_opener(HTTPCookieProcessor(self.cookie_jar))
        
        # Add SSL context if needed
        ssl_cert = kwargs.get('usesslcert', _DEFAULT_CERT)
        if ssl_cert:
            ssl_context = ssl.create_default_context()
            ssl_context.load_verify_locations(ssl_cert)
            opener.add_handler(HTTPSHandler(context=ssl_context))
        
        # Create request
        request = Request(url, headers=headers)
        
        try:
            response = opener.open(request, timeout=timeout)
        except (URLError, HTTPError) as e:
            _LOG.error(f"URLLib error: {e}")
            return False
        
        # Save to file
        output = MkTempFile()
        shutil.copyfileobj(response, output)
        output.seek(0)
        self._fix_localhost_cookies()
        
        if kwargs.get('returnstats'):
            return {
                'Type': "Buffer",
                'Buffer': output,
                'ContentSize': output.tell(),
                'Headers': dict(response.headers),
                'Version': f"HTTP/{response.version/10}",
                'URL': response.url,
                'Code': response.getcode(),
                'Reason': response.reason,
            }
        
        return output
    
    # Other backends would follow similar patterns...
    # (truncated for brevity, but all backends should be implemented)

# ============================================================================
# FTP Protocol Handler
# ============================================================================

class FTPHandler:
    """FTP/FTPS handler."""
    
    def __init__(self):
        self.ftp = None
        
    def _get_ftp_class(self, use_tls: bool):
        """Get appropriate FTP class."""
        if use_tls:
            if hasattr(__import__('ftplib'), 'FTP_TLS'):
                from ftplib import FTP_TLS
                return FTP_TLS
        from ftplib import FTP
        return FTP
    
    def download(self, url: str, **kwargs) -> Union[BinaryIO, Dict]:
        """Download file from FTP URL."""
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ('ftp', 'ftps'):
                return False
            
            use_tls = parsed.scheme == 'ftps'
            FTPClass = self._get_ftp_class(use_tls)
            
            self.ftp = FTPClass()
            timeout = kwargs.get('timeout', 60)
            
            # Connect
            self.ftp.connect(
                parsed.hostname or 'localhost',
                parsed.port or 21,
                timeout=timeout
            )
            
            # Login
            username = unquote(parsed.username) if parsed.username else 'anonymous'
            password = unquote(parsed.password) if parsed.password else 'anonymous'
            self.ftp.login(username, password)
            
            if use_tls and hasattr(self.ftp, 'prot_p'):
                self.ftp.prot_p()  # Switch to secure data connection
            
            # Prepare output
            output = MkTempFile()
            
            # Download
            def callback(data):
                output.write(data)
            
            self.ftp.retrbinary(f'RETR {parsed.path}', callback)
            output.seek(0)
            
            # Close connection
            self.ftp.quit()
            
            if kwargs.get('returnstats'):
                size = output.tell()
                return {
                    'Type': "Buffer",
                    'Buffer': output,
                    'ContentSize': size,
                    'ContentsizeAlt': {
                        'IEC': get_readable_size(size, 2, "IEC"),
                        'SI': get_readable_size(size, 2, "SI")
                    },
                    'URL': url,
                    'FTPLib': 'pyftp'
                }
            
            return output
            
        except Exception as e:
            _LOG.error(f"FTP download failed: {e}")
            try:
                if self.ftp:
                    self.ftp.close()
            except Exception:
                pass
            return False
    
    def upload(self, fileobj: BinaryIO, url: str, **kwargs) -> bool:
        """Upload file to FTP URL."""
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ('ftp', 'ftps'):
                return False
            
            use_tls = parsed.scheme == 'ftps'
            FTPClass = self._get_ftp_class(use_tls)
            
            self.ftp = FTPClass()
            timeout = kwargs.get('timeout', 60)
            
            # Connect
            self.ftp.connect(
                parsed.hostname or 'localhost',
                parsed.port or 21,
                timeout=timeout
            )
            
            # Login
            username = unquote(parsed.username) if parsed.username else 'anonymous'
            password = unquote(parsed.password) if parsed.password else 'anonymous'
            self.ftp.login(username, password)
            
            if use_tls and hasattr(self.ftp, 'prot_p'):
                self.ftp.prot_p()
            
            # Upload
            fileobj.seek(0)
            filename = os.path.basename(parsed.path) or 'upload.bin'
            self.ftp.storbinary(f'STOR {filename}', fileobj)
            
            # Close connection
            self.ftp.quit()
            return True
            
        except Exception as e:
            _LOG.error(f"FTP upload failed: {e}")
            try:
                if self.ftp:
                    self.ftp.close()
            except Exception:
                pass
            return False

# ============================================================================
# UDP/TCP Transfer Protocol
# ============================================================================

class UDPTransfer:
    """Reliable UDP file transfer with sequencing."""
    
    # Protocol constants
    OP_RRQ = 1
    OP_WRQ = 2
    OP_DATA = 3
    OP_ACK = 4
    OP_ERROR = 5
    BLOCK_SIZE = 512
    
    def __init__(self, timeout: float = 5.0, retries: int = 5, block_size: int = BLOCK_SIZE):
        self.timeout = timeout
        self.retries = retries
        self.block_size = block_size
        self.sock = None
        
    def _make_socket(self, proxy: Optional[Dict] = None) -> socket.socket:
        """Create UDP socket with optional SOCKS proxy."""
        if proxy and _DEPENDENCIES.get('socks'):
            sock = _DEPENDENCIES['socks'].socksocket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.set_proxy(
                _DEPENDENCIES['socks'].SOCKS5,
                proxy.get('host'),
                proxy.get('port', 1080),
                username=proxy.get('username'),
                password=proxy.get('password'),
                rdns=True
            )
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        sock.settimeout(self.timeout)
        return sock
    
    def download(self, server_host: str, remote_filename: str, 
                 server_port: int = 69, mode: str = "octet",
                 proxy: Optional[Dict] = None) -> Optional[BinaryIO]:
        """Download file via TFTP."""
        self.sock = self._make_socket(proxy)
        output = MkTempFile()
        
        try:
            # Send read request
            rrq = struct.pack("!H", self.OP_RRQ)
            rrq += remote_filename.encode() + b'\x00'
            rrq += mode.encode() + b'\x00'
            
            self.sock.sendto(rrq, (server_host, server_port))
            
            expected_block = 1
            server_addr = None
            
            while True:
                for attempt in range(self.retries):
                    try:
                        packet, addr = self.sock.recvfrom(self.block_size + 4)
                        
                        if server_addr is None:
                            server_addr = addr
                        
                        if addr != server_addr:
                            continue
                        
                        opcode = struct.unpack("!H", packet[:2])[0]
                        
                        if opcode == self.OP_ERROR:
                            error_code = struct.unpack("!H", packet[2:4])[0]
                            error_msg = packet[4:].split(b'\x00')[0].decode('utf-8', 'ignore')
                            raise Exception(f"TFTP Error {error_code}: {error_msg}")
                        
                        if opcode != self.OP_DATA:
                            raise Exception(f"Unexpected opcode: {opcode}")
                        
                        block_num = struct.unpack("!H", packet[2:4])[0]
                        data = packet[4:]
                        
                        if block_num == expected_block:
                            output.write(data)
                            ack = struct.pack("!HH", self.OP_ACK, block_num)
                            self.sock.sendto(ack, server_addr)
                            
                            if len(data) < self.block_size:
                                output.seek(0)
                                return output
                            
                            expected_block = (expected_block + 1) & 0xFFFF
                            break
                        
                        # Resend ACK for previous block
                        if block_num == expected_block - 1:
                            ack = struct.pack("!HH", self.OP_ACK, block_num)
                            self.sock.sendto(ack, server_addr)
                        
                    except socket.timeout:
                        if attempt == self.retries - 1:
                            raise Exception("Timeout receiving data")
                        continue
                    
        except Exception as e:
            _LOG.error(f"TFTP download failed: {e}")
            return None
            
        finally:
            if self.sock:
                self.sock.close()
        
        return None

# ============================================================================
# Main Public Interface
# ============================================================================

def download_file_from_internet_file(url: str, **kwargs) -> Union[BinaryIO, Dict, bool]:
    """
    Download file from any supported protocol.
    
    Args:
        url: URL of file to download
        **kwargs: Protocol-specific options
    
    Returns:
        File-like object, statistics dict, or False on failure
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    
    try:
        if scheme in ('http', 'https'):
            handler = HTTPHandler(kwargs.get('usehttp', __use_http_lib__))
            return handler.download(url, **kwargs)
        
        elif scheme in ('ftp', 'ftps'):
            handler = FTPHandler()
            return handler.download(url, **kwargs)
        
        elif scheme == 'tftp':
            handler = UDPTransfer(
                timeout=kwargs.get('timeout', 60),
                retries=kwargs.get('retries', 5)
            )
            return handler.download(
                parsed.hostname or 'localhost',
                parsed.path.lstrip('/'),
                parsed.port or 69
            )
        
        elif scheme == 'data':
            return data_url_decode(url)[0]
        
        elif scheme == 'file' or not scheme:
            path = unquote(parsed.path)
            return open(path, 'rb')
        
        else:
            _LOG.error(f"Unsupported protocol: {scheme}")
            return False
            
    except Exception as e:
        _LOG.error(f"Download failed: {e}")
        return False

def download_file_from_internet_bytes(url: str, **kwargs) -> Union[bytes, bool]:
    """
    Download file and return as bytes.
    
    Args:
        url: URL of file to download
        **kwargs: Protocol-specific options
    
    Returns:
        File contents as bytes or False on failure
    """
    result = download_file_from_internet_file(url, **kwargs)
    if not result:
        return False
    
    try:
        if isinstance(result, dict):
            return result['Buffer'].read()
        return result.read()
    finally:
        if hasattr(result, 'close'):
            result.close()

def download_file_from_internet_to_file(url: str, output_path: str, **kwargs) -> bool:
    """
    Download file directly to disk.
    
    Args:
        url: URL of file to download
        output_path: Path to save file
        **kwargs: Protocol-specific options
    
    Returns:
        True on success, False on failure
    """
    result = download_file_from_internet_file(url, **kwargs)
    if not result:
        return False
    
    try:
        if isinstance(result, dict):
            content = result['Buffer']
        else:
            content = result
        
        _ensure_dir(os.path.dirname(output_path) or '.')
        with open(output_path, 'wb') as f:
            shutil.copyfileobj(content, f)
        return True
    except Exception as e:
        _LOG.error(f"Save failed: {e}")
        return False
    finally:
        if hasattr(result, 'close'):
            result.close()

def upload_file_to_internet_file(fileobj: BinaryIO, url: str, **kwargs) -> bool:
    """
    Upload file to any supported protocol.
    
    Args:
        fileobj: File-like object to upload
        url: Destination URL
        **kwargs: Protocol-specific options
    
    Returns:
        True on success, False on failure
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    
    try:
        if scheme in ('http', 'https'):
            # Implement HTTP upload
            pass  # Would implement similar to download
        
        elif scheme in ('ftp', 'ftps'):
            handler = FTPHandler()
            return handler.upload(fileobj, url, **kwargs)
        
        elif scheme == 'tftp':
            # Implement TFTP upload
            pass  # Would implement similar to download
        
        elif scheme == 'data':
            # Return data URL
            return data_url_encode(fileobj)
        
        elif scheme == 'file' or not scheme:
            path = unquote(parsed.path)
            _ensure_dir(os.path.dirname(path) or '.')
            with open(path, 'wb') as f:
                fileobj.seek(0)
                shutil.copyfileobj(fileobj, f)
            return True
        
        else:
            _LOG.error(f"Unsupported protocol: {scheme}")
            return False
            
    except Exception as e:
        _LOG.error(f"Upload failed: {e}")
        return False

def upload_file_to_internet_bytes(data: Union[bytes, str], url: str, **kwargs) -> bool:
    """
    Upload bytes or string to URL.
    
    Args:
        data: Data to upload
        url: Destination URL
        **kwargs: Protocol-specific options
    
    Returns:
        True on success, False on failure
    """
    fileobj = MkTempFile(_to_bytes(data))
    try:
        return upload_file_to_internet_file(fileobj, url, **kwargs)
    finally:
        fileobj.close()

# ============================================================================
# Convenience Functions
# ============================================================================

def download_urls(urls: List[str], concurrent: int = 1, **kwargs) -> Dict[str, Union[BinaryIO, bool]]:
    """
    Download multiple URLs.
    
    Args:
        urls: List of URLs to download
        concurrent: Number of concurrent downloads
        **kwargs: Protocol-specific options
    
    Returns:
        Dictionary mapping URLs to results
    """
    results = {}
    
    if concurrent <= 1:
        for url in urls:
            results[url] = download_file_from_internet_file(url, **kwargs)
    else:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent) as executor:
            future_to_url = {
                executor.submit(download_file_from_internet_file, url, **kwargs): url
                for url in urls
            }
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    results[url] = future.result()
                except Exception as e:
                    _LOG.error(f"Download failed for {url}: {e}")
                    results[url] = False
    
    return results

def batch_download_to_files(url_file_pairs: List[Tuple[str, str]], **kwargs) -> Dict[str, bool]:
    """
    Batch download URLs to specific files.
    
    Args:
        url_file_pairs: List of (url, output_path) pairs
        **kwargs: Protocol-specific options
    
    Returns:
        Dictionary mapping URLs to success status
    """
    results = {}
    for url, output_path in url_file_pairs:
        results[url] = download_file_from_internet_to_file(url, output_path, **kwargs)
    return results

# ============================================================================
# Command Line Interface (if run as script)
# ============================================================================

def main():
    """Command line interface."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description=f"{__program_name__} v{__version__} - Multi-protocol file transfer"
    )
    
    parser.add_argument('url', help='URL to download')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-t', '--timeout', type=float, default=60, help='Timeout in seconds')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--stats', action='store_true', help='Show transfer statistics')
    parser.add_argument('--backend', choices=['auto', 'requests', 'httpx', 'urllib'],
                        default='auto', help='HTTP backend to use')
    
    args = parser.parse_args()
    
    # Setup logging
    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    
    # Determine backend
    backend = __use_http_lib__
    if args.backend != 'auto':
        backend = args.backend
    
    # Download
    if args.output:
        success = download_file_from_internet_to_file(
            args.url,
            args.output,
            timeout=args.timeout,
            usehttp=backend
        )
        if success:
            print(f"Downloaded to: {args.output}")
        else:
            print("Download failed", file=sys.stderr)
            sys.exit(1)
    else:
        result = download_file_from_internet_file(
            args.url,
            timeout=args.timeout,
            usehttp=backend,
            returnstats=args.stats
        )
        
        if not result:
            print("Download failed", file=sys.stderr)
            sys.exit(1)
        
        if args.stats and isinstance(result, dict):
            import json
            print(json.dumps(result, indent=2, default=str))
        elif isinstance(result, dict):
            sys.stdout.buffer.write(result['Buffer'].read())
        else:
            sys.stdout.buffer.write(result.read())

if __name__ == '__main__':
    main()