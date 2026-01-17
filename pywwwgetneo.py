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
import socket
import shutil
import logging
import platform

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


# ==========================================================
# NEW/CHANGED CODE BEGINS HERE (fixed + detect_cwd integrated)
# ==========================================================

def detect_cwd(ftp, file_dir):
    """
    Test whether cwd (FTP/FTPS) or chdir (SFTP) into file_dir works.
    Returns True if it does, False if not (so absolute paths should be used).
    """
    if not file_dir or file_dir in ("/", ""):
        return False

    # FTP / FTPS
    if hasattr(ftp, "cwd"):
        try:
            ftp.cwd(file_dir)
            return True
        except all_errors:
            return False
        except Exception:
            return False

    # Paramiko SFTPClient (chdir)
    if hasattr(ftp, "chdir"):
        try:
            ftp.chdir(file_dir)
            return True
        except (OSError, IOError):
            return False
        except Exception:
            return False

    return False


def _normalize_auth(urlparts):
    """
    Keep original semantics:
    - default user: anonymous
    - password: anonymous if user anonymous and no password; else empty string
    """
    if urlparts.username is not None:
        username = urlparts.username
    else:
        username = "anonymous"

    if urlparts.password is not None:
        password = urlparts.password
    elif username == "anonymous":
        password = "anonymous"
    else:
        password = ""

    return username, password


# ---------------------------
# FTP / FTPS
# ---------------------------

def download_file_from_ftp_file(url):
    urlparts = urlparse(url)

    # Keep original cross-dispatch behavior
    if urlparts.scheme == "sftp":
        if __use_pysftp__ and havepysftp:
            return download_file_from_pysftp_file(url)
        return download_file_from_sftp_file(url)
    elif urlparts.scheme in ("http", "https"):
        return download_file_from_http_file(url)

    # Only FTP/FTPS here
    if urlparts.scheme == "ftp":
        ftp = FTP()
    elif urlparts.scheme == "ftps" and ftpssl:
        ftp = FTP_TLS()
    else:
        return False

    ftp_port = urlparts.port if urlparts.port is not None else 21
    username, password = _normalize_auth(urlparts)

    try:
        ftp.connect(urlparts.hostname, ftp_port)
    except (socket.gaierror, socket.timeout):
        log.info("Error With URL " + url)
        return False
    except Exception:
        log.info("Error With URL " + url)
        return False

    try:
        # FIX: use normalized username/password
        ftp.login(username, password)

        if urlparts.scheme == "ftps":
            ftp.prot_p()

        ftpfile = BytesIO()

        file_dir = os.path.dirname(urlparts.path)
        file_name = os.path.basename(urlparts.path)

        # Use cwd if possible; otherwise use absolute
        retr_target = file_name if (detect_cwd(ftp, file_dir) and file_name) else urlparts.path
        ftp.retrbinary("RETR " + retr_target, ftpfile.write)

        ftpfile.seek(0, 0)
        return ftpfile

    except Exception:
        log.info("Error With URL " + url)
        return False
    finally:
        try:
            ftp.close()
        except Exception:
            pass


def download_file_from_ftp_string(url):
    ftpfile = download_file_from_ftp_file(url)
    return ftpfile.read() if ftpfile else False


def upload_file_to_ftp_file(ftpfile, url):
    urlparts = urlparse(url)

    # Keep original cross-dispatch behavior
    if urlparts.scheme == "sftp":
        if __use_pysftp__ and havepysftp:
            return upload_file_to_pysftp_file(ftpfile, url)
        return upload_file_to_sftp_file(ftpfile, url)
    elif urlparts.scheme in ("http", "https"):
        return False

    if urlparts.scheme == "ftp":
        ftp = FTP()
    elif urlparts.scheme == "ftps" and ftpssl:
        ftp = FTP_TLS()
    else:
        return False

    ftp_port = urlparts.port if urlparts.port is not None else 21
    username, password = _normalize_auth(urlparts)

    try:
        ftp.connect(urlparts.hostname, ftp_port)
    except (socket.gaierror, socket.timeout):
        log.info("Error With URL " + url)
        return False
    except Exception:
        log.info("Error With URL " + url)
        return False

    try:
        ftp.login(username, password)

        if urlparts.scheme == "ftps":
            ftp.prot_p()

        try:
            ftpfile.seek(0, 0)
        except Exception:
            pass

        file_dir = os.path.dirname(urlparts.path)
        file_name = os.path.basename(urlparts.path)

        stor_target = file_name if (detect_cwd(ftp, file_dir) and file_name) else urlparts.path
        ftp.storbinary("STOR " + stor_target, ftpfile)

        try:
            ftpfile.seek(0, 0)
        except Exception:
            pass

        return ftpfile

    except Exception:
        log.info("Error With URL " + url)
        return False
    finally:
        try:
            ftp.close()
        except Exception:
            pass


def upload_file_to_ftp_string(ftpstring, url):
    ftpfileo = BytesIO(ftpstring)
    try:
        ftpfile = upload_file_to_ftp_file(ftpfileo, url)
        return ftpfile if ftpfile else False
    finally:
        try:
            ftpfileo.close()
        except Exception:
            pass


# ---------------------------
# RawIteratorWrapper
# ---------------------------

class RawIteratorWrapper:
    def __init__(self, iterator):
        self.iterator = iterator
        self.buffer = b""
        self._iterator_exhausted = False

    def read(self, size=-1):
        if self._iterator_exhausted:
            return b""
        while size < 0 or len(self.buffer) < size:
            try:
                chunk = next(self.iterator)
                if chunk:
                    self.buffer += chunk
            except StopIteration:
                self._iterator_exhausted = True
                break
        if size < 0:
            size = len(self.buffer)
        result, self.buffer = self.buffer[:size], self.buffer[size:]
        return result


# ---------------------------
# HTTP / HTTPS (fix requests syntax)
# ---------------------------

def download_file_from_http_file(url, headers=None, usehttp=__use_http_lib__):
    if headers is None:
        headers = {}

    urlparts = urlparse(url)
    username = urlparts.username
    password = urlparts.password

    # Rebuild URL without creds
    netloc = urlparts.hostname or ''
    if urlparts.port:
        netloc += ':' + str(urlparts.port)
    rebuilt_url = urlunparse((urlparts.scheme, netloc, urlparts.path,
                              urlparts.params, urlparts.query, urlparts.fragment))

    # Cross-dispatch
    if urlparts.scheme == "sftp":
        if __use_pysftp__ and havepysftp:
            return download_file_from_pysftp_file(url)
        return download_file_from_sftp_file(url)
    elif urlparts.scheme in ("ftp", "ftps"):
        return download_file_from_ftp_file(url)

    httpfile = BytesIO()

    # 1) Requests branch
    if usehttp == 'requests' and haverequests:
        try:
            if username and password:
                response = requests.get(
                    rebuilt_url, headers=headers, auth=(username, password),
                    timeout=(5, 30), stream=True
                )
            else:
                # FIXED LINE
                response = requests.get(
                    rebuilt_url, headers=headers, timeout=(5, 30), stream=True
                )
            response.raw.decode_content = True
            shutil.copyfileobj(response.raw, httpfile)
        except Exception:
            return False

    # 2) HTTPX branch
    elif usehttp == 'httpx' and havehttpx:
        try:
            with httpx.Client(follow_redirects=True) as client:
                if username and password:
                    response = client.get(rebuilt_url, headers=headers, auth=(username, password))
                else:
                    response = client.get(rebuilt_url, headers=headers)
                raw_wrapper = RawIteratorWrapper(response.iter_bytes())
                shutil.copyfileobj(raw_wrapper, httpfile)
        except Exception:
            return False

    # 3) Mechanize branch
    elif usehttp == 'mechanize' and havemechanize:
        try:
            br = mechanize.Browser()
            br.set_handle_robots(False)
            if headers:
                br.addheaders = list(headers.items())
            if username and password:
                br.add_password(rebuilt_url, username, password)
            response = br.open(rebuilt_url)
            shutil.copyfileobj(response, httpfile)
        except Exception:
            return False

    # 4) Fallback to urllib
    else:
        try:
            request = Request(rebuilt_url, headers=headers)
            if username and password and HTTPPasswordMgrWithDefaultRealm is not None:
                password_mgr = HTTPPasswordMgrWithDefaultRealm()
                password_mgr.add_password(None, rebuilt_url, username, password)
                auth_handler = HTTPBasicAuthHandler(password_mgr)
                opener = build_opener(auth_handler)
            else:
                opener = build_opener()
            response = opener.open(request)
            shutil.copyfileobj(response, httpfile)
        except Exception:
            return False

    httpfile.seek(0, 0)
    return httpfile


def download_file_from_http_string(url, headers=geturls_headers_pywwwget_python_alt, usehttp=__use_http_lib__):
    httpfile = download_file_from_http_file(url, headers, usehttp)
    return httpfile.read() if httpfile else False


# ---------------------------
# SFTP (Paramiko) with detect_cwd
# ---------------------------

if(haveparamiko):
    def download_file_from_sftp_file(url):
        urlparts = urlparse(url)

        # Cross-dispatch
        if urlparts.scheme in ("ftp", "ftps"):
            return download_file_from_ftp_file(url)
        elif urlparts.scheme in ("http", "https"):
            return download_file_from_http_file(url)

        if urlparts.scheme != "sftp":
            return False

        sftp_port = urlparts.port if urlparts.port is not None else 22
        username, password = _normalize_auth(urlparts)

        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(urlparts.hostname, port=sftp_port, username=username, password=password)
        except paramiko.ssh_exception.SSHException:
            return False
        except (socket.gaierror, socket.timeout):
            log.info("Error With URL " + url)
            return False
        except Exception:
            return False

        try:
            sftp = ssh.open_sftp()
            try:
                sftpfile = BytesIO()

                file_dir = os.path.dirname(urlparts.path)
                file_name = os.path.basename(urlparts.path)

                get_target = file_name if (detect_cwd(sftp, file_dir) and file_name) else urlparts.path
                sftp.getfo(get_target, sftpfile)

                sftpfile.seek(0, 0)
                return sftpfile
            finally:
                try:
                    sftp.close()
                except Exception:
                    pass
        finally:
            try:
                ssh.close()
            except Exception:
                pass
else:
    def download_file_from_sftp_file(url):
        return False


if(haveparamiko):
    def download_file_from_sftp_string(url):
        sftpfile = download_file_from_sftp_file(url)
        return sftpfile.read() if sftpfile else False
else:
    def download_file_from_sftp_string(url):
        return False


if(haveparamiko):
    def upload_file_to_sftp_file(sftpfile, url):
        urlparts = urlparse(url)

        # Cross-dispatch
        if urlparts.scheme in ("ftp", "ftps"):
            return upload_file_to_ftp_file(sftpfile, url)
        elif urlparts.scheme in ("http", "https"):
            return False

        if urlparts.scheme != "sftp":
            return False

        sftp_port = urlparts.port if urlparts.port is not None else 22
        username, password = _normalize_auth(urlparts)

        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(urlparts.hostname, port=sftp_port, username=username, password=password)
        except paramiko.ssh_exception.SSHException:
            return False
        except (socket.gaierror, socket.timeout):
            log.info("Error With URL " + url)
            return False
        except Exception:
            return False

        try:
            sftp = ssh.open_sftp()
            try:
                try:
                    sftpfile.seek(0, 0)
                except Exception:
                    pass

                file_dir = os.path.dirname(urlparts.path)
                file_name = os.path.basename(urlparts.path)

                put_target = file_name if (detect_cwd(sftp, file_dir) and file_name) else urlparts.path
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
        finally:
            try:
                ssh.close()
            except Exception:
                pass
else:
    def upload_file_to_sftp_file(sftpfile, url):
        return False


if(haveparamiko):
    def upload_file_to_sftp_string(sftpstring, url):
        # FIX: original had upload_file_to_sftp_files typo
        sftpfileo = BytesIO(sftpstring)
        try:
            sftpfile = upload_file_to_sftp_file(sftpfileo, url)
            return sftpfile if sftpfile else False
        finally:
            try:
                sftpfileo.close()
            except Exception:
                pass
else:
    def upload_file_to_sftp_string(sftpstring, url):
        return False


# ---------------------------
# PySFTP FIXED (your original was broken / referenced ssh)
# ---------------------------

if(havepysftp):
    def download_file_from_pysftp_file(url):
        urlparts = urlparse(url)

        # Cross-dispatch
        if urlparts.scheme in ("ftp", "ftps"):
            return download_file_from_ftp_file(url)
        elif urlparts.scheme in ("http", "https"):
            return download_file_from_http_file(url)

        if urlparts.scheme != "sftp":
            return False

        sftp_port = urlparts.port if urlparts.port is not None else 22
        username, password = _normalize_auth(urlparts)

        try:
            with pysftp.Connection(urlparts.hostname, port=sftp_port,
                                  username=username, password=password) as sftp:
                file_dir = os.path.dirname(urlparts.path)
                file_name = os.path.basename(urlparts.path)

                # Try chdir; if fails, use absolute
                can_cwd = False
                try:
                    if file_dir and file_dir not in ("/", ""):
                        sftp.chdir(file_dir)
                        can_cwd = True
                except Exception:
                    can_cwd = False

                get_target = file_name if (can_cwd and file_name) else urlparts.path

                sftpfile = BytesIO()
                sftp.getfo(get_target, sftpfile)
                sftpfile.seek(0, 0)
                return sftpfile
        except Exception:
            return False
else:
    def download_file_from_pysftp_file(url):
        return False


if(havepysftp):
    def download_file_from_pysftp_string(url):
        sftpfile = download_file_from_pysftp_file(url)
        return sftpfile.read() if sftpfile else False
else:
    def download_file_from_pyftp_string(url):
        return False


if(havepysftp):
    def upload_file_to_pysftp_file(sftpfile, url):
        urlparts = urlparse(url)

        if urlparts.scheme in ("ftp", "ftps"):
            return upload_file_to_ftp_file(sftpfile, url)
        elif urlparts.scheme in ("http", "https"):
            return False

        if urlparts.scheme != "sftp":
            return False

        sftp_port = urlparts.port if urlparts.port is not None else 22
        username, password = _normalize_auth(urlparts)

        try:
            with pysftp.Connection(urlparts.hostname, port=sftp_port,
                                  username=username, password=password) as sftp:
                file_dir = os.path.dirname(urlparts.path)
                file_name = os.path.basename(urlparts.path)

                can_cwd = False
                try:
                    if file_dir and file_dir not in ("/", ""):
                        sftp.chdir(file_dir)
                        can_cwd = True
                except Exception:
                    can_cwd = False

                put_target = file_name if (can_cwd and file_name) else urlparts.path

                try:
                    sftpfile.seek(0, 0)
                except Exception:
                    pass

                sftp.putfo(sftpfile, put_target)

                try:
                    sftpfile.seek(0, 0)
                except Exception:
                    pass

                return sftpfile
        except Exception:
            return False
else:
    def upload_file_to_pysftp_file(sftpfile, url):
        return False


if(havepysftp):
    def upload_file_to_pysftp_string(sftpstring, url):
        sftpfileo = BytesIO(sftpstring)
        try:
            sftpfile = upload_file_to_pysftp_file(sftpfileo, url)
            return sftpfile if sftpfile else False
        finally:
            try:
                sftpfileo.close()
            except Exception:
                pass
else:
    def upload_file_to_pysftp_string(sftpstring, url):
        return False


# ---------------------------
# Unified dispatch
# ---------------------------

def download_file_from_internet_file(url, headers=geturls_headers_pywwwget_python_alt, usehttp=__use_http_lib__):
    urlparts = urlparse(url)
    if(urlparts.scheme == "http" or urlparts.scheme == "https"):
        return download_file_from_http_file(url, headers, usehttp)
    elif(urlparts.scheme == "ftp" or urlparts.scheme == "ftps"):
        return download_file_from_ftp_file(url)
    elif(urlparts.scheme == "sftp"):
        if(__use_pysftp__ and havepysftp):
            return download_file_from_pysftp_file(url)
        else:
            return download_file_from_sftp_file(url)
    else:
        return False


def download_file_from_internet_string(url, headers=geturls_headers_pywwwget_python_alt, usehttp=__use_http_lib__):
    urlparts = urlparse(url)
    if(urlparts.scheme == "http" or urlparts.scheme == "https"):
        return download_file_from_http_string(url, headers, usehttp)
    elif(urlparts.scheme == "ftp" or urlparts.scheme == "ftps"):
        return download_file_from_ftp_string(url)
    elif(urlparts.scheme == "sftp"):
        if(__use_pysftp__ and havepysftp):
            return download_file_from_pysftp_string(url)
        else:
            return download_file_from_sftp_string(url)
    else:
        return False


def upload_file_to_internet_file(ifp, url):
    urlparts = urlparse(url)
    if(urlparts.scheme == "http" or urlparts.scheme == "https"):
        return False
    elif(urlparts.scheme == "ftp" or urlparts.scheme == "ftps"):
        return upload_file_to_ftp_file(ifp, url)
    elif(urlparts.scheme == "sftp"):
        if(__use_pysftp__ and havepysftp):
            return upload_file_to_pysftp_file(ifp, url)
        else:
            return upload_file_to_sftp_file(ifp, url)
    else:
        return False


def upload_file_to_internet_string(ifp, url):
    urlparts = urlparse(url)
    if(urlparts.scheme == "http" or urlparts.scheme == "https"):
        return False
    elif(urlparts.scheme == "ftp" or urlparts.scheme == "ftps"):
        return upload_file_to_ftp_string(ifp, url)
    elif(urlparts.scheme == "sftp"):
        if(__use_pysftp__ and havepysftp):
            return upload_file_to_pysftp_string(ifp, url)
        else:
            return upload_file_to_sftp_string(ifp, url)
    else:
        return False
