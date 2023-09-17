#!/usr/bin/env python

'''
    This program is free software; you can redistribute it and/or modify
    it under the terms of the Revised BSD License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Revised BSD License for more details.

    Copyright 2016-2023 Game Maker 2k - https://github.com/GameMaker2k
    Copyright 2016-2023 Kazuki Przyborowski - https://github.com/KazukiPrzyborowski

    $FileInfo: pywwwget.py - Last Update: 9/17/2023 Ver. 1.2.0 RC 1 - Author: cooldude2k $
'''

from __future__ import division, absolute_import, print_function;
import re, os, sys, hashlib, shutil, platform, tempfile, urllib, gzip, time, argparse, cgi, subprocess, socket;
import logging as log;
from ftplib import FTP, FTP_TLS;
from base64 import b64encode;
haverequests = False;
try:
 import requests;
 haverequests = True;
except ImportError:
 haverequests = False;
havemechanize = False;
try:
 import mechanize;
 havemechanize = True;
except ImportError:
 havemechanize = False;
haveparamiko = False;
try:
 import paramiko;
 haveparamiko = True;
except ImportError:
 haveparamiko = False;
haveurllib3 = False;
try:
 import urllib3;
 haveurllib3 = True;
except ImportError:
 haveurllib3 = False;
havehttplib2 = False;
try:
 from httplib2 import HTTPConnectionWithTimeout, HTTPSConnectionWithTimeout;
 havehttplib2 = True;
except ImportError:
 havehttplib2 = False;
havehttpx = False;
try:
 import httpx;
 havehttpx = True;
except ImportError:
 havehttpx = False;
havehttpcore = False;
try:
 import httpcore;
 havehttpcore = True;
except ImportError:
 havehttpcore = False;
havebrotli = False;
try:
 import brotli;
 havebrotli = True;
except ImportError:
 havebrotli = False;
havezstd = False;
try:
 import zstandard;
 havezstd = True;
except ImportError:
 havezstd = False;
if(sys.version[0]=="2"):
 try:
  from cStringIO import StringIO;
 except ImportError:
  from StringIO import StringIO;
 # From http://python-future.org/compatible_idioms.html
 from urlparse import urlparse, urlunparse, urlsplit, urlunsplit, urljoin;
 from urllib import urlencode;
 from urllib import urlopen as urlopenalt;
 from urllib2 import urlopen, Request, install_opener, HTTPError, URLError, build_opener, HTTPCookieProcessor;
 import urlparse, cookielib;
 from httplib import HTTPConnection, HTTPSConnection;
if(sys.version[0]>="3"):
 from io import StringIO, BytesIO;
 # From http://python-future.org/compatible_idioms.html
 from urllib.parse import urlparse, urlunparse, urlsplit, urlunsplit, urljoin, urlencode;
 from urllib.request import urlopen, Request, install_opener, build_opener, HTTPCookieProcessor;
 from urllib.error import HTTPError, URLError;
 import urllib.parse as urlparse;
 import http.cookiejar as cookielib;
 from http.client import HTTPConnection, HTTPSConnection;

__program_name__ = "PyWWW-Get";
__program_alt_name__ = "PyWWWGet";
__program_small_name__ = "wwwget";
__project__ = __program_name__;
__project_url__ = "https://github.com/GameMaker2k/PyWWW-Get";
__version_info__ = (1, 2, 0, "RC 1", 1);
__version_date_info__ = (2023, 9, 17, "RC 1", 1);
__version_date__ = str(__version_date_info__[0])+"."+str(__version_date_info__[1]).zfill(2)+"."+str(__version_date_info__[2]).zfill(2);
__revision__ = __version_info__[3];
__revision_id__ = "$Id$";
if(__version_info__[4] is not None):
 __version_date_plusrc__ = __version_date__+"-"+str(__version_date_info__[4]);
if(__version_info__[4] is None):
 __version_date_plusrc__ = __version_date__;
if(__version_info__[3] is not None):
 __version__ = str(__version_info__[0])+"."+str(__version_info__[1])+"."+str(__version_info__[2])+" "+str(__version_info__[3]);
if(__version_info__[3] is None):
 __version__ = str(__version_info__[0])+"."+str(__version_info__[1])+"."+str(__version_info__[2]);

tmpfileprefix = "py"+str(sys.version_info[0])+__program_small_name__+str(__version_info__[0])+"-";
tmpfilesuffix = "-";
pytempdir = tempfile.gettempdir();

PyBitness = platform.architecture();
if(PyBitness=="32bit" or PyBitness=="32"):
 PyBitness = "32";
elif(PyBitness=="64bit" or PyBitness=="64"):
 PyBitness = "64";
else:
 PyBitness = "32";

compression_supported = "gzip, deflate";
if(havebrotli):
 compression_supported = "gzip, deflate, br";
else:
 compression_supported = "gzip, deflate";

geturls_cj = cookielib.CookieJar();
windowsNT4_ua_string = "Windows NT 4.0";
windowsNT4_ua_addon = {'SEC-CH-UA-PLATFORM': "Windows", 'SEC-CH-UA-ARCH': "x86", 'SEC-CH-UA-BITNESS': "32", 'SEC-CH-UA-PLATFORM': "4.0.0"};
windows2k_ua_string = "Windows NT 5.0";
windows2k_ua_addon = {'SEC-CH-UA-PLATFORM': "Windows", 'SEC-CH-UA-ARCH': "x86", 'SEC-CH-UA-BITNESS': "32", 'SEC-CH-UA-PLATFORM': "5.0.0"};
windowsXP_ua_string = "Windows NT 5.1";
windowsXP_ua_addon = {'SEC-CH-UA-PLATFORM': "Windows", 'SEC-CH-UA-ARCH': "x86", 'SEC-CH-UA-BITNESS': "32", 'SEC-CH-UA-PLATFORM': "5.1.0"};
windowsXP64_ua_string = "Windows NT 5.2; Win64; x64";
windowsXP64_ua_addon = {'SEC-CH-UA-PLATFORM': "Windows", 'SEC-CH-UA-ARCH': "x86", 'SEC-CH-UA-BITNESS': "64", 'SEC-CH-UA-PLATFORM': "5.1.0"};
windows7_ua_string = "Windows NT 6.1; Win64; x64";
windows7_ua_addon = {'SEC-CH-UA-PLATFORM': "Windows", 'SEC-CH-UA-ARCH': "x86", 'SEC-CH-UA-BITNESS': "64", 'SEC-CH-UA-PLATFORM': "6.1.0"};
windows8_ua_string = "Windows NT 6.2; Win64; x64";
windows8_ua_addon = {'SEC-CH-UA-PLATFORM': "Windows", 'SEC-CH-UA-ARCH': "x86", 'SEC-CH-UA-BITNESS': "64", 'SEC-CH-UA-PLATFORM': "6.2.0"};
windows81_ua_string = "Windows NT 6.3; Win64; x64";
windows81_ua_addon = {'SEC-CH-UA-PLATFORM': "Windows", 'SEC-CH-UA-ARCH': "x86", 'SEC-CH-UA-BITNESS': "64", 'SEC-CH-UA-PLATFORM': "6.3.0"};
windows10_ua_string = "Windows NT 10.0; Win64; x64";
windows10_ua_addon = {'SEC-CH-UA-PLATFORM': "Windows", 'SEC-CH-UA-ARCH': "x86", 'SEC-CH-UA-BITNESS': "64", 'SEC-CH-UA-PLATFORM': "10.0.0"};
windows11_ua_string = "Windows NT 11.0; Win64; x64";
windows11_ua_addon = {'SEC-CH-UA-PLATFORM': "Windows", 'SEC-CH-UA-ARCH': "x86", 'SEC-CH-UA-BITNESS': "64", 'SEC-CH-UA-PLATFORM': "11.0.0"};
geturls_ua_firefox_windows7 = "Mozilla/5.0 ("+windows7_ua_string+"; rv:109.0) Gecko/20100101 Firefox/117.0";
geturls_ua_seamonkey_windows7 = "Mozilla/5.0 ("+windows7_ua_string+"; rv:91.0) Gecko/20100101 Firefox/91.0 SeaMonkey/2.53.17";
geturls_ua_chrome_windows7 = "Mozilla/5.0 ("+windows7_ua_string+") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36";
geturls_ua_chromium_windows7 = "Mozilla/5.0 ("+windows7_ua_string+") AppleWebKit/537.36 (KHTML, like Gecko) Chromium/117.0.0.0 Chrome/117.0.0.0 Safari/537.36";
geturls_ua_palemoon_windows7 = "Mozilla/5.0 ("+windows7_ua_string+"; rv:102.0) Gecko/20100101 Goanna/6.3 Firefox/102.0 PaleMoon/32.4.0.1";
geturls_ua_opera_windows7 = "Mozilla/5.0 ("+windows7_ua_string+") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 OPR/102.0.0.0";
geturls_ua_vivaldi_windows7 = "Mozilla/5.0 ("+windows7_ua_string+") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Vivaldi/6.2.3105.48";
geturls_ua_internet_explorer_windows7 = "Mozilla/5.0 ("+windows7_ua_string+"; Trident/7.0; rv:11.0) like Gecko";
geturls_ua_microsoft_edge_windows7 = "Mozilla/5.0 ("+windows7_ua_string+") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.31";
geturls_ua_pywwwget_python = "Mozilla/5.0 (compatible; {proname}/{prover}; +{prourl})".format(proname=__project__, prover=__version__, prourl=__project_url__);
if(platform.python_implementation()!=""):
 py_implementation = platform.python_implementation();
if(platform.python_implementation()==""):
 py_implementation = "Python";
geturls_ua_pywwwget_python_alt = "Mozilla/5.0 ({osver}; {archtype}; +{prourl}) {pyimp}/{pyver} (KHTML, like Gecko) {proname}/{prover}".format(osver=platform.system()+" "+platform.release(), archtype=platform.machine(), prourl=__project_url__, pyimp=py_implementation, pyver=platform.python_version(), proname=__project__, prover=__version__);
geturls_ua_googlebot_google = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
geturls_ua_googlebot_google_old = "Googlebot/2.1 (+http://www.google.com/bot.html)";
geturls_ua = geturls_ua_firefox_windows7;
geturls_headers_firefox_windows7 = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_firefox_windows7, 'Accept-Encoding': compression_supported, 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close"};
geturls_headers_seamonkey_windows7 = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_seamonkey_windows7, 'Accept-Encoding': compression_supported, 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close"};
geturls_headers_chrome_windows7 = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_chrome_windows7, 'Accept-Encoding': compression_supported, 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close", 'SEC-CH-UA': "\"Google Chrome\";v=\"117\", \"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"117\"", 'SEC-CH-UA-FULL-VERSION': "117.0.5938.63"};
geturls_headers_chrome_windows7.update(windows7_ua_addon);
geturls_headers_chromium_windows7 = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_chromium_windows7, 'Accept-Encoding': compression_supported, 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close", 'SEC-CH-UA': "\"Chromium\";v=\"117\", \"Not;A=Brand\";v=\"24\"", 'SEC-CH-UA-FULL-VERSION': "117.0.5938.63"};
geturls_headers_chromium_windows7.update(windows7_ua_addon);
geturls_headers_palemoon_windows7 = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_palemoon_windows7, 'Accept-Encoding': compression_supported, 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close"};
geturls_headers_opera_windows7 = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_opera_windows7, 'Accept-Encoding': compression_supported, 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close", 'SEC-CH-UA': "\"Chromium\";v=\"116\", \"Not;A=Brand\";v=\"8\", \"Opera\";v=\"102\"", 'SEC-CH-UA-FULL-VERSION': "102.0.4880.56"};
geturls_headers_opera_windows7.update(windows7_ua_addon);
geturls_headers_vivaldi_windows7 = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_vivaldi_windows7, 'Accept-Encoding': compression_supported, 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close", 'SEC-CH-UA': "\"Google Chrome\";v=\"117\", \"Not;A=Brand\";v=\"8\", \"Vivaldi\";v=\"6.2\"", 'SEC-CH-UA-FULL-VERSION': "6.2.3105.48"};
geturls_headers_vivaldi_windows7.update(windows7_ua_addon);
geturls_headers_internet_explorer_windows7 = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_internet_explorer_windows7, 'Accept-Encoding': compression_supported, 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close"};
geturls_headers_microsoft_edge_windows7 = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_microsoft_edge_windows7, 'Accept-Encoding': compression_supported, 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close", 'SEC-CH-UA': "\"Microsoft Edge\";v=\"117\", \"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"117\"", 'SEC-CH-UA-FULL-VERSION': "117.0.2045.31"}
geturls_headers_microsoft_edge_windows7.update(windows7_ua_addon);
geturls_headers_pywwwget_python = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_pywwwget_python, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close", 'SEC-CH-UA': "\""+__project__+"\";v=\""+str(__version__)+"\", \"Not;A=Brand\";v=\"8\", \""+py_implementation+"\";v=\""+str(platform.release())+"\"", 'SEC-CH-UA-FULL-VERSION': str(__version__), 'SEC-CH-UA-PLATFORM': ""+py_implementation+"", 'SEC-CH-UA-ARCH': ""+platform.machine()+"", 'SEC-CH-UA-PLATFORM': str(__version__), 'SEC-CH-UA-BITNESS': str(PyBitness)};
geturls_headers_pywwwget_python_alt = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_pywwwget_python_alt, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close", 'SEC-CH-UA': "\""+__project__+"\";v=\""+str(__version__)+"\", \"Not;A=Brand\";v=\"8\", \""+py_implementation+"\";v=\""+str(platform.release())+"\"", 'SEC-CH-UA-FULL-VERSION': str(__version__), 'SEC-CH-UA-PLATFORM': ""+py_implementation+"", 'SEC-CH-UA-ARCH': ""+platform.machine()+"", 'SEC-CH-UA-PLATFORM': str(__version__), 'SEC-CH-UA-BITNESS': str(PyBitness)};
geturls_headers_googlebot_google = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_googlebot_google, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close"};
geturls_headers_googlebot_google_old = {'Referer': "http://google.com/", 'User-Agent': geturls_ua_googlebot_google_old, 'Accept-Encoding': "none", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close"};
geturls_headers = geturls_headers_firefox_windows7;
geturls_download_sleep = 0;

def verbose_printout(dbgtxt, outtype="log", dbgenable=True, dgblevel=20):
 if(outtype=="print" and dbgenable):
  print(dbgtxt);
  return True;
 elif(outtype=="log" and dbgenable):
  logging.info(dbgtxt);
  return True;
 elif(outtype=="warning" and dbgenable):
  logging.warning(dbgtxt);
  return True;
 elif(outtype=="error" and dbgenable):
  logging.error(dbgtxt);
  return True;
 elif(outtype=="critical" and dbgenable):
  logging.critical(dbgtxt);
  return True;
 elif(outtype=="exception" and dbgenable):
  logging.exception(dbgtxt);
  return True;
 elif(outtype=="logalt" and dbgenable):
  logging.log(dgblevel, dbgtxt);
  return True;
 elif(outtype=="debug" and dbgenable):
  logging.debug(dbgtxt);
  return True;
 elif(not dbgenable):
  return True;
 else:
  return False;
 return False;

def verbose_printout_return(dbgtxt, outtype="log", dbgenable=True, dgblevel=20):
 dbgout = verbose_printout(dbgtxt, outtype, dbgenable, dgblevel);
 if(not dbgout):
  return False;
 return dbgtxt;

def add_url_param(url, **params):
 n=3;
 parts = list(urlparse.urlsplit(url));
 d = dict(cgi.parse_qsl(parts[n])); # use cgi.parse_qs for list values
 d.update(params);
 parts[n]=urlencode(d);
 return urlparse.urlunsplit(parts);

os.environ["PATH"] = os.environ["PATH"] + os.pathsep + os.path.dirname(os.path.realpath(__file__)) + os.pathsep + os.getcwd();
def which_exec(execfile):
 for path in os.environ["PATH"].split(":"):
  if os.path.exists(path + "/" + execfile):
   return path + "/" + execfile;

def listize(varlist):
 il = 0;
 ix = len(varlist);
 ilx = 1;
 newlistreg = {};
 newlistrev = {};
 newlistfull = {};
 while(il < ix):
  newlistreg.update({ilx: varlist[il]});
  newlistrev.update({varlist[il]: ilx});
  ilx = ilx + 1;
  il = il + 1;
 newlistfull = {1: newlistreg, 2: newlistrev, 'reg': newlistreg, 'rev': newlistrev};
 return newlistfull;

def twolistize(varlist):
 il = 0;
 ix = len(varlist);
 ilx = 1;
 newlistnamereg = {};
 newlistnamerev = {};
 newlistdescreg = {};
 newlistdescrev = {};
 newlistfull = {};
 while(il < ix):
  newlistnamereg.update({ilx: varlist[il][0].strip()});
  newlistnamerev.update({varlist[il][0].strip(): ilx});
  newlistdescreg.update({ilx: varlist[il][1].strip()});
  newlistdescrev.update({varlist[il][1].strip(): ilx});
  ilx = ilx + 1;
  il = il + 1;
 newlistnametmp = {1: newlistnamereg, 2: newlistnamerev, 'reg': newlistnamereg, 'rev': newlistnamerev};
 newlistdesctmp = {1: newlistdescreg, 2: newlistdescrev, 'reg': newlistdescreg, 'rev': newlistdescrev};
 newlistfull = {1: newlistnametmp, 2: newlistdesctmp, 'name': newlistnametmp, 'desc': newlistdesctmp}
 return newlistfull;

def arglistize(proexec, *varlist):
 il = 0;
 ix = len(varlist);
 ilx = 1;
 newarglist = [proexec];
 while(il < ix):
  if varlist[il][0] is not None:
   newarglist.append(varlist[il][0]);
  if varlist[il][1] is not None:
   newarglist.append(varlist[il][1]);
  il = il + 1;
 return newarglist;

# hms_string by ArcGIS Python Recipes
# https://arcpy.wordpress.com/2012/04/20/146/
def hms_string(sec_elapsed):
 h = int(sec_elapsed / (60 * 60));
 m = int((sec_elapsed % (60 * 60)) / 60);
 s = sec_elapsed % 60.0;
 return "{}:{:>02}:{:>05.2f}".format(h, m, s);

# get_readable_size by Lipis
# http://stackoverflow.com/posts/14998888/revisions
def get_readable_size(bytes, precision=1, unit="IEC"):
 unit = unit.upper();
 if(unit!="IEC" and unit!="SI"):
  unit = "IEC";
 if(unit=="IEC"):
  units = [" B"," KiB"," MiB"," GiB"," TiB"," PiB"," EiB"," ZiB"];
  unitswos = ["B","KiB","MiB","GiB","TiB","PiB","EiB","ZiB"];
  unitsize = 1024.0;
 if(unit=="SI"):
  units = [" B"," kB"," MB"," GB"," TB"," PB"," EB"," ZB"];
  unitswos = ["B","kB","MB","GB","TB","PB","EB","ZB"];
  unitsize = 1000.0;
 return_val = {};
 orgbytes = bytes;
 for unit in units:
  if abs(bytes) < unitsize:
   strformat = "%3."+str(precision)+"f%s";
   pre_return_val = (strformat % (bytes, unit));
   pre_return_val = re.sub(r"([0]+) ([A-Za-z]+)", r" \2", pre_return_val);
   pre_return_val = re.sub(r"\. ([A-Za-z]+)", r" \1", pre_return_val);
   alt_return_val = pre_return_val.split();
   return_val = {'Bytes': orgbytes, 'ReadableWithSuffix': pre_return_val, 'ReadableWithoutSuffix': alt_return_val[0], 'ReadableSuffix': alt_return_val[1]}
   return return_val;
  bytes /= unitsize;
 strformat = "%."+str(precision)+"f%s";
 pre_return_val = (strformat % (bytes, "YiB"));
 pre_return_val = re.sub(r"([0]+) ([A-Za-z]+)", r" \2", pre_return_val);
 pre_return_val = re.sub(r"\. ([A-Za-z]+)", r" \1", pre_return_val);
 alt_return_val = pre_return_val.split();
 return_val = {'Bytes': orgbytes, 'ReadableWithSuffix': pre_return_val, 'ReadableWithoutSuffix': alt_return_val[0], 'ReadableSuffix': alt_return_val[1]}
 return return_val;

def get_readable_size_from_file(infile, precision=1, unit="IEC", usehashes=False, usehashtypes="md5,sha1"):
 unit = unit.upper();
 usehashtypes = usehashtypes.lower();
 getfilesize = os.path.getsize(infile);
 return_val = get_readable_size(getfilesize, precision, unit);
 if(usehashes):
  hashtypelist = usehashtypes.split(",");
  openfile = open(infile, "rb");
  filecontents = openfile.read();
  openfile.close();
  listnumcount = 0;
  listnumend = len(hashtypelist);
  while(listnumcount < listnumend):
   hashtypelistlow = hashtypelist[listnumcount].strip();
   hashtypelistup = hashtypelistlow.upper();
   filehash = hashlib.new(hashtypelistup);
   filehash.update(filecontents);
   filegethash = filehash.hexdigest();
   return_val.update({hashtypelistup: filegethash});
   listnumcount += 1;
 return return_val;

def get_readable_size_from_string(instring, precision=1, unit="IEC", usehashes=False, usehashtypes="md5,sha1"):
 unit = unit.upper();
 usehashtypes = usehashtypes.lower();
 getfilesize = len(instring);
 return_val = get_readable_size(getfilesize, precision, unit);
 if(usehashes):
  hashtypelist = usehashtypes.split(",");
  listnumcount = 0;
  listnumend = len(hashtypelist);
  while(listnumcount < listnumend):
   hashtypelistlow = hashtypelist[listnumcount].strip();
   hashtypelistup = hashtypelistlow.upper();
   filehash = hashlib.new(hashtypelistup);
   if(sys.version[0]=="2"):
    filehash.update(instring);
   if(sys.version[0]>="3"):
    filehash.update(instring.encode('utf-8'));
   filegethash = filehash.hexdigest();
   return_val.update({hashtypelistup: filegethash});
   listnumcount += 1;
 return return_val;

def make_http_headers_from_dict_to_list(headers={'Referer': "http://google.com/", 'User-Agent': geturls_ua, 'Accept-Encoding': compression_supported, 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close"}):
 if isinstance(headers, dict):
  returnval = [];
  if(sys.version[0]=="2"):
   for headkey, headvalue in headers.iteritems():
    returnval.append((headkey, headvalue));
  if(sys.version[0]>="3"):
   for headkey, headvalue in headers.items():
    returnval.append((headkey, headvalue));
 elif isinstance(headers, list):
  returnval = headers;
 else:
  returnval = False;
 return returnval;

def make_http_headers_from_dict_to_pycurl(headers={'Referer': "http://google.com/", 'User-Agent': geturls_ua, 'Accept-Encoding': compression_supported, 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close"}):
 if isinstance(headers, dict):
  returnval = [];
  if(sys.version[0]=="2"):
   for headkey, headvalue in headers.iteritems():
    returnval.append(headkey+": "+headvalue);
  if(sys.version[0]>="3"):
   for headkey, headvalue in headers.items():
    returnval.append(headkey+": "+headvalue);
 elif isinstance(headers, list):
  returnval = headers;
 else:
  returnval = False;
 return returnval;

def make_http_headers_from_list_to_dict(headers=[("Referer", "http://google.com/"), ("User-Agent", geturls_ua), ("Accept-Encoding", compression_supported), ("Accept-Language", "en-US,en;q=0.8,en-CA,en-GB;q=0.6"), ("Accept-Charset", "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7"), ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"), ("Connection", "close")]):
 if isinstance(headers, list):
  returnval = {};
  mli = 0;
  mlil = len(headers);
  while(mli<mlil):
   returnval.update({headers[mli][0]: headers[mli][1]});
   mli = mli + 1;
 elif isinstance(headers, dict):
  returnval = headers;
 else:
  returnval = False;
 return returnval;

def get_httplib_support(checkvalue=None):
 global haverequests, havemechanize, havehttplib2, haveurllib3, havehttpx, havehttpcore, haveparamiko;
 returnval = [];
 returnval.append("ftp");
 returnval.append("httplib");
 if(havehttplib2):
  returnval.append("httplib2");
 returnval.append("urllib");
 if(haveurllib3):
  returnval.append("urllib3");
  returnval.append("request3");
 returnval.append("request");
 if(haverequests):
  returnval.append("requests");
 if(havehttpx):
  returnval.append("httpx");
  returnval.append("httpx2");
 if(havemechanize):
  returnval.append("mechanize");
 if(haveparamiko):
  returnval.append("sftp");
 if(not checkvalue is None):
  if(checkvalue=="urllib1" or checkvalue=="urllib2"):
   checkvalue = "urllib";
  if(checkvalue=="httplib1"):
   checkvalue = "httplib";
  if(checkvalue in returnval):
   returnval = True;
  else:
   returnval = False;
 return returnval;

def check_httplib_support(checkvalue="urllib"):
 if(checkvalue=="urllib1" or checkvalue=="urllib2"):
  checkvalue = "urllib";
 if(checkvalue=="httplib1"):
  checkvalue = "httplib";
 returnval = get_httplib_support(checkvalue);
 return returnval;

def get_httplib_support_list():
 returnval = get_httplib_support(None);
 return returnval;

def download_from_url(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, httplibuse="urllib", sleep=-1):
 global geturls_download_sleep, haverequests, havemechanize, havehttplib2, haveurllib3, havehttpx, havehttpcore, haveparamiko;
 if(sleep<0):
  sleep = geturls_download_sleep;
 if(httplibuse=="urllib1" or httplibuse=="urllib2"):
  httplibuse = "urllib";
 if(httplibuse=="httplib1"):
  httplibuse = "httplib";
 if(not haverequests and httplibuse=="requests"):
  httplibuse = "urllib";
 if(not havehttpx and httplibuse=="httpx"):
  httplibuse = "urllib";
 if(not havehttpx and httplibuse=="httpx2"):
  httplibuse = "urllib";
 if(not havehttpcore and httplibuse=="httpcore"):
  httplibuse = "urllib";
 if(not havehttpcore and httplibuse=="httpcore2"):
  httplibuse = "urllib";
 if(not havemechanize and httplibuse=="mechanize"):
  httplibuse = "urllib";
 if(not havehttplib2 and httplibuse=="httplib2"):
  httplibuse = "httplib";
 if(not haveparamiko and httplibuse=="sftp"):
  httplibuse = "ftp";
 if(httplibuse=="urllib"):
  returnval = download_from_url_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep);
 elif(httplibuse=="request"):
  returnval = download_from_url_with_request(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep);
 elif(httplibuse=="request3"):
  returnval = download_from_url_with_request3(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep);
 elif(httplibuse=="httplib"):
  returnval = download_from_url_with_httplib(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep);
 elif(httplibuse=="httplib2"):
  returnval = download_from_url_with_httplib2(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep);
 elif(httplibuse=="urllib3"):
  returnval = download_from_url_with_urllib3(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep);
 elif(httplibuse=="requests"):
  returnval = download_from_url_with_requests(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep);
 elif(httplibuse=="httpx"):
  returnval = download_from_url_with_httpx(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep);
 elif(httplibuse=="httpx2"):
  returnval = download_from_url_with_httpx2(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep);
 elif(httplibuse=="httpcore"):
  returnval = download_from_url_with_httpcore(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep);
 elif(httplibuse=="httpcore2"):
  returnval = download_from_url_with_httpcore2(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep);
 elif(httplibuse=="mechanize"):
  returnval = download_from_url_with_mechanize(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep);
 elif(httplibuse=="ftp"):
  returnval = download_from_url_with_ftp(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep);
 elif(httplibuse=="sftp"):
  returnval = download_from_url_with_sftp(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep);
 else:
  returnval = False;
 return returnval;

def download_from_url_file(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, httplibuse="urllib", buffersize=524288, sleep=-1):
 global geturls_download_sleep, haverequests, havemechanize, havehttplib2, haveurllib3, havehttpx, havehttpcore, haveparamiko;
 if(sleep<0):
  sleep = geturls_download_sleep;
 if(httplibuse=="urllib1" or httplibuse=="urllib2"):
  httplibuse = "urllib";
 if(httplibuse=="httplib1"):
  httplibuse = "httplib";
 if(not haverequests and httplibuse=="requests"):
  httplibuse = "urllib";
 if(not havehttpx and httplibuse=="httpx"):
  httplibuse = "urllib";
 if(not havehttpx and httplibuse=="httpx2"):
  httplibuse = "urllib";
 if(not havehttpcore and httplibuse=="httpcore"):
  httplibuse = "urllib";
 if(not havehttpcore and httplibuse=="httpcore2"):
  httplibuse = "urllib";
 if(not havemechanize and httplibuse=="mechanize"):
  httplibuse = "urllib";
 if(not havehttplib2 and httplibuse=="httplib2"):
  httplibuse = "httplib";
 if(not haveparamiko and httplibuse=="sftp"):
  httplibuse = "ftp";
 if(httplibuse=="urllib"):
  returnval = download_from_url_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep);
 elif(httplibuse=="request"):
  returnval = download_from_url_file_with_request(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep);
 elif(httplibuse=="request3"):
  returnval = download_from_url_file_with_request3(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep);
 elif(httplibuse=="httplib"):
  returnval = download_from_url_file_with_httplib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep);
 elif(httplibuse=="httplib2"):
  returnval = download_from_url_file_with_httplib2(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep);
 elif(httplibuse=="urllib3"):
  returnval = download_from_url_file_with_urllib3(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep);
 elif(httplibuse=="requests"):
  returnval = download_from_url_file_with_requests(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep);
 elif(httplibuse=="httpx"):
  returnval = download_from_url_file_with_httpx(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep);
 elif(httplibuse=="httpx2"):
  returnval = download_from_url_file_with_httpx2(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep);
 elif(httplibuse=="httpcore"):
  returnval = download_from_url_file_with_httpcore(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep);
 elif(httplibuse=="httpcore2"):
  returnval = download_from_url_file_with_httpcore2(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep);
 elif(httplibuse=="mechanize"):
  returnval = download_from_url_file_with_mechanize(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep);
 elif(httplibuse=="ftp"):
  returnval = download_from_url_file_with_ftp(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep);
 elif(httplibuse=="sftp"):
  returnval = download_from_url_file_with_sftp(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep);
 else:
  returnval = False;
 return returnval;

def download_from_url_to_file(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, httplibuse="urllib", outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
 global geturls_download_sleep, haverequests, havemechanize, havehttplib2, haveurllib3, havehttpx, havehttpcorei, haveparamiko;
 if(sleep<0):
  sleep = geturls_download_sleep;
 if(httplibuse=="urllib1" or httplibuse=="urllib2"):
  httplibuse = "urllib";
 if(httplibuse=="httplib1"):
  httplibuse = "httplib";
 if(not haverequests and httplibuse=="requests"):
  httplibuse = "urllib";
 if(not havehttpx and httplibuse=="httpx"):
  httplibuse = "urllib";
 if(not havehttpx and httplibuse=="httpx2"):
  httplibuse = "urllib";
 if(not havehttpcore and httplibuse=="httpcore"):
  httplibuse = "urllib";
 if(not havehttpcore and httplibuse=="httpcore2"):
  httplibuse = "urllib";
 if(not havemechanize and httplibuse=="mechanize"):
  httplibuse = "urllib";
 if(not havehttplib2 and httplibuse=="httplib2"):
  httplibuse = "httplib";
 if(not haveparamiko and httplibuse=="sftp"):
  httplibuse = "ftp";
 if(httplibuse=="urllib"):
  returnval = download_from_url_to_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, outfile, outpath, buffersize, sleep);
 elif(httplibuse=="request"):
  returnval = download_from_url_to_file_with_request(httpurl, httpheaders, httpcookie, httpmethod, postdata, outfile, outpath, buffersize, sleep);
 elif(httplibuse=="request3"):
  returnval = download_from_url_to_file_with_request3(httpurl, httpheaders, httpcookie, httpmethod, postdata, outfile, outpath, buffersize, sleep);
 elif(httplibuse=="httplib"):
  returnval = download_from_url_to_file_with_httplib(httpurl, httpheaders, httpcookie, httpmethod, postdata, outfile, outpath, buffersize, sleep);
 elif(httplibuse=="httplib2"):
  returnval = download_from_url_to_file_with_httplib2(httpurl, httpheaders, httpcookie, httpmethod, postdata, outfile, outpath, buffersize, sleep);
 elif(httplibuse=="urllib3"):
  returnval = download_from_url_to_file_with_urllib3(httpurl, httpheaders, httpcookie, httpmethod, postdata, outfile, outpath, buffersize, sleep);
 elif(httplibuse=="requests"):
  returnval = download_from_url_to_file_with_requests(httpurl, httpheaders, httpcookie, httpmethod, postdata, outfile, outpath, buffersize, sleep);
 elif(httplibuse=="httpx"):
  returnval = download_from_url_file_with_httpx(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep);
 elif(httplibuse=="httpx2"):
  returnval = download_from_url_file_with_httpx2(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep);
 elif(httplibuse=="httpcore"):
  returnval = download_from_url_file_with_httpcore(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep);
 elif(httplibuse=="httpcore2"):
  returnval = download_from_url_file_with_httpcore2(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep);
 elif(httplibuse=="mechanize"):
  returnval = download_from_url_to_file_with_mechanize(httpurl, httpheaders, httpcookie, httpmethod, postdata, outfile, outpath, buffersize, sleep);
 elif(httplibuse=="ftp"):
  returnval = download_from_url_to_file_with_ftp(httpurl, httpheaders, httpcookie, httpmethod, postdata, outfile, outpath, buffersize, sleep);
 elif(httplibuse=="sftp"):
  returnval = download_from_url_to_file_with_sftp(httpurl, httpheaders, httpcookie, httpmethod, postdata, outfile, outpath, buffersize, sleep);
 else:
  returnval = False;
 return returnval;

def download_from_url_with_urllib(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
 global geturls_download_sleep, havebrotli;
 if(sleep<0):
  sleep = geturls_download_sleep;
 urlparts = urlparse.urlparse(httpurl);
 if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
 if(urlparts.username is not None or urlparts.password is not None):
  inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
  httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
 geturls_opener = build_opener(HTTPCookieProcessor(httpcookie));
 if(isinstance(httpheaders, dict)):
  httpheaders = make_http_headers_from_dict_to_list(httpheaders);
 geturls_opener.addheaders = httpheaders;
 time.sleep(sleep);
 if(postdata is not None and not isinstance(postdata, dict)):
  postdata = urlencode(postdata);
 try:
  if(httpmethod=="GET"):
   geturls_text = geturls_opener.open(httpurl);
  elif(httpmethod=="POST"):
   geturls_text = geturls_opener.open(httpurl, data=postdata);
  else:
   geturls_text = geturls_opener.open(httpurl);
 except HTTPError as geturls_text_error:
  geturls_text = geturls_text_error;
  log.info("Error With URL "+httpurl);
 except URLError:
  log.info("Error With URL "+httpurl);
  return False;
 except socket.timeout:
  log.info("Error With URL "+httpurl);
  return False;
 httpcodeout = geturls_text.getcode();
 httpversionout = "1.1";
 httpmethodout = httpmethod;
 httpurlout = geturls_text.geturl();
 httpheaderout = geturls_text.info();
 httpheadersentout = httpheaders;
 try:
  httpheaderout = geturls_text.info().headers;
  httpheaderkeys = geturls_text.info().keys();
  print(len(httpheaderkeys));
  imax = len(httpheaderkeys);
  ic = 0;  
  while(ic < imax):
   print(geturls_text.getheaders(httpheaderkeys[ic]));
   print(str(ic));
   ic += 1;
 except AttributeError:
  httpheaderout = geturls_text.info();
 if(isinstance(httpheaderout, list)):
   httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
 if(isinstance(httpheadersentout, list)):
   httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
 log.info("Downloading URL "+httpurl);
 if(httpheaderout.get("Content-Encoding")=="gzip" or httpheaderout.get("Content-Encoding")=="deflate"):
  if(sys.version[0]=="2"):
   strbuf = StringIO(geturls_text.read());
  if(sys.version[0]>="3"):
   strbuf = BytesIO(geturls_text.read());
  gzstrbuf = gzip.GzipFile(fileobj=strbuf);
  returnval_content = gzstrbuf.read()[:];
 if(httpheaderout.get("Content-Encoding")!="gzip" and httpheaderout.get("Content-Encoding")!="deflate" and httpheaderout.get("Content-Encoding")!="br"):
  returnval_content = geturls_text.read()[:];
 if(httpheaderout.get("Content-Encoding")=="br" and havebrotli):
  returnval_content = brotli.decompress(returnval_content);
 returnval = {'Type': "Content", 'Content': returnval_content, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
 geturls_text.close();
 return returnval;

def download_from_url_file_with_urllib(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
 global geturls_download_sleep, tmpfileprefix, tmpfilesuffix;
 exec_time_start = time.time();
 myhash = hashlib.new("sha1");
 if(sys.version[0]=="2"):
  myhash.update(httpurl);
  myhash.update(str(buffersize));
  myhash.update(str(exec_time_start));
 if(sys.version[0]>="3"):
  myhash.update(httpurl.encode('utf-8'));
  myhash.update(str(buffersize).encode('utf-8'));
  myhash.update(str(exec_time_start).encode('utf-8'));
 newtmpfilesuffix = tmpfilesuffix + str(myhash.hexdigest());
 if(sleep<0):
  sleep = geturls_download_sleep;
 urlparts = urlparse.urlparse(httpurl);
 if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
 if(urlparts.username is not None or urlparts.password is not None):
  inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
  httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
 geturls_opener = build_opener(HTTPCookieProcessor(httpcookie));
 if(isinstance(httpheaders, dict)):
  httpheaders = make_http_headers_from_dict_to_list(httpheaders);
 geturls_opener.addheaders = httpheaders;
 time.sleep(sleep);
 try:
  if(httpmethod=="GET"):
   geturls_text = geturls_opener.open(httpurl);
  elif(httpmethod=="POST"):
   geturls_text = geturls_opener.open(httpurl, data=postdata);
  else:
   geturls_text = geturls_opener.open(httpurl);
 except HTTPError as geturls_text_error:
  geturls_text = geturls_text_error;
  log.info("Error With URL "+httpurl);
 except URLError:
  log.info("Error With URL "+httpurl);
  return False;
 except socket.timeout:
  log.info("Error With URL "+httpurl);
  return False;
 except socket.timeout:
  log.info("Error With URL "+httpurl);
  return False;
 httpcodeout = geturls_text.getcode();
 httpversionout = "1.1";
 httpmethodout = httpmethod;
 httpurlout = geturls_text.geturl();
 httpheaderout = geturls_text.info();
 httpheadersentout = httpheaders;
 try:
  httpheaderout = geturls_text.info().headers;
  print(str(len(httpheaderout)));
 except AttributeError:
  httpheaderout = geturls_text.info();
 if(isinstance(httpheaderout, list)):
   httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
 if(isinstance(httpheadersentout, list)):
   httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
 downloadsize = httpheaderout.get('Content-Length');
 if(downloadsize is not None):
  downloadsize = int(downloadsize);
 if downloadsize is None: downloadsize = 0;
 fulldatasize = 0;
 prevdownsize = 0;
 log.info("Downloading URL "+httpurl);
 with tempfile.NamedTemporaryFile('wb+', prefix=tmpfileprefix, suffix=newtmpfilesuffix, delete=False) as f:
  tmpfilename = f.name;
  returnval = {'Type': "File", 'Filename': tmpfilename, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
  while True:
   databytes = geturls_text.read(buffersize);
   if not databytes: break;
   datasize = len(databytes);
   fulldatasize = datasize + fulldatasize;
   percentage = "";
   if(downloadsize>0):
    percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
   downloaddiff = fulldatasize - prevdownsize;
   log.info("Downloading "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Downloaded "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
   prevdownsize = fulldatasize;
   f.write(databytes);
  f.close();
 geturls_text.close();
 exec_time_end = time.time();
 log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to download file.");
 returnval.update({'Filesize': os.path.getsize(tmpfilename), 'DownloadTime': float(exec_time_start - exec_time_end), 'DownloadTimeReadable': hms_string(exec_time_start - exec_time_end)});
 return returnval;

def download_from_url_to_file_with_urllib(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
 global geturls_download_sleep;
 if(sleep<0):
  sleep = geturls_download_sleep;
 if(not outfile=="-"):
  outpath = outpath.rstrip(os.path.sep);
  filepath = os.path.realpath(outpath+os.path.sep+outfile);
  if(not os.path.exists(outpath)):
   os.makedirs(outpath);
  if(os.path.exists(outpath) and os.path.isfile(outpath)):
   return False;
  if(os.path.exists(filepath) and os.path.isdir(filepath)):
   return False;
  pretmpfilename = download_from_url_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
  if(not pretmpfilename):
   return False;
  tmpfilename = pretmpfilename['Filename'];
  downloadsize = os.path.getsize(tmpfilename);
  fulldatasize = 0;
  log.info("Moving file "+tmpfilename+" to "+filepath);
  exec_time_start = time.time();
  shutil.move(tmpfilename, filepath);
  exec_time_end = time.time();
  log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to move file.");
  if(os.path.exists(tmpfilename)):
   os.remove(tmpfilename);
  returnval = {'Type': "File", 'Filename': filepath, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
 if(outfile=="-" and sys.version[0]=="2"):
  pretmpfilename = download_from_url_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
  if(not pretmpfilename):
   return False;
  tmpfilename = pretmpfilename['Filename'];
  downloadsize = os.path.getsize(tmpfilename);
  fulldatasize = 0;
  prevdownsize = 0;
  exec_time_start = time.time();
  with open(tmpfilename, 'rb') as ft:
   f = StringIO();
   while True:
    databytes = ft.read(buffersize[1]);
    if not databytes: break;
    datasize = len(databytes);
    fulldatasize = datasize + fulldatasize;
    percentage = "";
    if(downloadsize>0):
     percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
    downloaddiff = fulldatasize - prevdownsize;
    log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
    prevdownsize = fulldatasize;
    f.write(databytes);
   f.seek(0);
   fdata = f.getvalue();
   f.close();
   ft.close();
   os.remove(tmpfilename);
   exec_time_end = time.time();
   log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
  returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
 if(outfile=="-" and sys.version[0]>="3"):
  pretmpfilename = download_from_url_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
  tmpfilename = pretmpfilename['Filename'];
  downloadsize = os.path.getsize(tmpfilename);
  fulldatasize = 0;
  prevdownsize = 0;
  exec_time_start = time.time();
  with open(tmpfilename, 'rb') as ft:
   f = BytesIO();
   while True:
    databytes = ft.read(buffersize[1]);
    if not databytes: break;
    datasize = len(databytes);
    fulldatasize = datasize + fulldatasize;
    percentage = "";
    if(downloadsize>0):
     percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
    downloaddiff = fulldatasize - prevdownsize;
    log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
    prevdownsize = fulldatasize;
    f.write(databytes);
   f.seek(0);
   fdata = f.getvalue();
   f.close();
   ft.close();
   os.remove(tmpfilename);
   exec_time_end = time.time();
   log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
  returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
 return returnval;

def download_from_url_with_httplib(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
 global geturls_download_sleep, havebrotli;
 if(sleep<0):
  sleep = geturls_download_sleep;
 urlparts = urlparse.urlparse(httpurl);
 if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
 if(urlparts.username is not None or urlparts.password is not None):
  inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
  httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
 geturls_opener = build_opener(HTTPCookieProcessor(httpcookie));
 geturls_opener.addheaders = httpheaders;
 time.sleep(sleep);
 if(urlparts[0]=="http"):
  httpconn = HTTPConnection(urlparts[1]);
 elif(urlparts[0]=="https"):
  httpconn = HTTPSConnection(urlparts[1]);
 else:
  return False;
 if(postdata is not None and not isinstance(postdata, dict)):
  postdata = urlencode(postdata);
 try:
  if(httpmethod=="GET"):
   httpconn.request("GET", urlparts[2], headers=httpheaders);
  elif(httpmethod=="POST"):
   httpconn.request("GET", urlparts[2], body=postdata, headers=httpheaders);
  else:
   httpconn.request("GET", urlparts[2], headers=httpheaders);
 except socket.timeout:
  log.info("Error With URL "+httpurl);
  return False;
 except socket.gaierror:
  log.info("Error With URL "+httpurl);
  return False;
 geturls_text = httpconn.getresponse();
 httpcodeout = geturls_text.status;
 httpversionout = "1.1";
 httpmethodout = httpmethod;
 httpurlout = httpurl;
 httpheaderout = geturls_text.getheaders();
 httpheadersentout = httpheaders;
 if(isinstance(httpheaderout, list)):
   httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
 if(isinstance(httpheadersentout, list)):
   httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
 log.info("Downloading URL "+httpurl);
 if(httpheaderout.get("Content-Encoding")=="gzip" or httpheaderout.get("Content-Encoding")=="deflate"):
  if(sys.version[0]=="2"):
   strbuf = StringIO(geturls_text.read());
  if(sys.version[0]>="3"):
   strbuf = BytesIO(geturls_text.read());
  gzstrbuf = gzip.GzipFile(fileobj=strbuf);
  returnval_content = gzstrbuf.read()[:];
 if(httpheaderout.get("Content-Encoding")!="gzip" and httpheaderout.get("Content-Encoding")!="deflate" and httpheaderout.get("Content-Encoding")!="br"):
  returnval_content = geturls_text.read()[:];
 if(httpheaderout.get("Content-Encoding")=="br" and havebrotli):
  returnval_content = brotli.decompress(returnval_content);
 returnval = {'Type': "Content", 'Content': returnval_content, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
 geturls_text.close();
 return returnval;

def download_from_url_file_with_httplib(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
 global geturls_download_sleep, tmpfileprefix, tmpfilesuffix;
 exec_time_start = time.time();
 myhash = hashlib.new("sha1");
 if(sys.version[0]=="2"):
  myhash.update(httpurl);
  myhash.update(str(buffersize));
  myhash.update(str(exec_time_start));
 if(sys.version[0]>="3"):
  myhash.update(httpurl.encode('utf-8'));
  myhash.update(str(buffersize).encode('utf-8'));
  myhash.update(str(exec_time_start).encode('utf-8'));
 newtmpfilesuffix = tmpfilesuffix + str(myhash.hexdigest());
 if(sleep<0):
  sleep = geturls_download_sleep;
 urlparts = urlparse.urlparse(httpurl);
 if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
 if(urlparts.username is not None or urlparts.password is not None):
  inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
  httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
 geturls_opener = build_opener(HTTPCookieProcessor(httpcookie));
 geturls_opener.addheaders = httpheaders;
 time.sleep(sleep);
 if(urlparts[0]=="http"):
  httpconn = HTTPConnection(urlparts[1]);
 elif(urlparts[0]=="https"):
  httpconn = HTTPSConnection(urlparts[1]);
 else:
  return False;
 if(postdata is not None and not isinstance(postdata, dict)):
  postdata = urlencode(postdata);
 try:
  if(httpmethod=="GET"):
   httpconn.request("GET", urlparts[2], headers=httpheaders);
  elif(httpmethod=="POST"):
   httpconn.request("GET", urlparts[2], body=postdata, headers=httpheaders);
  else:
   httpconn.request("GET", urlparts[2], headers=httpheaders);
 except socket.timeout:
  log.info("Error With URL "+httpurl);
  return False;
 except socket.gaierror:
  log.info("Error With URL "+httpurl);
  return False;
 geturls_text = httpconn.getresponse();
 httpcodeout = geturls_text.status;
 httpversionout = "1.1";
 httpmethodout = httpmethod;
 httpurlout = httpurl;
 httpheaderout = geturls_text.getheaders();
 httpheadersentout = httpheaders;
 if(isinstance(httpheaderout, list)):
   httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
 if(isinstance(httpheadersentout, list)):
   httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
 downloadsize = httpheaderout.get('Content-Length');
 if(downloadsize is not None):
  downloadsize = int(downloadsize);
 if downloadsize is None: downloadsize = 0;
 fulldatasize = 0;
 prevdownsize = 0;
 log.info("Downloading URL "+httpurl);
 with tempfile.NamedTemporaryFile('wb+', prefix=tmpfileprefix, suffix=newtmpfilesuffix, delete=False) as f:
  tmpfilename = f.name;
  returnval = {'Type': "File", 'Filename': tmpfilename, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'Type': "Content", 'Content': returnval_content, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
  while True:
   databytes = geturls_text.read(buffersize);
   if not databytes: break;
   datasize = len(databytes);
   fulldatasize = datasize + fulldatasize;
   percentage = "";
   if(downloadsize>0):
    percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
   downloaddiff = fulldatasize - prevdownsize;
   log.info("Downloading "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Downloaded "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
   prevdownsize = fulldatasize;
   f.write(databytes);
  f.close();
 geturls_text.close();
 exec_time_end = time.time();
 log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to download file.");
 returnval.update({'Filesize': os.path.getsize(tmpfilename), 'DownloadTime': float(exec_time_start - exec_time_end), 'DownloadTimeReadable': hms_string(exec_time_start - exec_time_end)});
 return returnval;

def download_from_url_to_file_with_httplib(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
 global geturls_download_sleep;
 if(sleep<0):
  sleep = geturls_download_sleep;
 if(not outfile=="-"):
  outpath = outpath.rstrip(os.path.sep);
  filepath = os.path.realpath(outpath+os.path.sep+outfile);
  if(not os.path.exists(outpath)):
   os.makedirs(outpath);
  if(os.path.exists(outpath) and os.path.isfile(outpath)):
   return False;
  if(os.path.exists(filepath) and os.path.isdir(filepath)):
   return False;
  pretmpfilename = download_from_url_file_with_httplib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
  if(not pretmpfilename):
   return False;
  tmpfilename = pretmpfilename['Filename'];
  downloadsize = os.path.getsize(tmpfilename);
  fulldatasize = 0;
  log.info("Moving file "+tmpfilename+" to "+filepath);
  exec_time_start = time.time();
  shutil.move(tmpfilename, filepath);
  exec_time_end = time.time();
  log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to move file.");
  if(os.path.exists(tmpfilename)):
   os.remove(tmpfilename);
  returnval = {'Type': "File", 'Filename': filepath, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
 if(outfile=="-" and sys.version[0]=="2"):
  pretmpfilename = download_from_url_file_with_httplib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
  if(not pretmpfilename):
   return False;
  tmpfilename = pretmpfilename['Filename'];
  downloadsize = os.path.getsize(tmpfilename);
  fulldatasize = 0;
  prevdownsize = 0;
  exec_time_start = time.time();
  with open(tmpfilename, 'rb') as ft:
   f = StringIO();
   while True:
    databytes = ft.read(buffersize[1]);
    if not databytes: break;
    datasize = len(databytes);
    fulldatasize = datasize + fulldatasize;
    percentage = "";
    if(downloadsize>0):
     percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
    downloaddiff = fulldatasize - prevdownsize;
    log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
    prevdownsize = fulldatasize;
    f.write(databytes);
   f.seek(0);
   fdata = f.getvalue();
   f.close();
   ft.close();
   os.remove(tmpfilename);
   exec_time_end = time.time();
   log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
  returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
 if(outfile=="-" and sys.version[0]>="3"):
  pretmpfilename = download_from_url_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
  tmpfilename = pretmpfilename['Filename'];
  downloadsize = os.path.getsize(tmpfilename);
  fulldatasize = 0;
  prevdownsize = 0;
  exec_time_start = time.time();
  with open(tmpfilename, 'rb') as ft:
   f = BytesIO();
   while True:
    databytes = ft.read(buffersize[1]);
    if not databytes: break;
    datasize = len(databytes);
    fulldatasize = datasize + fulldatasize;
    percentage = "";
    if(downloadsize>0):
     percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
    downloaddiff = fulldatasize - prevdownsize;
    log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
    prevdownsize = fulldatasize;
    f.write(databytes);
   f.seek(0);
   fdata = f.getvalue();
   f.close();
   ft.close();
   os.remove(tmpfilename);
   exec_time_end = time.time();
   log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
  returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
 return returnval;

if(havehttplib2):
 def download_from_url_with_httplib2(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  global geturls_download_sleep, havebrotli;
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(urlparts.username is not None or urlparts.password is not None):
   inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
   httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
  geturls_opener = build_opener(HTTPCookieProcessor(httpcookie));
  geturls_opener.addheaders = httpheaders;
  time.sleep(sleep);
  if(urlparts[0]=="http"):
   httpconn = HTTPConnectionWithTimeout(urlparts[1]);
  elif(urlparts[0]=="https"):
   httpconn = HTTPSConnectionWithTimeout(urlparts[1]);
  else:
   return False;
  if(postdata is not None and not isinstance(postdata, dict)):
   postdata = urlencode(postdata);
  try:
   if(httpmethod=="GET"):
    httpconn.request("GET", urlparts[2], headers=httpheaders);
   elif(httpmethod=="POST"):
    httpconn.request("GET", urlparts[2], body=postdata, headers=httpheaders);
   else:
    httpconn.request("GET", urlparts[2], headers=httpheaders);
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.gaierror:
   log.info("Error With URL "+httpurl);
   return False;
  geturls_text = httpconn.getresponse();
  httpcodeout = geturls_text.status;
  httpversionout = "1.1";
  httpmethodout = httpmethod;
  httpurlout = httpurl;
  httpheaderout = geturls_text.getheaders();
  httpheadersentout = httpheaders;
  if(isinstance(httpheaderout, list)):
    httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
  if(isinstance(httpheadersentout, list)):
    httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
  log.info("Downloading URL "+httpurl);
  if(httpheaderout.get("Content-Encoding")=="gzip" or httpheaderout.get("Content-Encoding")=="deflate"):
   if(sys.version[0]=="2"):
    strbuf = StringIO(geturls_text.read());
   if(sys.version[0]>="3"):
    strbuf = BytesIO(geturls_text.read());
   gzstrbuf = gzip.GzipFile(fileobj=strbuf);
   returnval_content = gzstrbuf.read()[:];
  if(httpheaderout.get("Content-Encoding")!="gzip" and httpheaderout.get("Content-Encoding")!="deflate" and httpheaderout.get("Content-Encoding")!="br"):
   returnval_content = geturls_text.read()[:];
  if(httpheaderout.get("Content-Encoding")=="br" and havebrotli):
   returnval_content = brotli.decompress(returnval_content);
  returnval = {'Type': "Content", 'Content': returnval_content, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
  geturls_text.close();
  return returnval;

if(not havehttplib2):
 def download_from_url_with_httplib2(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  returnval = download_from_url_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep)
  return returnval;

if(havehttplib2):
 def download_from_url_file_with_httplib2(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  global geturls_download_sleep, tmpfileprefix, tmpfilesuffix;
  exec_time_start = time.time();
  myhash = hashlib.new("sha1");
  if(sys.version[0]=="2"):
   myhash.update(httpurl);
   myhash.update(str(buffersize));
   myhash.update(str(exec_time_start));
  if(sys.version[0]>="3"):
   myhash.update(httpurl.encode('utf-8'));
   myhash.update(str(buffersize).encode('utf-8'));
   myhash.update(str(exec_time_start).encode('utf-8'));
  newtmpfilesuffix = tmpfilesuffix + str(myhash.hexdigest());
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(urlparts.username is not None or urlparts.password is not None):
   inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
   httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
  geturls_opener = build_opener(HTTPCookieProcessor(httpcookie));
  geturls_opener.addheaders = httpheaders;
  time.sleep(sleep);
  if(urlparts[0]=="http"):
   httpconn = HTTPConnectionWithTimeout(urlparts[1]);
  elif(urlparts[0]=="https"):
   httpconn = HTTPSConnectionWithTimeout(urlparts[1]);
  else:
   return False;
  if(postdata is not None and not isinstance(postdata, dict)):
   postdata = urlencode(postdata);
  try:
   if(httpmethod=="GET"):
    httpconn.request("GET", urlparts[2], headers=httpheaders);
   elif(httpmethod=="POST"):
    httpconn.request("GET", urlparts[2], body=postdata, headers=httpheaders);
   else:
    httpconn.request("GET", urlparts[2], headers=httpheaders);
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.gaierror:
   log.info("Error With URL "+httpurl);
   return False;
  geturls_text = httpconn.getresponse();
  httpcodeout = geturls_text.status;
  httpversionout = "1.1";
  httpmethodout = httpmethod;
  httpurlout = httpurl;
  httpheaderout = geturls_text.getheaders();
  httpheadersentout = httpheaders;
  if(isinstance(httpheaderout, list)):
    httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
  if(isinstance(httpheadersentout, list)):
    httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
  downloadsize = httpheaderout.get('Content-Length');
  if(downloadsize is not None):
   downloadsize = int(downloadsize);
  if downloadsize is None: downloadsize = 0;
  fulldatasize = 0;
  prevdownsize = 0;
  log.info("Downloading URL "+httpurl);
  with tempfile.NamedTemporaryFile('wb+', prefix=tmpfileprefix, suffix=newtmpfilesuffix, delete=False) as f:
   tmpfilename = f.name;
   returnval = {'Type': "File", 'Filename': tmpfilename, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
   while True:
    databytes = geturls_text.read(buffersize);
    if not databytes: break;
    datasize = len(databytes);
    fulldatasize = datasize + fulldatasize;
    percentage = "";
    if(downloadsize>0):
     percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
    downloaddiff = fulldatasize - prevdownsize;
    log.info("Downloading "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Downloaded "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
    prevdownsize = fulldatasize;
    f.write(databytes);
   f.close();
  geturls_text.close();
  exec_time_end = time.time();
  log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to download file.");
  returnval.update({'Filesize': os.path.getsize(tmpfilename), 'DownloadTime': float(exec_time_start - exec_time_end), 'DownloadTimeReadable': hms_string(exec_time_start - exec_time_end)});
  return returnval;

if(not havehttplib2):
 def download_from_url_file_with_httplib2(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  returnval = download_from_url_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep)
  return returnval;

if(havehttplib2):
 def download_from_url_to_file_with_httplib2(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  global geturls_download_sleep;
  if(sleep<0):
   sleep = geturls_download_sleep;
  if(not outfile=="-"):
   outpath = outpath.rstrip(os.path.sep);
   filepath = os.path.realpath(outpath+os.path.sep+outfile);
   if(not os.path.exists(outpath)):
    os.makedirs(outpath);
   if(os.path.exists(outpath) and os.path.isfile(outpath)):
    return False;
   if(os.path.exists(filepath) and os.path.isdir(filepath)):
    return False;
   pretmpfilename = download_from_url_file_with_httplib2(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   log.info("Moving file "+tmpfilename+" to "+filepath);
   exec_time_start = time.time();
   shutil.move(tmpfilename, filepath);
   exec_time_end = time.time();
   log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to move file.");
   if(os.path.exists(tmpfilename)):
    os.remove(tmpfilename);
   returnval = {'Type': "File", 'Filename': filepath, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]=="2"):
   pretmpfilename = download_from_url_file_with_httplib2(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = StringIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]>="3"):
   pretmpfilename = download_from_url_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = BytesIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  return returnval;

if(not havehttplib2):
 def download_from_url_to_file_with_httplib2(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  returnval = download_from_url_to_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, outfile, outpath, sleep)
  return returnval;

def download_from_url_with_request(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
 global geturls_download_sleep, havebrotli;
 if(sleep<0):
  sleep = geturls_download_sleep;
 urlparts = urlparse.urlparse(httpurl);
 if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
 if(urlparts.username is not None or urlparts.password is not None):
  inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
  httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
 geturls_opener = build_opener(HTTPCookieProcessor(httpcookie));
 if(isinstance(httpheaders, dict)):
  httpheaders = make_http_headers_from_dict_to_list(httpheaders);
 geturls_opener.addheaders = httpheaders;
 urllib.request.install_opener(geturls_opener);
 time.sleep(sleep);
 httpheaders = make_http_headers_from_list_to_dict(httpheaders);
 if(postdata is not None and not isinstance(postdata, dict)):
  postdata = urlencode(postdata);
 try:
  if(httpmethod=="GET"):
   geturls_request = Request(httpurl, headers=httpheaders);
   geturls_text = urlopen(geturls_request);
  elif(httpmethod=="POST"):
   geturls_request = Request(httpurl, headers=httpheaders);
   geturls_text = urlopen(geturls_request, data=postdata);
  else:
   geturls_request = Request(httpurl, headers=httpheaders);
   geturls_text = urlopen(geturls_request);
 except HTTPError as geturls_text_error:
  geturls_text = geturls_text_error;
  log.info("Error With URL "+httpurl);
 except URLError:
  log.info("Error With URL "+httpurl);
  return False;
 except socket.timeout:
  log.info("Error With URL "+httpurl);
  return False;
 httpcodeout = geturls_text.getcode();
 httpversionout = "1.1";
 httpmethodout = httpmethod;
 httpurlout = geturls_text.geturl();
 httpheaderout = geturls_text.headers;
 httpheadersentout = httpheaders;
 if(isinstance(httpheaderout, list)):
   httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
 if(isinstance(httpheadersentout, list)):
   httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
 log.info("Downloading URL "+httpurl);
 if(httpheaderout.get("Content-Encoding")=="gzip" or httpheaderout.get("Content-Encoding")=="deflate"):
  if(sys.version[0]=="2"):
   strbuf = StringIO(geturls_text.read());
  if(sys.version[0]>="3"):
   strbuf = BytesIO(geturls_text.read());
  gzstrbuf = gzip.GzipFile(fileobj=strbuf);
  returnval_content = gzstrbuf.read()[:];
 if(httpheaderout.get("Content-Encoding")!="gzip" and httpheaderout.get("Content-Encoding")!="deflate" and httpheaderout.get("Content-Encoding")!="br"):
  returnval_content = geturls_text.read()[:];
 if(httpheaderout.get("Content-Encoding")=="br" and havebrotli):
  returnval_content = brotli.decompress(returnval_content);
 returnval = {'Type': "Content", 'Content': returnval_content, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
 geturls_text.close();
 return returnval;

def download_from_url_file_with_request(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
 global geturls_download_sleep, tmpfileprefix, tmpfilesuffix;
 exec_time_start = time.time();
 myhash = hashlib.new("sha1");
 if(sys.version[0]=="2"):
  myhash.update(httpurl);
  myhash.update(str(buffersize));
  myhash.update(str(exec_time_start));
 if(sys.version[0]>="3"):
  myhash.update(httpurl.encode('utf-8'));
  myhash.update(str(buffersize).encode('utf-8'));
  myhash.update(str(exec_time_start).encode('utf-8'));
 newtmpfilesuffix = tmpfilesuffix + str(myhash.hexdigest());
 if(sleep<0):
  sleep = geturls_download_sleep;
 urlparts = urlparse.urlparse(httpurl);
 if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
 if(urlparts.username is not None or urlparts.password is not None):
  inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
  httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
 geturls_opener = build_opener(HTTPCookieProcessor(httpcookie));
 if(isinstance(httpheaders, dict)):
  httpheaders = make_http_headers_from_dict_to_list(httpheaders);
 geturls_opener.addheaders = httpheaders;
 urllib.request.install_opener(geturls_opener);
 time.sleep(sleep);
 httpheaders = make_http_headers_from_list_to_dict(httpheaders);
 if(postdata is not None and not isinstance(postdata, dict)):
  postdata = urlencode(postdata);
 try:
  if(httpmethod=="GET"):
   geturls_request = Request(httpurl, headers=httpheaders);
   geturls_text = urlopen(geturls_request);
  elif(httpmethod=="POST"):
   geturls_request = Request(httpurl, headers=httpheaders);
   geturls_text = urlopen(geturls_request, data=postdata);
  else:
   geturls_request = Request(httpurl, headers=httpheaders);
   geturls_text = urlopen(geturls_request);
 except HTTPError as geturls_text_error:
  geturls_text = geturls_text_error;
  log.info("Error With URL "+httpurl);
 except URLError:
  log.info("Error With URL "+httpurl);
  return False;
 except socket.timeout:
  log.info("Error With URL "+httpurl);
  return False;
 httpcodeout = geturls_text.getcode();
 httpversionout = "1.1";
 httpmethodout = httpmethod;
 httpurlout = geturls_text.geturl();
 httpheaderout = geturls_text.headers;
 httpheadersentout = httpheaders;
 if(isinstance(httpheaderout, list)):
   httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
 if(isinstance(httpheadersentout, list)):
   httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
 downloadsize = httpheaderout.get('Content-Length');
 if(downloadsize is not None):
  downloadsize = int(downloadsize);
 if downloadsize is None: downloadsize = 0;
 fulldatasize = 0;
 prevdownsize = 0;
 log.info("Downloading URL "+httpurl);
 with tempfile.NamedTemporaryFile('wb+', prefix=tmpfileprefix, suffix=newtmpfilesuffix, delete=False) as f:
  tmpfilename = f.name;
  returnval = {'Type': "File", 'Filename': tmpfilename, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
  while True:
   databytes = geturls_text.read(buffersize);
   if not databytes: break;
   datasize = len(databytes);
   fulldatasize = datasize + fulldatasize;
   percentage = "";
   if(downloadsize>0):
    percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
   downloaddiff = fulldatasize - prevdownsize;
   log.info("Downloading "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Downloaded "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
   prevdownsize = fulldatasize;
   f.write(databytes);
  f.close();
 geturls_text.close();
 exec_time_end = time.time();
 log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to download file.");
 returnval.update({'Filesize': os.path.getsize(tmpfilename), 'DownloadTime': float(exec_time_start - exec_time_end), 'DownloadTimeReadable': hms_string(exec_time_start - exec_time_end)});
 return returnval;

def download_from_url_to_file_with_request(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
 global geturls_download_sleep;
 if(sleep<0):
  sleep = geturls_download_sleep;
 if(not outfile=="-"):
  outpath = outpath.rstrip(os.path.sep);
  filepath = os.path.realpath(outpath+os.path.sep+outfile);
  if(not os.path.exists(outpath)):
   os.makedirs(outpath);
  if(os.path.exists(outpath) and os.path.isfile(outpath)):
   return False;
  if(os.path.exists(filepath) and os.path.isdir(filepath)):
   return False;
  pretmpfilename = download_from_url_file_with_request(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
  if(not pretmpfilename):
   return False;
  tmpfilename = pretmpfilename['Filename'];
  downloadsize = os.path.getsize(tmpfilename);
  fulldatasize = 0;
  log.info("Moving file "+tmpfilename+" to "+filepath);
  exec_time_start = time.time();
  shutil.move(tmpfilename, filepath);
  exec_time_end = time.time();
  log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to move file.");
  if(os.path.exists(tmpfilename)):
   os.remove(tmpfilename);
  returnval = {'Type': "File", 'Filename': filepath, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent':pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
 if(outfile=="-" and sys.version[0]=="2"):
  pretmpfilename = download_from_url_file_with_request(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
  if(not pretmpfilename):
   return False;
  tmpfilename = pretmpfilename['Filename'];
  downloadsize = os.path.getsize(tmpfilename);
  fulldatasize = 0;
  prevdownsize = 0;
  exec_time_start = time.time();
  with open(tmpfilename, 'rb') as ft:
   f = StringIO();
   while True:
    databytes = ft.read(buffersize[1]);
    if not databytes: break;
    datasize = len(databytes);
    fulldatasize = datasize + fulldatasize;
    percentage = "";
    if(downloadsize>0):
     percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
    downloaddiff = fulldatasize - prevdownsize;
    log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
    prevdownsize = fulldatasize;
    f.write(databytes);
   f.seek(0);
   fdata = f.getvalue();
   f.close();
   ft.close();
   os.remove(tmpfilename);
   exec_time_end = time.time();
   log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
  returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
 if(outfile=="-" and sys.version[0]>="3"):
  pretmpfilename = download_from_url_file_with_request(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
  tmpfilename = pretmpfilename['Filename'];
  downloadsize = os.path.getsize(tmpfilename);
  fulldatasize = 0;
  prevdownsize = 0;
  exec_time_start = time.time();
  with open(tmpfilename, 'rb') as ft:
   f = BytesIO();
   while True:
    databytes = ft.read(buffersize[1]);
    if not databytes: break;
    datasize = len(databytes);
    fulldatasize = datasize + fulldatasize;
    percentage = "";
    if(downloadsize>0):
     percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
    downloaddiff = fulldatasize - prevdownsize;
    log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
    prevdownsize = fulldatasize;
    f.write(databytes);
   f.seek(0);
   fdata = f.getvalue();
   f.close();
   ft.close();
   os.remove(tmpfilename);
   exec_time_end = time.time();
   log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
  returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
 return returnval;

if(haverequests):
 def download_from_url_with_requests(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  global geturls_download_sleep, havebrotli;
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(urlparts.username is not None or urlparts.password is not None):
   inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
   httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
  time.sleep(sleep);
  if(postdata is not None and not isinstance(postdata, dict)):
   postdata = urlencode(postdata);
  try:
   if(httpmethod=="GET"):
    geturls_text = requests.get(httpurl, headers=httpheaders, cookies=httpcookie);
   elif(httpmethod=="POST"):
    geturls_text = requests.post(httpurl, data=postdata, headers=httpheaders, cookies=httpcookie);
   else:
    geturls_text = requests.get(httpurl, headers=httpheaders, cookies=httpcookie);
  except requests.exceptions.ConnectTimeout:
   log.info("Error With URL "+httpurl);
   return False;
  except requests.exceptions.ConnectError:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  httpcodeout = geturls_text.status_code;
  httpversionout = "1.1";
  httpmethodout = httpmethod;
  httpurlout = geturls_text.url;
  httpheaderout = geturls_text.headers;
  httpheadersentout = httpheaders;
  if(isinstance(httpheaderout, list)):
    httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
  if(isinstance(httpheadersentout, list)):
    httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
  log.info("Downloading URL "+httpurl);
  if(httpheaderout.get('Content-Type')=="gzip" or httpheaderout.get('Content-Type')=="deflate"):
   if(sys.version[0]=="2"):
    strbuf = StringIO(geturls_text.content);
   if(sys.version[0]>="3"):
    strbuf = BytesIO(geturls_text.content);
   gzstrbuf = gzip.GzipFile(fileobj=strbuf);
   returnval_content = gzstrbuf.content[:];
  if(httpheaderout.get('Content-Type')!="gzip" and httpheaderout.get('Content-Type')!="deflate" and httpheaderout.get('Content-Type')!="br"):
   returnval_content = geturls_text.content[:];
  if(httpheaderout.get("Content-Encoding")=="br" and havebrotli):
   returnval_content = brotli.decompress(returnval_content);
  returnval = {'Type': "Content", 'Content': returnval_content, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
  geturls_text.close();
  return returnval;

if(not haverequests):
 def download_from_url_with_requests(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  returnval = download_from_url_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep)
  return returnval;

if(haverequests):
 def download_from_url_file_with_requests(httpurl, httpheaders, httpcookie, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  global geturls_download_sleep, tmpfileprefix, tmpfilesuffix;
  exec_time_start = time.time();
  myhash = hashlib.new("sha1");
  if(sys.version[0]=="2"):
   myhash.update(httpurl);
   myhash.update(str(buffersize));
   myhash.update(str(exec_time_start));
  if(sys.version[0]>="3"):
   myhash.update(httpurl.encode('utf-8'));
   myhash.update(str(buffersize).encode('utf-8'));
   myhash.update(str(exec_time_start).encode('utf-8'));
  newtmpfilesuffix = tmpfilesuffix + str(myhash.hexdigest());
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(urlparts.username is not None or urlparts.password is not None):
   inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
   httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
  time.sleep(sleep);
  if(postdata is not None and not isinstance(postdata, dict)):
   postdata = urlencode(postdata);
  try:
   if(httpmethod=="GET"):
    geturls_text = requests.get(httpurl, headers=httpheaders, cookies=httpcookie);
   elif(httpmethod=="POST"):
    geturls_text = requests.post(httpurl, data=postdata, headers=httpheaders, cookies=httpcookie);
   else:
    geturls_text = requests.get(httpurl, headers=httpheaders, cookies=httpcookie);
  except requests.exceptions.ConnectTimeout:
   log.info("Error With URL "+httpurl);
   return False;
  except requests.exceptions.ConnectError:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  httpcodeout = geturls_text.status_code;
  httpversionout = "1.1";
  httpmethodout = httpmethod;
  httpurlout = geturls_text.url;
  httpheaderout = geturls_text.headers;
  httpheadersentout = httpheaders;
  if(isinstance(httpheaderout, list)):
    httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
  if(isinstance(httpheadersentout, list)):
    httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
  downloadsize = int(httpheaderout.get('Content-Length'));
  if(downloadsize is not None):
   downloadsize = int(downloadsize);
  if downloadsize is None: downloadsize = 0;
  fulldatasize = 0;
  prevdownsize = 0;
  log.info("Downloading URL "+httpurl);
  with tempfile.NamedTemporaryFile('wb+', prefix=tmpfileprefix, suffix=newtmpfilesuffix, delete=False) as f:
   tmpfilename = f.name;
   returnval = {'Type': "File", 'Filename': tmpfilename, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
   for databytes in geturls_text.iter_content(chunk_size=buffersize):
    datasize = len(databytes);
    fulldatasize = datasize + fulldatasize;
    percentage = "";
    if(downloadsize>0):
     percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
    downloaddiff = fulldatasize - prevdownsize;
    log.info("Downloading "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Downloaded "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
    prevdownsize = fulldatasize;
    f.write(databytes);
   f.close();
  geturls_text.close();
  exec_time_end = time.time();
  log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to download file.");
  returnval.update({'Filesize': os.path.getsize(tmpfilename), 'DownloadTime': float(exec_time_start - exec_time_end), 'DownloadTimeReadable': hms_string(exec_time_start - exec_time_end)});
  return returnval;

if(not haverequests):
 def download_from_url_file_with_requests(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  returnval = download_from_url_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep)
  return returnval;

if(haverequests):
 def download_from_url_to_file_with_requests(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  global geturls_download_sleep;
  if(sleep<0):
   sleep = geturls_download_sleep;
  if(not outfile=="-"):
   outpath = outpath.rstrip(os.path.sep);
   filepath = os.path.realpath(outpath+os.path.sep+outfile);
   if(not os.path.exists(outpath)):
    os.makedirs(outpath);
   if(os.path.exists(outpath) and os.path.isfile(outpath)):
    return False;
   if(os.path.exists(filepath) and os.path.isdir(filepath)):
    return False;
   pretmpfilename = download_from_url_file_with_requests(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   log.info("Moving file "+tmpfilename+" to "+filepath);
   exec_time_start = time.time();
   shutil.move(tmpfilename, filepath);
   exec_time_end = time.time();
   log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to move file.");
   if(os.path.exists(tmpfilename)):
    os.remove(tmpfilename);
   returnval = {'Type': "File", 'Filename': filepath, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]=="2"):
   pretmpfilename = download_from_url_file_with_requests(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = StringIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': ['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]>="3"):
   pretmpfilename = download_from_url_file_with_requests(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = BytesIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  return returnval;

if(not haverequests):
 def download_from_url_to_file_with_requests(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  returnval = download_from_url_to_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, outfile, outpath, sleep)
  return returnval;

if(havehttpx):
 def download_from_url_with_httpx(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  global geturls_download_sleep, havebrotli;
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(urlparts.username is not None or urlparts.password is not None):
   inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
   httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
  time.sleep(sleep);
  if(postdata is not None and not isinstance(postdata, dict)):
   postdata = urlencode(postdata);
  try:
   if(httpmethod=="GET"):
    httpx_pool = httpx.Client(http1=True, http2=False, trust_env=True);
    geturls_text = httpx_pool.get(httpurl, headers=httpheaders, cookies=httpcookie);
   elif(httpmethod=="POST"):
    httpx_pool = httpx.Client(http1=True, http2=False, trust_env=True);
    geturls_text = httpx_pool.post(httpurl, data=postdata, headers=httpheaders, cookies=httpcookie);
   else:
    httpx_pool = httpx.Client(http1=True, http2=False, trust_env=True);
    geturls_text = httpx_pool.get(httpurl, headers=httpheaders, cookies=httpcookie);
  except httpx.ConnectTimeout:
   log.info("Error With URL "+httpurl);
   return False;
  except httpx.ConnectError:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  httpcodeout = geturls_text.status_code;
  httpversionout = geturls_text.http_version;
  httpmethodout = httpmethod;
  httpurlout = str(geturls_text.url);
  httpheaderout = geturls_text.headers;
  httpheadersentout = httpheaders;
  if(isinstance(httpheaderout, list)):
    httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
  if(isinstance(httpheadersentout, list)):
    httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
  log.info("Downloading URL "+httpurl);
  if(httpheaderout.get('Content-Type')=="gzip" or httpheaderout.get('Content-Type')=="deflate"):
   if(sys.version[0]=="2"):
    strbuf = StringIO(geturls_text.content);
   if(sys.version[0]>="3"):
    strbuf = BytesIO(geturls_text.content);
   gzstrbuf = gzip.GzipFile(fileobj=strbuf);
   returnval_content = gzstrbuf.content[:];
  if(httpheaderout.get('Content-Type')!="gzip" and httpheaderout.get('Content-Type')!="deflate" and httpheaderout.get('Content-Type')!="br"):
   returnval_content = geturls_text.content[:];
  if(httpheaderout.get("Content-Encoding")=="br" and havebrotli):
   returnval_content = brotli.decompress(returnval_content);
  returnval = {'Type': "Content", 'Content': returnval_content, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
  geturls_text.close();
  return returnval;

if(not havehttpx):
 def download_from_url_with_httpx(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  returnval = download_from_url_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep)
  return returnval;

if(havehttpx):
 def download_from_url_file_with_httpx(httpurl, httpheaders, httpcookie, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  global geturls_download_sleep, tmpfileprefix, tmpfilesuffix;
  exec_time_start = time.time();
  myhash = hashlib.new("sha1");
  if(sys.version[0]=="2"):
   myhash.update(httpurl);
   myhash.update(str(buffersize));
   myhash.update(str(exec_time_start));
  if(sys.version[0]>="3"):
   myhash.update(httpurl.encode('utf-8'));
   myhash.update(str(buffersize).encode('utf-8'));
   myhash.update(str(exec_time_start).encode('utf-8'));
  newtmpfilesuffix = tmpfilesuffix + str(myhash.hexdigest());
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(urlparts.username is not None or urlparts.password is not None):
   inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
   httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
  time.sleep(sleep);
  if(postdata is not None and not isinstance(postdata, dict)):
   postdata = urlencode(postdata);
  try:
   if(httpmethod=="GET"):
    httpx_pool = httpx.Client(http1=True, http2=False, trust_env=True);
    geturls_text = httpx_pool.get(httpurl, headers=httpheaders, cookies=httpcookie);
   elif(httpmethod=="POST"):
    httpx_pool = httpx.Client(http1=True, http2=False, trust_env=True);
    geturls_text = httpx_pool.post(httpurl, data=postdata, headers=httpheaders, cookies=httpcookie);
   else:
    httpx_pool = httpx.Client(http1=True, http2=False, trust_env=True);
    geturls_text = httpx_pool.get(httpurl, headers=httpheaders, cookies=httpcookie);
  except httpx.ConnectTimeout:
   log.info("Error With URL "+httpurl);
   return False;
  except httpx.ConnectError:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  httpcodeout = geturls_text.status_code;
  httpversionout = geturls_text.http_version;
  httpmethodout = httpmethod;
  httpurlout = str(geturls_text.url);
  httpheaderout = geturls_text.headers;
  httpheadersentout = httpheaders;
  if(isinstance(httpheaderout, list)):
    httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
  if(isinstance(httpheadersentout, list)):
    httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
  downloadsize = int(httpheaderout.get('Content-Length'));
  if(downloadsize is not None):
   downloadsize = int(downloadsize);
  if downloadsize is None: downloadsize = 0;
  fulldatasize = 0;
  prevdownsize = 0;
  log.info("Downloading URL "+httpurl);
  with tempfile.NamedTemporaryFile('wb+', prefix=tmpfileprefix, suffix=newtmpfilesuffix, delete=False) as f:
   tmpfilename = f.name;
   returnval = {'Type': "File", 'Filename': tmpfilename, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
   for databytes in geturls_text.iter_content(chunk_size=buffersize):
    datasize = len(databytes);
    fulldatasize = datasize + fulldatasize;
    percentage = "";
    if(downloadsize>0):
     percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
    downloaddiff = fulldatasize - prevdownsize;
    log.info("Downloading "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Downloaded "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
    prevdownsize = fulldatasize;
    f.write(databytes);
   f.close();
  geturls_text.close();
  exec_time_end = time.time();
  log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to download file.");
  returnval.update({'Filesize': os.path.getsize(tmpfilename), 'DownloadTime': float(exec_time_start - exec_time_end), 'DownloadTimeReadable': hms_string(exec_time_start - exec_time_end)});
  return returnval;

if(not havehttpx):
 def download_from_url_file_with_httpx(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  returnval = download_from_url_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep)
  return returnval;

if(havehttpx):
 def download_from_url_to_file_with_httpx(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  global geturls_download_sleep;
  if(sleep<0):
   sleep = geturls_download_sleep;
  if(not outfile=="-"):
   outpath = outpath.rstrip(os.path.sep);
   filepath = os.path.realpath(outpath+os.path.sep+outfile);
   if(not os.path.exists(outpath)):
    os.makedirs(outpath);
   if(os.path.exists(outpath) and os.path.isfile(outpath)):
    return False;
   if(os.path.exists(filepath) and os.path.isdir(filepath)):
    return False;
   pretmpfilename = download_from_url_file_with_httpx(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   log.info("Moving file "+tmpfilename+" to "+filepath);
   exec_time_start = time.time();
   shutil.move(tmpfilename, filepath);
   exec_time_end = time.time();
   log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to move file.");
   if(os.path.exists(tmpfilename)):
    os.remove(tmpfilename);
   returnval = {'Type': "File", 'Filename': filepath, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]=="2"):
   pretmpfilename = download_from_url_file_with_httpx(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = StringIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': ['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]>="3"):
   pretmpfilename = download_from_url_file_with_httpx(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = BytesIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  return returnval;

if(not havehttpx):
 def download_from_url_to_file_with_httpx(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  returnval = download_from_url_to_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, outfile, outpath, sleep)
  return returnval;

if(havehttpx):
 def download_from_url_with_httpx2(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  global geturls_download_sleep, havebrotli;
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(urlparts.username is not None or urlparts.password is not None):
   inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
   httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
  time.sleep(sleep);
  if(postdata is not None and not isinstance(postdata, dict)):
   postdata = urlencode(postdata);
  try:
   if(httpmethod=="GET"):
    httpx_pool = httpx.Client(http1=True, http2=True, trust_env=True);
    geturls_text = httpx_pool.get(httpurl, headers=httpheaders, cookies=httpcookie);
   elif(httpmethod=="POST"):
    httpx_pool = httpx.Client(http1=True, http2=True, trust_env=True);
    geturls_text = httpx_pool.post(httpurl, data=postdata, headers=httpheaders, cookies=httpcookie);
   else:
    httpx_pool = httpx.Client(http1=True, http2=True, trust_env=True);
    geturls_text = httpx_pool.get(httpurl, headers=httpheaders, cookies=httpcookie);
  except httpx.ConnectTimeout:
   log.info("Error With URL "+httpurl);
   return False;
  except httpx.ConnectError:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  httpcodeout = geturls_text.status_code;
  httpversionout = geturls_text.http_version;
  httpmethodout = httpmethod;
  httpurlout = str(geturls_text.url);
  httpheaderout = geturls_text.headers;
  httpheadersentout = httpheaders;
  if(isinstance(httpheaderout, list)):
    httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
  if(isinstance(httpheadersentout, list)):
    httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
  log.info("Downloading URL "+httpurl);
  if(httpheaderout.get('Content-Type')=="gzip" or httpheaderout.get('Content-Type')=="deflate"):
   if(sys.version[0]=="2"):
    strbuf = StringIO(geturls_text.content);
   if(sys.version[0]>="3"):
    strbuf = BytesIO(geturls_text.content);
   gzstrbuf = gzip.GzipFile(fileobj=strbuf);
   returnval_content = gzstrbuf.content[:];
  if(httpheaderout.get('Content-Type')!="gzip" and httpheaderout.get('Content-Type')!="deflate" and httpheaderout.get('Content-Type')!="br"):
   returnval_content = geturls_text.content[:];
  if(httpheaderout.get("Content-Encoding")=="br" and havebrotli):
   returnval_content = brotli.decompress(returnval_content);
  returnval = {'Type': "Content", 'Content': returnval_content, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
  geturls_text.close();
  return returnval;

if(not havehttpx):
 def download_from_url_with_httpx2(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  returnval = download_from_url_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep)
  return returnval;

if(havehttpx):
 def download_from_url_file_with_httpx2(httpurl, httpheaders, httpcookie, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  global geturls_download_sleep, tmpfileprefix, tmpfilesuffix;
  exec_time_start = time.time();
  myhash = hashlib.new("sha1");
  if(sys.version[0]=="2"):
   myhash.update(httpurl);
   myhash.update(str(buffersize));
   myhash.update(str(exec_time_start));
  if(sys.version[0]>="3"):
   myhash.update(httpurl.encode('utf-8'));
   myhash.update(str(buffersize).encode('utf-8'));
   myhash.update(str(exec_time_start).encode('utf-8'));
  newtmpfilesuffix = tmpfilesuffix + str(myhash.hexdigest());
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(urlparts.username is not None or urlparts.password is not None):
   inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
   httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
  time.sleep(sleep);
  if(postdata is not None and not isinstance(postdata, dict)):
   postdata = urlencode(postdata);
  try:
   if(httpmethod=="GET"):
    httpx_pool = httpx.Client(http1=True, http2=True, trust_env=True);
    geturls_text = httpx_pool.get(httpurl, headers=httpheaders, cookies=httpcookie);
   elif(httpmethod=="POST"):
    httpx_pool = httpx.Client(http1=True, http2=True, trust_env=True);
    geturls_text = httpx_pool.post(httpurl, data=postdata, headers=httpheaders, cookies=httpcookie);
   else:
    httpx_pool = httpx.Client(http1=True, http2=True, trust_env=True);
    geturls_text = httpx_pool.get(httpurl, headers=httpheaders, cookies=httpcookie);
  except httpx.ConnectTimeout:
   log.info("Error With URL "+httpurl);
   return False;
  except httpx.ConnectError:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  httpcodeout = geturls_text.status_code;
  httpversionout = geturls_text.http_version;
  httpmethodout = httpmethod;
  httpurlout = str(geturls_text.url);
  httpheaderout = geturls_text.headers;
  httpheadersentout = httpheaders;
  if(isinstance(httpheaderout, list)):
    httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
  if(isinstance(httpheadersentout, list)):
    httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
  downloadsize = int(httpheaderout.get('Content-Length'));
  if(downloadsize is not None):
   downloadsize = int(downloadsize);
  if downloadsize is None: downloadsize = 0;
  fulldatasize = 0;
  prevdownsize = 0;
  log.info("Downloading URL "+httpurl);
  with tempfile.NamedTemporaryFile('wb+', prefix=tmpfileprefix, suffix=newtmpfilesuffix, delete=False) as f:
   tmpfilename = f.name;
   returnval = {'Type': "File", 'Filename': tmpfilename, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
   for databytes in geturls_text.iter_content(chunk_size=buffersize):
    datasize = len(databytes);
    fulldatasize = datasize + fulldatasize;
    percentage = "";
    if(downloadsize>0):
     percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
    downloaddiff = fulldatasize - prevdownsize;
    log.info("Downloading "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Downloaded "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
    prevdownsize = fulldatasize;
    f.write(databytes);
   f.close();
  geturls_text.close();
  exec_time_end = time.time();
  log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to download file.");
  returnval.update({'Filesize': os.path.getsize(tmpfilename), 'DownloadTime': float(exec_time_start - exec_time_end), 'DownloadTimeReadable': hms_string(exec_time_start - exec_time_end)});
  return returnval;

if(not havehttpx):
 def download_from_url_file_with_httpx2(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  returnval = download_from_url_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep)
  return returnval;

if(havehttpx):
 def download_from_url_to_file_with_httpx2(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  global geturls_download_sleep;
  if(sleep<0):
   sleep = geturls_download_sleep;
  if(not outfile=="-"):
   outpath = outpath.rstrip(os.path.sep);
   filepath = os.path.realpath(outpath+os.path.sep+outfile);
   if(not os.path.exists(outpath)):
    os.makedirs(outpath);
   if(os.path.exists(outpath) and os.path.isfile(outpath)):
    return False;
   if(os.path.exists(filepath) and os.path.isdir(filepath)):
    return False;
   pretmpfilename = download_from_url_file_with_httpx2(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   log.info("Moving file "+tmpfilename+" to "+filepath);
   exec_time_start = time.time();
   shutil.move(tmpfilename, filepath);
   exec_time_end = time.time();
   log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to move file.");
   if(os.path.exists(tmpfilename)):
    os.remove(tmpfilename);
   returnval = {'Type': "File", 'Filename': filepath, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]=="2"):
   pretmpfilename = download_from_url_file_with_httpx2(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = StringIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': ['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]>="3"):
   pretmpfilename = download_from_url_file_with_httpx2(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = BytesIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  return returnval;

if(not havehttpx):
 def download_from_url_to_file_with_httpx2(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  returnval = download_from_url_to_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, outfile, outpath, sleep)
  return returnval;

if(havehttpcore):
 def download_from_url_with_httpcore(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  global geturls_download_sleep, havebrotli;
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(urlparts.username is not None or urlparts.password is not None):
   inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
   httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
  time.sleep(sleep);
  if(postdata is not None and not isinstance(postdata, dict)):
   postdata = urlencode(postdata);
  try:
   if(httpmethod=="GET"):
    httpx_pool = httpcore.ConnectionPool(http1=True, http2=False);
    geturls_text = httpx_pool.request("GET", httpurl, headers=httpheaders);
   elif(httpmethod=="POST"):
    httpx_pool = httpcore.ConnectionPool(http1=True, http2=False);
    geturls_text = httpx_pool.request("GET", httpurl, data=postdata, headers=httpheaders);
   else:
    httpx_pool = httpcore.ConnectionPool(http1=True, http2=False);
    geturls_text = httpx_pool.request("GET", httpurl, headers=httpheaders);
  except httpcore.ConnectTimeout:
   log.info("Error With URL "+httpurl);
   return False;
  except httpcore.ConnectError:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  httpcodeout = geturls_text.status;
  httpversionout = "1.1";
  httpmethodout = httpmethod;
  httpurlout = str(httpurl);
  httpheaderout = geturls_text.headers;
  httpheadersentout = httpheaders;
  if(isinstance(httpheaderout, list)):
    httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
  if(isinstance(httpheadersentout, list)):
    httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
  log.info("Downloading URL "+httpurl);
  if(httpheaderout.get('Content-Type')=="gzip" or httpheaderout.get('Content-Type')=="deflate"):
   if(sys.version[0]=="2"):
    strbuf = StringIO(geturls_text.content);
   if(sys.version[0]>="3"):
    strbuf = BytesIO(geturls_text.content);
   gzstrbuf = gzip.GzipFile(fileobj=strbuf);
   returnval_content = gzstrbuf.content[:];
  if(httpheaderout.get('Content-Type')!="gzip" and httpheaderout.get('Content-Type')!="deflate" and httpheaderout.get('Content-Type')!="br"):
   returnval_content = geturls_text.content[:];
  if(httpheaderout.get("Content-Encoding")=="br" and havebrotli):
   returnval_content = brotli.decompress(returnval_content);
  returnval = {'Type': "Content", 'Content': returnval_content, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
  geturls_text.close();
  return returnval;

if(not havehttpcore):
 def download_from_url_with_httpcore(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  returnval = download_from_url_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep)
  return returnval;

if(havehttpcore):
 def download_from_url_file_with_httpcore(httpurl, httpheaders, httpcookie, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  global geturls_download_sleep, tmpfileprefix, tmpfilesuffix;
  exec_time_start = time.time();
  myhash = hashlib.new("sha1");
  if(sys.version[0]=="2"):
   myhash.update(httpurl);
   myhash.update(str(buffersize));
   myhash.update(str(exec_time_start));
  if(sys.version[0]>="3"):
   myhash.update(httpurl.encode('utf-8'));
   myhash.update(str(buffersize).encode('utf-8'));
   myhash.update(str(exec_time_start).encode('utf-8'));
  newtmpfilesuffix = tmpfilesuffix + str(myhash.hexdigest());
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(urlparts.username is not None or urlparts.password is not None):
   inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
   httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
  time.sleep(sleep);
  if(postdata is not None and not isinstance(postdata, dict)):
   postdata = urlencode(postdata);
  try:
   if(httpmethod=="GET"):
    httpx_pool = httpcore.ConnectionPool(http1=True, http2=False);
    geturls_text = httpx_pool.request("GET", httpurl, headers=httpheaders);
   elif(httpmethod=="POST"):
    httpx_pool = httpcore.ConnectionPool(http1=True, http2=False);
    geturls_text = httpx_pool.request("GET", httpurl, data=postdata, headers=httpheaders);
   else:
    httpx_pool = httpcore.ConnectionPool(http1=True, http2=False);
    geturls_text = httpx_pool.request("GET", httpurl, headers=httpheaders);
  except httpcore.ConnectTimeout:
   log.info("Error With URL "+httpurl);
   return False;
  except httpcore.ConnectError:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  httpcodeout = geturls_text.status;
  httpversionout = "1.1";
  httpmethodout = httpmethod;
  httpurlout = str(httpurl);
  httpheaderout = geturls_text.headers;
  httpheadersentout = httpheaders;
  if(isinstance(httpheaderout, list)):
    httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
  if(isinstance(httpheadersentout, list)):
    httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
  downloadsize = int(httpheaderout.get('Content-Length'));
  if(downloadsize is not None):
   downloadsize = int(downloadsize);
  if downloadsize is None: downloadsize = 0;
  fulldatasize = 0;
  prevdownsize = 0;
  log.info("Downloading URL "+httpurl);
  with tempfile.NamedTemporaryFile('wb+', prefix=tmpfileprefix, suffix=newtmpfilesuffix, delete=False) as f:
   tmpfilename = f.name;
   returnval = {'Type': "File", 'Filename': tmpfilename, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
   for databytes in geturls_text.iter_content(chunk_size=buffersize):
    datasize = len(databytes);
    fulldatasize = datasize + fulldatasize;
    percentage = "";
    if(downloadsize>0):
     percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
    downloaddiff = fulldatasize - prevdownsize;
    log.info("Downloading "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Downloaded "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
    prevdownsize = fulldatasize;
    f.write(databytes);
   f.close();
  geturls_text.close();
  exec_time_end = time.time();
  log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to download file.");
  returnval.update({'Filesize': os.path.getsize(tmpfilename), 'DownloadTime': float(exec_time_start - exec_time_end), 'DownloadTimeReadable': hms_string(exec_time_start - exec_time_end)});
  return returnval;

if(not havehttpcore):
 def download_from_url_file_with_httpcore(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  returnval = download_from_url_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep)
  return returnval;

if(havehttpcore):
 def download_from_url_to_file_with_httpcore(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  global geturls_download_sleep;
  if(sleep<0):
   sleep = geturls_download_sleep;
  if(not outfile=="-"):
   outpath = outpath.rstrip(os.path.sep);
   filepath = os.path.realpath(outpath+os.path.sep+outfile);
   if(not os.path.exists(outpath)):
    os.makedirs(outpath);
   if(os.path.exists(outpath) and os.path.isfile(outpath)):
    return False;
   if(os.path.exists(filepath) and os.path.isdir(filepath)):
    return False;
   pretmpfilename = download_from_url_file_with_httpcore(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   log.info("Moving file "+tmpfilename+" to "+filepath);
   exec_time_start = time.time();
   shutil.move(tmpfilename, filepath);
   exec_time_end = time.time();
   log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to move file.");
   if(os.path.exists(tmpfilename)):
    os.remove(tmpfilename);
   returnval = {'Type': "File", 'Filename': filepath, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]=="2"):
   pretmpfilename = download_from_url_file_with_httpcore(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = StringIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': ['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]>="3"):
   pretmpfilename = download_from_url_file_with_httpcore(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = BytesIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  return returnval;

if(not havehttpcore):
 def download_from_url_to_file_with_httpcore(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  returnval = download_from_url_to_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, outfile, outpath, sleep)
  return returnval;

if(havehttpcore):
 def download_from_url_with_httpcore2(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  global geturls_download_sleep, havebrotli;
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(urlparts.username is not None or urlparts.password is not None):
   inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
   httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
  time.sleep(sleep);
  if(postdata is not None and not isinstance(postdata, dict)):
   postdata = urlencode(postdata);
  try:
   if(httpmethod=="GET"):
    httpx_pool = httpcore.ConnectionPool(http1=True, http2=True);
    geturls_text = httpx_pool.request("GET", httpurl, headers=httpheaders);
   elif(httpmethod=="POST"):
    httpx_pool = httpcore.ConnectionPool(http1=True, http2=True);
    geturls_text = httpx_pool.request("GET", httpurl, data=postdata, headers=httpheaders);
   else:
    httpx_pool = httpcore.ConnectionPool(http1=True, http2=True);
    geturls_text = httpx_pool.request("GET", httpurl, headers=httpheaders);
  except httpcore.ConnectTimeout:
   log.info("Error With URL "+httpurl);
   return False;
  except httpcore.ConnectError:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  httpcodeout = geturls_text.status;
  httpversionout = "1.1";
  httpmethodout = httpmethod;
  httpurlout = str(httpurl);
  httpheaderout = geturls_text.headers;
  httpheadersentout = httpheaders;
  if(isinstance(httpheaderout, list)):
    httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
  if(isinstance(httpheadersentout, list)):
    httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
  log.info("Downloading URL "+httpurl);
  if(httpheaderout.get('Content-Type')=="gzip" or httpheaderout.get('Content-Type')=="deflate"):
   if(sys.version[0]=="2"):
    strbuf = StringIO(geturls_text.content);
   if(sys.version[0]>="3"):
    strbuf = BytesIO(geturls_text.content);
   gzstrbuf = gzip.GzipFile(fileobj=strbuf);
   returnval_content = gzstrbuf.content[:];
  if(httpheaderout.get('Content-Type')!="gzip" and httpheaderout.get('Content-Type')!="deflate" and httpheaderout.get('Content-Type')!="br"):
   returnval_content = geturls_text.content[:];
  if(httpheaderout.get("Content-Encoding")=="br" and havebrotli):
   returnval_content = brotli.decompress(returnval_content);
  returnval = {'Type': "Content", 'Content': returnval_content, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
  geturls_text.close();
  return returnval;

if(not havehttpcore):
 def download_from_url_with_httpcore2(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  returnval = download_from_url_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep)
  return returnval;

if(havehttpcore):
 def download_from_url_file_with_httpcore2(httpurl, httpheaders, httpcookie, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  global geturls_download_sleep, tmpfileprefix, tmpfilesuffix;
  exec_time_start = time.time();
  myhash = hashlib.new("sha1");
  if(sys.version[0]=="2"):
   myhash.update(httpurl);
   myhash.update(str(buffersize));
   myhash.update(str(exec_time_start));
  if(sys.version[0]>="3"):
   myhash.update(httpurl.encode('utf-8'));
   myhash.update(str(buffersize).encode('utf-8'));
   myhash.update(str(exec_time_start).encode('utf-8'));
  newtmpfilesuffix = tmpfilesuffix + str(myhash.hexdigest());
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(urlparts.username is not None or urlparts.password is not None):
   inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
   httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
  time.sleep(sleep);
  if(postdata is not None and not isinstance(postdata, dict)):
   postdata = urlencode(postdata);
  try:
   if(httpmethod=="GET"):
    httpx_pool = httpcore.ConnectionPool(http1=True, http2=True);
    geturls_text = httpx_pool.request("GET", httpurl, headers=httpheaders);
   elif(httpmethod=="POST"):
    httpx_pool = httpcore.ConnectionPool(http1=True, http2=True);
    geturls_text = httpx_pool.request("GET", httpurl, data=postdata, headers=httpheaders);
   else:
    httpx_pool = httpcore.ConnectionPool(http1=True, http2=True);
    geturls_text = httpx_pool.request("GET", httpurl, headers=httpheaders);
  except httpcore.ConnectTimeout:
   log.info("Error With URL "+httpurl);
   return False;
  except httpcore.ConnectError:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  httpcodeout = geturls_text.status;
  httpversionout = "1.1";
  httpmethodout = httpmethod;
  httpurlout = str(httpurl);
  httpheaderout = geturls_text.headers;
  httpheadersentout = httpheaders;
  if(isinstance(httpheaderout, list)):
    httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
  if(isinstance(httpheadersentout, list)):
    httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
  downloadsize = int(httpheaderout.get('Content-Length'));
  if(downloadsize is not None):
   downloadsize = int(downloadsize);
  if downloadsize is None: downloadsize = 0;
  fulldatasize = 0;
  prevdownsize = 0;
  log.info("Downloading URL "+httpurl);
  with tempfile.NamedTemporaryFile('wb+', prefix=tmpfileprefix, suffix=newtmpfilesuffix, delete=False) as f:
   tmpfilename = f.name;
   returnval = {'Type': "File", 'Filename': tmpfilename, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
   for databytes in geturls_text.iter_content(chunk_size=buffersize):
    datasize = len(databytes);
    fulldatasize = datasize + fulldatasize;
    percentage = "";
    if(downloadsize>0):
     percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
    downloaddiff = fulldatasize - prevdownsize;
    log.info("Downloading "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Downloaded "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
    prevdownsize = fulldatasize;
    f.write(databytes);
   f.close();
  geturls_text.close();
  exec_time_end = time.time();
  log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to download file.");
  returnval.update({'Filesize': os.path.getsize(tmpfilename), 'DownloadTime': float(exec_time_start - exec_time_end), 'DownloadTimeReadable': hms_string(exec_time_start - exec_time_end)});
  return returnval;

if(not havehttpcore):
 def download_from_url_file_with_httpcore2(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  returnval = download_from_url_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep)
  return returnval;

if(havehttpcore):
 def download_from_url_to_file_with_httpcore2(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  global geturls_download_sleep;
  if(sleep<0):
   sleep = geturls_download_sleep;
  if(not outfile=="-"):
   outpath = outpath.rstrip(os.path.sep);
   filepath = os.path.realpath(outpath+os.path.sep+outfile);
   if(not os.path.exists(outpath)):
    os.makedirs(outpath);
   if(os.path.exists(outpath) and os.path.isfile(outpath)):
    return False;
   if(os.path.exists(filepath) and os.path.isdir(filepath)):
    return False;
   pretmpfilename = download_from_url_file_with_httpcore2(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   log.info("Moving file "+tmpfilename+" to "+filepath);
   exec_time_start = time.time();
   shutil.move(tmpfilename, filepath);
   exec_time_end = time.time();
   log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to move file.");
   if(os.path.exists(tmpfilename)):
    os.remove(tmpfilename);
   returnval = {'Type': "File", 'Filename': filepath, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]=="2"):
   pretmpfilename = download_from_url_file_with_httpcore2(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = StringIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': ['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]>="3"):
   pretmpfilename = download_from_url_file_with_httpcore2(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = BytesIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  return returnval;

if(not havehttpx):
 def download_from_url_to_file_with_httpcore2(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  returnval = download_from_url_to_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, outfile, outpath, sleep)
  return returnval;

if(haveurllib3):
 def download_from_url_with_request3(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  global geturls_download_sleep, havebrotli;
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(urlparts.username is not None or urlparts.password is not None):
   inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
   httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
  time.sleep(sleep);
  urllib_pool = urllib3.PoolManager(headers=httpheaders);
  if(postdata is not None and not isinstance(postdata, dict)):
   postdata = urlencode(postdata);
  try:
   if(httpmethod=="GET"):
    geturls_text = geturls_text = urllib_pool.request("GET", httpurl, headers=httpheaders, preload_content=False);
   elif(httpmethod=="POST"):
    geturls_text = geturls_text = urllib_pool.request("POST", httpurl, body=postdata, headers=httpheaders, preload_content=False);
   else:
    geturls_text = geturls_text = urllib_pool.request("GET", httpurl, headers=httpheaders, preload_content=False);
  except urllib3.exceptions.ConnectTimeoutError:
   log.info("Error With URL "+httpurl);
   return False;
  except urllib3.exceptions.ConnectError:
   log.info("Error With URL "+httpurl);
   return False;
  except urllib3.exceptions.MaxRetryError:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  httpcodeout = geturls_text.status;
  httpversionout = "1.1";
  httpmethodout = httpmethod;
  httpurlout = geturls_text.geturl();
  httpheaderout = geturls_text.info();
  httpheadersentout = httpheaders;
  if(isinstance(httpheaderout, list)):
    httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
  if(isinstance(httpheadersentout, list)):
    httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
  log.info("Downloading URL "+httpurl);
  if(httpheaderout.get("Content-Encoding")=="gzip" or httpheaderout.get("Content-Encoding")=="deflate"):
   if(sys.version[0]=="2"):
    strbuf = StringIO(geturls_text.read());
   if(sys.version[0]>="3"):
    strbuf = BytesIO(geturls_text.read());
   gzstrbuf = gzip.GzipFile(fileobj=strbuf);
   returnval_content = gzstrbuf.read()[:];
  if(httpheaderout.get("Content-Encoding")!="gzip" and httpheaderout.get("Content-Encoding")!="deflate" and httpheaderout.get("Content-Encoding")!="br"):
   returnval_content = geturls_text.read()[:];
  if(httpheaderout.get("Content-Encoding")=="br" and havebrotli):
   returnval_content = brotli.decompress(returnval_content);
  returnval = {'Type': "Content", 'Content': returnval_content, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
  geturls_text.close();
  return returnval;

if(not haveurllib3):
 def download_from_url_with_request3(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  returnval = download_from_url_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep)
  return returnval;

if(haveurllib3):
 def download_from_url_file_with_request3(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  global geturls_download_sleep, tmpfileprefix, tmpfilesuffix;
  exec_time_start = time.time();
  myhash = hashlib.new("sha1");
  if(sys.version[0]=="2"):
   myhash.update(httpurl);
   myhash.update(str(buffersize));
   myhash.update(str(exec_time_start));
  if(sys.version[0]>="3"):
   myhash.update(httpurl.encode('utf-8'));
   myhash.update(str(buffersize).encode('utf-8'));
   myhash.update(str(exec_time_start).encode('utf-8'));
  newtmpfilesuffix = tmpfilesuffix + str(myhash.hexdigest());
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(urlparts.username is not None or urlparts.password is not None):
   inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
   httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
  time.sleep(sleep);
  urllib_pool = urllib3.PoolManager(headers=httpheaders);
  if(postdata is not None and not isinstance(postdata, dict)):
   postdata = urlencode(postdata);
  try:
   if(httpmethod=="GET"):
    geturls_text = geturls_text = urllib_pool.request("GET", httpurl, headers=httpheaders, preload_content=False);
   elif(httpmethod=="POST"):
    geturls_text = geturls_text = urllib_pool.request("POST", httpurl, body=postdata, headers=httpheaders, preload_content=False);
   else:
    geturls_text = geturls_text = urllib_pool.request("GET", httpurl, headers=httpheaders, preload_content=False);
  except urllib3.exceptions.ConnectTimeoutError:
   log.info("Error With URL "+httpurl);
   return False;
  except urllib3.exceptions.ConnectError:
   log.info("Error With URL "+httpurl);
   return False;
  except urllib3.exceptions.MaxRetryError:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  httpcodeout = geturls_text.status;
  httpversionout = "1.1";
  httpmethodout = httpmethod;
  httpurlout = geturls_text.geturl();
  httpheaderout = geturls_text.info();
  httpheadersentout = httpheaders;
  if(isinstance(httpheaderout, list)):
    httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
  if(isinstance(httpheadersentout, list)):
    httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
  downloadsize = int(geturls_text.headers.get('Content-Length'));
  if(downloadsize is not None):
   downloadsize = int(downloadsize);
  if downloadsize is None: downloadsize = 0;
  fulldatasize = 0;
  prevdownsize = 0;
  log.info("Downloading URL "+httpurl);
  with tempfile.NamedTemporaryFile('wb+', prefix=tmpfileprefix, suffix=newtmpfilesuffix, delete=False) as f:
   tmpfilename = f.name;
   returnval = {'Type': "File", 'Filename': tmpfilename, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
   while True:
    databytes = geturls_text.read(buffersize);
    if not databytes: break;
    datasize = len(databytes);
    fulldatasize = datasize + fulldatasize;
    percentage = "";
    if(downloadsize>0):
     percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
    downloaddiff = fulldatasize - prevdownsize;
    log.info("Downloading "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Downloaded "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
    prevdownsize = fulldatasize;
    f.write(databytes);
   f.close();
  geturls_text.close();
  exec_time_end = time.time();
  log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to download file.");
  returnval.update({'Filesize': os.path.getsize(tmpfilename), 'DownloadTime': float(exec_time_start - exec_time_end), 'DownloadTimeReadable': hms_string(exec_time_start - exec_time_end)});
  return returnval;

if(not haveurllib3):
 def download_from_url_file_with_request3(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  returnval = download_from_url_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep)
  return returnval;

if(haveurllib3):
 def download_from_url_to_file_with_request3(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  global geturls_download_sleep;
  if(sleep<0):
   sleep = geturls_download_sleep;
  if(not outfile=="-"):
   outpath = outpath.rstrip(os.path.sep);
   filepath = os.path.realpath(outpath+os.path.sep+outfile);
   if(not os.path.exists(outpath)):
    os.makedirs(outpath);
   if(os.path.exists(outpath) and os.path.isfile(outpath)):
    return False;
   if(os.path.exists(filepath) and os.path.isdir(filepath)):
    return False;
   pretmpfilename = download_from_url_file_with_request3(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   log.info("Moving file "+tmpfilename+" to "+filepath);
   exec_time_start = time.time();
   shutil.move(tmpfilename, filepath);
   exec_time_end = time.time();
   log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to move file.");
   if(os.path.exists(tmpfilename)):
    os.remove(tmpfilename);
   returnval = {'Type': "File", 'Filename': filepath, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]=="2"):
   pretmpfilename = download_from_url_file_with_request3(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = StringIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]>="3"):
   pretmpfilename = download_from_url_file_with_request3(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = BytesIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  return returnval;

if(not haveurllib3):
 def download_from_url_to_file_with_request3(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  returnval = download_from_url_to_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, outfile, outpath, sleep)
  return returnval;

if(haveurllib3):
 def download_from_url_with_urllib3(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  global geturls_download_sleep, havebrotli;
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(urlparts.username is not None or urlparts.password is not None):
   inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
   httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
  time.sleep(sleep);
  urllib_pool = urllib3.PoolManager(headers=httpheaders);
  if(postdata is not None and not isinstance(postdata, dict)):
   postdata = urlencode(postdata);
  try:
   if(httpmethod=="GET"):
    geturls_text = urllib_pool.urlopen("GET", httpurl, headers=httpheaders, preload_content=False);
   elif(httpmethod=="POST"):
    geturls_text = urllib_pool.urlopen("GET", httpurl, body=postdata, headers=httpheaders, preload_content=False);
   else:
    geturls_text = urllib_pool.urlopen("GET", httpurl, headers=httpheaders, preload_content=False);
  except urllib3.exceptions.ConnectTimeoutError:
   log.info("Error With URL "+httpurl);
   return False;
  except urllib3.exceptions.ConnectError:
   log.info("Error With URL "+httpurl);
   return False;
  except urllib3.exceptions.MaxRetryError:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  httpcodeout = geturls_text.status;
  httpversionout = "1.1";
  httpmethodout = httpmethod;
  httpurlout = geturls_text.geturl();
  httpheaderout = geturls_text.info();
  httpheadersentout = httpheaders;
  if(isinstance(httpheaderout, list)):
    httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
  if(isinstance(httpheadersentout, list)):
    httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
  log.info("Downloading URL "+httpurl);
  if(httpheaderout.get("Content-Encoding")=="gzip" or httpheaderout.get("Content-Encoding")=="deflate"):
   if(sys.version[0]=="2"):
    strbuf = StringIO(geturls_text.read());
   if(sys.version[0]>="3"):
    strbuf = BytesIO(geturls_text.read());
   gzstrbuf = gzip.GzipFile(fileobj=strbuf);
   returnval_content = gzstrbuf.read()[:];
  if(httpheaderout.get("Content-Encoding")!="gzip" and httpheaderout.get("Content-Encoding")!="deflate" and httpheaderout.get("Content-Encoding")!="br"):
   returnval_content = geturls_text.read()[:];
  if(httpheaderout.get("Content-Encoding")=="br" and havebrotli):
   returnval_content = brotli.decompress(returnval_content);
  returnval = {'Type': "Content", 'Content': returnval_content, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
  geturls_text.close();
  return returnval;

if(not haveurllib3):
 def download_from_url_with_urllib3(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  returnval = download_from_url_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep)
  return returnval;

if(haveurllib3):
 def download_from_url_file_with_urllib3(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  global geturls_download_sleep, tmpfileprefix, tmpfilesuffix;
  exec_time_start = time.time();
  myhash = hashlib.new("sha1");
  if(sys.version[0]=="2"):
   myhash.update(httpurl);
   myhash.update(str(buffersize));
   myhash.update(str(exec_time_start));
  if(sys.version[0]>="3"):
   myhash.update(httpurl.encode('utf-8'));
   myhash.update(str(buffersize).encode('utf-8'));
   myhash.update(str(exec_time_start).encode('utf-8'));
  newtmpfilesuffix = tmpfilesuffix + str(myhash.hexdigest());
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(urlparts.username is not None or urlparts.password is not None):
   inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
   httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
  time.sleep(sleep);
  urllib_pool = urllib3.PoolManager(headers=httpheaders);
  if(postdata is not None and not isinstance(postdata, dict)):
   postdata = urlencode(postdata);
  try:
   if(httpmethod=="GET"):
    geturls_text = urllib_pool.urlopen("GET", httpurl, headers=httpheaders, preload_content=False);
   elif(httpmethod=="POST"):
    geturls_text = urllib_pool.urlopen("GET", httpurl, body=postdata, headers=httpheaders, preload_content=False);
   else:
    geturls_text = urllib_pool.urlopen("GET", httpurl, headers=httpheaders, preload_content=False);
  except urllib3.exceptions.ConnectTimeoutError:
   log.info("Error With URL "+httpurl);
   return False;
  except urllib3.exceptions.ConnectError:
   log.info("Error With URL "+httpurl);
   return False;
  except urllib3.exceptions.MaxRetryError:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  httpcodeout = geturls_text.status;
  httpversionout = "1.1";
  httpmethodout = httpmethod;
  httpurlout = geturls_text.geturl();
  httpheaderout = geturls_text.info();
  httpheadersentout = httpheaders;
  if(isinstance(httpheaderout, list)):
    httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
  if(isinstance(httpheadersentout, list)):
    httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
  downloadsize = int(geturls_text.headers.get('Content-Length'));
  if(downloadsize is not None):
   downloadsize = int(downloadsize);
  if downloadsize is None: downloadsize = 0;
  fulldatasize = 0;
  prevdownsize = 0;
  log.info("Downloading URL "+httpurl);
  with tempfile.NamedTemporaryFile('wb+', prefix=tmpfileprefix, suffix=newtmpfilesuffix, delete=False) as f:
   tmpfilename = f.name;
   returnval = {'Type': "File", 'Filename': tmpfilename, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
   while True:
    databytes = geturls_text.read(buffersize);
    if not databytes: break;
    datasize = len(databytes);
    fulldatasize = datasize + fulldatasize;
    percentage = "";
    if(downloadsize>0):
     percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
    downloaddiff = fulldatasize - prevdownsize;
    log.info("Downloading "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Downloaded "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
    prevdownsize = fulldatasize;
    f.write(databytes);
   f.close();
  geturls_text.close();
  exec_time_end = time.time();
  log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to download file.");
  returnval.update({'Filesize': os.path.getsize(tmpfilename), 'DownloadTime': float(exec_time_start - exec_time_end), 'DownloadTimeReadable': hms_string(exec_time_start - exec_time_end)});
  return returnval;

if(not haveurllib3):
 def download_from_url_file_with_urllib3(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  returnval = download_from_url_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep)
  return returnval;

if(haveurllib3):
 def download_from_url_to_file_with_urllib3(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  global geturls_download_sleep;
  if(sleep<0):
   sleep = geturls_download_sleep;
  if(not outfile=="-"):
   outpath = outpath.rstrip(os.path.sep);
   filepath = os.path.realpath(outpath+os.path.sep+outfile);
   if(not os.path.exists(outpath)):
    os.makedirs(outpath);
   if(os.path.exists(outpath) and os.path.isfile(outpath)):
    return False;
   if(os.path.exists(filepath) and os.path.isdir(filepath)):
    return False;
   pretmpfilename = download_from_url_file_with_urllib3(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   log.info("Moving file "+tmpfilename+" to "+filepath);
   exec_time_start = time.time();
   shutil.move(tmpfilename, filepath);
   exec_time_end = time.time();
   log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to move file.");
   if(os.path.exists(tmpfilename)):
    os.remove(tmpfilename);
   returnval = {'Type': "File", 'Filename': filepath, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]=="2"):
   pretmpfilename = download_from_url_file_with_urllib3(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = StringIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]>="3"):
   pretmpfilename = download_from_url_file_with_urllib3(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = BytesIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  return returnval;

if(not haveurllib3):
 def download_from_url_to_file_with_urllib3(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  returnval = download_from_url_to_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, outfile, outpath, sleep)
  return returnval;

if(havemechanize):
 def download_from_url_with_mechanize(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  global geturls_download_sleep, havebrotli;
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(urlparts.username is not None or urlparts.password is not None):
   inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
   httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
  geturls_opener = mechanize.Browser();
  if(isinstance(httpheaders, dict)):
   httpheaders = make_http_headers_from_dict_to_list(httpheaders);
  time.sleep(sleep);
  geturls_opener.addheaders = httpheaders;
  geturls_opener.set_cookiejar(httpcookie);
  geturls_opener.set_handle_robots(False);
  if(postdata is not None and not isinstance(postdata, dict)):
   postdata = urlencode(postdata);
  try:
   if(httpmethod=="GET"):
    geturls_text = geturls_opener.open(httpurl);
   elif(httpmethod=="POST"):
    geturls_text = geturls_opener.open(httpurl, data=postdata);
   else:
    geturls_text = geturls_opener.open(httpurl);
  except mechanize.HTTPError as geturls_text_error:
   geturls_text = geturls_text_error;
   log.info("Error With URL "+httpurl);
  except URLError:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  httpcodeout = geturls_text.code;
  httpversionout = "1.1";
  httpmethodout = httpmethod;
  httpurlout = geturls_text.geturl();
  httpheaderout = geturls_text.info();
  httpheadersentout = httpheaders;
  if(isinstance(httpheaderout, list)):
    httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
  if(isinstance(httpheadersentout, list)):
    httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
  log.info("Downloading URL "+httpurl);
  if(httpheaderout.get("Content-Encoding")=="gzip" or httpheaderout.get("Content-Encoding")=="deflate"):
   if(sys.version[0]=="2"):
    strbuf = StringIO(geturls_text.read());
   if(sys.version[0]>="3"):
    strbuf = BytesIO(geturls_text.read());
   gzstrbuf = gzip.GzipFile(fileobj=strbuf);
   returnval_content = gzstrbuf.read()[:];
  if(httpheaderout.get("Content-Encoding")!="gzip" and httpheaderout.get("Content-Encoding")!="deflate" and httpheaderout.get("Content-Encoding")!="br"):
   returnval_content = geturls_text.read()[:];
  if(httpheaderout.get("Content-Encoding")=="br" and havebrotli):
   returnval_content = brotli.decompress(returnval_content);
  returnval = {'Type': "Content", 'Content': returnval_content, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
  geturls_text.close();
  return returnval;

if(not havemechanize):
 def download_from_url_with_mechanize(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  returnval = download_from_url_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, sleep)
  return returnval;

if(havemechanize):
 def download_from_url_file_with_mechanize(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  global geturls_download_sleep, tmpfileprefix, tmpfilesuffix;
  exec_time_start = time.time();
  myhash = hashlib.new("sha1");
  if(sys.version[0]=="2"):
   myhash.update(httpurl);
   myhash.update(str(buffersize));
   myhash.update(str(exec_time_start));
  if(sys.version[0]>="3"):
   myhash.update(httpurl.encode('utf-8'));
   myhash.update(str(buffersize).encode('utf-8'));
   myhash.update(str(exec_time_start).encode('utf-8'));
  newtmpfilesuffix = tmpfilesuffix + str(myhash.hexdigest());
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(urlparts.username is not None or urlparts.password is not None):
   inurlencode = b64encode(str(urlparts.username+":"+urlparts.password).encode()).decode("UTF-8");
   httpheaders.update( { 'Authorization': "Basic "+inurlencode } );
  geturls_opener = mechanize.Browser();
  if(isinstance(httpheaders, dict)):
   httpheaders = make_http_headers_from_dict_to_list(httpheaders);
  time.sleep(sleep);
  geturls_opener.addheaders = httpheaders;
  geturls_opener.set_cookiejar(httpcookie);
  geturls_opener.set_handle_robots(False);
  if(postdata is not None and not isinstance(postdata, dict)):
   postdata = urlencode(postdata);
  try:
   if(httpmethod=="GET"):
    geturls_text = geturls_opener.open(httpurl);
   elif(httpmethod=="POST"):
    geturls_text = geturls_opener.open(httpurl, data=postdata);
   else:
    geturls_text = geturls_opener.open(httpurl);
  except mechanize.HTTPError as geturls_text_error:
   geturls_text = geturls_text_error;
   log.info("Error With URL "+httpurl);
  except URLError:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  httpcodeout = geturls_text.code;
  httpversionout = "1.1";
  httpmethodout = httpmethod;
  httpurlout = geturls_text.geturl();
  httpheaderout = geturls_text.info();
  httpheadersentout = httpheaders;
  if(isinstance(httpheaderout, list)):
    httpheaderout = dict(make_http_headers_from_list_to_dict(httpheaderout));
  if(isinstance(httpheadersentout, list)):
    httpheadersentout = dict(make_http_headers_from_list_to_dict(httpheadersentout));
  downloadsize = int(httpheaderout.get('Content-Length'));
  if(downloadsize is not None):
   downloadsize = int(downloadsize);
  if downloadsize is None: downloadsize = 0;
  fulldatasize = 0;
  prevdownsize = 0;
  log.info("Downloading URL "+httpurl);
  with tempfile.NamedTemporaryFile('wb+', prefix=tmpfileprefix, suffix=newtmpfilesuffix, delete=False) as f:
   tmpfilename = f.name;
   returnval = {'Type': "File", 'Filename': tmpfilename, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'Headers': httpheaderout, 'Version': httpversionout, 'Method': httpmethodout, 'HeadersSent': httpheadersentout, 'URL': httpurlout, 'Code': httpcodeout};
   while True:
    databytes = geturls_text.read(buffersize);
    if not databytes: break;
    datasize = len(databytes);
    fulldatasize = datasize + fulldatasize;
    percentage = "";
    if(downloadsize>0):
     percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
    downloaddiff = fulldatasize - prevdownsize;
    log.info("Downloading "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Downloaded "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
    prevdownsize = fulldatasize;
    f.write(databytes);
   f.close();
  geturls_text.close();
  exec_time_end = time.time();
  log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to download file.");
  returnval.update({'Filesize': os.path.getsize(tmpfilename), 'DownloadTime': float(exec_time_start - exec_time_end), 'DownloadTimeReadable': hms_string(exec_time_start - exec_time_end)});
  return returnval;

if(not havemechanize):
 def download_from_url_file_with_mechanize(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  returnval = download_from_url_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, sleep)
  return returnval;

if(havemechanize):
 def download_from_url_to_file_with_mechanize(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  global geturls_download_sleep;
  if(sleep<0):
   sleep = geturls_download_sleep;
  if(not outfile=="-"):
   outpath = outpath.rstrip(os.path.sep);
   filepath = os.path.realpath(outpath+os.path.sep+outfile);
   if(not os.path.exists(outpath)):
    os.makedirs(outpath);
   if(os.path.exists(outpath) and os.path.isfile(outpath)):
    return False;
   if(os.path.exists(filepath) and os.path.isdir(filepath)):
    return False;
   pretmpfilename = download_from_url_file_with_mechanize(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   log.info("Moving file "+tmpfilename+" to "+filepath);
   exec_time_start = time.time();
   shutil.move(tmpfilename, filepath);
   exec_time_end = time.time();
   log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to move file.");
   if(os.path.exists(tmpfilename)):
    os.remove(tmpfilename);
   returnval = {'Type': "File", 'Filename': filepath, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]=="2"):
   pretmpfilename = download_from_url_file_with_mechanize(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = StringIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]>="3"):
   pretmpfilename = download_from_url_file_with_mechanize(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = BytesIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': httpmethod, 'HeadersSent': ['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  return returnval;

if(not havemechanize):
 def download_from_url_to_file_with_mechanize(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  returnval = download_from_url_to_file_with_urllib(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize, outfile, outpath, sleep)
  return returnval;

def download_file_from_ftp_file(url):
 urlparts = urlparse.urlparse(url);
 file_name = os.path.basename(urlparts.path);
 file_dir = os.path.dirname(urlparts.path);
 if(urlparts.username is not None):
  ftp_username = urlparts.username;
 else:
  ftp_username = "anonymous";
 if(urlparts.password is not None):
  ftp_password = urlparts.password;
 elif(urlparts.password is None and urlparts.username=="anonymous"):
  ftp_password = "anonymous";
 else:
  ftp_password = "";
 if(urlparts.scheme=="ftp"):
  ftp = FTP();
 elif(urlparts.scheme=="ftps"):
  ftp = FTP_TLS();
 else:
  return False;
 if(urlparts.scheme=="http" or urlparts.scheme=="https"):
  return False;
 ftp_port = urlparts.port;
 if(urlparts.port is None):
  ftp_port = 21;
 try:
  ftp.connect(urlparts.hostname, ftp_port);
 except socket.gaierror:
  log.info("Error With URL "+httpurl);
  return False;
 except socket.timeout:
  log.info("Error With URL "+httpurl);
  return False;
 ftp.login(urlparts.username, urlparts.password);
 if(urlparts.scheme=="ftps"):
  ftp.prot_p();
 ftpfile = BytesIO();
 ftp.retrbinary("RETR "+urlparts.path, ftpfile.write);
 #ftp.storbinary("STOR "+urlparts.path, ftpfile.write);
 ftp.close();
 ftpfile.seek(0, 0);
 return ftpfile;

def download_file_from_ftp_string(url):
 ftpfile = download_file_from_ftp_file(url);
 return ftpfile.read();

def download_from_url_with_ftp(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
 global geturls_download_sleep, havebrotli;
 if(sleep<0):
  sleep = geturls_download_sleep;
 urlparts = urlparse.urlparse(httpurl);
 if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
 if(isinstance(httpheaders, dict)):
  httpheaders = make_http_headers_from_dict_to_list(httpheaders);
 time.sleep(sleep);
 geturls_text = download_file_from_ftp_file(httpurl);
 if(not geturls_text):
  return False;
 log.info("Downloading URL "+httpurl);
 returnval_content = geturls_text.read()[:];
 returnval = {'Type': "Content", 'Content': returnval_content, 'Headers': None, 'Version': None, 'Method': None, 'HeadersSent': None, 'URL': httpurl, 'Code': None};
 geturls_text.close();
 return returnval;

def download_from_url_file_with_ftp(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
 global geturls_download_sleep, tmpfileprefix, tmpfilesuffix;
 exec_time_start = time.time();
 myhash = hashlib.new("sha1");
 if(sys.version[0]=="2"):
  myhash.update(httpurl);
  myhash.update(str(buffersize));
  myhash.update(str(exec_time_start));
 if(sys.version[0]>="3"):
  myhash.update(httpurl.encode('utf-8'));
  myhash.update(str(buffersize).encode('utf-8'));
  myhash.update(str(exec_time_start).encode('utf-8'));
 newtmpfilesuffix = tmpfilesuffix + str(myhash.hexdigest());
 if(sleep<0):
  sleep = geturls_download_sleep;
 urlparts = urlparse.urlparse(httpurl);
 if(isinstance(httpheaders, list)):
   httpheaders = make_http_headers_from_list_to_dict(httpheaders);
 if(isinstance(httpheaders, dict)):
  httpheaders = make_http_headers_from_dict_to_list(httpheaders);
 time.sleep(sleep);
 geturls_text = download_file_from_ftp_file(httpurl);
 if(not geturls_text):
  return False;
 geturls_text.seek(0, 2);
 downloadsize = geturls_text.tell();
 geturls_text.seek(0, 0);
 if(downloadsize is not None):
  downloadsize = int(downloadsize);
 if downloadsize is None: downloadsize = 0;
 fulldatasize = 0;
 prevdownsize = 0;
 log.info("Downloading URL "+httpurl);
 with tempfile.NamedTemporaryFile('wb+', prefix=tmpfileprefix, suffix=newtmpfilesuffix, delete=False) as f:
  tmpfilename = f.name;
  returnval = {'Type': "File", 'Filename': tmpfilename, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'Headers': None, 'Version': None, 'Method': None, 'HeadersSent': None, 'URL': httpurl, 'Code': None};
  while True:
   databytes = geturls_text.read(buffersize);
   if not databytes: break;
   datasize = len(databytes);
   fulldatasize = datasize + fulldatasize;
   percentage = "";
   if(downloadsize>0):
    percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
   downloaddiff = fulldatasize - prevdownsize;
   log.info("Downloading "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Downloaded "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
   prevdownsize = fulldatasize;
   f.write(databytes);
  f.close();
 geturls_text.close();
 exec_time_end = time.time();
 log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to download file.");
 returnval.update({'Filesize': os.path.getsize(tmpfilename), 'DownloadTime': float(exec_time_start - exec_time_end), 'DownloadTimeReadable': hms_string(exec_time_start - exec_time_end)});
 return returnval;

def download_from_url_to_file_with_ftp(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
 global geturls_download_sleep;
 if(sleep<0):
  sleep = geturls_download_sleep;
 if(not outfile=="-"):
  outpath = outpath.rstrip(os.path.sep);
  filepath = os.path.realpath(outpath+os.path.sep+outfile);
  if(not os.path.exists(outpath)):
   os.makedirs(outpath);
  if(os.path.exists(outpath) and os.path.isfile(outpath)):
   return False;
  if(os.path.exists(filepath) and os.path.isdir(filepath)):
   return False;
  pretmpfilename = download_from_url_file_with_ftp(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
  if(not pretmpfilename):
   return False;
  tmpfilename = pretmpfilename['Filename'];
  downloadsize = os.path.getsize(tmpfilename);
  fulldatasize = 0;
  log.info("Moving file "+tmpfilename+" to "+filepath);
  exec_time_start = time.time();
  shutil.move(tmpfilename, filepath);
  exec_time_end = time.time();
  log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to move file.");
  if(os.path.exists(tmpfilename)):
   os.remove(tmpfilename);
  returnval = {'Type': "File", 'Filename': filepath, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': None, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
 if(outfile=="-" and sys.version[0]=="2"):
  pretmpfilename = download_from_url_file_with_ftp(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
  if(not pretmpfilename):
   return False;
  tmpfilename = pretmpfilename['Filename'];
  downloadsize = os.path.getsize(tmpfilename);
  fulldatasize = 0;
  prevdownsize = 0;
  exec_time_start = time.time();
  with open(tmpfilename, 'rb') as ft:
   f = StringIO();
   while True:
    databytes = ft.read(buffersize[1]);
    if not databytes: break;
    datasize = len(databytes);
    fulldatasize = datasize + fulldatasize;
    percentage = "";
    if(downloadsize>0):
     percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
    downloaddiff = fulldatasize - prevdownsize;
    log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
    prevdownsize = fulldatasize;
    f.write(databytes);
   f.seek(0);
   fdata = f.getvalue();
   f.close();
   ft.close();
   os.remove(tmpfilename);
   exec_time_end = time.time();
   log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
  returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': None, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
 if(outfile=="-" and sys.version[0]>="3"):
  pretmpfilename = download_from_url_file_with_ftp(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
  tmpfilename = pretmpfilename['Filename'];
  downloadsize = os.path.getsize(tmpfilename);
  fulldatasize = 0;
  prevdownsize = 0;
  exec_time_start = time.time();
  with open(tmpfilename, 'rb') as ft:
   f = BytesIO();
   while True:
    databytes = ft.read(buffersize[1]);
    if not databytes: break;
    datasize = len(databytes);
    fulldatasize = datasize + fulldatasize;
    percentage = "";
    if(downloadsize>0):
     percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
    downloaddiff = fulldatasize - prevdownsize;
    log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
    prevdownsize = fulldatasize;
    f.write(databytes);
   f.seek(0);
   fdata = f.getvalue();
   f.close();
   ft.close();
   os.remove(tmpfilename);
   exec_time_end = time.time();
   log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
  returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': None, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
 return returnval;

def upload_file_to_ftp_file(ftpfile, url):
 urlparts = urlparse.urlparse(url);
 file_name = os.path.basename(urlparts.path);
 file_dir = os.path.dirname(urlparts.path);
 if(urlparts.username is not None):
  ftp_username = urlparts.username;
 else:
  ftp_username = "anonymous";
 if(urlparts.password is not None):
  ftp_password = urlparts.password;
 elif(urlparts.password is None and urlparts.username=="anonymous"):
  ftp_password = "anonymous";
 else:
  ftp_password = "";
 if(urlparts.scheme=="ftp"):
  ftp = FTP();
 elif(urlparts.scheme=="ftps"):
  ftp = FTP_TLS();
 else:
  return False;
 if(urlparts.scheme=="http" or urlparts.scheme=="https"):
  return False;
 ftp_port = urlparts.port;
 if(urlparts.port is None):
  ftp_port = 21;
 try:
  ftp.connect(urlparts.hostname, ftp_port);
 except socket.gaierror:
  log.info("Error With URL "+httpurl);
  return False;
 except socket.timeout:
  log.info("Error With URL "+httpurl);
  return False;
 ftp.login(urlparts.username, urlparts.password);
 if(urlparts.scheme=="ftps"):
  ftp.prot_p();
 ftp.storbinary("STOR "+urlparts.path, ftpfile);
 ftp.close();
 ftpfile.seek(0, 0);
 return ftpfile;

def upload_file_to_ftp_string(ftpstring, url):
 ftpfileo = BytesIO(ftpstring);
 ftpfile = upload_file_to_ftp_file(ftpfileo, url);
 ftpfileo.close();
 return ftpfile;

if(haveparamiko):
 def download_file_from_sftp_file(url):
  urlparts = urlparse.urlparse(url);
  file_name = os.path.basename(urlparts.path);
  file_dir = os.path.dirname(urlparts.path);
  if(urlparts.scheme=="http" or urlparts.scheme=="https"):
   return False;
  sftp_port = urlparts.port;
  if(urlparts.port is None):
   sftp_port = 22;
  else:
   sftp_port = urlparts.port;
  if(urlparts.username is not None):
   sftp_username = urlparts.username;
  else:
   sftp_username = "anonymous";
  if(urlparts.password is not None):
   sftp_password = urlparts.password;
  elif(urlparts.password is None and urlparts.username=="anonymous"):
   sftp_password = "anonymous";
  else:
   sftp_password = "";
  if(urlparts.scheme!="sftp"):
   return False;
  ssh = paramiko.SSHClient();
  ssh.load_system_host_keys();
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy());
  try:
   ssh.connect(urlparts.hostname, port=sftp_port, username=urlparts.username, password=urlparts.password);
  except paramiko.ssh_exception.SSHException:
   return False;
  except socket.gaierror:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  sftp = ssh.open_sftp();
  sftpfile = BytesIO();
  sftp.getfo(urlparts.path, sftpfile);
  sftp.close();
  ssh.close();
  sftpfile.seek(0, 0);
  return sftpfile;
else:
 def download_file_from_sftp_file(url):
  return False;

if(haveparamiko):
 def download_file_from_sftp_string(url):
  sftpfile = download_file_from_sftp_file(url);
  return sftpfile.read();
else:
 def download_file_from_ftp_string(url):
  return False;

if(haveparamiko):
 def download_from_url_with_sftp(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  global geturls_download_sleep, havebrotli;
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
    httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(isinstance(httpheaders, dict)):
   httpheaders = make_http_headers_from_dict_to_list(httpheaders);
  time.sleep(sleep);
  geturls_text = download_file_from_sftp_file(httpurl);
  if(not geturls_text):
   return False;
  log.info("Downloading URL "+httpurl);
  returnval_content = geturls_text.read()[:];
  returnval = {'Type': "Content", 'Content': returnval_content, 'Headers': None, 'Version': None, 'Method': None, 'HeadersSent': None, 'URL': httpurl, 'Code': None};
  geturls_text.close();
  return returnval;

if(not haveparamiko):
 def download_from_url_with_sftp(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, sleep=-1):
  return False;

if(haveparamiko):
 def download_from_url_file_with_sftp(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  global geturls_download_sleep, tmpfileprefix, tmpfilesuffix;
  exec_time_start = time.time();
  myhash = hashlib.new("sha1");
  if(sys.version[0]=="2"):
   myhash.update(httpurl);
   myhash.update(str(buffersize));
   myhash.update(str(exec_time_start));
  if(sys.version[0]>="3"):
   myhash.update(httpurl.encode('utf-8'));
   myhash.update(str(buffersize).encode('utf-8'));
   myhash.update(str(exec_time_start).encode('utf-8'));
  newtmpfilesuffix = tmpfilesuffix + str(myhash.hexdigest());
  if(sleep<0):
   sleep = geturls_download_sleep;
  urlparts = urlparse.urlparse(httpurl);
  if(isinstance(httpheaders, list)):
    httpheaders = make_http_headers_from_list_to_dict(httpheaders);
  if(isinstance(httpheaders, dict)):
   httpheaders = make_http_headers_from_dict_to_list(httpheaders);
  time.sleep(sleep);
  geturls_text = download_file_from_sftp_file(httpurl);
  if(not geturls_text):
   return False;
  geturls_text.seek(0, 2);
  downloadsize = geturls_text.tell();
  geturls_text.seek(0, 0);
  if(downloadsize is not None):
   downloadsize = int(downloadsize);
  if downloadsize is None: downloadsize = 0;
  fulldatasize = 0;
  prevdownsize = 0;
  log.info("Downloading URL "+httpurl);
  with tempfile.NamedTemporaryFile('wb+', prefix=tmpfileprefix, suffix=newtmpfilesuffix, delete=False) as f:
   tmpfilename = f.name;
   returnval = {'Type': "File", 'Filename': tmpfilename, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'Headers': None, 'Version': None, 'Method': None, 'HeadersSent': None, 'URL': httpurl, 'Code': None};
   while True:
    databytes = geturls_text.read(buffersize);
    if not databytes: break;
    datasize = len(databytes);
    fulldatasize = datasize + fulldatasize;
    percentage = "";
    if(downloadsize>0):
     percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
    downloaddiff = fulldatasize - prevdownsize;
    log.info("Downloading "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Downloaded "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
    prevdownsize = fulldatasize;
    f.write(databytes);
   f.close();
  geturls_text.close();
  exec_time_end = time.time();
  log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to download file.");
  returnval.update({'Filesize': os.path.getsize(tmpfilename), 'DownloadTime': float(exec_time_start - exec_time_end), 'DownloadTimeReadable': hms_string(exec_time_start - exec_time_end)});
  return returnval;

if(not haveparamiko):
 def download_from_url_file_with_sftp(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, buffersize=524288, sleep=-1):
  return False;

if(haveparamiko):
 def download_from_url_to_file_with_sftp(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  global geturls_download_sleep;
  if(sleep<0):
   sleep = geturls_download_sleep;
  if(not outfile=="-"):
   outpath = outpath.rstrip(os.path.sep);
   filepath = os.path.realpath(outpath+os.path.sep+outfile);
   if(not os.path.exists(outpath)):
    os.makedirs(outpath);
   if(os.path.exists(outpath) and os.path.isfile(outpath)):
    return False;
   if(os.path.exists(filepath) and os.path.isdir(filepath)):
    return False;
   pretmpfilename = download_from_url_file_with_sftp(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   log.info("Moving file "+tmpfilename+" to "+filepath);
   exec_time_start = time.time();
   shutil.move(tmpfilename, filepath);
   exec_time_end = time.time();
   log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to move file.");
   if(os.path.exists(tmpfilename)):
    os.remove(tmpfilename);
   returnval = {'Type': "File", 'Filename': filepath, 'Filesize': downloadsize, 'FilesizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': None, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]=="2"):
   pretmpfilename = download_from_url_file_with_sftp(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   if(not pretmpfilename):
    return False;
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = StringIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': None, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  if(outfile=="-" and sys.version[0]>="3"):
   pretmpfilename = download_from_url_file_with_sftp(httpurl, httpheaders, httpcookie, httpmethod, postdata, buffersize[0], sleep);
   tmpfilename = pretmpfilename['Filename'];
   downloadsize = os.path.getsize(tmpfilename);
   fulldatasize = 0;
   prevdownsize = 0;
   exec_time_start = time.time();
   with open(tmpfilename, 'rb') as ft:
    f = BytesIO();
    while True:
     databytes = ft.read(buffersize[1]);
     if not databytes: break;
     datasize = len(databytes);
     fulldatasize = datasize + fulldatasize;
     percentage = "";
     if(downloadsize>0):
      percentage = str("{0:.2f}".format(float(float(fulldatasize / downloadsize) * 100))).rstrip('0').rstrip('.')+"%";
     downloaddiff = fulldatasize - prevdownsize;
     log.info("Copying "+get_readable_size(fulldatasize, 2, "SI")['ReadableWithSuffix']+" / "+get_readable_size(downloadsize, 2, "SI")['ReadableWithSuffix']+" "+str(percentage)+" / Copied "+get_readable_size(downloaddiff, 2, "IEC")['ReadableWithSuffix']);
     prevdownsize = fulldatasize;
     f.write(databytes);
    f.seek(0);
    fdata = f.getvalue();
    f.close();
    ft.close();
    os.remove(tmpfilename);
    exec_time_end = time.time();
    log.info("It took "+hms_string(exec_time_start - exec_time_end)+" to copy file.");
   returnval = {'Type': "Content", 'Content': fdata, 'Contentsize': downloadsize, 'ContentsizeAlt': {'IEC': get_readable_size(downloadsize, 2, "IEC"), 'SI': get_readable_size(downloadsize, 2, "SI")}, 'DownloadTime': pretmpfilename['DownloadTime'], 'DownloadTimeReadable': pretmpfilename['DownloadTimeReadable'], 'MoveFileTime': float(exec_time_start - exec_time_end), 'MoveFileTimeReadable': hms_string(exec_time_start - exec_time_end), 'Headers': pretmpfilename['Headers'], 'Version': pretmpfilename['Version'], 'Method': pretmpfilename['Method'], 'Method': None, 'HeadersSent': pretmpfilename['HeadersSent'], 'URL': pretmpfilename['URL'], 'Code': pretmpfilename['Code']};
  return returnval;

if(not haveparamiko):
 def download_from_url_to_file_with_sftp(httpurl, httpheaders=geturls_headers, httpcookie=geturls_cj, httpmethod="GET", postdata=None, outfile="-", outpath=os.getcwd(), buffersize=[524288, 524288], sleep=-1):
  return False;

if(haveparamiko):
 def upload_file_to_sftp_file(sftpfile, url):
  urlparts = urlparse.urlparse(url);
  file_name = os.path.basename(urlparts.path);
  file_dir = os.path.dirname(urlparts.path);
  sftp_port = urlparts.port;
  if(urlparts.scheme=="http" or urlparts.scheme=="https"):
   return False;
  if(urlparts.port is None):
   sftp_port = 22;
  else:
   sftp_port = urlparts.port;
  if(urlparts.username is not None):
   sftp_username = urlparts.username;
  else:
   sftp_username = "anonymous";
  if(urlparts.password is not None):
   sftp_password = urlparts.password;
  elif(urlparts.password is None and urlparts.username=="anonymous"):
   sftp_password = "anonymous";
  else:
   sftp_password = "";
  if(urlparts.scheme!="sftp"):
   return False;
  ssh = paramiko.SSHClient();
  ssh.load_system_host_keys();
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy());
  try:
   ssh.connect(urlparts.hostname, port=sftp_port, username=urlparts.username, password=urlparts.password);
  except paramiko.ssh_exception.SSHException:
   return False;
  except socket.gaierror:
   log.info("Error With URL "+httpurl);
   return False;
  except socket.timeout:
   log.info("Error With URL "+httpurl);
   return False;
  sftp = ssh.open_sftp();
  sftp.putfo(sftpfile, urlparts.path);
  sftp.close();
  ssh.close();
  sftpfile.seek(0, 0);
  return sftpfile;
else:
 def upload_file_to_sftp_file(sftpfile, url):
  return False;

if(haveparamiko):
 def upload_file_to_sftp_string(sftpstring, url):
  sftpfileo = BytesIO(sftpstring);
  sftpfile = upload_file_to_sftp_files(ftpfileo, url);
  sftpfileo.close();
  return sftpfile;
else:
 def upload_file_to_sftp_string(url):
  return False;
