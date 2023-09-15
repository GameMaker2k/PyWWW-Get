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

    $FileInfo: pywwwget-dl.py - Last Update: 9/15/2023 Ver. 0.9.0 RC 1 - Author: cooldude2k $
'''

from __future__ import division, absolute_import, print_function;
import re, os, sys, pywwwget, argparse;
import logging as log;

__project__ = pywwwget.__project__;
__program_name__ = pywwwget.__program_name__;
__project_url__ = pywwwget.__project_url__;
__version_info__ = pywwwget.__version_info__;
__version_date_info__ = pywwwget.__version_date_info__;
__version_date__ = pywwwget.__version_date__;
__version_date_plusrc__ = pywwwget.__version_date_plusrc__
__version__ = pywwwget.__version__;
__version_date_plusrc__ = pywwwget.__version_date_plusrc__;

geturls_cj = pywwwget.geturls_cj;
geturls_ua = pywwwget.geturls_ua;
geturls_ua_firefox_windows7 = pywwwget.geturls_ua_firefox_windows7;
geturls_ua_seamonkey_windows7 = pywwwget.geturls_ua_seamonkey_windows7;
geturls_ua_chrome_windows7 = pywwwget.geturls_ua_chrome_windows7;
geturls_ua_chromium_windows7 = pywwwget.geturls_ua_chromium_windows7;
geturls_ua_palemoon_windows7 = pywwwget.geturls_ua_palemoon_windows7;
geturls_ua_opera_windows7 = pywwwget.geturls_ua_opera_windows7;
geturls_ua_vivaldi_windows7 = pywwwget.geturls_ua_chromium_windows7;
geturls_ua_internet_explorer_windows7 = pywwwget.geturls_ua_internet_explorer_windows7;
geturls_ua_microsoft_edge_windows7 = pywwwget.geturls_ua_microsoft_edge_windows7;
geturls_ua_pywwwget_python = pywwwget.geturls_ua_pywwwget_python;
geturls_ua_pywwwget_python_alt = pywwwget.geturls_ua_pywwwget_python_alt;
geturls_ua_googlebot_google = pywwwget.geturls_ua_googlebot_google;
geturls_ua_googlebot_google_old = pywwwget.geturls_ua_googlebot_google_old;
geturls_headers = pywwwget.geturls_headers;
geturls_headers_firefox_windows7 = pywwwget.geturls_headers_firefox_windows7;
geturls_headers_seamonkey_windows7 = pywwwget.geturls_headers_seamonkey_windows7;
geturls_headers_chrome_windows7 = pywwwget.geturls_headers_chrome_windows7;
geturls_headers_chromium_windows7 = pywwwget.geturls_headers_chromium_windows7;
geturls_headers_palemoon_windows7 = pywwwget.geturls_headers_palemoon_windows7;
geturls_headers_opera_windows7 = pywwwget.geturls_headers_opera_windows7;
geturls_headers_vivaldi_windows7 = pywwwget.geturls_headers_vivaldi_windows7;
geturls_headers_internet_explorer_windows7 = pywwwget.geturls_headers_internet_explorer_windows7;
geturls_headers_microsoft_edge_windows7 = pywwwget.geturls_headers_microsoft_edge_windows7;
geturls_headers_pywwwget_python = pywwwget.geturls_headers_pywwwget_python;
geturls_headers_pywwwget_python_alt = pywwwget.geturls_headers_pywwwget_python_alt;
geturls_headers_googlebot_google = pywwwget.geturls_headers_googlebot_google;
geturls_headers_googlebot_google_old = pywwwget.geturls_headers_googlebot_google_old;
geturls_download_sleep = pywwwget.geturls_download_sleep;

parser = argparse.ArgumentParser(description="Python libary/module to download files.", conflict_handler="resolve", add_help=True);
parser.add_argument("url", help="enter a url");
parser.add_argument("-V", "--version", action="version", version=__program_name__+" "+__version__);
parser.add_argument("-u", "--update", action="store_true", help="update this program to latest version. Make sure that you have sufficient permissions (run with sudo if needed)");
parser.add_argument("-d", "--dump-user-agent", action="store_true", help="display the current browser identification");
parser.add_argument("-u", "--user-agent", default=geturls_ua_firefox_windows7, help="specify a custom user agent");
parser.add_argument("-r", "--referer", default="https://www.google.com/", help="specify a custom referer, use if the video access");
parser.add_argument("-O", "--output-document", default="-", help="specify a file name for output");
parser.add_argument("-o", "--output-directory", default=os.path.realpath(os.getcwd()), help="specify a directory to output file to");
parser.add_argument("-l", "--use-httplib", default="urllib", help="select library to download file can be urllib or requests or mechanize");
parser.add_argument("-b", "--set-buffersize", default=524288, type=int, help="set how big buffersize is in bytes. how much it will download");
parser.add_argument("-v", "--verbose", action="store_true", help="print various debugging information");
getargs = parser.parse_args();

if(not pywwwget.check_httplib_support(getargs.use_httplib)):
 getargs.use_httplib = "urllib";

getargs_cj = geturls_cj;
getargs_headers = {'Referer': getargs.referer, 'User-Agent': getargs.user_agent, 'Accept-Encoding': "gzip, deflate", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close"};

getargs.output_directory = os.path.realpath(getargs.output_directory);

if(getargs.verbose==True):
 log.basicConfig(format="%(levelname)s: %(message)s", level=log.DEBUG);

if(getargs.dump_user_agent==True):
 print(getargs.user_agent);
 sys.exit();

if(getargs.output_document=="-"):
 if(sys.version[0]=="2"):
  precontstr = pywwwget.download_from_url_to_file(getargs.url, getargs_headers, geturls_cj, httplibuse=getargs.use_httplib, buffersize=[getargs.set_buffersize, getargs.set_buffersize], outfile=getargs.output_document, outpath=os.getcwd());
  print(precontstr['Content']);
 if(sys.version[0]>="3"):
  precontstr = pywwwget.download_from_url_to_file(getargs.url, getargs_headers, geturls_cj, httplibuse=getargs.use_httplib, buffersize=[getargs.set_buffersize, getargs.set_buffersize], outfile=getargs.output_document, outpath=os.getcwd());
  print(precontstr['Content'].decode('ascii', 'replace'));

if(getargs.output_document!="-"):
 pywwwget.download_from_url_to_file(getargs.url, getargs_headers, geturls_cj, httplibuse=getargs.use_httplib, buffersize=[getargs.set_buffersize, getargs.set_buffersize], outfile=getargs.output_document, outpath=getargs.output_directory);
