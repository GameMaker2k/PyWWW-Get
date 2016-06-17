#!/usr/bin/env python

'''
    This program is free software; you can redistribute it and/or modify
    it under the terms of the Revised BSD License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Revised BSD License for more details.

    Copyright 2016 Cool Dude 2k - http://idb.berlios.de/
    Copyright 2016 Game Maker 2k - http://intdb.sourceforge.net/
    Copyright 2016 Kazuki Przyborowski - https://github.com/KazukiPrzyborowski

    $FileInfo: pywwwget-dl.py - Last Update: 6/17/2016 Ver. 0.4.7 RC 1 - Author: cooldude2k $
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
geturls_ua_internet_explorer_windows7 = pywwwget.geturls_ua_internet_explorer_windows7;
geturls_ua_pywwwget_python = pywwwget.geturls_ua_pywwwget_python;
geturls_ua_pywwwget_python_alt = pywwwget.geturls_ua_pywwwget_python_alt;
geturls_ua_googlebot_google = pywwwget.geturls_ua_googlebot_google;
geturls_ua_googlebot_google_old = pywwwget.geturls_ua_googlebot_google_old;
geturls_headers = pywwwget.geturls_headers;
geturls_headers_firefox_windows7 = pywwwget.geturls_headers_firefox_windows7;
geturls_headers_seamonkey_windows7 = pywwwget.geturls_headers_seamonkey_windows7;
geturls_headers_chrome_windows7 = pywwwget.geturls_headers_chrome_windows7;
geturls_headers_chromium_windows7 = pywwwget.geturls_headers_chromium_windows7;
geturls_headers_internet_explorer_windows7 = pywwwget.geturls_headers_internet_explorer_windows7;
geturls_headers_pywwwget_python = pywwwget.geturls_headers_pywwwget_python;
geturls_headers_pywwwget_python_alt = pywwwget.geturls_headers_pywwwget_python_alt;
geturls_headers_googlebot_google = pywwwget.geturls_headers_googlebot_google;
geturls_headers_googlebot_google_old = pywwwget.geturls_headers_googlebot_google_old;
geturls_download_sleep = pywwwget.geturls_download_sleep;

parser = argparse.ArgumentParser(description="Python libary/module to download files.", conflict_handler="resolve", add_help=True);
parser.add_argument("url", help="motherless url");
parser.add_argument("-V", "--version", action="version", version=__program_name__+" "+__version__);
parser.add_argument("-u", "--update", action="store_true", help="update this program to latest version. Make sure that you have sufficient permissions (run with sudo if needed)");
parser.add_argument("-d", "--dump-user-agent", action="store_true", help="display the current browser identification");
parser.add_argument("-u", "--user-agent", default="Mozilla/5.0 (Windows NT 6.1; rv:44.0) Gecko/20100101 Firefox/44.0", help="specify a custom user agent");
parser.add_argument("-r", "--referer", default="https://www.google.com/", help="specify a custom referer, use if the video access");
parser.add_argument("-o", "--output-document", default="-", help="specify a custom referer, use if the video access");
parser.add_argument("-v", "--verbose", action="store_true", help="print various debugging information");
getargs = parser.parse_args();

getargs_cj = geturls_cj;
getargs_headers = {'Referer': getargs.referer, 'User-Agent': getargs.user_agent, 'Accept-Encoding': "gzip, deflate", 'Accept-Language': "en-US,en;q=0.8,en-CA,en-GB;q=0.6", 'Accept-Charset': "ISO-8859-1,ISO-8859-15,utf-8;q=0.7,*;q=0.7", 'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'Connection': "close"};

if(getargs.verbose==True):
 log.basicConfig(format="%(levelname)s: %(message)s", level=log.DEBUG);

if(getargs.dump_user_agent==True):
 print(getargs.user_agent);
 sys.exit();

if(getargs.output_document=="-"):
 print(pywwwget.download_from_url_to_file(getargs.url, getargs_headers, geturls_cj, outfile=getargs.output_document, outpath=os.getcwd())['Content']);

if(not getargs.output_document=="-"):
 pywwwget.download_from_url_to_file(getargs.url, getargs_headers, geturls_cj, outfile=getargs.output_document, outpath=os.getcwd());