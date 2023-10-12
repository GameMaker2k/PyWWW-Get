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

    $FileInfo: pyhttpserv.py - Last Update: 10/5/2023 Ver. 2.0.2 RC 1 - Author: cooldude2k $
'''

import os, argparse, gzip, zlib, bz2;

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
havelzma = False;
try:
 import lzma;
 havelzma = True;
except ImportError:
 havelzma = False;

__program_name__ = "PyHTTPServer";
__program_alt_name__ = "PyHTTPServer";
__program_small_name__ = "httpserver";
__project__ = __program_name__;
__project_url__ = "https://github.com/GameMaker2k/PyWWW-Get";
__version_info__ = (2, 0, 2, "RC 1", 1);
__version_date_info__ = (2023, 10, 5, "RC 1", 1);
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

parser = argparse.ArgumentParser(description="Simple HTTP Server in Python.", conflict_handler="resolve", add_help=True);
parser.add_argument("-V", "--version", action="version", version=__program_name__+" "+__version__);
parser.add_argument("-e", "--enablessl", action="store_true", help="Enable SSL");
parser.add_argument("-k", "--sslkeypem", default=None, help="specify a custom user agent");
parser.add_argument("-c", "--sslcertpem", default=None, help="specify a custom referer, use if the video access");
parser.add_argument("-p", "--servport", type=int, default=8080, help="specify a file name for output");
getargs = parser.parse_args();

enablessl = getargs.enablessl;
sslkeypem = getargs.sslkeypem;
sslcertpem = getargs.sslcertpem;
servport = int(getargs.servport);
if(isinstance(servport, int)):
    if(servport<1 or servport>65535):
        servport = 8080;
elif(isinstance(servport, str)):
    if(servport.isnumeric()):
        servport = int(servport);
        if(servport<1 or servport>65535):
            servport = 8080;
    else:
        servport = 8080;
else:
    servport = 8080;
if(enablessl):
    if(sslkeypem is not None and 
      (not os.path.exists(sslkeypem) or not os.path.isfile(sslkeypem))):
        sslkeypem = None;
        enablessl = False;
    if(sslcertpem is not None and 
      (not os.path.exists(sslkeypem) or not os.path.isfile(sslkeypem))):
        sslcertpem = None;
        enablessl = False;
pyoldver = True;
try:
    from BaseHTTPServer import HTTPServer;
    from SimpleHTTPServer import SimpleHTTPRequestHandler;
    from urlparse import parse_qs;
    from Cookie import SimpleCookie
except ImportError:
    from http.server import SimpleHTTPRequestHandler, HTTPServer;
    from urllib.parse import parse_qs;
    from http.cookies import SimpleCookie;
    pyoldver = False;
if(enablessl and 
  (sslkeypem is not None and (os.path.exists(sslkeypem) and os.path.isfile(sslkeypem))) and 
  (sslcertpem is not None and (os.path.exists(sslkeypem) and os.path.isfile(sslkeypem)))):
    import ssl;
# HTTP/HTTPS Server Class
class CustomHTTPRequestHandler(SimpleHTTPRequestHandler):
    def compress_content(self, content):
        """Compress content using gzip or deflate depending on Accept-Encoding header."""
        accept_encoding = self.headers.get('Accept-Encoding', '');
        accept_encoding = None;
        if 'gzip' in accept_encoding:
            self.send_header('Content-Encoding', 'gzip');
            compressed_content = gzip.compress(content.encode('utf-8'));
            self.send_header('Content-Length', len(compressed_content));
            return compressed_content;
        elif 'deflate' in accept_encoding:
            self.send_header('Content-Encoding', 'deflate');
            compressed_content = zlib.compress(content.encode('utf-8'));
            self.send_header('Content-Length', len(compressed_content));
            return compressed_content;
        elif 'br' in accept_encoding:
            self.send_header('Content-Encoding', 'br');
            compressed_content = brotli.compress(content.encode('utf-8'));
            self.send_header('Content-Length', len(compressed_content));
            return compressed_content;
        elif 'zstd' in accept_encoding:
            self.send_header('Content-Encoding', 'zstd');
            compressed_content = zstandard.compress(content.encode('utf-8'));
            self.send_header('Content-Length', len(compressed_content));
            return compressed_content;
        elif 'lzma' in accept_encoding:
            self.send_header('Content-Encoding', 'lzma');
            compressed_content = lzma.compress(content.encode('utf-8'));
            self.send_header('Content-Length', len(compressed_content));
            return compressed_content;
        elif 'xz' in accept_encoding:
            self.send_header('Content-Encoding', 'xz');
            compressed_content = lzma.compress(content.encode('utf-8'));
            self.send_header('Content-Length', len(compressed_content));
            return compressed_content;
        else:
            self.send_header('Content-Length', len(content));
            return content.encode('utf-8');
        return content.encode();
    def display_info(self):
        # Setting headers for the response
        self.send_response(200);
        self.send_header('Content-type', 'text/plain');
        # Set a sample cookie in the response;
        self.send_header('Set-Cookie', 'sample_cookie=sample_value; Path=/;');
        self.end_headers();
        # Displaying request method
        response = 'Method: {}\n'.format(self.command);
        response += 'Path: {}\n'.format(self.path);
        # Displaying all headers
        headers_list = ["{}: {}".format(key.title(), self.headers[key]) for key in self.headers];
        response += '\nHeaders:\n' + '\n'.join(headers_list) + '\n';
        # Extract and display cookies from headers
        if 'Cookie' in self.headers:
            response += '\nCookies:\n';
            cookies = SimpleCookie(self.headers['Cookie']);
            for key, morsel in cookies.items():
                response += '{}: {}\n'.format(key, morsel.value);
        # Displaying GET parameters (if any)
        if self.command == 'GET':
            query = self.path.split('?', 1)[-1];
            params = parse_qs(query);
            if params:
                response += '\nGET Parameters:\n';
                for key, values in params.items():
                    response += '{}: {}\n'.format(key, ', '.join(values));
        # Sending the response
        self.wfile.write(self.compress_content(response));
    # Get Method
    def do_GET(self):
        self.display_info();
    # Post Method
    def do_POST(self):
        if 'Transfer-Encoding' in self.headers and self.headers['Transfer-Encoding'] == 'chunked':
            post_data = '';
            while True:
                chunk_size_line = self.rfile.readline().decode('utf-8');
                chunk_size = int(chunk_size_line, 16);
                if chunk_size == 0:
                    self.rfile.readline();
                    break;
                chunk_data = self.rfile.read(chunk_size).decode('utf-8');
                post_data += chunk_data;
                self.rfile.readline();
        else:
            content_length = int(self.headers['Content-Length']);
            post_data = self.rfile.read(content_length).decode('utf-8');
        params = parse_qs(post_data);
        response = 'POST Parameters:\n';
        for key, values in params.items():
            response += '{}: {}\n'.format(key, ', '.join(values));
        self.send_response(200);
        self.send_header('Content-type', 'text/plain');
        self.send_header('Set-Cookie', 'sample_cookie=sample_value; Path=/;');
        self.end_headers();
        self.wfile.write(self.compress_content(response));
# Start Server Forever
if __name__ == "__main__":
    server_address = ('', int(servport));
    httpd = HTTPServer(server_address, CustomHTTPRequestHandler);
    if(enablessl and sslkeypem is not None and sslcertpem is not None):
        httpd.socket = ssl.wrap_socket (httpd.socket, 
        keyfile=sslkeypem, certfile=sslcertpem, server_side=True);
    if(enablessl):
        print("Server started at https://localhost:"+str(servport));
    else:
        print("Server started at http://localhost:"+str(servport));
    httpd.serve_forever();
