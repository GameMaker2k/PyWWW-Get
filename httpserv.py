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

    $FileInfo: httpserv.py - Last Update: 9/24/2023 Ver. 1.5.0 RC 1 - Author: cooldude2k $
'''

pyoldver = True;
try:
    from BaseHTTPServer import HTTPServer;
    from SimpleHTTPServer import SimpleHTTPRequestHandler;
except ImportError:
    from http.server import SimpleHTTPRequestHandler, HTTPServer;
    pyoldver = False;



class CustomHTTPRequestHandler(SimpleHTTPRequestHandler):
    
    def do_GET(self):
        # Set response status code
        self.send_response(200);

        # Set headers
        self.send_header('Content-type', 'text/plain');
        self.end_headers();

        # Print all headers
        headers_list = ["{}: {}".format(key, self.headers[key]) for key in self.headers];
        headers_str = "\n".join(headers_list);
        self.wfile.write(headers_str.encode('utf-8'));

    def do_HEAD(self):
        self.send_response(200);
        self.send_header('Content-type', 'text/plain');
        self.end_headers();

if __name__ == "__main__":
    server_address = ('', 8080);
    httpd = HTTPServer(server_address, CustomHTTPRequestHandler);
    print("Server started at http://localhost:8080");
    httpd.serve_forever();
