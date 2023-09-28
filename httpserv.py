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
    from urlparse import parse_qs;
except ImportError:
    from http.server import SimpleHTTPRequestHandler, HTTPServer;
    from urllib.parse import parse_qs;
    pyoldver = False;

class CustomHTTPRequestHandler(SimpleHTTPRequestHandler):
    def display_info(self):
        # Setting headers for the response
        self.send_response(200);
        self.send_header('Content-type', 'text/plain');
        self.end_headers();
        # Displaying request method
        response = 'Method: {}\n'.format(self.command);
        response += 'Path: {}\n'.format(self.path);
        # Displaying all headers
        headers_list = ["{}: {}".format(key.title(), self.headers[key]) for key in self.headers];
        response += '\nHeaders:\n' + '\n'.join(headers_list) + '\n';
        # Displaying GET parameters (if any)
        if self.command == 'GET':
            query = self.path.split('?', 1)[-1];
            params = parse_qs(query);
            if params:
                response += '\nGET Parameters:\n';
                for key, values in params.items():
                    response += '{}: {}\n'.format(key, ', '.join(values));
        # Sending the response
        self.wfile.write(response.encode('utf-8'));
    def do_GET(self):
        self.display_info();
    def do_POST(self):
        content_length = int(self.headers['Content-Length']);
        post_data = self.rfile.read(content_length).decode('utf-8');
        params = parse_qs(post_data);
        # Displaying POST parameters
        response = 'POST Parameters:\n';
        for key, values in params.items():
            response += '{}: {}\n'.format(key, ', '.join(values));
        # Setting headers for the response
        self.send_response(200);
        self.send_header('Content-type', 'text/plain');
        self.end_headers();
        # Sending the response
        self.wfile.write(response.encode('utf-8'));

if __name__ == "__main__":
    server_address = ('', 8080);
    httpd = HTTPServer(server_address, CustomHTTPRequestHandler);
    print("Server started at http://localhost:8080");
    httpd.serve_forever();
