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

    $FileInfo: pyhttpserv.py - Last Update: 9/24/2023 Ver. 1.5.0 RC 1 - Author: cooldude2k $
'''

enablessl = False;
sslkeypem = None;
sslcertpem = None;
serverport = 8080;
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
        self.wfile.write(response.encode('utf-8'));
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
        self.wfile.write(response.encode('utf-8'));
# Start Server Forever
if __name__ == "__main__":
    server_address = ('', int(serverport));
    httpd = HTTPServer(server_address, CustomHTTPRequestHandler);
    if(enablessl and 
      (sslkeypem is not None and (os.path.exists(sslkeypem) and os.path.isfile(sslkeypem))) and 
      (sslcertpem is not None and (os.path.exists(sslkeypem) and os.path.isfile(sslkeypem)))):
        httpd.socket = ssl.wrap_socket (httpd.socket, 
            keyfile="path/to/key.pem", 
            certfile='path/to/cert.pem', server_side=True);
    print("Server started at http://localhost:"+str(serverport));
    httpd.serve_forever();
