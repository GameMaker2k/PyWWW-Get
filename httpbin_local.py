#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import sys
import argparse
import json

try:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import parse_qs, urlparse
    from http.cookies import SimpleCookie
    py3 = True
except ImportError:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from urlparse import parse_qs, urlparse
    from Cookie import SimpleCookie
    py3 = False

__program_name__ = "PyHTTPBin"
__version__ = "1.0.0"
__project_url__ = "https://github.com/GameMaker2k/PyWWW-Get"

parser = argparse.ArgumentParser(description="httpbin-like local server")
parser.add_argument("-p", "--port", type=int, default=8080, help="Port to bind to")
parser.add_argument("-e", "--enablessl", action="store_true", help="Enable SSL")
parser.add_argument("-k", "--sslkeypem", default=None, help="Path to SSL key PEM file")
parser.add_argument("-c", "--sslcertpem", default=None, help="Path to SSL cert PEM file")
parser.add_argument("-V", "--version", action="version", version=__program_name__ + " " + __version__)
args = parser.parse_args()

if args.port < 1 or args.port > 65535:
    print("Invalid port. Falling back to 8080.")
    args.port = 8080

if args.enablessl:
    if not (args.sslkeypem and os.path.isfile(args.sslkeypem)) or \
       not (args.sslcertpem and os.path.isfile(args.sslcertpem)):
        print("Invalid SSL files provided. Disabling SSL.")
        args.enablessl = False

class RequestHandler(BaseHTTPRequestHandler):
    def _json_response(self, data, status=200):
        payload = json.dumps(data, indent=2)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(payload.encode('utf-8') if py3 else payload)

    def _parse_request(self):
        parsed_url = urlparse(self.path)
        return {
            "method": self.command,
            "path": parsed_url.path,
            "query": parse_qs(parsed_url.query),
            "headers": dict(self.headers),
            "cookies": {k: v.value for k, v in SimpleCookie(self.headers.get('Cookie', '')).items()},
            "origin": self.client_address[0]
        }

    def do_GET(self):
        info = self._parse_request()
        if info['path'] == "/get":
            self._json_response(info)
        elif info['path'] == "/headers":
            self._json_response({"headers": info['headers']})
        elif info['path'] == "/ip":
            self._json_response({"origin": info['origin']})
        elif info['path'] == "/user-agent":
            self._json_response({"user-agent": info['headers'].get("User-Agent", "")})
        elif info['path'] == "/cookies":
            self._json_response({"cookies": info['cookies']})
        elif info['path'] == "/anything":
            self._json_response(info)
        else:
            self._json_response({"message": "Not Found"}, 404)

    def do_POST(self):
        info = self._parse_request()
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        if py3:
            body = body.decode('utf-8')
        form = parse_qs(body)
        info["form"] = form
        info["data"] = body
        self._json_response(info)

    def log_message(self, format, *args):
        sys.stdout.write("%s - - [%s] %s\n" %
                         (self.client_address[0],
                          self.log_date_time_string(),
                          format % args))

if __name__ == "__main__":
    server = HTTPServer(('', args.port), RequestHandler)
    if args.enablessl:
        import ssl
        server.socket = ssl.wrap_socket(server.socket,
                                        keyfile=args.sslkeypem,
                                        certfile=args.sslcertpem,
                                        server_side=True)
        print("Serving HTTPS on port %d" % args.port)
    else:
        print("Serving HTTP on port %d" % args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()
