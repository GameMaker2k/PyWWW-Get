import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pywwwget_py3_advanced as wwwget


class TestPyWWWGet(unittest.TestCase):
    def test_import(self):
        self.assertTrue(hasattr(wwwget, "download_file_from_internet_file"))
        self.assertTrue(hasattr(wwwget, "data_url_encode"))
        self.assertTrue(hasattr(wwwget, "data_url_decode"))

    def test_data_url_roundtrip(self):
        payload = b"hello world\n\x00\x01\x02"
        url = wwwget.data_url_encode(fileobj=wwwget.io.BytesIO(payload), mime="application/octet-stream", is_text=False, base64_encode=True)
        fp, mime, was_base64 = wwwget.data_url_decode(url)
        try:
            self.assertEqual(fp.read(), payload)
        finally:
            try:
                fp.close()
            except Exception:
                pass
        self.assertEqual(mime, "application/octet-stream")
        self.assertTrue(was_base64)

    def test_hdr_query_parsing(self):
        qs = wwwget.parse_qs("hdr_x_test=123&hdr_user_agent=ua")
        hdrs = wwwget._parse_kv_headers(qs, prefix="hdr_")
        # underscore becomes dash
        self.assertEqual(hdrs.get("x-test"), "123")
        self.assertEqual(hdrs.get("user-agent"), "ua")

    def test_parse_net_url_defaults_udp(self):
        parts, o = wwwget._parse_net_url("udp://127.0.0.1:9999/")
        self.assertEqual(parts.scheme, "udp")
        # default UDP mode is "seq"
        self.assertEqual(o.get("mode"), "seq")

    def test_http_download_local_server(self):
        body = b"local-test-payload"

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/file":
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            url = f"http://127.0.0.1:{port}/file"
            data = wwwget.download_file_from_internet_bytes(url, timeout=5, usehttp="urllib")
            self.assertEqual(data, body)
        finally:
            httpd.shutdown()
            httpd.server_close()
            t.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
