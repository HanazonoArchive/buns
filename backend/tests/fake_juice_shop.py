"""A tiny stand-in for OWASP Juice Shop used by the test-suite.

It reproduces only the responses the cURL probes look at, copied from the
behaviour of the real application, so the probes can be exercised with the
real curl binary without Docker.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

JWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6Mn19.c2lnbmF0dXJlLXBsYWNlaG9sZGVy"
USERS = [
    {"id": 1, "email": "admin@juice-sh.op", "role": "admin"},
    {"id": 2, "email": "jim@juice-sh.op", "role": "customer"},
    {"id": 3, "email": "bender@juice-sh.op", "role": "customer"},
]


class Handler(BaseHTTPRequestHandler):
    server_version = "FakeJuice/1.0"
    sys_version = ""

    def log_message(self, *_args):
        pass

    def _send(self, status: int, body: str | dict, ctype: str = "application/json", extra: dict | None = None,
              short_by: int = 0):
        data = json.dumps(body) if isinstance(body, dict) else body
        raw = data.encode()
        self.send_response(status)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Content-Length", str(len(raw) + short_by))
        if short_by:
            self.close_connection = True
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _authed(self) -> bool:
        return self.headers.get("Authorization", "") == f"Bearer {JWT}"

    def do_GET(self):
        url = urlsplit(self.path)
        path, query = url.path, parse_qs(url.query)
        if path == "/":
            return self._send(200, "<!doctype html><title>OWASP Juice Shop</title><app-root></app-root>", "text/html")
        if path == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /ftp", "text/plain")
        if path in ("/ftp", "/ftp/"):
            # Real Juice Shop declares a Content-Length 12 bytes longer than the
            # body it sends here; curl exits with code 18 on it.
            return self._send(200, (
                "<html><title>listing directory /ftp</title><body><ul>"
                '<li><a href="/ftp/acquisitions.md">acquisitions.md</a></li>'
                '<li><a href="/ftp/package.json.bak">package.json.bak</a></li>'
                '<li><a href="/ftp/legal.md">legal.md</a></li></ul></body></html>'
            ), "text/html", short_by=12)
        if path.startswith("/api/buns-"):
            return self._send(500, (
                "<html><h1>OWASP Juice Shop (Express ^4.21.0)</h1><h2>500 Error: Unexpected path: "
                f"{path}</h2><ul><li>at /juice-shop/build/routes/angular.js:38:18</li>"
                "<li>at Layer.handle [as handle_request] (/juice-shop/node_modules/express/lib/router/layer.js:95:5)</li></ul></html>"
            ), "text/html")
        if path == "/rest/products/search":
            q = query.get("q", [""])[0]
            if "'" in q:
                return self._send(500, {"error": {"message": 'SQLITE_ERROR: near "%": syntax error',
                                                  "name": "SequelizeDatabaseError"}})
            return self._send(200, {"status": "success", "data": []})
        if path == "/api/Users":
            if not self._authed():
                return self._send(401, "<html>No Authorization header was found</html>", "text/html")
            return self._send(200, {"status": "success", "data": USERS})
        if path.startswith("/rest/basket/"):
            if not self._authed():
                return self._send(401, {"error": "unauthorized"})
            bid = int(path.rsplit("/", 1)[1])
            return self._send(200, {"status": "success", "data": {"id": bid, "UserId": bid, "Products": []}})
        return self._send(200, "<!doctype html><app-root></app-root>", "text/html")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        path = urlsplit(self.path).path
        if path == "/rest/user/login":
            email = unquote(str(body.get("email", "")))
            if "' OR 1=1--" in email or (email == "jim@juice-sh.op" and body.get("password") == "ncc-1701"):
                return self._send(200, {"authentication": {"token": JWT, "bid": 2, "umail": email}})
            return self._send(401, "Invalid email or password.", "text/html")
        if path == "/api/Users":
            return self._send(201, {"status": "success", "data": {"id": 99, "email": body.get("email"), "role": "customer"}})
        return self._send(404, {"error": "not found"})


class FakeJuiceShop:
    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
