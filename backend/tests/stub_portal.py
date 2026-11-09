"""Local stub portal: /login (+ /otp for two-step). Bypass code 444444. Users: alice/Secret!pw, locked/any."""
import http.server
import threading
from urllib.parse import parse_qs

CSRF, CODE = "tok-123", "444444"


class Portal(http.server.BaseHTTPRequestHandler):
    two_step = False
    seen: list = []

    def log_message(self, *a):
        pass

    def _send(self, status, body="", headers=()):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        if self.path == "/login":
            return self._send(200, f'<form><input type="hidden" name="csrf" value="{CSRF}"><input name="u"></form>')
        if self.path == "/otp":
            return self._send(200, f'<form><input type="hidden" name="csrf" value="{CSRF}"></form>')
        if self.path == "/home":
            ok = "sid=good" in self.headers.get("Cookie", "")
            return self._send(200, "Welcome. Sign out" if ok else "Please sign in")
        self._send(404)

    def do_POST(self):
        f = {k: v[0] for k, v in parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode()).items()}
        self.seen.append(f)
        if f.get("csrf") != CSRF:
            return self._send(403, "bad csrf")
        if self.path == "/login":
            if f.get("u") == "locked":
                return self._send(423, "Account locked")
            if f.get("u") != "alice" or f.get("p") != "Secret!pw":
                return self._send(200, "Please sign in. Wrong password")
            return self._send(302, "", [("Location", "/otp" if self.two_step else "/home"), ("Set-Cookie", "sid=good; Path=/")])
        if self.path == "/otp":
            if f.get("code") != CODE:
                return self._send(200, "Enter the code. Wrong code")
            return self._send(302, "", [("Location", "/home")])
        self._send(404)


def serve(two_step=False):
    h = type("H", (Portal,), {"two_step": two_step, "seen": []})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), h)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, h
