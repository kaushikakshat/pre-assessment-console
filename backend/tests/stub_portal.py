"""Local stub portal: /login (+ /otp for two-step). Bypass code 444444. Users: alice/Secret!pw (role user), boss/Secret!pw (admin), locked/any."""
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
        self.hits.append(self.path)
        sid = self.headers.get("Cookie", "")
        if self.path == "/admin/panel":  # admin only; others get the login page
            return self._send(200, "Admin panel. Users, billing and secrets live here." if "sid=admin" in sid else "Please sign in")
        if self.path == "/shell":  # one shell for everyone; non-admins also get a denial line
            return self._send(200, "Reports shell with a long navigation menu and plenty of words " * 6
                              + ("" if "sid=admin" in sid else "You have no permission to view this"))
        if self.path == "/account":  # a change-password page: has a password input but is not the login page
            return self._send(200, '<form action="/account/password"><input type="password" name="new"></form> Change your password')
        if self.path in ("/leaky", "/shared", "/user/delete/5"):
            return self._send(200, f"Page {self.path} with plenty of shared words for the similarity measure to compare. Welcome alice and boss")
        if self.path == "/login":
            return self._send(200, f'<form><input type="hidden" name="csrf" value="{CSRF}"><input name="u"></form>')
        if self.path == "/otp":
            return self._send(200, f'<form><input type="hidden" name="csrf" value="{CSRF}"></form>' + getattr(self, "otp_text", ""))
        if self.path == "/home":
            ok = "sid=good" in self.headers.get("Cookie", "") or "sid=admin" in self.headers.get("Cookie", "")
            return self._send(200, "Welcome. Sign out" if ok else "Please sign in")
        self._send(404)

    def do_POST(self):
        if self.path in ("/admin/lax", "/admin/strict", "/admin/csrf", "/admin/menu"):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.hits.append("POST " + self.path)
            if self.path == "/admin/strict" and "sid=admin" not in self.headers.get("Cookie", ""):
                return self._send(403, "Forbidden")
            return self._send(200, {"/admin/csrf": "Invalid CSRF token", "/admin/menu": '<title>Admin</title><input type="hidden" name="csrf_token" value="x"><a>Error log</a> Saved'}.get(self.path, "Done"))
        f = {k: v[0] for k, v in parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode()).items()}
        self.seen.append({**f, "_path": self.path})
        if f.get("csrf") != CSRF:
            return self._send(403, "bad csrf")
        if self.path == "/login":
            if f.get("u") == "locked":
                return self._send(423, "Account locked")
            if f.get("u") == "badloc":
                return self._send(302, "", [("Location", "http://[::1")])
            if f.get("u") == "echo":
                return self._send(200, "Please sign in. Sign out")
            if f.get("u") == "boss" and f.get("p") == "Secret!pw":
                return self._send(302, "", [("Location", "/home"), ("Set-Cookie", "sid=admin; Path=/")])
            if f.get("u") != "alice" or f.get("p") != "Secret!pw":
                return self._send(200, "Please sign in. Wrong password")
            return self._send(302, "", [("Location", "/otp" if self.two_step else "/home"), ("Set-Cookie", "sid=good; Path=/")])
        if self.path == "/otp":
            if f.get("code") != CODE:
                return self._send(200, "Enter the code. Wrong code")
            return self._send(302, "", [("Location", "/home")])
        self._send(404)


def serve(two_step=False, otp_text=""):
    h = type("H", (Portal,), {"two_step": two_step, "seen": [], "hits": [], "otp_text": otp_text})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), h)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, h
