"""Dev-only demo portal with deliberate flaws (never deploy). Accounts citizen/citizen-pass, officer/officer-pass, code 444444.
Planted: /officer/reports opens for any signed-in user; /search reflects q unencoded; jQuery 1.8.3.
shortcut: sessions are never revoked server-side (logout only clears the cookie), so a spider that follows /logout cannot end a scan."""
import http.server
import secrets
from urllib.parse import parse_qs, urlsplit

USERS = {"citizen": "citizen-pass", "officer": "officer-pass"}
CODE = "444444"
SESSIONS: dict[str, str] = {}  # sid -> role
PENDING: dict[str, str] = {}   # two-step: pre token -> role
HEAD = '<!doctype html><title>Portal</title><script src="/static/jquery-1.8.3.min.js"></script>'
LOGIN = HEAD + '<h1>Sign in to continue</h1>{msg}<form method="post" action="{act}">' \
    '<input type="hidden" name="csrf" value="x"><input name="username"><input type="password" name="password">{code}<button>Sign in</button></form>'
CODE_FIELD = '<input name="code">'


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, status=200, body="", headers=(), ctype="text/html"):
        b = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def cookies(self):
        return dict(c.strip().partition("=")[::2] for c in self.headers.get("Cookie", "").split(";") if c)

    def role(self):
        return SESSIONS.get(self.cookies().get("sid", ""))

    def go(self, to, *cookies):
        self.send(302, "", [("Location", to), *[("Set-Cookie", c) for c in cookies]])

    def do_GET(self):
        u = urlsplit(self.path)
        role = self.role()
        if u.path == "/" and role:  # signed-in visitors land on their home so a spider with a session finds the role pages
            return self.go("/home")
        if u.path == "/":
            return self.send(200, HEAD + '<h1>City services portal</h1><a href="/login">Citizen sign in</a> <a href="/login2">Two-step sign in</a> '
                             '<a href="/search?q=permit">Search services</a><p>Apply for permits, track requests and read notices from your city office.</p>')
        if u.path == "/static/jquery-1.8.3.min.js":
            return self.send(200, "/*! jQuery v1.8.3 (dev stub) */", ctype="application/javascript")
        if u.path == "/search":  # planted XSS: q is reflected without encoding
            return self.send(200, HEAD + f"<h1>Search</h1><p>Results for {parse_qs(u.query).get('q', [''])[0]}</p>")
        if u.path == "/login":
            return self.send(200, LOGIN.format(msg="", act="/login", code=CODE_FIELD))
        if u.path == "/login2":
            return self.send(200, LOGIN.format(msg="", act="/login2", code=""))
        if u.path == "/otp":
            return self.send(200, HEAD + '<h1>Sign in to continue</h1><form method="post" action="/otp"><input name="code"><button>Verify</button></form>')
        if u.path == "/logout":
            return self.send(200, HEAD + "<p>You are signed out.</p>", [("Set-Cookie", "sid=; Path=/; Max-Age=0")])
        if not role:
            return self.go("/login")
        if u.path == "/home":
            extra = '<a href="/officer/reports">Officer reports</a> ' if role == "officer" else ""
            return self.send(200, HEAD + f'<h1>Welcome, {role}.</h1><a href="/my/requests">My requests</a> {extra}<a href="/search?q=permit">Search</a> <a href="/logout">Sign out</a>')
        if u.path == "/my/requests":
            return self.send(200, HEAD + f"<h1>My requests</h1><p>Requests filed by {role}.</p>")
        if u.path == "/officer/reports":  # planted access-control flaw: no role check, identical page for every signed-in user
            return self.send(200, HEAD + "<h1>Officer reports</h1>" + "<p>Case summaries, pending approvals and inspection notes for the district office.</p>" * 8)
        self.send(404, "Not found")

    def do_POST(self):
        u = urlsplit(self.path)
        f = {k: v[0] for k, v in parse_qs(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()).items()}
        fail = lambda act, code: self.send(200, LOGIN.format(msg="<p>Wrong credentials.</p>", act=act, code=code))
        user, ok = f.get("username", ""), USERS.get(f.get("username", "")) == f.get("password")
        if u.path == "/login":
            if not ok or f.get("code") != CODE:
                return fail("/login", CODE_FIELD)
            sid = secrets.token_hex(12)
            SESSIONS[sid] = user
            return self.go("/home", f"sid={sid}; Path=/")
        if u.path == "/login2":
            if not ok:
                return fail("/login2", "")
            tok = secrets.token_hex(12)
            PENDING[tok] = user
            return self.go("/otp", f"pre={tok}; Path=/")
        if u.path == "/otp":
            pre = PENDING.get(self.cookies().get("pre", ""))
            if not pre or f.get("code") != CODE:
                return self.send(200, HEAD + "<h1>Sign in to continue</h1><p>Wrong code.</p>")
            sid = secrets.token_hex(12)
            SESSIONS[sid] = pre
            return self.go("/home", f"sid={sid}; Path=/")
        self.send(404, "Not found")


http.server.ThreadingHTTPServer(("0.0.0.0", 80), H).serve_forever()
