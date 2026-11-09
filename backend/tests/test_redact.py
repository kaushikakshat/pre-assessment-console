from app.worker.redact import R, build_evidence, redact


def test_redacts_headers_pairs_tokens_jwt_emails():
    s = ("GET / HTTP/1.1\nCookie: sid=abc; other=1\nSet-Cookie: sid=abc; HttpOnly\nAuthorization: Basic Zm9v\n"
         "DB_PASSWORD=hunter2\napi_key='abc 123'\nmy-secret=xyz&x=1\nx-token = tkn9\n"
         "Bearer abc.def-123\neyJhbGciOi.eyJzdWIiOiIx.sig_nature\nmail bob@corp.example.com now\n"
         '{"auth_token": "zzz", "name": "ok"}\nSAFE=value')
    out = redact(s)
    for secret in ("sid=abc", "Zm9v", "hunter2", "abc 123", "xyz", "tkn9", "abc.def-123", "eyJhbGciOi", "bob@corp", "zzz"):
        assert secret not in out
    assert "Cookie: " + R in out and "DB_PASSWORD=" + R in out and "SAFE=value" in out and '"name": "ok"' in out


def test_build_evidence_limits_and_selects():
    body = "\n".join(f"line{i}" for i in range(50)).encode()
    ev = build_evidence("GET", "http://t/", 200, {"server": "nginx", "set-cookie": "a=b", "x-other": "1"},
                        body, ("server", "set-cookie"))
    lines = ev.splitlines()
    assert lines[:2] == ["GET http://t/", "HTTP 200"] and "server: nginx" in ev and "x-other" not in ev
    assert "set-cookie: " + R in ev and "a=b" not in ev
    assert "line19" in ev and "line20" not in ev
    assert "line0" not in build_evidence("GET", "http://t/", 200, {}, None)


def test_redacts_url_userinfo():
    out = redact("see https://admin:s3cret@db.example.com/x and ftp://u:p@h/")
    assert "s3cret" not in out and "admin" not in out and "https://" + R + "@db.example.com/x" in out


def test_redacts_token_only_userinfo():
    out = redact("clone https://ghp_abc123@github.com/o/r and https://u:p@h/ and https://h.example/a@b")
    assert "ghp_abc123" not in out and "u:p" not in out and "https://" + R + "@github.com/o/r" in out
    assert "https://h.example/a@b" in out
