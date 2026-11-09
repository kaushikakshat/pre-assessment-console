"""Evidence redaction. Everything stored as evidence passes through redact()."""
import re

R = "[REDACTED]"
_HEADER = re.compile(r"(?im)^((?:cookie|set-cookie|authorization|proxy-authorization)\s*:\s*).*$")
_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@:]+(?::[^\s/@]*)?@")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_JWT = re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]*")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_KEYS = r"[\w.-]*(?:pass|secret|token|key|auth)[\w.-]*"
_PAIR = re.compile(rf"""(?i)(\b{_KEYS}\s*=\s*)("[^"\n]*"|'[^'\n]*'|[^\s&;,"']+)""")
_JSON_PAIR = re.compile(rf"""(?i)("{_KEYS}"\s*:\s*)("[^"\n]*"|[^\s,}}]+)""")


def redact(text: str) -> str:
    text = _USERINFO.sub(lambda m: m.group(1) + R + "@", text)
    text = _HEADER.sub(lambda m: m.group(1) + R, text)
    text = _BEARER.sub(R, text)
    text = _JWT.sub(R, text)
    text = _PAIR.sub(lambda m: m.group(1) + R, text)
    text = _JSON_PAIR.sub(lambda m: m.group(1) + R, text)
    return _EMAIL.sub(R, text)


def build_evidence(method: str, url: str, status: int, headers, body: bytes | None, names=(), max_lines: int = 20) -> str:
    """Request line + selected response headers + at most max_lines of body, all redacted. body=None omits it."""
    lines = [f"{method} {url}", f"HTTP {status}"]
    lines += [f"{n}: {headers[n]}" for n in names if n in headers]
    if body is not None:
        lines += ["", *(ln[:200] for ln in body.decode("utf-8", "replace").splitlines()[:max_lines])]
    return redact("\n".join(lines))
