import json
import os
import re
import signal
import shutil
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime, timezone

from app.worker.subproc import clean_env

from .base import REFS, FindingDraft, ModuleResult, location

# OpenSSL verify codes: 10 expired, 18/19/20/21 self-signed or untrusted chain, 62 hostname mismatch
UNTRUSTED = {18, 19, 20, 21}


def _connect(ctx, ip, context):
    s = socket.create_connection((ip, ctx.port), timeout=max(1, min(10, ctx.remaining())))
    try:
        return context.wrap_socket(s, server_hostname=ctx.host)
    except Exception:
        s.close()
        raise


def _finding(ctx, sev, title, desc, impact, fix, evidence):
    return FindingDraft(sev, "confirmed", title, f"{ctx.host}:{ctx.port}", location(ctx, "TLS certificate" if "ertificate" in title else "Network service"),
                        desc, impact, evidence, f"Run: openssl s_client -connect {ctx.host}:{ctx.port} -servername {ctx.host}", fix, [REFS["tls"]])


def run(ctx) -> ModuleResult:
    if ctx.scheme != "https":
        return ModuleResult("skipped", "Target uses http; TLS not tested", [FindingDraft(
            "medium", "confirmed", "Site is served without HTTPS", ctx.host, location(ctx, "Web page"),
            "The target address uses http, so traffic between users and the site is not encrypted.",
            "Anyone on the network path can read or change what users send and receive, including sign-in details.",
            f"Target URL: {ctx.url}", f"Open {ctx.url} and note that it is not served over HTTPS.",
            "Serve the site over HTTPS and redirect http requests to it.", [REFS["hsts"]])])
    ip, out = ctx.safe_ip(), []
    trusted = ssl.create_default_context()
    evidence = f"TLS connection to {ctx.host}:{ctx.port}"
    try:
        with _connect(ctx, ip, trusted) as s:
            cert, version = s.getpeercert(), s.version()
        days = (ssl.cert_time_to_seconds(cert["notAfter"]) - datetime.now(timezone.utc).timestamp()) / 86400
        if days < 30:
            out.append(_finding(ctx, "low", "Certificate expires soon",
                                f"The certificate expires in {int(days)} day(s).", "Users will see browser warnings when it expires.",
                                "Renew the certificate and automate renewal.", f"{evidence}\nnotAfter: {cert['notAfter']}"))
    except ssl.SSLCertVerificationError as e:
        code, version = e.verify_code, None
        if code == 62:
            out.append(_finding(ctx, "high", "Certificate does not match the site name",
                                f"The certificate is not valid for {ctx.host}.", "Browsers warn users and cannot confirm the site's identity.",
                                "Install a certificate that lists this hostname.", f"{evidence}\nVerification: {e.verify_message}"))
        elif code == 10:
            out.append(_finding(ctx, "high", "Certificate has expired", "The certificate's validity period has ended.",
                                "Browsers block or warn on every visit.", "Renew and install the certificate.",
                                f"{evidence}\nVerification: {e.verify_message}"))
        elif code in UNTRUSTED:
            out.append(_finding(ctx, "medium", "Certificate is self-signed or not trusted",
                                "The certificate chain does not lead to a trusted authority.", "Users cannot tell the real site from an impostor.",
                                "Use a certificate from a trusted authority and include the full chain.", f"{evidence}\nVerification: {e.verify_message}"))
        else:
            out.append(_finding(ctx, "medium", "Certificate could not be verified", "The certificate failed verification.",
                                "Users cannot rely on the connection being private.", "Fix the certificate chain.",
                                f"{evidence}\nVerification: {e.verify_message}"))
        with _connect(ctx, ip, _lenient()) as s:  # still learn the protocol version
            version = s.version()
    skipped, failed = False, 0
    for name, v in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            c = _lenient(v)
            offered = _can_offer(c)
        except (ValueError, ssl.SSLError):
            offered = False
        if not offered:  # a client that cannot offer the version says nothing about the server
            skipped = True
            continue
        try:
            with _connect(ctx, ip, c) as s:
                out.append(_finding(ctx, "medium", f"Server accepts outdated {name}", f"The server completed a handshake using {name}.",
                                    "Old protocol versions have known weaknesses.", f"Disable {name} and allow TLS 1.2 or newer only.",
                                    f"{evidence}\nNegotiated: {s.version()}"))
        except ssl.SSLError:
            pass  # offered and refused
        except OSError:  # timeout or connection error: the probe failed, the server did not refuse
            failed += 1
    deep, tool, note = ctx.run_ctx.get("profile") in ("pre", "deep"), None, ""
    if deep:
        found, tool, note = _testssl(ctx, ip)
        out += found
    if skipped or failed or note:
        return ModuleResult("completed-warnings", ". ".join(x for x in (
            "Outdated protocol check could not run" if skipped else "",
            f"{failed} outdated protocol probe(s) failed and were not checked" if failed else "", note) if x), out, tool)
    return ModuleResult("completed", f"Checked certificate and protocol versions (negotiated {version}){' and ran testssl.sh' if deep else ''}; {len(out)} issue(s).", out, tool)


# testssl rows that are grades or scan metadata, or that the native checks above already report
SKIP_IDS = {"overall_grade", "scanTime", "cert_trust", "cert_chain_of_trust", "TLS1", "TLS1_1"}
SKIP_PREFIXES = ("grade_", "engine", "service", "pre_", "scanProblem", "clientsimulation")


def _testssl(ctx, ip):
    """Deep TLS checks with testssl.sh aimed only at the guard-checked address. -> (drafts, version, warning)."""
    exe = shutil.which("testssl.sh")
    if not exe:
        return [], None, "Deep TLS checks are not available: testssl.sh is not installed."
    m = re.search(r'(?m)^\s*(?:(?:readonly|declare -r)\s+)?VERSION="?([\w.]+)', Path(exe).resolve().read_text("utf-8", "replace")[:20000])
    version = f"testssl.sh {m.group(1)}" if m else "testssl.sh"
    # shortcut: `--jsonfile -` makes testssl write a file literally named "-" in the cwd, so a private temp file is used instead.
    with tempfile.TemporaryDirectory() as d:
        out_file = str(Path(d) / "out.json")
        proc = subprocess.Popen([exe, "--quiet", "--jsonfile", out_file, "--ip", ip, "--nodns", "none", "--warnings", "off", "--fast",
                                 f"{ctx.host}:{ctx.port}"], env=clean_env(), cwd=d, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            proc.wait(timeout=max(1, ctx.remaining()))
            rows = json.loads(Path(out_file).read_text())
        except subprocess.TimeoutExpired:
            return [], version, "Deep TLS checks ran out of time."
        except (OSError, ValueError):
            return [], version, "Deep TLS checks could not be completed."
        finally:
            if proc.poll() is None:  # openssl children live in the same session: stop them all
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
                proc.wait()
    if not isinstance(rows, list):
        return [], version, "Deep TLS checks could not be completed."
    groups = {}
    for r in rows:
        rid, sev = str(r.get("id", "")) if isinstance(r, dict) else "", str(r.get("severity", "")).lower() if isinstance(r, dict) else ""
        if sev not in ("medium", "high", "critical") or rid in SKIP_IDS or rid.startswith(SKIP_PREFIXES):
            continue
        g = groups.setdefault(re.match(r"[A-Za-z0-9]+", rid).group(0) if re.match(r"[A-Za-z0-9]+", rid) else rid, {})
        g.setdefault(rid, (sev, str(r.get("finding"))[:200], r.get("cve")))
    out = []
    for cat, rows_ in groups.items():
        sev = "high" if any(x[0] in ("high", "critical") for x in rows_.values()) else "medium"  # one testssl row never means critical
        lines = [f"{i}: {x[1]}" + (f" ({x[2]})" if x[2] else "") for i, x in list(rows_.items())[:30]]
        out.append(_finding(ctx, sev, f"TLS weakness: {cat}", f"testssl.sh reports {len(rows_)} issue(s) in the {cat} category.",
                            "Weak TLS settings can let attackers read or change traffic.", "Follow the testssl.sh findings to change the TLS configuration.",
                            f"{ctx.host}:{ctx.port}\n" + "\n".join(lines)))
    return out, version, ""


def _lenient(only=None):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
    if only:
        c.set_ciphers("ALL:@SECLEVEL=0")
        c.minimum_version = c.maximum_version = only
    return c


def _can_offer(context) -> bool:
    """True when this client can actually produce a ClientHello for the context (no network involved)."""
    try:
        context.wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO(), server_hostname="probe.invalid").do_handshake()
    except ssl.SSLWantReadError:
        return True
    except (ssl.SSLError, ValueError):
        return False
    return False
