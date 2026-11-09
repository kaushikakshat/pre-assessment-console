import socket
import ssl
from datetime import datetime, timezone

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
    for name, v in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            with _connect(ctx, ip, _lenient(v)) as s:
                out.append(_finding(ctx, "medium", f"Server accepts outdated {name}", f"The server completed a handshake using {name}.",
                                    "Old protocol versions have known weaknesses.", f"Disable {name} and allow TLS 1.2 or newer only.",
                                    f"{evidence}\nNegotiated: {s.version()}"))
        except (ssl.SSLError, OSError):
            pass  # not accepted (or this client cannot offer it)
    return ModuleResult("completed", f"Checked certificate and protocol versions (negotiated {version}); {len(out)} issue(s).", out)


def _lenient(only=None):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
    if only:
        c.set_ciphers("ALL:@SECLEVEL=0")
        c.minimum_version = c.maximum_version = only
    return c
