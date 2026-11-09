from fastapi import APIRouter, Depends

from app.core.security import current_user

router = APIRouter()

QUICK = ["reach", "ports", "tls", "headers", "exposed", "finger"]
PRE = QUICK + ["crawl", "cms", "config"]
DEEP = PRE + ["dast", "api", "auth", "access", "cval"]
PROFILES = [
    ("quick", "Quick Scan", "A fast, low-impact check of reachability, ports, certificates, headers, exposed files and technology.",
     QUICK, True, "Seconds to minutes for small targets", "Low"),
    ("pre", "Pre-Assessment", "Quick Scan plus a bounded crawl and common configuration checks.",
     PRE, False, "Minutes to tens of minutes", "Moderate"),
    ("deep", "Deep Scan", "The widest set of checks, including authenticated and access-control testing.",
     DEEP, False, "Tens of minutes to hours (not exhaustive)", "Higher"),
]
MODULES = [
    ("reach", "Reachability", "Checks that the target responds and where its redirects lead."),
    ("ports", "Open ports", "Looks for open network ports among a short list of common ones."),
    ("tls", "Certificates and encryption", "Checks the TLS certificate, expiry and protocol versions."),
    ("headers", "Security headers", "Checks the response headers that protect browsers."),
    ("exposed", "Exposed files", "Looks for commonly exposed files and admin pages."),
    ("finger", "Technology detection", "Identifies visible server and framework versions."),
    ("crawl", "Page discovery", "Follows links to map pages within the approved scope."),
    ("cms", "CMS checks", "Checks known content management systems for common weaknesses."),
    ("config", "Configuration checks", "Checks settings such as cookies and cross-origin rules."),
    ("dast", "Web vulnerability tests", "Sends safe test inputs to look for common web flaws."),
    ("api", "API checks", "Checks API endpoints for common weaknesses."),
    ("auth", "Authenticated testing", "Tests signed-in areas using an approved credential reference."),
    ("access", "Access control checks", "Checks that users cannot reach data they should not."),
    ("cval", "Control validation", "Confirms that security controls behave as intended."),
]


@router.get("/catalog")
def catalog(user=Depends(current_user)):
    return {
        "profiles": [{"key": k, "name": n, "description": d, "modules": m, "available": a, "duration": dur, "impact": imp}
                     for k, n, d, m, a, dur, imp in PROFILES],
        "modules": [{"key": k, "name": n, "description": d, "available": k in QUICK,
                     "profiles": [p[0] for p in PROFILES if k in p[3]]} for k, n, d in MODULES],
    }
