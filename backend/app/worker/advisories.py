"""Offline advisories from vendored data: retire.js jsrepository.json and endoflife.date cycle data (with eol dates)."""
import json
import os
import re
from datetime import date
from functools import lru_cache
from pathlib import Path
from urllib.parse import urljoin

from .redact import redact
from .modules.base import FindingDraft, location

VENDOR = Path(os.environ.get("VENDOR_DIR", "/opt/vendor"))
AS_OF = json.loads((Path(__file__).parents[2] / "vendor" / "manifest.json").read_text())["advisory_as_of"]
_SEV = {"low": "low", "medium": "medium", "high": "high", "critical": "critical"}
_SCRIPT = re.compile(r"(?is)<script\b[^>]*?\bsrc\s*=\s*[\"']?([^\"'\s>]+)")


@lru_cache
def _retire() -> dict:
    try:
        return json.loads((VENDOR / "retire" / "jsrepository.json").read_text())
    except OSError:
        return {}


def _ver(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v.split("-")[0])[:4])


def _cmp(a: str, b: str) -> int:
    """-1/0/1; tuples padded so 4.0 == 4.0.0. shortcut: pre-release tags (1.9.0b1) compare as their numeric part."""
    x, y = _ver(a), _ver(b)
    n = max(len(x), len(y), 1)
    x, y = x + (0,) * (n - len(x)), y + (0,) * (n - len(y))
    return (x > y) - (x < y)


def affected(ver: str, v: dict) -> bool:
    """retire.js range: atOrAbove / above / below / atOrBelow, all that are present must hold."""
    if not ({"below", "atOrBelow"} & set(v)):
        return False
    return ((("atOrAbove" not in v) or _cmp(ver, v["atOrAbove"]) >= 0) and (("above" not in v) or _cmp(ver, v["above"]) > 0)
            and (("below" not in v) or _cmp(ver, v["below"]) < 0) and (("atOrBelow" not in v) or _cmp(ver, v["atOrBelow"]) <= 0))


def js_library_findings(url: str, body: bytes) -> list[FindingDraft]:
    out, seen = [], set()
    for src in _SCRIPT.findall(body.decode("utf-8", "replace")):
        full = urljoin(url, src)
        for name, lib in _retire().items():
            ex = lib.get("extractors", {})
            ver = None
            for rx in ex.get("uri", []) + ex.get("filename", []):
                try:
                    if m := re.search(rx.replace("§§version§§", r"[0-9][0-9.a-z_\-]+"), full):
                        ver = m.group(1)
                        break
                except re.error:
                    continue  # one bad vendored pattern must not stop the scan
            if not ver or (name, ver) in seen:
                continue
            seen.add((name, ver))
            for v in lib.get("vulnerabilities", []):
                if not affected(ver, v):
                    continue
                ids = v.get("identifiers", {})
                cve = ", ".join(ids.get("CVE", [])) or ids.get("githubID", "no CVE listed")
                summary = ids.get("summary", "Known vulnerability")
                out.append(FindingDraft(
                    _SEV.get(v.get("severity"), "medium"), "suspected", f"{name} {ver} has a known vulnerability: {summary[:80]}",
                    full, location_for(url, full),
                    f"The page loads {name} {ver}, which is in the affected range. {summary}",
                    "Attackers may use the published weakness in this library against visitors.",
                    redact(f"Script: {full}\nDetected version: {ver}\nAdvisory: {cve}\nAdvisory data as of {AS_OF}"),
                    f"Open {url} and view the script address {full}.", f"Update {name} to a release newer than the affected range.", v.get("info", [])[:3]))
    return out


def location_for(page, script):
    return {"url": page, "host": None, "port": None, "path": None, "param": None, "method": "GET",
            "component": script, "kind": "Script"}


@lru_cache
def _eol_data(product: str) -> list:
    try:
        rows = json.loads((VENDOR / "eol" / f"{product}.json").read_text())
    except (OSError, ValueError):
        return []
    return [r for r in rows if isinstance(r, dict) and "cycle" in r] if isinstance(rows, list) else []


def eol_findings(product: str, version: str, today: date | None = None) -> list[FindingDraft]:
    """Unsupported only when the vendored endoflife.date cycle says so (eol true, or an eol date in the past)."""
    today = today or date.today()
    ver = ".".join(re.findall(r"\d+", version))
    match = [r for r in _eol_data(product) if ver == str(r["cycle"]) or ver.startswith(str(r["cycle"]) + ".")]
    if not match:
        return []
    c = max(match, key=lambda r: len(str(r["cycle"])))
    eol = c.get("eol")
    if not (eol is True or (isinstance(eol, str) and date.fromisoformat(eol) < today)):
        return []
    return [FindingDraft(
        "medium", "confirmed", f"{product} {version} is no longer supported", product, {
            "url": None, "host": None, "port": None, "path": None, "param": None, "method": None,
            "component": product, "kind": "Software"},
        f"{product} {version} belongs to release series {c['cycle']}, which reached end of life" + (f" on {eol}." if eol is not True else "."),
        "Unsupported software no longer receives security fixes, so new weaknesses stay open.",
        f"Detected version: {version}\nEnd of life: {eol}\nAdvisory data as of {AS_OF}",
        f"Check the {product} version on the site and compare it with https://endoflife.date/{product}.",
        f"Upgrade {product} to a supported release.", ["https://endoflife.date/" + product])]
