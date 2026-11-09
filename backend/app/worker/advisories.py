"""Offline advisories from vendored data: retire.js jsrepository.json and endoflife.date release data."""
import json
import os
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urljoin

from .modules.base import FindingDraft, location

VENDOR = Path(os.environ.get("VENDOR_DIR", "/opt/vendor"))
AS_OF = json.loads((Path(__file__).parents[2] / "vendor" / "manifest.json").read_text())["advisory_as_of"]
_SEV = {"low": "low", "medium": "medium", "high": "high", "critical": "critical"}
_SCRIPT = re.compile(r"(?is)<script\b[^>]*?\bsrc\s*=\s*[\"']?([^\"'\s>]+)")
# The vendored endoflife.date release data lists releases but no end-of-life dates, so support is judged by cycle:
# a cycle older than the newest SUPPORTED cycles of the product is reported unsupported. Cycle = first N version parts.
# shortcut: approximates vendor policies; upgrade when the vendored data carries real eol dates.
CYCLE_PARTS = {"nodejs": 1, "drupal": 1, "jquery": 1, "angular": 1, "laravel": 1, "postgresql": 1, "tomcat": 1}
SUPPORTED = {"drupal": 2}  # newest cycles still supported; default 3


@lru_cache
def _retire() -> dict:
    try:
        return json.loads((VENDOR / "retire" / "jsrepository.json").read_text())
    except OSError:
        return {}


def _ver(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v.split("-")[0])[:4]) or (0,)


def _lt(a: str, b: str) -> bool:  # a below b; "1.9.0b1" counts as 1.9.0 (shortcut: pre-release tags ignored)
    return _ver(a) < _ver(b)


def js_library_findings(url: str, body: bytes) -> list[FindingDraft]:
    out, seen = [], set()
    for src in _SCRIPT.findall(body.decode("utf-8", "replace")):
        full = urljoin(url, src)
        for name, lib in _retire().items():
            ex = lib.get("extractors", {})
            ver = next((m.group(1) for rx in ex.get("uri", []) + ex.get("filename", [])
                        if (m := re.search(rx.replace("§§version§§", r"[0-9][0-9.a-z_\-]+"), full))), None)
            if not ver or (name, ver) in seen:
                continue
            seen.add((name, ver))
            for v in lib.get("vulnerabilities", []):
                if (v.get("atOrAbove") and _lt(ver, v["atOrAbove"])) or not _lt(ver, v.get("below", "0")):
                    continue
                ids = v.get("identifiers", {})
                cve = ", ".join(ids.get("CVE", [])) or ids.get("githubID", "no CVE listed")
                summary = ids.get("summary", "Known vulnerability")
                out.append(FindingDraft(
                    _SEV.get(v.get("severity"), "medium"), "suspected", f"{name} {ver} has a known vulnerability: {summary[:80]}",
                    full, location_for(url, full),
                    f"The page loads {name} {ver}, which is below {v['below']}. {summary}",
                    "Attackers may use the published weakness in this library against visitors.",
                    f"Script: {full}\nDetected version: {ver}\nAdvisory: {cve}\nAdvisory data as of {AS_OF}",
                    f"Open {url} and view the script address {full}.", f"Update {name} to {v['below']} or newer.", v.get("info", [])[:3]))
    return out


def location_for(page, script):
    return {"url": page, "host": None, "port": None, "path": None, "param": None, "method": "GET",
            "component": script, "kind": "Script"}


@lru_cache
def _cycles(product: str) -> dict:
    try:
        versions = json.loads((VENDOR / "eol" / f"{product}.json").read_text())["versions"]
    except (OSError, KeyError, ValueError):
        return {}
    n, cycles = CYCLE_PARTS.get(product, 2), {}
    for v in versions:
        cycles.setdefault(".".join(re.findall(r"\d+", v)[:n]), _ver(v))
    return cycles


def eol_findings(product: str, version: str) -> list[FindingDraft]:
    cycles = _cycles(product)
    n = CYCLE_PARTS.get(product, 2)
    cycle = ".".join(re.findall(r"\d+", version)[:n])
    newest = sorted(cycles, key=lambda c: _ver(c), reverse=True)[:SUPPORTED.get(product, 3)]
    if cycle not in cycles or cycle in newest:
        return []
    return [FindingDraft(
        "medium", "suspected", f"{product} {version} is no longer supported", product, {
            "url": None, "host": None, "port": None, "path": None, "param": None, "method": None,
            "component": product, "kind": "Software"},
        f"{product} {version} belongs to release series {cycle}, which is older than the series the vendor still maintains.",
        "Unsupported software no longer receives security fixes, so new weaknesses stay open.",
        f"Detected version: {version}\nCurrent series: {', '.join(newest)}\nAdvisory data as of {AS_OF}",
        f"Check the {product} version on the site and compare it with the vendor's release list.",
        f"Upgrade {product} to a supported release.", ["https://endoflife.date/" + product])]
