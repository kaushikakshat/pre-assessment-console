"""Thin client for the ZAP JSON API (ZAP sits on the internal network and reaches targets only through the egress
guard proxy, so this client never talks to targets and does not use SafeClient). The API key travels in the
X-ZAP-Api-Key header, never in a URL or a log line, and values (cookies) go in POST bodies.

Scan policies, created on first use. Both are allowlists, so DoS-class, brute-force and anything ZAP marks DANGEROUS
are excluded by construction (ids not installed in the running ZAP are skipped):
  pa-safe (Pre-Assessment): 6 path traversal, 7 remote file inclusion, 40012 reflected XSS, 40018 SQL injection,
    40003 CRLF injection, 40008 parameter tampering, 20019 external redirect, 90023 XXE, 90021 XPath injection,
    40032 .htaccess leak, 40034 .env leak, 40035 hidden files.
  pa-deep (Deep) = pa-safe plus 40014/40016/40017 stored XSS, 40026 DOM XSS, 40009 server-side include,
    90019 server-side code injection, 90020 OS command injection, 90025 expression language injection,
    90035/90036 server-side template injection, 90017 XSLT injection, 10095 backup files, 40028 ELMAH, 40029 trace.axd.
"""
import re
import time
from urllib.parse import urlsplit

import httpx

from app.worker.modules.base import FindingDraft, location

POLICIES = {"pa-safe": [6, 7, 40012, 40018, 40003, 40008, 20019, 90023, 90021, 40032, 40034, 40035]}
POLICIES["pa-deep"] = POLICIES["pa-safe"] + [40014, 40016, 40017, 40026, 40009, 90019, 90020, 90025, 90035, 90036,
                                             90017, 10095, 40028, 40029]
SEVERITY = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
_ID_SEG = re.compile(r"^(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$")


class EngineError(Exception):
    """The engine answered but refused or garbled a call; the module fails with a plain detail."""
    def __init__(self, msg, code=None):
        super().__init__(msg)
        self.code = code  # ZAP's own error code (e.g. bad_external_data) when it sent one


class EngineDown(Exception):
    """The scanning engine (or its egress guard) cannot be reached."""


def normalize_path(path: str) -> str:
    return "/".join("{id}" if _ID_SEG.match(s) else s for s in path.split("/"))


class Zap:
    def __init__(self, base_url: str, api_key: str, *, poll: float = 1.0):
        self.base, self.poll, self._ctx, self._policies = base_url.rstrip("/"), poll, {}, set()
        self._http = httpx.Client(timeout=30, headers={"X-ZAP-Api-Key": api_key})

    def _call(self, kind, path, **params):
        try:
            r = (self._http.get if kind == "view" else self._http.post)(
                f"{self.base}/JSON/{path}/", **({"params": params} if kind == "view" else {"data": params}))
        except httpx.HTTPError as e:
            raise EngineDown("The scanning engine is not running.") from e
        if r.status_code >= 500:
            raise EngineDown("The scanning engine is not running.")
        if r.status_code >= 400:  # ZAP refused the call (bad parameter, unknown scan): a failure, not an outage
            try:
                code = r.json().get("code")
            except (ValueError, AttributeError):
                code = None
            raise EngineError(f"The scanning engine rejected {path} ({r.status_code}).", code)
        try:
            return r.json()
        except ValueError as e:
            raise EngineError(f"The scanning engine returned an unreadable answer for {path}.") from e

    def _field(self, r, key, path):
        try:
            return r[key]
        except (KeyError, TypeError) as e:
            raise EngineError(f"The scanning engine answered {path} without {key}.") from e

    def version(self) -> str:
        return self._field(self._call("view", "core/view/version"), "version", "version")

    def new_session(self) -> None:
        self._call("action", "core/action/newSession", overwrite="true")
        for opt in ("spider/action/setOptionAcceptCookies", "core/action/setOptionHttpStateEnabled"):
            self._call("action", opt, Boolean="false")  # only the injected Cookie header may identify an account

    def setup_context(self, name, include, exclude) -> int:
        cid = int(self._field(self._call("action", "context/action/newContext", contextName=name), "contextId", "newContext"))
        self._ctx[cid] = name
        for rx in include:
            self._call("action", "context/action/includeInContext", contextName=name, regex=rx)
        for rx in exclude:
            self._call("action", "context/action/excludeFromContext", contextName=name, regex=rx)
        return cid

    def set_header(self, name, value) -> None:
        self._call("action", "replacer/action/addRule", description=name, enabled="true", matchType="REQ_HEADER",
                   matchRegex="false", matchString=name, replacement=value)

    def clear_headers(self) -> None:
        for r in self._call("view", "replacer/view/rules").get("rules", []):
            self._call("action", "replacer/action/removeRule", description=r["description"])

    def _wait(self, comp, scan_id, deadline) -> int:
        """Polls until 100% or the deadline; on the deadline the scan is stopped and the partial progress returned."""
        pct = 0
        while True:
            pct = int(self._field(self._call("view", f"{comp}/view/status", scanId=scan_id), "status", "status"))
            if pct >= 100:
                return 100
            if time.monotonic() + self.poll >= deadline:
                self._call("action", f"{comp}/action/stop", scanId=scan_id)
                return pct
            time.sleep(self.poll)

    def spider(self, url, context_id, max_children, deadline) -> tuple[list[str], list[str], int]:
        """-> (urls found in scope, urls the spider saw out of scope, percent finished)."""
        sid = self._field(self._call("action", "spider/action/scan", url=url, maxChildren=max_children, recurse="true",
                                     contextName=self._ctx[context_id], subtreeOnly="true"), "scan", "spider scan")
        pct = self._wait("spider", sid, deadline)
        urls = self._field(self._call("view", "spider/view/results", scanId=sid), "results", "spider results")
        full = self._call("view", "spider/view/fullResults", scanId=sid).get("fullResults") or [{}]
        return urls, [u for u in (full[0].get("urlsOutOfScope") or []) if isinstance(u, str)], pct

    def messages(self, base_url, start=0) -> list[dict]:
        """History messages for base_url from index start (ZAP numbers them per base_url filter)."""
        out = []
        while True:
            page = self._field(self._call("view", "core/view/messages", baseurl=base_url, start=start, count=500), "messages", "messages")
            out += page
            if len(page) < 500:
                return out
            start += 500

    def message_count(self, base_url) -> int:
        return int(self._field(self._call("view", "core/view/numberOfMessages", baseurl=base_url), "numberOfMessages", "numberOfMessages"))

    def import_openapi(self, url, context_id) -> int:
        r = self._call("action", "openapi/action/importUrl", url=url, contextId=context_id)
        return len(r["importUrl"]) if isinstance(r.get("importUrl"), list) else 0

    def _ensure_policy(self, name):
        if name in self._policies:
            return
        if name not in POLICIES:
            raise ValueError("policy")
        have = set(self._call("view", "ascan/view/scanPolicyNames").get("scanPolicyNames", []))
        if name not in have:
            self._call("action", "ascan/action/addScanPolicy", scanPolicyName=name)
        self._call("action", "ascan/action/disableAllScanners", scanPolicyName=name)
        installed = {int(s["id"]) for s in self._call("view", "ascan/view/scanners", scanPolicyName=name).get("scanners", [])}
        ids = ",".join(str(i) for i in POLICIES[name] if i in installed)
        if ids:
            self._call("action", "ascan/action/enableScanners", ids=ids, scanPolicyName=name)
        self._policies.add(name)

    def active_scan(self, url, context_id, policy, deadline) -> int:
        self._ensure_policy(policy)
        sid = self._field(self._call("action", "ascan/action/scan", url=url, contextId=context_id, scanPolicyName=policy,
                                     recurse="true"), "scan", "active scan")
        return self._wait("ascan", sid, deadline)

    def alerts(self, base_url) -> list[dict]:
        out, start = [], 0
        while True:
            page = self._field(self._call("view", "core/view/alerts", baseurl=base_url, start=start, count=500), "alerts", "alerts")
            out += page
            if len(page) < 500:
                return out
            start += 500

    def wipe(self) -> None:
        self.new_session()
        self.clear_headers()
        self._ctx.clear()


def alert_to_draft(alert: dict, ctx) -> FindingDraft:
    u, param = urlsplit(alert.get("url", "")), alert.get("param", "")
    path = normalize_path(u.path or "/")
    d = FindingDraft(
        SEVERITY.get(alert.get("risk"), "info"), "confirmed" if alert.get("confidence") in ("High", "Confirmed", "User Confirmed") else "suspected",
        alert.get("alert") or alert.get("name") or "Scanner finding", u.hostname or ctx.host,
        location(ctx, "Endpoint", path=u.path or "/", port=u.port, method=alert.get("method"), param=param or None,
                 url=alert.get("url")),
        alert.get("description", ""), alert.get("other") or "See the description.",
        "\n".join(x for x in (f"{alert.get('method', '')} {alert.get('url', '')}".strip(),
                              f"Parameter: {param}" if param else "", f"Attack: {alert['attack']}" if alert.get("attack") else "",
                              f"Evidence: {alert['evidence']}" if alert.get("evidence") else "") if x),
        f"Send {alert.get('method') or 'a request'} to {alert.get('url', '')}" + (f" with the {param} parameter changed." if param else "."),
        alert.get("solution", ""), [r for r in alert.get("reference", "").split() if r.startswith("http")])
    d.fingerprint_key = f"zap:{alert.get('pluginId')}:{path}:{param}"
    return d
