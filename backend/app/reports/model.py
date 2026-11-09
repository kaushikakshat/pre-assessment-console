"""One report model for the React preview and the PDF (DESIGN_SYSTEM §6.30). No credential data is read here;
every string is redacted once, at the end."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.api.catalog import MODULES, PROFILES
from app.models import Assessment, Finding, Job, ModuleRun, PolicyVersion, Report, User
from app.worker.redact import redact

WATERMARK = ("PRE-ASSESSMENT RESULTS — not a penetration test, statutory certificate or security clearance. "
             "Results are not exhaustive and may include false positives.")
LIMITATIONS = ("Finding states are shown as of {at}. This report reflects the checks that ran against the target at the time of the scan. Checks that were blocked, "
               "skipped, interrupted or could not finish are listed as not tested. A finding marked suspected has not been "
               "confirmed and may be a false positive. Absence of a finding does not mean the target is secure. This is not a "
               "penetration test, statutory certificate or security clearance.")
CATEGORIES = [("confirmed", "Confirmed"), ("suspected", "Suspected"), ("false-positive", "False positive"),
              ("unresolved", "Unresolved"), ("blocked", "Blocked"), ("skipped", "Skipped"), ("not-tested", "Not tested")]
SEV = ["critical", "high", "medium", "low", "info"]
OPEN = ("new", "open", "under-review", "reopened", "not-retested")
NOT_TESTED = ("interrupted", "inconclusive", "unavailable", "failed", "queued", "running", "cancelled")
NAMES = {k: n for k, n, _ in MODULES}
PROFILE_NAMES = {k: n for k, n, *_ in PROFILES}
IST = timezone(timedelta(hours=5, minutes=30))


def ist(t) -> str | None:
    if isinstance(t, str):
        try:
            t = datetime.fromisoformat(t.replace("Z", "+00:00"))
        except ValueError:
            return t
    return t.astimezone(IST).strftime("%d %b %Y, %H:%M IST") if t else None


def one_line(loc: dict) -> str:
    loc = loc or {}
    if loc.get("component") and loc.get("kind") in ("Cookie", "Response header"):
        return f"{loc['kind']} {loc['component']} · {loc.get('url') or loc.get('host', '')}"
    return loc.get("url") or (f"{loc['host']}:{loc['port']}" if loc.get("host") else "") or loc.get("component") or ""


def _scrub(v):
    if isinstance(v, str):
        return redact(v)
    if isinstance(v, list):
        return [_scrub(x) for x in v]
    if isinstance(v, dict):
        return {k: _scrub(x) for k, x in v.items()}
    return v


def build(db, report: Report) -> dict:
    a, job = db.get(Assessment, report.assessment_id), db.get(Job, report.job_id)
    by = db.get(User, report.requested_by).name
    runs = db.scalars(select(ModuleRun).where(ModuleRun.job_id == job.id).order_by(ModuleRun.id)).all()
    # Snapshot of the assessment as of the scan's end; later findings and later retests do not appear in an older report.
    q = select(Finding).where(Finding.assessment_id == a.id)
    if job.ended_at:
        q = q.where(Finding.first_seen_at <= job.ended_at)
    finds = sorted(db.scalars(q), key=lambda f: (SEV.index(f.severity) if f.severity in SEV else 9, f.confidence, f.id))
    pol = db.get(PolicyVersion, job.policy_version) if job.policy_version else None
    tools = sorted({f"{NAMES.get(r.key, r.key)} {r.tool_version}" for r in runs if r.tool_version})
    mods = [{"key": r.key, "name": NAMES.get(r.key, r.key), "state": r.state, "detail": r.detail or "", "untested": r.untested}
            for r in runs]
    live = [f for f in finds if f.state != "false-positive"]
    count = {"confirmed": sum(f.confidence == "confirmed" for f in live), "suspected": sum(f.confidence == "suspected" for f in live),
             "false-positive": len(finds) - len(live), "unresolved": sum(f.state in OPEN for f in finds),
             "blocked": sum(m["state"] == "blocked" for m in mods), "skipped": sum(m["state"] == "skipped" for m in mods),
             "not-tested": sum(m["untested"] > 0 or m["state"] in NOT_TESTED for m in mods)}
    sev = {s: sum(f.severity == s for f in live) for s in SEV}
    secs = (job.ended_at - job.started_at).total_seconds() if job.ended_at and job.started_at else None
    tech = report.type == "technical"
    ver = {r.key: r.tool_version for r in runs}

    def where(f):
        last = next((h["text"] for h in reversed(f.history or []) if h["text"].startswith(("Fixed in", "Still present in"))), None)
        return {"path": None, "param": None, "method": None, **(f.location or {}), "module": NAMES.get(f.module, f.module), "engine_version": ver.get(f.module),
                "found_by": f"{job.display_id} · {job.policy_version or 'no policy'}", "first_seen": ist(f.first_seen_at),
                "last_seen": ist(f.last_seen_at), "latest_retest": last}

    now = ist(datetime.now(timezone.utc))
    m = {"header": {"product": "Pre-Assessment Platform", "classification": "TBD · OD-8"},
         "title": {"assessment": a.name, "type": "Technical report" if tech else "Management summary",
                   "report_id": report.display_id, "version": report.version, "generated_at": now, "by": by},
         "watermark": WATERMARK,
         "scope": {"target": a.target, "in_scope": a.hosts, "exclusions": a.exclusions or "None", "environment": a.env,
                   "scan": f"{job.display_id} · {PROFILE_NAMES.get(job.profile, 'Custom modules')}",
                   "run_time": f"{int(secs // 60)} min {int(secs % 60)} s" if secs is not None else "Not finished",
                   "policy": f"{pol.version}" if pol else "None", "tools": ", ".join(tools) or "None recorded",
                   "hosts_with_findings": ", ".join(sorted({f.asset for f in live})) or "None"},
         "categories": [{"key": k, "label": lab, "count": count[k]} for k, lab in CATEGORIES],
         "modules": mods,
         "summary": {"by_severity": sev, "total": len(live), "still_open": sum(f.state in OPEN for f in live)},
         "findings_overview": [{"n": i, "id": f.display_id, "severity": f.severity, "title": f.title, "location": one_line(f.location),
                                "confidence": f.confidence, "state": f.state} for i, f in enumerate(live, 1)],
         "details": [{"id": f.display_id, "severity": f.severity, "confidence": f.confidence, "state": f.state, "title": f.title,
                      "location": where(f), "description": f.description, "impact": f.impact, "evidence": f.evidence,
                      "reproduce": f.reproduce, "remediation": f.remediation, "references": f.references or [],
                      "history": f.history or []} for f in live] if tech else [],
         "limitations": LIMITATIONS.format(at=now)}
    return _scrub(m)
