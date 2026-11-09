"""Staged time budgets and the guarded engine session."""
import logging
import os
import re
import time

import httpx

from app.engine.zap import EngineDown, Zap

log = logging.getLogger("worker")
SPLIT = {"crawl": .3, "active": .5, "access": .2}
MODULE_STAGE = {"crawl": "crawl", "dast": "active", "api": "active", "access": "access"}
NEVER = r"(?i).*(?:logout|signout|sign-out|delete|remove|password|deactivate|unsubscribe).*"  # Global Constraints pattern


class Budget:
    """total_s of run time split by stage. A stage's time is shared evenly by the modules scheduled in it (run in
    order, so a module's leftover reaches the next one); a stage's unused time, and the whole share of a stage with no
    scheduled modules, rolls into the next stage that starts."""
    def __init__(self, total_s: float, plan=(), clock=time.monotonic):
        self.total, self.clock, self.carry, self.split = total_s, clock, 0.0, SPLIT
        self.left = {st: [k for k in plan if MODULE_STAGE.get(k) == st] for st in SPLIT}  # modules not yet ended
        self.stage_end, self.credited = {}, set()

    def _open(self, stage):
        if stage in self.stage_end:
            return
        for st in SPLIT:  # earlier stages that had nothing scheduled hand their time forward
            if st == stage:
                break
            if not self.left[st] and st not in self.stage_end and st not in self.credited:
                self.credited.add(st)
                self.carry += self.total * SPLIT[st]
        self.stage_end[stage] = self.clock() + self.total * SPLIT[stage] + self.carry
        self.carry = 0.0

    def start(self, key) -> float:
        st = MODULE_STAGE[key]
        self._open(st)
        return self.clock() + max(0.0, self.stage_end[st] - self.clock()) / max(1, len(self.left[st]))

    def end(self, key) -> None:
        st = MODULE_STAGE[key]
        self._open(st)
        if key in self.left[st]:
            self.left[st].remove(key)
        if not self.left[st]:
            self.carry += max(0.0, self.stage_end[st] - self.clock())
            self.stage_end[st] = float("-inf")  # ended


def excluded_regexes(assessment, extra=()) -> list[str]:
    """ZAP exclusion regexes (ZAP full-matches them, so each is wrapped in .*): never-touch actions, the assessment's
    exclusions (glob paths) and login/OTP URLs."""
    ex = [NEVER]
    for tok in re.split(r"[\s,]+", assessment.exclusions or ""):
        if tok:
            ex.append(".*" + re.escape(tok).replace(r"\*", ".*") + ".*")
    return ex + [re.escape(u) + ".*" for u in extra]


class EngineSession:
    """PUTs the job's scope to the egress guard, then resets ZAP. On exit ZAP is wiped and the scope is DELETEd,
    always, even when the body raised."""
    def __init__(self, job, assessment, scope, *, zap=None, egress_url=None, token=None, extra_exclude=(), ttl_s=7200):
        self.job, self.scope, self.ttl_s = job, scope, ttl_s  # scope: {"hosts": set, "ports": set, "internal": {host: [cidr] | None}}
        self.zap = zap or Zap(os.environ.get("ENGINE_URL", ""), os.environ.get("ZAP_API_KEY", ""))
        self.egress, self.token = egress_url or os.environ.get("EGRESS_CONTROL", ""), token or os.environ.get("EGRESS_TOKEN", "")
        self.exclude = excluded_regexes(assessment, extra_exclude)

    def _egress(self, method, **kw):
        try:
            r = httpx.request(method, f"{self.egress}/scope", params=kw.pop("params", None), headers={"X-Egress-Token": self.token}, timeout=10, **kw)
        except httpx.HTTPError as e:
            raise EngineDown("The scanning engine is not running.") from e
        if r.status_code != 204:
            raise EngineDown("The scanning engine is not running.")

    def __enter__(self):
        s = self.scope
        self._egress("PUT", json={"job_id": self.job.display_id, "hosts": sorted(s["hosts"]), "ports": sorted(s["ports"]),
                                  "internal": s["internal"], "ttl_s": self.ttl_s})
        try:
            self.zap.wipe()
        except BaseException:
            self._clear_scope()
            raise
        return self

    def _clear_scope(self):
        for attempt in (1, 2):  # job_id: a late DELETE never ends a newer job's scope; the scope also expires by ttl
            try:
                return self._egress("DELETE", params={"job_id": self.job.display_id})
            except Exception:
                log.exception("could not clear the egress scope (attempt %s)", attempt)

    def __exit__(self, *exc):
        try:
            self.zap.wipe()
        except Exception:
            log.exception("could not wipe the scan engine session")
        finally:
            self._clear_scope()
