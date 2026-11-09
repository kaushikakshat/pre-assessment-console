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
NEVER = r"(?i)logout|signout|sign-out|delete|remove|password|deactivate|unsubscribe"  # Global Constraints pattern


class Budget:
    """total_s of run time split by stage; what a stage leaves unused rolls into the next stage that starts."""
    def __init__(self, total_s: float, clock=time.monotonic):
        self.total, self.clock, self.split, self.carry, self.deadlines = total_s, clock, SPLIT, 0.0, {}

    def start(self, stage) -> float:
        if stage not in self.deadlines:  # a stage with several modules keeps one deadline
            self.deadlines[stage] = self.clock() + self.total * self.split[stage] + self.carry
            self.carry = 0.0
        return self.deadlines[stage]

    def end(self, stage) -> None:
        if stage in self.deadlines:
            self.carry += max(0.0, self.deadlines[stage] - self.clock())
            self.deadlines[stage] = float("-inf")  # ended: never start again with a stale deadline


def excluded_regexes(assessment, extra=()) -> list[str]:
    """ZAP exclusion regexes: never-touch actions, the assessment's exclusions (glob paths) and login/OTP URLs."""
    ex = [NEVER]
    for tok in re.split(r"[\s,]+", assessment.exclusions or ""):
        if tok:
            ex.append(".*" + re.escape(tok).replace(r"\*", ".*") + ".*")
    return ex + [re.escape(u) + ".*" for u in extra]


class EngineSession:
    """PUTs the job's scope to the egress guard, then resets ZAP. On exit ZAP is wiped and the scope is DELETEd,
    always, even when the body raised."""
    def __init__(self, job, assessment, scope, *, zap=None, egress_url=None, token=None, extra_exclude=()):
        self.job, self.scope = job, scope  # scope: {"hosts": set, "ports": set, "internal": {host: [cidr] | None}}
        self.zap = zap or Zap(os.environ.get("ENGINE_URL", ""), os.environ.get("ZAP_API_KEY", ""))
        self.egress, self.token = egress_url or os.environ.get("EGRESS_CONTROL", ""), token or os.environ.get("EGRESS_TOKEN", "")
        self.exclude = excluded_regexes(assessment, extra_exclude)

    def _egress(self, method, **kw):
        try:
            r = httpx.request(method, f"{self.egress}/scope", headers={"X-Egress-Token": self.token}, timeout=10, **kw)
        except httpx.HTTPError as e:
            raise EngineDown("The scanning engine is not running.") from e
        if r.status_code != 204:
            raise EngineDown("The scanning engine is not running.")

    def __enter__(self):
        s = self.scope
        self._egress("PUT", json={"job_id": self.job.display_id, "hosts": sorted(s["hosts"]), "ports": sorted(s["ports"]),
                                  "internal": s["internal"]})
        try:
            self.zap.wipe()
        except BaseException:
            self._clear_scope()
            raise
        return self

    def _clear_scope(self):
        try:
            self._egress("DELETE")
        except Exception:
            log.exception("could not clear the egress scope; the next job's scope replaces it")

    def __exit__(self, *exc):
        try:
            self.zap.wipe()
        except Exception:
            log.exception("could not wipe the scan engine session")
        finally:
            self._clear_scope()
