import time

from .base import ModuleResult


def run(ctx) -> ModuleResult:
    t0 = time.monotonic()
    r = ctx.get()  # connection errors propagate; the runner reports them as a failed module
    ms = int((time.monotonic() - t0) * 1000)
    return ModuleResult("completed", f"Target responded with HTTP {r.status_code} in {ms} ms.")
