import re

from app.worker.redact import build_evidence

from .base import REFS, FindingDraft, ModuleResult, location

_GEN = re.compile(r"""<meta\s[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']""", re.I)
_VERSIONED = re.compile(r"\d+\.\d+|/\d")


def run(ctx) -> ModuleResult:
    r = ctx.get()
    found = [(name, r.headers[name]) for name in ("server", "x-powered-by", "x-aspnet-version") if name in r.headers]
    if (m := _GEN.search(r.text[:100_000])):
        found.append(("meta generator", m.group(1).strip()))
    out = []
    for name, value in found:
        value = value[:120]
        versioned = bool(_VERSIONED.search(value))
        out.append(FindingDraft(
            "info", "confirmed" if versioned else "suspected", f"Software version disclosed: {value}", ctx.host,
            location(ctx, "Response header" if name != "meta generator" else "Web page", component=name, method="GET"),
            f"The {name} value names the software behind this site" + ("." if versioned else ", without a version."),
            "Attackers can look up known flaws for the exact version in use.",
            build_evidence("GET", ctx.url, r.status_code, r.headers, None, (name,)) if name != "meta generator"
            else f"GET {ctx.url}\nHTTP {r.status_code}\n<meta name=\"generator\" content=\"{value}\">",
            f"Run: curl -sI {ctx.url} and read the {name} value.",
            "Remove or genericise version details in server and framework configuration.", [REFS["info"]]))
    return ModuleResult("completed", f"Looked for visible server and framework details; {len(out)} found.", out)
