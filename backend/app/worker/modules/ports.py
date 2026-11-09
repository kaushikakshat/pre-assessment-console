import subprocess

from app.worker.subproc import clean_env
import xml.etree.ElementTree as ET

from .base import REFS, FindingDraft, ModuleResult, location


def run(ctx) -> ModuleResult:
    ip = ctx.safe_ip()  # only an address that passed the guard is ever handed to nmap
    cmd = ["nmap", "-sT", "-Pn", "-n", "--top-ports", "100", "--host-timeout", "150s", "-oX", "-", ip]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=max(1, min(175, ctx.remaining())), shell=False, env=clean_env())
    except subprocess.TimeoutExpired:
        return ModuleResult("inconclusive", "The port check ran out of time before it finished.")
    except FileNotFoundError:
        return ModuleResult("failed", "The port scanning tool is not available.")
    if p.returncode != 0:
        return ModuleResult("failed", "The port scan could not be completed.")
    try:
        root = ET.fromstring(p.stdout)
    except ET.ParseError:
        return ModuleResult("failed", "The port scan returned an unreadable result.")
    version = root.get("version")
    if root.find("host") is None:
        return ModuleResult("inconclusive", "The port scan returned no result for this host.", tool_version=version)
    out, open_ports = [], 0
    for port in root.iterfind("host/ports/port"):
        st = port.find("state")
        if st is None or st.get("state") != "open":
            continue
        open_ports += 1
        num, svc = int(port.get("portid")), (port.find("service").get("name") if port.find("service") is not None else "unknown")
        if num in ctx.permitted_ports:
            continue
        out.append(FindingDraft(
            "low", "confirmed", f"Unexpected open port {num}/{svc}", f"{ctx.host}:{num}",
            location(ctx, "Network service", port=num),
            f"Port {num} ({svc}) accepts connections but is not in this assessment's permitted ports.",
            "Extra network services widen the attack surface and may be unintended.",
            f"nmap -sT: {num}/{port.get('protocol')} open {svc}", f"Run: nmap -sT -Pn -p {num} {ctx.host}",
            "Close the port or restrict it with a firewall if the service is not needed.", [REFS["ports"]]))
    return ModuleResult("completed", f"Checked the 100 most common ports; {open_ports} open.", out, version)
