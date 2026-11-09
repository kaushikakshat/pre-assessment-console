#!/bin/sh
# Build-time only: fetches the artifacts pinned in manifest.json into $1 (default /opt/vendor), failing on any mismatch.
# git sources are pinned by commit (content-addressed); single files by sha256.
set -eu
OUT="${1:-/opt/vendor}"
M="$(dirname "$0")/manifest.json"
mkdir -p "$OUT"
exec python3 - "$M" "$OUT" <<'PY'
import hashlib, json, os, re, shutil, subprocess, sys, tempfile, urllib.request, zipfile
m, out = json.load(open(sys.argv[1])), sys.argv[2]

def get(url, sha, dest):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    data = urllib.request.urlopen(url, timeout=120).read()
    if hashlib.sha256(data).hexdigest() != sha:
        sys.exit(f"sha256 mismatch for {url}")
    open(dest, "wb").write(data)

def clone(repo, commit, sparse=None):
    d = tempfile.mkdtemp()
    run = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, stdout=subprocess.DEVNULL)
    run("init", "-q"); run("remote", "add", "origin", repo)
    if sparse:
        run("sparse-checkout", "set", *sparse)
    run("fetch", "-q", "--depth=1", "--filter=blob:none" if sparse else "--depth=1", "origin", commit)
    run("checkout", "-q", "FETCH_HEAD")
    head = subprocess.check_output(["git", "-C", d, "rev-parse", "HEAD"], text=True).strip()
    if head != commit:
        sys.exit(f"commit mismatch for {repo}")
    return d

s = m["seclists"]
d, bad = clone(s["repo"], s["commit"], s["paths"]), re.compile(s["exclude"])
for p in s["paths"]:
    for root, _, files in os.walk(os.path.join(d, p)):
        for f in files:
            src = os.path.join(root, f)
            rel = os.path.relpath(src, d)
            if bad.search(rel):
                continue
            dst = os.path.join(out, "seclists", rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(src, dst)
shutil.rmtree(d)

t = m["testssl"]
d = clone(t["repo"], t["commit"])
shutil.rmtree(os.path.join(d, ".git"))
shutil.copytree(d, os.path.join(out, "testssl"), dirs_exist_ok=True)
shutil.rmtree(d)

r = m["retire"]
get(r["url"], r["sha256"], os.path.join(out, r["dest"]))
for name, sha in m["eol"]["files"].items():
    get(m["eol"]["url"].format(name=name), sha, os.path.join(out, "eol", name + ".json"))
for f in m["fonts"]:
    z = os.path.join(tempfile.mkdtemp(), "f.zip")
    get(f["url"], f["sha256"], z)
    with zipfile.ZipFile(z) as zf:
        for n in zf.namelist():
            if "/fonts/complete/ttf/" in n and n.endswith(".ttf"):
                dst = os.path.join(out, "fonts", os.path.basename(n))
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                open(dst, "wb").write(zf.read(n))
PY
