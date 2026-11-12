# Target Policies Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Admins draft, validate, dry-run, publish, compare and roll back target policy versions from two admin pages (`DESIGN_SYSTEM.md` §7.20).

**Architecture:** Pure policy logic (`check_policy`, `evaluate_outcome`, `content_hash`) lives in `backend/app/targets/policy.py`. A new admin router `backend/app/api/policies.py` owns the draft lifecycle, dry run, publish (with the stricter-outcome reset) and rollback. The policy document shape in `policy_versions.rules` is unchanged, so `validate_target` is untouched. Two React pages under `frontend/src/pages/admin/`.

**Tech Stack:** FastAPI, SQLAlchemy 2, hand-written SQL Alembic migration, Postgres 16; React 18 + TS + Vite, vitest.

**Spec:** `docs/superpowers/specs/2026-11-12-target-policies-design.md`

## Global Constraints

- Branch `policies` off `main`. Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Backend tests run in Docker only: `docker-compose --profile test run --rm test pytest tests/<file> -q` (full suite: drop the path). If a pull fails on `docker-credential-desktop`, `export DOCKER_CONFIG=<scratch dir>`; never edit `~/.docker`. Never run `docker-compose down -v`.
- Frontend: `cd frontend && npx tsc --noEmit && npm test`.
- Every route is admin-only (router-level `Depends(sec.require_admin)`, as in `app/api/admin.py:18`); mutations need the existing CSRF header (already enforced by middleware).
- Audit every mutation with `app.core.audit.record(db, actor, "policy", <action>, <version>, outcome, detail, version)`. Actions: `draft-start`, `draft-save`, `draft-import`, `draft-discard`, `draft-validate`, `dry-run`, `publish`, `rollback`; per reset assessment: area `validation`, action `policy-reset`.
- Hard invariants stay in `ipguard`; nothing in this plan may weaken `ipguard.classify` or `validate_target`.
- The dry run and publish send **no HTTP request** to any target; DNS only, via `ipguard.resolve(host, timeout=3)`, at most 8 lookups in parallel.
- Environments: `Development, Staging, UAT, Production` (`app/api/assessments.py:18` `ENVS`; import it, do not copy).
- Copy: sentence case; schema error format `rules[<index>] (<id>): <message>`, e.g. `rules[2] (R-07): CIDR must look like 203.0.113.0/24`.
- Outcome rank for "stricter": `allowed` 0 < `approval` 1 < `blocked` 2. `unresolved` never triggers a reset.
- Only `queued` jobs are cancelled by a reset; `scheduled`, `running`, `cancelling` are left alone.

## Review Focus

1. A validation that started before a publish and finishes after it must not save the old version's outcome → validate re-checks its version is still published (Task 3, `test_validate_racing_publish_is_refused`).
2. Tests share one database; a test that publishes must leave `v1` as the only published version → `restore_policy` fixture (Task 2), used by every test that writes policy rows.
3. An admin-approved assessment (stored outcome `approval`, status `active`) whose draft outcome is still `approval` must stay approved → Task 3 `test_publish_keeps_approved_when_not_stricter`.
4. Two admins editing one draft: the second save with a stale `rev` gets 409, nothing is lost silently → Task 2 `test_stale_rev_conflict`.
5. JSON import of a non-object, huge or deeply nested payload is rejected without changing the draft → Task 2 `test_import_rejects_bad_json` (body limit 256 KB, max 500 rules).

---

### Task 1: Migration 0013 and pure policy logic

**Files:**
- Create: `backend/alembic/versions/0013_policy_drafts.py`
- Create: `backend/app/targets/policy.py`
- Modify: `backend/app/models.py` (`PolicyVersion`)
- Test: `backend/tests/test_policy.py`

**Interfaces:**
- Produces (`app.targets.policy`):
  - `INVARIANTS: list[str]` — the locked list shown on the Safety invariants card: `"Loopback addresses (127.0.0.0/8, ::1)"`, `"Unspecified addresses (0.0.0.0, ::)"`, `"Link-local addresses (169.254.0.0/16, fe80::/10)"`, `"Cloud metadata (169.254.169.254, fd00:ec2::254)"`, `"Private ranges, unless an allow rule permits private addresses"`, `"Redirects or DNS answers that leave the approved scope"`.
  - `check_policy(doc: dict) -> list[dict]` — items `{"key": "schema"|"conflicts"|"invariants"|"ports", "label": str, "result": "pass"|"warn"|"fail", "detail": str}`, one item per problem plus one `pass` item per group with no problems. Labels: `Schema`, `Conflicts`, `Safety invariants`, `Ports`.
  - `schema_errors(doc) -> list[str]` — the schema group only (used by import).
  - `content_hash(doc: dict) -> str` — sha256 hex of `json.dumps(doc, sort_keys=True, separators=(",", ":"))`.
  - `evaluate_outcome(target: str, env: str, ports_field: str, policy: dict, addrs: list[str] | None, app_env: str) -> str` — `"allowed"|"approval"|"blocked"|"unresolved"`; `addrs=None` means DNS failed → `"unresolved"`.
  - `RANK = {"allowed": 0, "approval": 1, "blocked": 2}`.
- Model `PolicyVersion` gains `note`, `created_by`, `created_at`, `rev: int`, `dry_run: dict|None`, `validation: dict|None`; `published_at` nullable.

- [ ] **Step 1: Write the failing tests** in `backend/tests/test_policy.py` (pure, no DB):

```python
from app.targets.policy import check_policy, content_hash, evaluate_outcome, schema_errors

BASE = {"rules": [], "permitted_ports": [80, 443], "no_match": "approval"}
def doc(*rules, **kw): return {**BASE, "rules": list(rules), **kw}
def r(i, outcome="allow", match="suffix", value="example.com", **kw): return {"id": i, "outcome": outcome, "match": match, "value": value, "note": "", **kw}
def fails(d): return [c["detail"] for c in check_policy(d) if c["result"] == "fail"]
def warns(d): return [c["detail"] for c in check_policy(d) if c["result"] == "warn"]

def test_clean_policy_passes_all_groups():
    out = check_policy(doc(r("R-01")))
    assert {c["key"] for c in out} == {"schema", "conflicts", "invariants", "ports"} and all(c["result"] == "pass" for c in out)

def test_schema_messages_name_the_rule():
    d = doc(r("R-01"), r("R-02"), r("R-07", match="cidr", value="10.0.0/33"))
    assert "rules[2] (R-07): CIDR must look like 203.0.113.0/24" in fails(d)
    assert any("rules[0] (R-01)" in e and "outcome" in e for e in schema_errors(doc(r("R-01", outcome="maybe"))))
    assert any("IP" in e for e in schema_errors(doc(r("R-01", match="ip", value="1.2.3"))))
    assert any("environment" in e.lower() for e in schema_errors(doc(r("R-01", match="env", value="Prod"))))
    assert any("Duplicate rule ID" in e for e in schema_errors(doc(r("R-01"), r("R-01", value="b.com"))))
    assert any("no_match" in e for e in schema_errors(doc(no_match="maybe")))
    assert schema_errors([]) and schema_errors({"rules": "x", "permitted_ports": [80], "no_match": "approval"})

def test_conflicts_and_shadowing():
    assert fails(doc(r("R-01"), r("R-02", outcome="deny")))                       # same match+value, different outcome
    assert warns(doc(r("R-01"), r("R-02")))                                        # exact duplicate
    assert any("R-02" in w and "R-01" in w for w in warns(doc(r("R-01", value="example.com"), r("R-02", match="domain", value="a.example.com"))))  # shadowed

def test_invariant_overrides():
    assert fails(doc(r("R-01", match="cidr", value="127.0.0.0/8")))
    assert fails(doc(r("R-01", match="ip", value="169.254.169.254")))
    assert warns(doc(r("R-01", match="cidr", value="10.20.0.0/16")))               # private allow without internal
    assert not warns(doc(r("R-01", match="cidr", value="10.20.0.0/16", internal=True)))
    assert warns(doc(no_match="allow"))
    assert fails(doc(r("R-01", outcome="deny", match="env", value="Staging", internal=True)))  # internal only on allow + host/address match

def test_ports():
    assert fails(doc(permitted_ports=[])) and fails(doc(permitted_ports=[0])) and fails(doc(permitted_ports=[80, 80]))

def test_content_hash_is_order_stable():
    assert content_hash({"a": 1, "b": [1]}) == content_hash({"b": [1], "a": 1})

def test_evaluate_outcome():
    pol = doc(r("R-01", outcome="deny", value="bad.com"), r("R-02", match="cidr", value="10.0.0.0/8", internal=True))
    assert evaluate_outcome("https://x.bad.com/", "Staging", "", pol, ["93.184.216.34"], "prod") == "blocked"
    assert evaluate_outcome("https://ok.com/", "Staging", "", pol, ["93.184.216.34"], "prod") == "approval"
    assert evaluate_outcome("https://in.corp/", "Staging", "", pol, ["10.1.2.3"], "prod") == "allowed"
    assert evaluate_outcome("https://ok.com:9999/", "Staging", "", pol, ["93.184.216.34"], "prod") == "blocked"  # port
    assert evaluate_outcome("https://ok.com/", "Staging", "", pol, ["127.0.0.1"], "prod") == "blocked"
    assert evaluate_outcome("https://ok.com/", "Staging", "", pol, None, "prod") == "unresolved"
```

- [ ] **Step 2: Run** `docker-compose --profile test run --rm test pytest tests/test_policy.py -q` → FAIL (module missing).

- [ ] **Step 3: Implement `app/targets/policy.py`.** Reuse `validate.parse_target`, `parse_ports`, `first_rule`, `_internal`, `_check_addrs` and `ipguard.classify`/`normalize_host`; `evaluate_outcome` mirrors `validate_target`'s url → addresses → ports → rules order without the redirect step. Value formats: suffix/domain via `normalize_host` + `validate._HOSTNAME`; ip via `ipaddress.ip_address`; cidr via `ip_network(strict=False)` and must contain `/`; env in `ENVS`. Rule IDs match `^R-\d{2,}$`. Shadowing: an earlier rule shadows a later one when the earlier is `suffix` and the later's `domain`/`suffix` value equals or ends with `.`+earlier value, or both are identical (match, value). Forbidden check: an ip/cidr whose address/network overlaps any network for which `classify` returns `"hard"` (test the network's first, last and the network address of each hard range in `ipguard`); private = `classify(...)[0] == "private"`.

- [ ] **Step 4: Migration 0013** (`down_revision = "0012"`, forward-only like 0012):

```sql
ALTER TABLE policy_versions ALTER COLUMN published_at DROP NOT NULL, ALTER COLUMN published_at DROP DEFAULT,
  ADD COLUMN note text, ADD COLUMN created_by text, ADD COLUMN created_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN rev integer NOT NULL DEFAULT 0, ADD COLUMN dry_run jsonb, ADD COLUMN validation jsonb,
  ADD CONSTRAINT policy_status_ck CHECK (status IN ('draft','published','superseded'));
CREATE UNIQUE INDEX policy_one_draft ON policy_versions ((true)) WHERE status = 'draft';
CREATE UNIQUE INDEX policy_one_published ON policy_versions ((true)) WHERE status = 'published';
UPDATE policy_versions SET note = 'Initial policy' WHERE version = 'v1' AND note IS NULL;
```
Update `PolicyVersion` in `models.py` to match (`published_at` → `Mapped[datetime | None]`, no server default).

- [ ] **Step 5: Run** the Task 1 tests plus `tests/test_schema.py tests/test_validate.py` → PASS.

- [ ] **Step 6: Commit** `feat(policy): drafts schema and pure policy checks`.

---

### Task 2: Draft lifecycle API

**Files:**
- Create: `backend/app/api/policies.py`
- Modify: `backend/app/main.py` (include router after `admin.router`)
- Test: `backend/tests/test_policies_api.py`

**Interfaces:**
- Consumes: Task 1 `check_policy`, `schema_errors`, `content_hash`, `INVARIANTS`.
- Produces: `router = APIRouter(prefix="/admin/policies", dependencies=[Depends(sec.require_admin)])`; helper `published(db) -> PolicyVersion` (raises 503 like `assessments.validate`); `next_label(db) -> str` (`v<max N + 1>`); `version_shape(db, pv) -> dict`.
- Draft shape (used by Tasks 3–5): `{"version", "status", "document", "note", "rev", "created_by", "created_at", "stage": "draft"|"validated"|"dry-run", "checks": list|None, "dry_run": {"at", "rows": [...], "changed": int, "resets": int}|None}`. `stage` is `validated` when `validation.hash == content_hash(document)` and no check failed; `dry-run` when additionally `dry_run.hash` matches. `checks`/`dry_run` are returned only when their hash matches the current document, else `None`.
- Routes:
  - `GET ""` → `{"published": version_shape, "draft": draft_shape|None, "invariants": INVARIANTS}`; `version_shape` = `{"version","status","document","note","published_at","published_by","rules":len,"used_by":int}`.
  - `POST /draft` `{}` → 201 draft (copy of published document, `note=""`); 409 `"A draft is already open."`.
  - `PUT /draft` `{"document": dict, "note": str (≤500), "rev": int}` → 200 draft; 409 `"Someone else changed this draft. Reload to see their changes."` on stale rev; 422 with `{"detail": "...", "errors": [...]}` when `schema_errors` is non-empty; bumps `rev`, clears `validation` and `dry_run`.
  - `POST /draft/import` `{"text": str (≤ 262144 chars), "rev": int}` → parses with `json.loads`; non-dict, >500 rules, or schema errors → 422 with `errors` and no change; else same as PUT keeping the current note.
  - `DELETE /draft` → 204; 404 when none.
  - `POST /draft/validate` → stores `{"hash", "checks"}` in `validation`, returns draft.

- [ ] **Step 1: Write failing tests** in `backend/tests/test_policies_api.py`. Add fixture `restore_policy` (autouse in this file): after each test, with the owner engine from `conftest.OWNER_URL` or app engine, run `UPDATE assessments SET policy_version='v1' WHERE policy_version <> 'v1'; UPDATE jobs SET policy_version='v1' WHERE policy_version <> 'v1'; DELETE FROM policy_versions WHERE version <> 'v1'; UPDATE policy_versions SET status='published' WHERE version='v1'`. Tests:
  - `test_owner_forbidden_on_every_route` — each route above (and Task 3's) returns 403 for an owner.
  - `test_start_save_discard` — GET shows `draft: None`, `published.version == "v1"`; POST → 201 `version == "v2"`, `stage == "draft"`, document equals published; second POST → 409; PUT with `rev` 0 adding rule `R-03` → 200, `rev == 1`; DELETE → 204; GET → `draft: None`; audit has `draft-start`, `draft-save`, `draft-discard`.
  - `test_stale_rev_conflict` — two PUTs with `rev: 0` → second is 409, document is the first's.
  - `test_save_rejects_schema_errors` — PUT with CIDR `10.0.0/33` → 422, `errors` contains `CIDR must look like 203.0.113.0/24`, draft unchanged.
  - `test_import_rejects_bad_json` — `"{"`, `"[]"`, a 501-rule doc, and `"x" * 262145` → 422 each, draft `rev` unchanged; a valid JSON text → 200 and document replaced.
  - `test_validate_sets_stage_and_edit_clears_it` — validate clean draft → `stage == "validated"`, `checks` non-empty; PUT → `stage == "draft"`, `checks is None`; draft with forbidden CIDR (`127.0.0.0/8`, passes schema) → validate → stage stays `draft`, a check has `result == "fail"`.
  - `test_draft_never_used_for_validation` — start a draft that adds `deny` suffix `example.com`; `POST /api/assessments/{id}/validate` on an owner's `https://app.example.com/` assessment (resolver: monkeypatch `ipguard.resolve` / `socket.getaddrinfo` as `test_assessments.py` does) → `policy_version == "v1"` and outcome not `blocked` by the draft rule.

- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** the routes. Lock the draft row `FOR UPDATE` on every mutation; `rev` check inside the lock. Starting a draft catches the unique-index violation and returns 409.
- [ ] **Step 4: Run** `tests/test_policies_api.py tests/test_admin.py` → PASS.
- [ ] **Step 5: Add** the routes to `docs/API.md` (one line each, the file's existing format).
- [ ] **Step 6: Commit** `feat(policy): draft lifecycle API`.

---

### Task 3: Dry run, publish with reset, versions, rollback

**Files:**
- Modify: `backend/app/api/policies.py`, `backend/app/api/assessments.py` (validate race guard), `backend/app/api/jobs.py` (`apply_cancel` gains `commit: bool = True`)
- Test: `backend/tests/test_policies_api.py` (append)

**Interfaces:**
- Consumes: Task 1 `evaluate_outcome`, `RANK`; Task 2 router, `published`, `next_label`, `version_shape`, draft shape.
- Produces:
  - `outcomes(db, published_doc, draft_doc, app_env) -> list[dict]` rows `{"assessment": display_id, "name", "target", "env", "owner": name, "stored": str, "published": str, "draft": str, "changed": bool, "reset": bool}` for every assessment with `validation IS NOT NULL`; `changed = published != draft`; `reset = draft in RANK and RANK[draft] > RANK[stored]` where `stored = validation["outcome"]`. DNS via `ipguard.resolve(host, timeout=3)` in a `ThreadPoolExecutor(max_workers=8)`, one lookup per distinct host; OSError → `None`.
  - `apply_publish(db, new_doc, label, actor, note) -> dict` — shared by publish and rollback; returns `{"version", "changed", "reset", "jobs_cancelled"}`.
  - `POST /draft/dry-run` → 409 `"Validate the draft first."` unless stage ≥ validated; stores `{"hash","at","rows","changed","resets"}`; returns draft.
  - `POST /draft/publish` `{"rev": int}` → 409 `"Run a dry run of the current draft first."` unless stage `dry-run`; returns publish result.
  - `GET /versions` → list of `version_shape` without `document`, newest first, drafts excluded. `GET /versions/{v}` → `version_shape` with `document`; 404 for unknown or draft.
  - `POST /versions/{v}/rollback` `{"reason": str}` (blank → 422) → 409 `"Discard or publish the open draft first."` if a draft exists; 409 `"This version is already in force."` for the published one; else new label with `note = f"Rollback to {v}: {reason}"`, via `apply_publish`.

`apply_publish` algorithm (one transaction):
1. Lock the current published row `FOR UPDATE` (and the draft row when publishing a draft).
2. Lock all assessments with `validation IS NOT NULL` `FOR UPDATE`, compute `outcomes(...)` against them.
3. Old published → `superseded`; new row → `published`, `published_at = now()`, `published_by = actor`, `note`.
4. For each `reset` row: set `validation = approval = policy_version = NULL`, `status = 'draft'`, `updated_at = now()`; lock its `queued` jobs and `apply_cancel(db, j, actor, ". Reason: target policy " + label + " made this target stricter", commit=False)`; `record(... "validation", "policy-reset", a.display_id, "success", f"Policy {label}: outcome now {draft}; validate again", label)`.
5. `record(... "policy", "publish"|"rollback", label, "success", f"{changed} targets change, {reset} need re-validation, {n} queued scans cancelled", label)`; commit.

- [ ] **Step 1: Write failing tests** (append). Use `make_assessment` + set `validation` via SQL as `test_admin.pending` does; monkeypatch `app.targets.ipguard.resolve` (as imported in `policies.py`) to return `["93.184.216.34"]`, or raise `OSError` for host `gone.example.com`.
  - `test_dry_run_requires_validation_and_lists_changes` — dry run on unvalidated draft → 409; add rule `deny` domain `app.example.com`, validate, dry run → row for the assessment with `published == "approval"` (v1 no-match) and `draft == "blocked"`, `changed` true; a `gone.example.com` assessment shows `draft == "unresolved"`, `reset` false; no HTTP: monkeypatch `httpx.Client.send` to raise and assert the dry run still succeeds.
  - `test_publish_requires_current_dry_run` — dry run, then PUT an edit → publish 409.
  - `test_publish_resets_stricter_and_cancels_queued_only` — assessment A stored `allowed` status `active` with one `queued` and one `running` job; draft denies its host; publish → A `status == "draft"`, `validation is None`; queued job `cancelled`; running job still `running`; v1 `superseded`, v2 `published` with `published_at` set; result `reset == 1`, `jobs_cancelled == 1`; audit has `publish` and `policy-reset`.
  - `test_publish_keeps_approved_when_not_stricter` — assessment stored `approval`, status `active` (approved); draft unchanged rules except an unrelated rule → after publish status still `active`.
  - `test_looser_outcome_untouched` — stored `approval`; draft allows its host → not reset, row `changed` true.
  - `test_versions_and_rollback` — after a publish: `GET /versions` lists v2 published, v1 superseded with `used_by` counts; rollback v2 → 409; rollback v1 with blank reason → 422; with an open draft → 409; after discard, rollback v1 → new `v3` published with v1's document and note `Rollback to v1: <reason>`.
  - `test_validate_racing_publish_is_refused` — call the validate endpoint with `validate_target` monkeypatched to publish a new version (via `apply_publish` in a separate session) before returning → 409 `"The target policy changed while validating. Validate again."`.

- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.** In `assessments.validate`, after the assessment row lock, re-read `pv` with `FOR SHARE` and raise the 409 above if `pv.status != "published"`. `apply_cancel(..., commit=True)` keeps current behaviour for existing callers.
- [ ] **Step 4: Run** the full backend suite → PASS.
- [ ] **Step 5: Add** routes to `docs/API.md`; one paragraph "Target policy lifecycle" to `docs/ARCHITECTURE.md` (draft → validate → dry run → publish; stricter-outcome reset; drafts never used for validation).
- [ ] **Step 6: Commit** `feat(policy): dry run, publish with stricter-outcome reset, versions and rollback`.

---

### Task 4: Target Policies page

**Files:**
- Create: `frontend/src/pages/admin/Policies.tsx`, `frontend/src/pages/admin/policyTypes.ts`
- Modify: `frontend/src/App.tsx` (route `admin/policies`), `frontend/src/pages/Shell.tsx` (nav item after Profiles & Modules: `Target Policies` icon `shield`; CRUMBS `/admin/policies`), `frontend/src/styles/app.css` (only if a needed class is missing)
- Test: `frontend/src/test/policies.test.tsx`

**Interfaces:**
- Consumes: Task 2/3 routes and shapes.
- Produces (`policyTypes.ts`): `Rule`, `PolicyDoc`, `Check`, `DryRow`, `Draft`, `VersionInfo` mirroring the backend shapes; `stageIndex(d: Draft | null, published: boolean) -> 0|1|2|3` (Draft, Validated, Dry run, Published); `nextRuleId(rules: Rule[]) -> string` (`R-` + max number + 1, two digits minimum).

Layout per §7.20 and the spec's Frontend section, using existing components (`Banner`, `Button`, `Card`, `DataTable`, `Modal`, `ConfirmDialog`, `Select`, `TextField`, `Textarea`, `Checkbox`, `Tabs` for the "Visual rules | Structured config" segment, `TbdMarker` for OD-18, `useLoad`, `useAct` from `./common`). The stepper reuses the stepper markup/class from `components/Scan.tsx`. Copy fixed by the spec:
- No-draft banner: `Published policy {v} is in force. Start a draft to change it; nothing changes until you publish.` Button `Start new draft`.
- Outcome labels: `Allow`, `Needs approval`, `Deny`. Match labels: `Hostname suffix`, `Exact domain`, `IP address`, `CIDR range`, `Environment`. Tags: `Dev only`, `Private allowed`. Checkbox (allow + suffix/domain/ip/cidr only): `Allow private addresses`.
- Next step card buttons: `Validate draft`, `Run dry run`, `Publish {v}`; `Discard draft`.
- Publish ConfirmDialog body: `{changed} targets change outcome. {resets} will need to be validated again and their queued scans cancelled. Running scans continue.` Confirm `Publish {v}`, cancel `Keep draft`.
- Discard ConfirmDialog: `Discard draft {v}? Your changes are lost. The published policy is not affected.` Confirm `Discard draft`, cancel `Keep draft`.
- Structured config button: `Validate & apply to draft`; errors listed under the textarea.
- A 409 on save shows the server message in a danger Banner with a `Reload` button.

- [ ] **Step 1: Write failing tests** (`policies.test.tsx`, reuse the `mockApi` pattern from `admin.test.tsx`):
  - `stageIndex` and `nextRuleId(["R-01","R-09"]) === "R-10"`, `nextRuleId([]) === "R-01"`.
  - No draft → banner text and `Start new draft` posts `POST /admin/policies/draft`.
  - Draft view: adding a rule through the modal sends `PUT /admin/policies/draft` with the new rule and the current `rev`; Move down swaps order in the PUT body.
  - Structured config: server 422 `errors` are shown; nothing else sent.
  - Dry-run rows with `changed` get the highlight class; Publish dialog shows the counts from `dry_run`, confirm sends `POST /admin/policies/draft/publish`.
  - Owner navigating to `/admin/policies` sees the existing denied state (as other admin routes do).
- [ ] **Step 2: Run** `npm test` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx tsc --noEmit && npm test` → PASS.
- [ ] **Step 5: Commit** `feat(policy): Target Policies page`.

---

### Task 5: Policy Versions page and compare

**Files:**
- Create: `frontend/src/pages/admin/PolicyVersions.tsx`
- Modify: `frontend/src/pages/admin/policyTypes.ts` (add `diffPolicies`), `frontend/src/App.tsx` (route `admin/policies/versions`), `frontend/src/pages/Shell.tsx` (nav `Policy Versions` icon `doc`; CRUMBS `/admin/policies/versions`)
- Test: `frontend/src/test/policies.test.tsx` (append)

**Interfaces:**
- Consumes: `GET /admin/policies/versions`, `GET /admin/policies/versions/{v}`, `POST /admin/policies/versions/{v}/rollback`; Task 4 types.
- Produces: `diffPolicies(a: PolicyDoc, b: PolicyDoc) -> { added: Rule[]; removed: Rule[]; changed: { id: string; from: Rule; to: Rule }[]; ports: { added: number[]; removed: number[] }; noMatch: { from: string; to: string } | null }` — rules matched by `id`; a rule is changed when any field differs or its position differs.

Table columns per §7.20: Version, Status (badge: Published / Superseded), Published (IST via existing date helper), Published by, Rules, Note, Used by, action `Roll back to this` (superseded only) → `ReasonConfirm` titled `Roll back to {v}?` with body `This publishes a new version with the rules of {v}. Targets that become stricter must be validated again.` Compare card: two `Select`s (defaults: published and the previous version) → lists Added / Removed / Changed rules, Ports, When no rule matches; `No differences.` when empty. A 409 from rollback shows the server message.

- [ ] **Step 1: Write failing tests:** `diffPolicies` (added, removed, changed value, moved position, ports, no-match); table renders `Roll back to this` only on superseded rows; rollback sends the reason; compare shows an added rule's ID.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `npx tsc --noEmit && npm test` → PASS.
- [ ] **Step 5: Live check:** rebuild `api`, `worker`, `web` (`docker-compose up -d --build api worker web`), run migrations (the `migrate` service runs on up), then exercise through `http://web/api` from inside the api container with a short script in the scratchpad: start draft → add deny rule for `testtarget` → validate → dry run (expect testtarget assessments changed) → discard. Do **not** publish on the dev database. Expected: each call 2xx, discard leaves `v1` published.
- [ ] **Step 6: Commit** `feat(policy): Policy Versions page with compare and rollback`.
