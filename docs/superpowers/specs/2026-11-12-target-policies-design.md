# Target Policies and Policy Versions — design

Status: draft for approval · 12 Nov 2026 · Builds on `main` (Phase 3 merged). Implements `DESIGN_SYSTEM.md` §7.20 in full (PD-5).

## Why

Today the target policy is one row (`v1`) seeded by migrations. Admins approve targets one at a time but cannot add standing rules ("always allow `*.qcin.org`", "never touch 10.20.0.0/16") without editing the database. On the org server most real portals will sit on internal addresses, so admins need to publish internal-allow rules themselves, safely, with a record of who changed what.

## Goals

- Admin screens **Target Policies** (`/admin/policies`) and **Policy Versions** (`/admin/policies/versions`), both in the admin nav, exactly as §7.20 describes: draft → validate → dry run → publish, visual and JSON editors, safety invariants card, versions table, compare, roll back.
- Publishing never weakens the hard safety rules in `ipguard` (loopback, unspecified, link-local, metadata, multicast, reserved, CGNAT). No policy can override them.
- Every policy action is audited (area `policy`).

## Non-goals

Per-team policies, scheduled publishing, approval of policies by a second admin (PD-5 says no), notifications to owners beyond the audit log and the assessment's own state.

## Decided by the user

- **On publish, stricter outcomes reset.** An assessment whose outcome gets stricter under the new version (Allowed → Needs approval or Blocked, Needs approval → Blocked) has its validation cleared and must re-validate before its next scan. Looser outcomes are left alone; the owner may re-validate. Running scans are not stopped.
- Full §7.20 scope.

## Data (migration 0013)

`policy_versions` gains: `note text`, `created_by text`, `created_at timestamptz default now()`, `rev int default 0` (optimistic lock for edits), `dry_run jsonb` (last dry run + the content hash it ran on), `validation jsonb` (last check results + content hash). `published_at` becomes nullable and is set only on publish (v1 keeps its value). `status` is one of `draft | published | superseded`. Partial unique indexes: at most one `draft`, at most one `published`.

The policy document (`rules` column) keeps today's shape, so `validate_target` is unchanged:
```
{"rules": [{"id","outcome","match","value","note","internal"?, "dev_only"?}], "permitted_ports": [int], "no_match": "allow|approval|deny"}
```
- `outcome`: allow | approval | deny. `match`: suffix | domain | ip | cidr | env. Rules are evaluated top-down, first match wins, so the editor supports reordering.
- `internal: true` ("Allow private addresses") is offered only on allow rules matching suffix/domain/ip/cidr, mirroring `_internal()`.
- `dev_only` rules (R-01, R-02) are kept and shown with a "Dev only" tag; the UI does not create new ones (JSON can).
- Version labels: `v<N>`, N = highest existing + 1, assigned when a draft is started. A discarded draft row is deleted (nothing references drafts).
- Lookups of the policy in force (`assessments.validate`, `signin.py`) already filter `status = 'published'`; drafts are never used for validation. A test pins this.

## Backend

New router `app/api/policies.py` (admin only, same session/CSRF as other admin routes), logic in `app/targets/policy.py`:

- `check_policy(doc) -> list[{key, label, result: pass|warn|fail, detail}]`, pure, four groups:
  - **Schema:** types, required fields, unique rule IDs, value formats. Messages name the rule, e.g. `rules[2] (R-07): CIDR must look like 203.0.113.0/24`. Suffix/domain go through `ipguard.normalize_host`; env values must be one of `Development, Staging, UAT, Production`.
  - **Conflicts:** the same match+value twice (fail if outcomes differ, warn if same); a rule fully shadowed by an earlier one (warn).
  - **Invariant overrides:** an ip/cidr rule touching a hard-forbidden range → fail ("can never be scanned"); an allow rule on a private ip/cidr without `internal` → warn ("will still be blocked as private"); `no_match: allow` → warn.
  - **Ports:** at least one, each 1–65535, no duplicates.
- `GET /admin/policies` → published version, current draft (or null), safety invariants list.
- `POST /admin/policies/draft` (start, copies the published document; 409 if a draft exists) · `PUT /admin/policies/draft` (whole document + note + `rev`; 409 on stale `rev`; any change clears validation and dry run) · `DELETE /admin/policies/draft` (discard).
- `POST /admin/policies/draft/import` — JSON text from the Structured config tab. Parsed with `json.loads` only; must pass schema checks or nothing is applied (errors returned inline). Never executes anything.
- `POST /admin/policies/draft/validate` → stores and returns check results. Any `fail` blocks the next step.
- `POST /admin/policies/draft/dry-run` → requires a passing validation of the current content. For every assessment that has a validation outcome, recompute the outcome under the published and draft documents using only the pure checks (fresh DNS resolve with a short timeout, addresses, ports, rules, environment). **No HTTP requests to targets.** A DNS failure shows as "Unresolved" and counts as changed. Stores and returns rows: target, env, owner, published outcome, draft outcome, changed.
- `POST /admin/policies/draft/publish` → requires a dry run of the current content. In one transaction (row lock on the draft): recompute outcomes as in the dry run (so assessments validated since the dry run are included), supersede the old version, publish the draft (`published_at = now`, `published_by`), then for each assessment whose outcome got stricter: clear validation/approval/policy_version, set status `draft`, cancel its **queued** (not running) jobs, and write an audit row per assessment. Returns counts: changed, reset, jobs cancelled.
- `GET /admin/policies/versions` → version, status, published, published by, rule count, note, used by (count of assessments whose `policy_version` is that version).
- `GET /admin/policies/versions/{v}` → full document (for compare).
- `POST /admin/policies/versions/{v}/rollback` (reason required) → only from a superseded version, only when no draft is open (409 otherwise). Publishes a **new** version `v<N+1>` with the old document and the note "Rollback to {v}: {reason}", applying the same stricter-outcome reset as publish.

## Frontend

- **Target Policies page:**
  - No draft: info banner "Published policy {v} is in force…" + **Start new draft**, and the published rules read-only.
  - Draft: Stepper (Draft → Validated → Dry run → Published), derived from the draft's stored validation/dry-run hashes. Segmented "Visual rules | Structured config".
  - Visual: rules table (ID, outcome badge, match type, value mono, note, tags Dev only / Private allowed, Move up/down, Edit, Remove), **Add rule** modal with client-side format hints (server is the authority), Permitted ports field, "When no rule matches" select with `TBD · OD-18` marker (default stays Needs approval), change note, Save draft.
  - Structured config: JSON textarea prefilled with the draft, **Validate & apply to draft**, inline errors.
  - Right column: **Safety invariants** card (locked list from §7.20) and **Next step** card: Validate draft → checks list → Run dry run → table with changed rows highlighted → **Publish {v}** ConfirmDialog stating how many targets change and how many will need re-validation. **Discard draft** ConfirmDialog.
- **Policy Versions page:** table per §7.20 with "Roll back to this" on superseded rows (ReasonConfirm), and Compare (two selects → added / removed / changed rules, ports, no-match outcome). The diff is computed client-side from two fetched documents.
- Breadcrumbs and nav entries for both pages.

## Tests that prove it

- `check_policy` table: each schema error message, duplicate/conflict/shadow, forbidden CIDR (127.0.0.0/8, 169.254.169.254/32) fails, private CIDR allow without internal warns, bad ports.
- Draft is never used by `/assessments/{id}/validate` or the sign-in test.
- Single draft (second start → 409); stale `rev` → 409; edit clears validation and dry run.
- Publish without a dry run of current content → 409.
- Publish: an Allowed assessment newly denied is reset to draft and its queued job cancelled; its running job is untouched; a newly-looser one is untouched; audit rows written.
- Rollback creates a new version with the old rules; refused with an open draft or for the published version.
- Import: invalid JSON or schema errors change nothing.
- Owner gets 403 on every policy route.
- Frontend: compare-diff function; stepper state derivation.

## My calls (please check)

1. Queued jobs of reset assessments are cancelled (running ones continue), so a newly denied target is not scanned later from an old decision.
2. Publish recomputes outcomes rather than trusting the stored dry run, so the confirm count can differ slightly from the result; the result toast states the real numbers.
3. The dry run re-resolves DNS but sends no request to any target.
4. Rollback is refused while a draft is open, to keep one change in flight at a time.
5. Both pages ship together on a branch `policies`; your uncommitted QR-code change on `main` will be committed first as its own commit so the branch starts clean.
