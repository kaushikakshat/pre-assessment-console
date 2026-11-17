# Architecture

## ADR summary
- **Stack**: Python 3.12 FastAPI + SQLAlchemy 2 (sync, psycopg 3) + Alembic; React 18/TS/Vite SPA behind nginx; Postgres 16; all in Docker Compose.
- **Postgres-only queue**: jobs live in the `jobs` table; workers claim with `SELECT ... FOR UPDATE SKIP LOCKED` ordered by priority/aging then `seq` (a DB sequence, so FIFO is server-assigned). One datastore means transactional state changes, audit and queue together; no broker to secure or run at this scale.
- **Global gate**: the concurrency limit (`scheduler_config.concurrency_limit`, default 1, range 1-3) is enforced atomically in the DB when claiming a job (lease counted under a row lock on the config row). No in-memory counters, so any number of workers/API replicas stay correct.
- **Worker model**: stateless `worker` containers (scalable with `--scale worker=N`) heartbeat into `workers`, hold a lease (`lease_owner`, `lease_expires_at`) per job, and mark expired leases `interrupted` for admin review. Scans run from the `scanner` non-root user with `nmap` available.
- **DB roles**: migrations run as the owner; `api`/`worker` run as `app_user`, which has no UPDATE/DELETE on `audit_events` (append-only).

## Components
| Component | Responsibility |
|---|---|
| `web` | Serves the SPA, proxies `/api` to `api` |
| `api` | Auth (argon2 + TOTP, sessions), role and ownership checks, target validation, assessments/jobs/findings APIs, audit |
| `migrate` | Runs `alembic upgrade head` as the DB owner, then exits; `api` and `worker` start after it |
| `worker` | Claims jobs, runs the profile's modules, writes redacted findings, renders report PDFs (WeasyPrint) to the `reports` volume, heartbeats |
| `zap` | OWASP ZAP daemon (compose profile `dast`, `-Xmx1g`); on internal-only `engine` network, egress only via `egress` |
| `egress` | Guard proxy (`python -m app.egress`): ipguard + scope on every connection; proxy on 3128, control API on 3129 (token-gated; zap can reach it on `engine` but has no token); on `engine` + `outbound` only (not `default`), so api/db/web cannot reach it; no published ports |
| `db` | System of record, queue, audit |
| `testtarget` | Intentionally weak nginx demo target (dev only; compose profile `dev`) |
| `testportal` | Small portal with planted flaws and test accounts, for signed-in and access-control checks (dev only; profile `dev`) |

## Scan profiles
- **Quick**: `reach`, `ports` (nmap, validated IP only), `tls`, `headers`, `exposed`, `finger`. Runs without ZAP.
- **Pre-Assessment** and **Deep**: Quick plus crawling, signed-in testing (`auth`), access control, API, CMS and wordlist checks, and a ZAP scan (`dast`). Each has a time budget, request cap and rate limit in `scheduler_config` (defaults: 30 min / 5,000 requests and 180 min / 50,000, both 10 req/s). These profiles are shown as unavailable, with a reason, while the engine (ZAP + egress) is not healthy; they never produce placeholder results.

## Data model
users, sessions (token hash), login_attempts, assessments, policy_versions (draft / published / superseded), jobs, module_runs, findings (fingerprint dedupes across jobs), workers, scheduler_config (single row), audit_events, login_setups and credentials (test accounts; secrets sealed with the credentials public key), wordlists, reports. Display IDs (`U-001`, `A-0001`, `JOB-000001`, `F-0001`) come from Postgres sequences; integer PKs stay internal.

## Threat model (STRIDE-lite)
| Surface | Main threats | Mitigations |
|---|---|---|
| Browser -> API | Spoofing, CSRF, enumeration, brute force | HttpOnly SameSite=Strict session, double-submit CSRF, mandatory TOTP, login throttling, 404 for no-access objects, generic errors |
| Worker -> target (SSRF) | Scanning unauthorised/internal hosts, metadata services | Validation outcome gate before any traffic; loopback/link-local/metadata never overridable; permitted ports; scope exclusions; re-resolve at scan time |
| Admin console | Privilege abuse, self-approval | Role enforced server-side, reasons required, self-approval flagged in audit, safety invariants never overridable |
| Audit | Tampering, repudiation | Append-only for app role; every state change and export audited; secrets redacted as `[REDACTED]` |

## Rulings
- 404 for missing and no-access objects (no existence oracle).
- MFA (TOTP) mandatory for all roles, one prompt per sign-in.
- When no policy rule matches, the default outcome is "approval required".
- Password reset: an admin creates a temporary password, shown once; resetting MFA forces re-enrolment.
- Dev-only internal-target rule allows `testtarget` when `APP_ENV=dev`; loopback/link-local/metadata never overridable.

## Target policy lifecycle

A policy change moves draft, validate (schema, conflicts, invariants, ports), dry run (every validated assessment re-evaluated under the published and draft documents using DNS only), then publish. Publishing is one transaction: the old version is superseded, and any assessment whose outcome becomes stricter (allowed < approval < blocked) loses its validation and approval, returns to `draft`, and has its queued scans cancelled; running scans and looser outcomes are untouched. Rollback republishes an old document under a new label through the same path. Drafts are never used for validation: `validate` always reads the published version, and refuses to store a result if that version was superseded mid-validation.

## Run locally
See the [README quick start](../README.md#quick-start). Only the UI is published (:8080); the API is reached through it at http://localhost:8080/api. Backend tests use a separate `preassess_test` database.
