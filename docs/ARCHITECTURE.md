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
| `api` | Auth (argon2 + TOTP, sessions), permFor/can authorization, target validation, assessments/jobs/findings APIs, audit |
| `worker` | Claims jobs, runs modules, writes redacted findings, heartbeats (stub until task B4) |
| `zap` | OWASP ZAP daemon (compose profile `dast`, `-Xmx1g`); on internal-only `engine` network, egress only via `egress` |
| `egress` | Guard proxy (`python -m app.egress`): ipguard + scope on every connection; proxy on 3128, control API on 3129 (token-gated; zap can reach it on `engine` but has no token); on `engine` + `outbound` only (not `default`), so api/db/web cannot reach it; no published ports |
| `db` | System of record, queue, audit |
| `testtarget` | Intentionally weak nginx demo target (dev only; compose profile `dev`) |

## Data model
users, sessions (token hash), login_attempts, assessments, policy_versions, jobs, module_runs, findings (fingerprint dedupes across jobs), workers, scheduler_config (single row), audit_events. Display IDs (`U-001`, `A-0001`, `JOB-000001`, `F-0001`) come from Postgres sequences; integer PKs stay internal.

## Threat model (STRIDE-lite)
| Surface | Main threats | Mitigations |
|---|---|---|
| Browser -> API | Spoofing, CSRF, enumeration, brute force | HttpOnly SameSite=Strict session, double-submit CSRF, mandatory TOTP, login throttling, 404 for no-access objects, generic errors |
| Worker -> target (SSRF) | Scanning unauthorised/internal hosts, metadata services | Validation outcome gate before any traffic; loopback/link-local/metadata never overridable; permitted ports; scope exclusions; re-resolve at scan time |
| Admin console | Privilege abuse, self-approval | Role enforced server-side, reasons required, self-approval flagged in audit, safety invariants never overridable |
| Audit | Tampering, repudiation | Append-only for app role; every state change and export audited; secrets redacted as `[REDACTED]` |

## Rulings
- Plan tasks regrouped into backend B1-B5 (sequential) and frontend F1-F3 (parallel, frontend/ only).
- 404 for missing and no-access objects (no existence oracle).
- MFA (TOTP) mandatory for all roles, one prompt per sign-in (OD-5 open).
- OD-18: "no rule matches" defaults to approval required.
- OD-11: password reset = admin creates temp password shown once; reset-mfa forces re-enrol.
- `pre`/`deep` profiles and non-Quick modules are `available: false` with a reason; no placeholder results.
- Dev-only internal-target rule allows `testtarget` when `APP_ENV=dev`; loopback/link-local/metadata never overridable.

## Run locally
Set `ZAP_API_KEY`, `EGRESS_TOKEN` and the credential keypair (`python -m app.cli gen-credential-keys`) in `.env`; add `--profile dast` to start ZAP. `cp .env.example .env`, `docker-compose --profile dev up -d --build --scale worker=2`, then `docker-compose exec api python -m app.cli create-admin --email ... --name ...`. Only the UI is published (:8080); the API is reached through it at http://localhost:8080/api. Tests: `docker-compose --profile test run --rm test` (uses a separate `preassess_test` database).
