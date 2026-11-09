# API contract — Phase 2 slice

Binding contract between `backend/` (FastAPI) and `frontend/` (React). Change it only with a recorded decision.
UI vocabulary, enums and copy come from `DESIGN_SYSTEM.md` §5, §8, §12.

## Conventions
- Base path `/api`. JSON in/out. Timestamps: ISO-8601 UTC strings (`2026-11-09T08:50:00Z`); the UI shows IST.
- Auth: session cookie `pa_session` (HttpOnly, SameSite=Strict, Secure when `COOKIE_SECURE=true`).
- CSRF: double-submit. Server sets readable cookie `pa_csrf`; every non-GET request must send header `X-CSRF-Token` equal to it, else 403.
- Errors: `{"detail": "<plain user-safe sentence>"}`. Never stack traces, hosts, worker names.
  - 401 not signed in · 403 forbidden (role) · **404 for both "does not exist" and "no access" on objects** (no existence oracle; UI shows DeniedState) · 409 conflict · 422 validation (`detail` may be a string or `{"fields": {"name": "message"}}`) · 429 throttled · 503 submissions blocked / service down.
- IDs are strings in display format: `A-0112`, `JOB-001402`, `F-2204`, `v1`, `U-007`.

## Enums (identical to DESIGN_SYSTEM §12)
```
Role            = 'owner' | 'admin'                      (labels: Assessment Owner | Platform Administrator)
Environment     = 'Development' | 'Staging' | 'UAT' | 'Production'
ProfileKey      = 'quick' | 'pre' | 'deep'
ModuleKey       = 'reach'|'ports'|'tls'|'headers'|'exposed'|'finger'|'crawl'|'cms'|'config'|'dast'|'api'|'auth'|'access'|'cval'
JobState        = 'queued'|'validating'|'scheduled'|'running'|'cancelling'|'completed'|'completed-warnings'|'failed'|'cancelled'|'blocked'|'interrupted'
ModuleState     = 'queued'|'running'|'completed'|'completed-warnings'|'skipped'|'blocked'|'failed'|'cancelled'|'unavailable'|'inconclusive'|'interrupted'
FindingState    = 'new'|'open'|'under-review'|'false-positive'|'resolved'|'reopened'|'not-retested'|'accepted-risk'
Severity        = 'critical'|'high'|'medium'|'low'|'info'
Confidence      = 'confirmed'|'suspected'
ValidationOutcome = 'allowed'|'approval'|'blocked'
CheckResult     = 'pass'|'warn'|'fail'|'skip'
Priority        = 'High'|'Normal'|'Low'
AssessmentStatus= 'draft'|'active'|'awaiting-approval'|'blocked'
```
Phase 2 implements modules `reach, ports, tls, headers, exposed, finger` (= Quick Scan). All others are `available: false` and, if ever part of a job, run as `unavailable` ("Not available in this release"). Profiles `pre` and `deep` are `available: false`.

## Shapes
```ts
User        { id, name, email, role: Role, team: string|null, status: 'active'|'deactivated', mfa: 'enrolled'|'pending', last_login_at: string|null, sessions: number }
Me          { id, name, email, role: Role, team: string|null, must_change_password: boolean }
Check       { key: 'url'|'dns'|'addresses'|'redirects'|'ports'|'rules'|'environment', label: string, result: CheckResult, detail: string }
Validation  { outcome: ValidationOutcome, checks: Check[] /* fixed order above */, normalized_target: string, policy_version: string, decided_at: string }
Assessment  { id, name, owner: {id, name}, target, env: Environment, hosts, paths, ports, exclusions, notes: string|null,
              status: AssessmentStatus, validation: Validation|null, approval: {state:'pending'|'approved'|'refused', note: string|null, by: string|null, at: string|null, self: boolean}|null,
              allow_untrusted_cert: boolean, active_job_id: string|null, created_at, updated_at, access: 'owner'|'admin' }
AssessmentSummary { id, name, target, env, status, validation_outcome: ValidationOutcome|null, last_job: {id, state, submitted_at}|null, open_findings: number, created_at }
ModuleRun   { key: ModuleKey, name: string, state: ModuleState, detail: string|null, started_at: string|null, ended_at: string|null }
Job         { id, seq: number, assessment_id, assessment_name, type: 'scan'|'retest', retest_of: string[]|null /* finding ids */, profile: ProfileKey|null, priority: Priority, state: JobState,
              submitted_at, started_at: string|null, ended_at: string|null, policy_version, requested_by: string,
              note: string|null, resume_of: string|null, review: 'resumed'|'rerun-advised'|'closed'|null,
              modules: ModuleRun[], queue_position: number|null, wait_estimate: {lo_min: number, hi_min: number}|null }
Capacity    { active: number, limit: number, effective_limit: number, queued: number, healthy_workers: number, ceiling: number /* 3 */, blocked_reason: 'emergency'|'paused'|'queue-down'|null }
Location    { url, host, port, path: string|null, param: string|null, method: string|null, component: string|null,
              kind: 'Web page'|'API endpoint'|'File'|'Network service'|'Cookie'|'Response header'|'TLS certificate' }
Finding     { id, assessment_id, job_id, severity: Severity, confidence: Confidence, state: FindingState, module: ModuleKey,
              title, asset: string, first_seen_at, last_seen_at }
FindingDetail = Finding & { location: Location, description, impact, evidence: string /* already redacted */, reproduce, remediation,
              references: string[], policy_version, history: {at, by, text}[], comments: {at, by, text}[] }
AuditEvent  { id /* string */, at, actor: string, area: 'auth'|'users'|'assessment'|'validation'|'job'|'finding'|'capacity'|'worker'|'approval'|'scheduler'|'system'|'cli', action: string,
              object: string, outcome: 'success'|'blocked'|'failure', detail: string, policy_version: string|null }
Worker      { id, name /* admin only */, status: 'healthy'|'heartbeat-lost'|'standby', enabled: boolean, last_seen_at, current_job: string|null }
ModuleInfo  { key: ModuleKey, name, description, available: boolean, profiles: ProfileKey[] }
ProfileInfo { key: ProfileKey, name, description, modules: ModuleKey[], available: boolean, duration: string, impact: 'Low'|'Moderate'|'Higher' }
```

## Auth
| Method & path | Body | Result |
|---|---|---|
| POST `/auth/login` | `{email, password}` | 200 `{next: 'mfa'}` or `{next: 'enrol', secret, otpauth_uri}`; sets short-lived `pa_pending` cookie. 401 "The email or password is incorrect." · 429 "Too many attempts. Wait 5 minutes before trying again." · 403 "This account cannot sign in. Contact your platform administrator." (only after a correct password) |
| POST `/auth/mfa` | `{code}` | 200 `Me`; sets `pa_session` + `pa_csrf`. 401 "That code is not valid. Try again." |
| POST `/auth/logout` | – | 204 |
| GET `/auth/me` | – | `Me` or 401 |
| POST `/auth/password` | `{current_password, new_password}` | 200 `Me`; stores the new password, clears `must_change_password`, signs out the user's other sessions (this one stays). 400 "Your current password is incorrect." (counts toward the login throttle) · 422 `{fields: {new_password}}` "Use at least 12 characters." (12-256) / "Choose a password you have not just used." · 429 as login |
| GET `/auth/csrf` | – | 204, (re)sets `pa_csrf` |

While `must_change_password` is true (admin-created accounts and `create-admin`), every endpoint outside `/auth/*` returns 403 "Change your temporary password to continue."

MFA (TOTP) is required for every role, one prompt per sign-in.

## Owner
| Method & path | Body | Result |
|---|---|---|
| GET `/catalog` | – | `{profiles: ProfileInfo[], modules: ModuleInfo[], limits: {pre, deep: {budget_min, request_cap, rate_per_s}}, advisory_as_of: string, wordlists: {key, category: 'discovery'|'fuzzing', label, lines}[] /* enabled only */}`. `pre`/`deep` and modules `crawl`,`dast`,`api` are `available` only while a healthy worker reports the engine (ZAP and egress guard) up; `cms`,`config`,`auth`,`access`,`cval` are always available. Module lists are in execution order. |
| GET `/dashboard` | – | `{counts: {assessments, open_findings, active_jobs}, active_job: Job|null, recent: AssessmentSummary[], capacity: Capacity}` |
| GET `/assessments` | – | `AssessmentSummary[]` (own only; admins also only their own here) |
| POST `/assessments` | `{name, target, env, hosts, paths, ports, exclusions, notes, allow_untrusted_cert?}` | 201 `Assessment` (status `draft`). 422 with field errors (target errors per DESIGN_SYSTEM §7.2) |
| GET `/assessments/{id}` | – | `Assessment` (owner, or admin read-only) |
| PATCH `/assessments/{id}` | same fields; `allow_untrusted_cert` (owner only; omitted keeps the stored value) lets scans and sign-in tests accept self-signed or internal-CA certificates for test environments. The address is still guarded and the hostname still used for SNI. Changing it is audited as "allow untrusted certificate: on/off" | `Assessment`; clears validation/approval, status → `draft` |
| POST `/assessments/{id}/validate` | – | `Validation`; sets status: allowed→`active`, approval→`awaiting-approval` (approval.state pending), blocked→`blocked` |
| GET `/assessments/{id}/jobs` | – | `Job[]` newest first |
| GET `/assessments/{id}/findings` | – | `Finding[]` sorted severity then confidence |
| GET `/assessments/{id}/activity` | – | `AuditEvent[]` for this assessment (owner, admin) |
| GET `/assessments/{id}/signin` | – | `{setup: {style, login_url, username_field, password_field, code_field, otp_url, otp_field, logged_in_indicator, logged_out_indicator, bypass_code_set, updated_at}|null, accounts: [{id, role_label, username_hint, last_test: 'ok'|'failed'|null, last_tested_at}]}`. Owner only (admins get 404). No secret is ever returned; `username_hint` is the first 2 characters + `•••` (just `•••` for usernames of 4 characters or fewer) |
| PUT `/assessments/{id}/signin` | `{style: 'single'|'two-step', login_url, username_field, password_field, code_field?, otp_url?, otp_field?, logged_in_indicator, logged_out_indicator?, bypass_code?}` | setup (as above). `bypass_code` omitted keeps the stored value, `""` clears it. 422 `{fields}`; URLs outside the in-scope hosts: `login_url`/`otp_url` "The login page must be on an in-scope host." |
| POST `/assessments/{id}/accounts` | `{role_label, username, password, test, authorized, bypass_code?}` | 201 `{id, role_label, username_hint, last_test, last_tested_at, test_result: string|null}`. Max 10 per assessment (409). `test` needs `authorized: true` (422) and a validation outcome of allowed or approved (409), plus saved setup (409); it signs in from the API within 20 s. Limits: 1 test per 30 s and 5 per hour per assessment (429 "Wait before testing sign-in again."); an account that tested as locked refuses further tests until replaced (409); 503 while scanning is paused. The login and OTP URLs must use a permitted port and not be in an excluded path (422). `bypass_code` here is used for that test only and never stored (the API cannot decrypt the saved one). Password and username are sealed with the public key and write-only |
| PUT `/assessments/{id}/accounts/{cid}` | `{role_label?, username, password, test, authorized, bypass_code?}` | same shape; replaces the sealed credentials |
| DELETE `/assessments/{id}/accounts/{cid}` | – | 204; soft delete, encrypted fields blanked |
| GET `/findings/{id}` | – | `FindingDetail` |
| POST `/findings/{id}/state` | `{action: 'acknowledge'|'under-review'|'false-positive'|'accept-risk'|'reopen', reason?}` | `FindingDetail`; transitions + required reasons per DESIGN_SYSTEM §7.6; owner only |
| POST `/findings/{id}/comments` | `{text}` | `FindingDetail`; owner only |
| POST `/jobs` | `{assessment_id, profile: 'quick'|'pre'|'deep'|null, modules: ModuleKey[]|null, authorized: true, idempotency_key: string, wordlists?: string[] /* catalog keys */, credential_ids?: string[] /* this assessment's, not deleted */}` | 202 `Job` (with queue_position/wait_estimate). Same idempotency_key → same job. 422 if `authorized` not true, or no profile/modules · 409 if assessment not `active` · 503 `{detail}` when blocked (paused/emergency) · 429 queue cap / per-user quota reached. `reach` is always included. 422 field errors: `profile` when `pre`/`deep` is chosen while the engine is down; `wordlists` for unknown/disabled lists, fuzzing lists without `deep`, any list without `pre`/`deep`, or `"This selection needs about {n} requests; the limit for this profile is {cap}."`; `credential_ids` for accounts not on this assessment. Production stays Quick only. Jobs using engine modules wait while `engine_slots` are full; Quick Scans behind them still start. |
| GET `/jobs/{id}` | – | `Job` (owner of the assessment, or admin) |
| POST `/jobs/{id}/cancel` | – | `Job`; owner only; queued→cancelled (modules skipped), running→cancelling |
| POST `/assessments/{id}/retest` | `{finding_ids: string[], authorized: true, idempotency_key: string}` | 202 `Job` (`type: 'retest'`, `retest_of`). Owner only (others 404); assessment must be `active` (409). Modules = `reach` + the findings' modules; engine findings add `crawl`; findings found with an account add `auth` and that account (a deleted account is not re-added). 422 `finding_ids` for unknown ids or findings that are `false-positive`/`accepted-risk`; same `authorized`, blocked (503), quota/queue (429), idempotency and Production rules as `POST /jobs`. At job end the worker sets each targeted finding: seen again → stays, or `resolved`→`reopened` ("Still present in JOB-…"); not seen and its modules completed → `resolved` ("Fixed in JOB-…"); module incomplete or account deleted/failed → `not-retested` with a reason. Other findings from the job's modules that were not observed become `not-retested`. Evidence is never changed. The retest inherits the profile (limits, budget) and applicable wordlists of the jobs that last observed the selected findings (422 `wordlists` if the union is over the request cap). 409 "This assessment already has a queued or running scan." while any other job is active; `POST /jobs` returns 409 "A retest is running for this assessment. Wait for it to finish." while a retest is active. Production runs only Quick Scan modules; findings from other modules become `not-retested`. A fixed (`resolved`) finding a retest cannot verify stays resolved and gets a history line. Cancelled or blocked retests leave finding states unchanged. |
| GET `/queue` | – | `{capacity: Capacity, mine: Job[] /* queued+running */, platform: {position: number, mine: boolean, state: JobState, job_id: string|null /* null when not mine */}[], recent: Job[] /* last 10 finished */}` |

## Admin (role `admin`, else 403)
| Method & path | Body | Result |
|---|---|---|
| GET `/admin/overview` | – | `{capacity, workers: Worker[], approvals_pending: number, interrupted_unreviewed: number, running: (Job & {owner: string, target: string})[], recent_audit: AuditEvent[]}` |
| GET `/admin/users` | – | `User[]` |
| POST `/admin/users` | `{name, email, role, team}` | 201 `{user: User, temporary_password: string}` (shown once; MFA enrol on first sign-in). 409 email exists |
| POST `/admin/users/{id}/actions` | `{action: 'change-role'|'deactivate'|'reactivate'|'reset-mfa'|'revoke-sessions', role?, reason}` | `User`. 422 without reason. Cannot deactivate/demote self |
| GET `/admin/approvals` | – | `{assessment: Assessment, requested_at, own: boolean}[]` |
| POST `/admin/approvals/{assessment_id}` | `{decision: 'approve'|'refuse', note}` | `Assessment`. approve → status `active`; refuse → `blocked`. Self-approval allowed, audited with `self-approval` flag. Never overrides safety invariants (a target that is `blocked` by invariant is never in this list) |
| GET `/admin/jobs?filter=active|interrupted|all` | – | `(Job & {owner: string /* owner display name */, target: string})[]` |
| GET `/admin/assessments` | – | `(AssessmentSummary & {owner: {id, name}})[]` — every assessment, for the All assessments tab (opens Administrator view) |
| POST `/admin/jobs/{id}/cancel` | `{reason}` | `Job` |
| POST `/admin/jobs/{id}/priority` | `{priority, reason}` | `Job`; queued only, else 409 |
| POST `/admin/jobs/{id}/review` | `{outcome: 'resume'|'rerun-advised'|'closed', reason}` | `Job`; interrupted only; `resume` creates a new linked job (`resume_of`) with only the unfinished modules |
| GET `/admin/capacity` | – | `{config: {limit, aging_enabled, aging_minutes, queue_cap, per_user_quota, paused, engine_slots: 1–3, profile_limits: {pre, deep: {budget_min, request_cap, rate_per_s}}}, capacity: Capacity, workers: Worker[], history: AuditEvent[]}` |
| GET `/admin/wordlists` | – | `{key, category, label, lines, enabled}[]` |
| PUT `/admin/wordlists` | `{key, enabled, reason}` | the updated wordlist. 422 empty reason · 404 unknown key. Audited (area `capacity`) |
| PUT `/admin/capacity` | `{limit, aging_enabled, aging_minutes, queue_cap, per_user_quota, engine_slots?: 1–3, profile_limits?: {pre?, deep?: {budget_min: 5–600, request_cap: 100–200000, rate_per_s: 1–50}}, reason}` (unnamed profiles keep their limits; changes audited) | same as GET. 422 `"Only {n} healthy worker is available. Enable or provision more workers before raising the limit to {x}."` when limit > healthy workers; limit range 1–3. 422 `"Only one scanning engine is provisioned."` when `engine_slots` > 1 (one ZAP and one egress scope are provisioned) |
| POST `/admin/workers/{id}` | `{action: 'enable'|'drain', reason}` | `Worker[]` |
| GET `/admin/audit?q=&area=&actor=&outcome=` | – | `AuditEvent[]` newest first, capped at 500. Always sends `X-Total-Count` (all matches); `X-Truncated: true` when capped |
| GET `/admin/audit.csv?…` | – | `text/csv`, all matching rows (no cap); the export itself is audited |

## Health
GET `/health` → `{status: 'ok'}` (unauthenticated, no details).
