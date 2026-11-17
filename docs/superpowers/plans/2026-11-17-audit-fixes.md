# Audit fixes (items 1, 2, 3, 6, 8 + policy DNS bug)

Branch `audit-fixes`. Each task: failing test first, then the fix, then the full backend suite green
(`DOCKER_CONFIG=<scratch dockercfg> docker-compose --profile test run --build --rm test`). Smallest change that fully works;
reuse existing helpers. No new dependencies.

## Task 1 — Exclusions honoured by every module; failed fetches never count as clean (audit #1, #3)

**#1 Exclusions.** Today `run_ctx["exclude"]` holds only login URLs until the ZAP session starts
(`backend/app/worker/main.py` ~228), and `exposed` and `wordlists.discover` never check it.
- Build the run's exclusion list once at job start from `stages.excluded_regexes(assessment, login_urls)`
  (`backend/app/engine/stages.py:53`) and keep it in `run_ctx["exclude"]` for the whole job.
- Every module that requests a path it chose itself (at least `exposed`, `wordlists.discover`, `config`, `cms`; grep
  every caller of `ctx.get(` and the access/api modules) skips URLs where `access.excluded(rc, url)` is true. A skipped
  URL is neither a finding nor a failure. One central check (e.g. in `Ctx.get`) is preferred over per-module copies if
  it keeps module behaviour readable.
- `Assessment.paths` ("in-scope paths") stays as it is (out of scope for this task).
- Test: an assessment with exclusion `/.env` (and one with `/admin/*`) — the exposed-files module makes no request to
  the excluded URL and reports no finding for it; wordlist discovery skips an excluded path.

**#3 Failed fetches.** `config.py` (~69) and `cms.py` (~71) `except FAILS: continue` silently and still end
"completed"; `tls.py` (~89) treats any `OSError` (timeout) as "refused".
- Count failed fetches; when any happened, end the module in the same "completed with warnings" state the `exposed`
  module already uses (read how it does it and match), with the count in the detail, so retests do not mark findings
  fixed. Check `reconcile`/retest logic in `worker/main.py` treats that state as "not proven fixed" (as it does for
  `exposed`).
- `tls.py`: only a real TLS handshake refusal (`ssl.SSLError`) means "refused"; a timeout / connection error is a
  failed probe (counted as above, never "refused").
- Tests: a config check whose fetch raises a connection error ends with warnings, not plain completed; a TLS 1.0 probe
  that times out is not reported as refused.

## Task 2 — ZAP waits stop on cancel / lost lease; redact locations, references and every .env line (audit #2, #6)

**#2.** `ZapClient._wait` (`backend/app/engine/zap.py:100`) only checks its deadline.
- Add a `should_stop` callable (default never) to `_wait` and thread it through `spider`/ajax/active-scan callers.
  When it returns true: call the component's stop action (as the deadline path does) and return the partial percent.
- The worker passes `halt.is_set` OR "job cancel requested" (reuse the existing `_gate`/cancel query in
  `worker/main.py` ~183, not a new query style; poll it at most every few seconds). After a stop because of cancel,
  the job ends as cancelled the same way it does between modules today.
- Tests: `_wait` with a fake ZAP that never reaches 100% and `should_stop` returning true on the second poll → the stop
  action is called and the partial percent returned well before the deadline.

**#6.** `store_findings` (`worker/main.py` ~82-96) redacts text fields and evidence, but `location` values and
`references` are stored raw; `exposed.py` (~49) masks only `[A-Z_]+=` lines in `.env` evidence.
- Apply the existing `redact` to every string value in `location` and to each reference.
- `.env` evidence: mask the value of every `key=value` line, any key case/characters (`(?m)^([\w.-]+)\s*=.*$`).
- Tests: a finding whose location url is `https://t/cb?token=abc123` is stored without `abc123`; `.env` evidence
  `stripe=sk_live_x` is stored as `stripe=[REDACTED]`.

## Task 3 — Test sign-in only to the validated target host; policy outcome exact without DNS when it can be (audit #8, DNS bug)

**#8.** `backend/app/api/signin.py` (~56-91) accepts a login page on any host in `assessment.hosts` and resolves every
listed host serially.
- The login page (and any OTP/step URL it posts to) must be on the assessment's validated target host (same host as
  `parse_target(assessment.target)`; scheme/port as today). Anything else → the existing 422-style error with a clear
  message ("The sign-in page must be on the target host").
- Resolve only that host. Apply the same host rule wherever the worker performs the saved sign-in (find the shared code
  in `targets/login.py`; enforce once in shared code if both paths use it).
- Tests: login URL on another listed host → rejected and no request/DNS lookup is made for it; login URL on the target
  host → accepted.

**DNS bug.** `evaluate_outcome` (`backend/app/targets/policy.py:170`) returns "unresolved" whenever DNS failed, so a
stricter domain/suffix/env rule never resets an allowed target at publish.
- Ruling: with no addresses, the outcome is exact when no `ip`/`cidr` rule (that is active for this `app_env`) appears
  before the matched rule — or, with no match, when the policy has no active `ip`/`cidr` rule at all. Return the real
  outcome then ("allowed"/"approval"/"blocked"). Only otherwise return "unresolved" (unchanged behaviour).
- Tests: allowed target, DNS failing, draft adds `approval` domain rule for its host → publish resets it; a draft whose
  first rule is a CIDR rule above the domain rule → still "unresolved", not reset.
