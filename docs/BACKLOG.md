# Backlog — deferred review findings (Phase 2 slice)

Triaged in the final whole-branch review. Pre-UAT items are already fixed; these remain.

## Before promoting to the org server
- Dockerfile: remove apt lists; pin remaining backend deps (requirements.txt)
- DB CHECK constraints for concurrency_limit (1-3) and non-negative caps
- POSTGRES_PASSWORD placeholder check at startup
- CSV audit export is buffered in memory, not streamed
- TLS terminator in front of nginx (COOKIE_SECURE=true requires it)

## Can wait
- B1: no CHECK concurrency_limit 1..3 / non-negative caps
- B1: schema test checks only U- display id; add A/JOB/F, seq increasing, TRUNCATE denied
- B1: conftest KeyError when TEST_* unset
- B1: requirements.txt unpinned
- B1: Dockerfile apt lists not removed
- B1: api port binds 0.0.0.0 — use 127.0.0.1:8000
- B1: init-app-role.sh only on fresh volume; document
- B1: cli create-admin IntegrityError race
- F1: MFA digit clear truncates following digits
- F1: Shell refetches /dashboard on every route change
- F1: scrim click closes alertdialogs (typed STOP risk); no body scroll lock
- F1: no direct tests for Drawer/Tabs/ProfileCard/Stepper/CapacityMeter; deps pinned only by lockfile
- B2: pa_pending not single-use (#5); SECRET_KEY validated lazily (#8); security headers missing on unhandled 500 (#11); extra auth edge tests (#12)
- B2: temp password never force-changed; no password-change endpoint (OD-11) — surface to user
- B2: reset-mfa does not clear last_totp_step (one spurious 401 possible)
- B2: migration 0003 doesn't lowercase existing rows
- F2: success card focus/live region (#9)
- F2: AssessmentDetail /catalog fetch unguarded (falls back to key)
- B3: /validate no 409 on active job / no row lock; DNS hang pins threadpool; pre-approval redirect GET by spec
- F3: missing tests for lowering copy, priority-only-queued, review POST body, users action reason, worker enable/drain; single Decide button vs Refuse/Approve columns (acceptable)
- F3: All assessments status shows 'Active' for active (DS §5.5 says show latest job state)
- F3: capacity poll in flight can clear override after PUT (self-heals)
- B3: RuntimeError path doesn't close client; per-hop DNS 3s not inside 15s budget
- B4: nmap -6 for IPv6; TLS reports only first verify error; queue N+1; make validate helpers public
- B4: token-only userinfo (https://token@host) not redacted
- B5: CSV formula guard untested; CSV export silently capped at 500; wid int→422 vs 404; invented caps on aging/queue/quota bounds; no test for statement_timeout; scheduled-job cancel 409; resume doesn't check other active job
- Worker: on graceful shutdown (SIGTERM) clear its own heartbeat so a replaced worker stops counting as healthy immediately (today it counts for up to 30s after a restart, so an admin could briefly raise the limit above real capacity)
- Egress scope covers the target host only (the validated host). Links to other in-scope hosts are reported as untested. — deviation recorded during Task 6
- Phase 3: credential key rotation (today a new keypair makes saved test accounts unreadable; owners must re-enter them)
- Phase 3: the ZAP AJAX spider is not enabled (memory: it needs a headless browser beyond the 1.6 GB cap); single-page apps are crawled by the classic spider only

## Phase 3 deferred items (from per-task and final reviews)
- T1: dead MAX_HEAD check; control token no rate limit (network-isolated in Task 2)
- T1: idle timeout per direction can kill a tunnel during a >120s one-way stream; bare \n header lines forwarded raw; in-flight allowed() can bump new scope counters
- T2: shared 510 MB image across api/egress/migrate (split worker target later); ZAP api key visible on command line; no public/private key pair check; testssl arm64 legacy-protocol coverage
- T2: zap container shows "unhealthy" (image healthcheck targets a different port) — fix healthcheck to 8090 in Task 5
- T3: test_phase3_tables_exist asserts count>=0 (existence only); grants on login_setups/reports untested for DML; no test for reports unique / login_setups cascade
- T4: cookie jar not host/path-scoped; ciphertext AAD lacks field context
- T4: locked-account state lives in audit rows (lost if audit pruned; LIKE query unindexed); per-test bypass_code required for code logins (frontend must ask for it)
- T5: wordlists list length unbounded; credential_ids accepted on quick; missing tests for deleted credential / cancelling counts / deep over cap; seeded rows never pruned
- T12: no tests for admin-hidden tab / 409 locked message
- T13: tests for polling start/stop, admin view, retest payload, blocked state
- T14: missing tests (wordlist PUT failure, toast, Available/OD-13 text); folder icon duplicate; limits fallback unexplained
- T6: _field guards not on import_openapi/clear_headers/_ensure_policy; no-profile TTL fallback 3720s
- T7: non-form bodies parsed as garbage; api untested hard-coded 1; crawl untested ignores unvisited pages
- T7: alerts from a crawl that fails mid-way harvested later under another account
- T8: accounts that failed initial login are excluded for the whole run (no cval retry); B-side session loss looks like denial (false negative)
- T9: malformed vendored eol date → cms failed instead of skipping row
- T10: enqueue lock is global (SchedulerConfig row) — coarse; mixed pre/deep retest runs at deep
- T11: unclaimed report (no worker running) stays generating indefinitely; default docker build target is now `test`
- T15: web nginx caches api address → restart web after api recreate; /login2 recorded POST counted untested (SENSITIVE_PATH misses login2)
- Fix soon after UAT: an account that fails its first login is skipped for the whole run; a session lost on the second account's side looks like a denial (missed finding, not a false one).
- DOM-XSS (ZAP rule 40026) disabled — needs a headless browser and more memory; re-enable on the server.
- Cross-account findings can't be auto-resolved by retest (no owner account recorded).
