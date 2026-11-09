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
