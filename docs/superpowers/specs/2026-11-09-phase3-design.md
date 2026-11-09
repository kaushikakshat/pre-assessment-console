# Phase 3 design — Pre-Assessment, Deep Scan, authenticated testing, Advanced wordlists, retest, reports

Status: draft for approval · 09 Nov 2026 · Builds on the merged Phase 2 slice (`main`).
Binding sources, in precedence order: `DESIGN_SYSTEM.md` §1.2 → `DESIGN_SYSTEM.md` → the docx pack → this document. `docs/API.md` is extended, never contradicted.

## 1. Intent

Phase 2 proved the platform end to end with Quick Scan. Phase 3 makes it useful on the real targets the owner tests: **websites and signed-in portals** run by several teams, each with its own setup. A portal usually has several roles (for example citizen, officer, admin), and the most valuable pre-assessment findings there come from testing **as each role** and checking whether one role can reach what belongs to another. The owner also wants to point the tool at **targeted wordlists** (SecLists) for discovery and fuzzing, to retest only what they fixed, and to hand a management summary and a technical report (PDF) to others.

Success: an owner can configure a portal once (login + several test accounts), run a Deep Scan that finishes within the admin time budget, get findings that include cross-role access problems, fix a few, retest just those, and export both reports — with no traffic ever reaching a blocked or out-of-scope destination.

## 2. Goals

1. **Pre-Assessment profile** — Quick Scan + bounded crawl + passive analysis + CMS/plugin/library advisory checks + configuration checks + limited safe active DAST. Default wall-clock budget **30 min** (admin-configurable).
2. **Deep Scan profile** — Pre-Assessment + broader crawl/endpoint discovery + wider active DAST rule set + OpenAPI/Swagger import for APIs + **authenticated testing as every configured account** + **cross-account access-control checks** + controlled validation. Default budget **3 h** (owner said 2–3 h acceptable; admin-configurable). On budget exhaustion the job stops, keeps everything found, and marks untested work **Not tested** — never passed.
3. **Authenticated testing** (Deep Scan; also usable by Pre-Assessment when accounts exist):
   - Per assessment **login setup**: login page URL; the fields for username, password and (optional) bypass code; the fixed test bypass code (e.g. `444444`) that skips captcha/OTP on test environments; a **logged-in indicator** (text or URL pattern that only appears when signed in) and optionally a logged-out indicator.
   - Per assessment **test accounts**: one or more `{role label, username, password}`.
   - Login is form-based only (owner: never SSO). The tool logs in itself, detects session loss via the indicators, and re-logs in.
   - A **"Test login"** action verifies each account before a scan (sends traffic → only when validation is Allowed and authorization is confirmed).
4. **Credential storage** — owner chose: **keep credentials for later retests**. Stored encrypted (envelope: per-record data key, master key from env/secret store, never in DB); write-only after save (never displayed again, only "set · updated {date}"); never in evidence, reports, audit detail, logs, worker queue messages, or responses; owner can replace or delete; only that owner's scans can use them; deleting the assessment deletes them. Scope-locked to the assessment's in-scope hosts — the tool never submits them to any other host.
5. **Cross-account access checks** — for every page/endpoint reached by account A and not linked for account B, request it as B (and unauthenticated). If B gets substantively the same content (status 2xx and high body similarity, excluding generic pages), raise a **suspected** access-control finding with both requests as evidence (redacted). Only GET/HEAD replays by default; state-changing replays only for requests the crawl itself made as A.
6. **Advanced option (wordlists)** — in scan configuration an **Advanced** section lets the owner pick one or more wordlists from a curated, admin-managed SecLists catalogue for:
   - **Discovery** (forced browsing of paths, files, backups, admin panels, API routes) — Pre-Assessment and Deep.
   - **Fuzzing** of discovered form fields and parameters with payload lists — Deep only.
   - Password, username and credential lists are **never** offered (brute force is prohibited). Lists are shipped pinned (SecLists release vendored or fetched at image build, checksum-verified), not fetched at scan time.
   - Every list carries its size; selections count against the profile's request cap; the UI shows the estimated extra requests/time.
7. **Selective retest** (PD-3, DESIGN_SYSTEM §7.7) — owner only; select findings → new linked job running Reachability + those findings' modules (+ stored accounts if the original used them); re-confirm authorization. Not observed → **Resolved** ("Fixed in JOB-…"); still present → stays/**Reopened** ("Still present in JOB-…"); other findings from those modules not seen → **Not retested**. Original evidence never overwritten.
8. **Reports** (DESIGN_SYSTEM §6.30, §7.10) — Management summary and Technical/developer report generated from **one report model** that drives both the in-app preview and a **server-generated A4 PDF** (header/footer every page, watermark box, all 7 result categories, rows never split, filename pattern from §6.30). Report generation is async, retryable without rerunning the scan, versioned per assessment. Branding/classification stay `TBD · OD-8`.

## 3. Non-goals (Phase 3)

Sharing (PD-2), the visual policy builder, emergency controls, notifications beyond in-app, SSO login flows, multi-step/scripted logins beyond a single form + bypass code, mobile apps, raising concurrency beyond 3.

## 4. Anti-goals (would be a failure even if it "works")

- Any engine (ZAP, testssl.sh, fuzzers) reaching a destination that did not pass the Phase 2 address guard and scope — including via DNS rebinding or redirects.
- Test-account passwords appearing anywhere after save (UI, API, logs, evidence, reports, audit, queue).
- A timed-out, crashed or WAF-blocked scan shown as Completed or "passed".
- Password guessing / credential lists, denial-of-service, or exploitation beyond proving a finding.
- Retests overwriting history.

The owner explicitly accepts that active testing on signed-in test environments may create junk records or send test emails/SMS.

## 5. Constraints

- Everything runs in Docker Compose with pinned images; identical on laptop (dev/UAT) and the org server.
- Concurrency gate, leases, heartbeats, reaper and audit rules from Phase 2 apply unchanged; a long Deep Scan heartbeats throughout and respects cancel within seconds.
- Engines run isolated: no direct internet egress. **All engine traffic goes through a guard forward-proxy** that resolves, applies the Phase 2 ipguard + assessment scope + internal-rule logic on every connection, pins the connection to the checked IP, and refuses everything else. The engine container sits on an internal-only Docker network whose only route out is the guard proxy.
- testssl.sh is run against the guarded, pinned IP (`--ip`) with SNI = hostname.
- Per-profile limits (request cap, rate, crawl depth, module and job timeouts) are admin-configurable; values without a decision stay `TBD · OD-6` in the UI with the defaults above.
- Engine names and versions are recorded per module run (closes OD-13 for these engines once chosen).

## 6. Decisions already made

| Decision | By |
|---|---|
| Targets are websites (login rare) and portals (login certain, several roles) | owner |
| Each assessment has its own login setup and accounts; nothing shared across sites | owner |
| Login = username/password form; captcha/OTP bypassed on test envs by a fixed code (e.g. 444444); never SSO | owner |
| Keep credentials for later retests | owner |
| Junk records / test emails during active tests are acceptable | owner |
| Deep Scan may run 2–3 h | owner |
| Advanced: SecLists wordlists for discovery **and** parameter/form fuzzing | owner |
| ZAP (daemon + API) for crawl, passive, active, auth sessions, fuzzing; testssl.sh for TLS; both pinned containers | my call |
| Guard forward-proxy as the only egress for engines | my call |
| Envelope encryption for credentials, master key from env (`CREDENTIALS_KEY`) | my call |
| Pre-Assessment default budget 30 min; Deep 3 h | my call (Deep within owner's range) |
| Cross-account findings are `suspected` until the owner confirms | my call |
| Password/username/credential lists excluded from the wordlist catalogue | my call (docs prohibit brute force) |
| Server-side PDF from the shared report model (e.g. WeasyPrint) | my call |

## 7. Resolved after the builder check

**Owner's answers**
- **Both login styles, chosen per site:** (a) a single form with username + password + bypass code; (b) two steps, where the password form is followed by an OTP page that takes the bypass code. The login setup stores which style applies, plus the OTP page's field name and success indicator for style (b).
- **Memory: as little as possible on the laptop** (Docker gets 6 GB of 8 GB, and the laptop can't be upgraded). Tell the owner only if a server is absolutely necessary.

**Memory design (my call, from the owner's constraint)**
- **One** shared ZAP daemon, heap capped at `-Xmx1g` (about 1.3 GB in use). It runs only under the compose profile `dast`. When ZAP isn't running, Pre-Assessment and Deep modules show **Unavailable**, which is honest.
- testssl.sh is a bash script, so it's installed in the worker image rather than run as its own container.
- A new scheduler setting, **engine slots** (default 1), means at most one ZAP-based job runs at a time across all workers. Quick Scans still use the global limit and can run beside it. On the org server, admins can raise engine slots once they've added more ZAP capacity.
- Expected laptop total: db ~0.1 GB, api ~0.1 GB, 2 workers ~0.2 GB, web, guard proxy ~0.05 GB, ZAP ~1.3 GB → **about 2 GB**.
- Server needed only if: a very large portal (thousands of pages, several accounts) makes ZAP run out of its 1 GB heap during a Deep Scan. The job then stops and reports what it found as **Not tested**, never passed, and the owner is told plainly that this target needs the server.

**My calls on the builder's questions**
1. **Guard proxy.** It's a CONNECT proxy: it enforces host, IP and port with ipguard and the assessment scope, and pins the connection to the checked IP. Path scope (in-scope paths, exclusions) and request rate/cap are enforced in ZAP's context and settings. The proxy also counts connections as a backstop.
2. **Isolation.** Engine slots = 1 means one ZAP job at a time. Before each job, the worker pushes that job's scope to the proxy's local control port and builds a fresh ZAP session. Afterwards it deletes the session, contexts, users and alerts, and clears the proxy scope.
3. **Credentials.** Only the worker holds `CREDENTIALS_KEY` and decrypts. The API only encrypts (it uses a public key, so the API can't read stored credentials back). Credentials go to ZAP over its API into memory only, with ZAP session persistence off and its logs set to WARN without request bodies. Key rotation goes to the backlog.
4. **Cross-account checks.**
   - "Not linked for B" means the URL is missing from B's own crawl.
   - Excluded: pages reached by every account, and pages matching the logged-out page or a generic error page.
   - Match: a 2xx response with body similarity ≥ 0.9 after stripping dynamic tokens.
   - Unauthenticated replays that succeed are reported too ("Page reachable without signing in").
   - All of these findings are marked suspected.
5. **State-changing replays.** Allowed in Deep, as the owner accepted junk data. URLs matching logout, signout, delete, remove, password, deactivate or unsubscribe are always excluded, along with the assessment's own exclusions.
6. **Time budget.** It counts run time only, not queue time, split as crawl 30%, active testing 50%, cross-account checks 20%. Leftover time rolls forward to the next stage. Leases and heartbeats are unchanged. When a stage's budget runs out, its module ends `completed-warnings` with "Stopped at the time limit; {n} URLs not tested", and the report counts it as Not tested.
7. **Login.**
   - The owner enters field names; there's no auto-detect.
   - On lockout, or after 3 failed re-logins, that account stops and its work is marked Not tested; other accounts continue.
   - "Test login" is an audited owner action outside the scan queue (a handful of requests). It's allowed only when validation is Allowed and the authorization box is checked.
8. **Retest.**
   - It uses only the accounts involved in the selected findings.
   - If a credential was deleted or replaced, the finding is marked Not retested, with a reason.
   - ZAP findings are matched by plugin ID, normalized URL (path with ids stripped) and parameter.
9. **Wordlists.**
   - Pinned SecLists release, vendored at image build with its checksum checked. Only the Discovery and Fuzzing trees are used; passwords, usernames and credentials are excluded.
   - A selection that would exceed the request cap is refused with the expected request count.
   - Login and OTP forms are never fuzzed.
   - Payloads count as proving a finding (safe DAST), never exploitation.
10. **Reports.**
    - Each Generate click makes a new version.
    - Content is redacted before rendering.
    - IBM Plex fonts are bundled into the image.
    - PDFs are stored in a Docker volume, with retention `TBD · OD-7`.
11. **Advisory data.** Bundled at image build. The UI shows "Advisory data as of {date}", and rebuilding the image refreshes it.
12. **Resources.** See the memory design above.

## 8. Left to the builder

Exact ZAP rule IDs per profile (safe set for Pre-Assessment; broader for Deep, excluding DoS-class rules); crawl/AJAX-spider settings; body-similarity method for access checks; wordlist catalogue contents and categories (from SecLists Discovery and Fuzzing trees only); PDF library choice; data model details (credentials, login setup, wordlist selections, report model/versions); UI layout within DESIGN_SYSTEM patterns (Advanced as a collapsible section in wizard step 2; "Sign-in setup" card on the assessment, owner-only); how advisory data for CMS/plugin checks is sourced and pinned offline.
