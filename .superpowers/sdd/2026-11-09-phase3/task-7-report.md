# Task 7 report
Status: DONE. Full suite 259 passed (8 new in test_modules_engine.py, 1 new + 1 updated in test_egress.py).

Added crawl.py, dast.py, api.py (registered in modules/__init__.py). Contract for Task 8:
- run_ctx.sessions = {credential display id: Cookie header value} (written by the login step); run_ctx.pages {id|None: set(urls)};
  run_ctx.requests {id|None: [(METHOD, url, form dict)]} (non-GET, from ZAP message history per account). run_ctx also now carries
  profile and notes (set in run_job). Helpers crawl.accounts/context/as_account are reusable (one ZAP context per account, Cookie via replacer, cleared in finally).
- crawl: per-account spider, detail "{n} pages found[; {k} links to other hosts not tested]", untested=k (other-host links from results and spider fullResults); spider hitting its deadline -> completed-warnings.
- dast: pa-safe (pre) / pa-deep (deep) per account; alerts deduped by ZAP alert id (shared run_ctx.seen_alerts), drafts carry credential_id (display id) and a per-credential fingerprint; deadline -> completed-warnings "Stopped at the time limit; {u} URLs not tested", untested=u (pages share not scanned plus unreached accounts).
- api: deep only (else skipped); `openapi: <url>` in notes if in scope (host and permitted port), else /openapi.json, /swagger.json, /v3/api-docs; none importable -> skipped "No API description found"; out-of-scope explicit URL is ignored, defaults tried.
- Supporting: Zap.spider now returns (urls, out_of_scope, pct); Zap.messages/message_count added; FindingDraft.credential_id, store_findings maps display id to findings.credential_id.
- Egress: every refusal logged INFO `refused host= port= reason=` (host sanitized, no path/query/headers; __main__ now configures INFO logging); GET /stats adds recent_refused (last 20, reset on new scope).

Live run (real ZAP, http://testtarget/, 2 workers, EngineSession + crawl + dast pre):
crawl completed "3 pages found" untested 0; pages [/, /robots.txt, /sitemap.xml]; requests {None: []}
dast completed "Active tests finished; 20 issues reported"
stats {"job_id":"JOB-LIVE7","connections":69,"refused":2,"recent_refused":[{"host":"tel.zaproxy.org","port":443,"reason":"host out of scope"},{"host":"cfu.zaproxy.org","port":443,"reason":"host out of scope"}]}
No refusal has host=testtarget port=80 (the two are ZAP's own telemetry/update calls).

Concerns: per-account fullResults/messages/credential flows verified only against the fake ZAP (live had no accounts, no POST forms); alert attribution is by first scan to see it (ZAP's alert store is shared).

## Fix round 1
Suite: 265 passed (6 new in test_modules_engine.py).
1. Alert attribution: crawl and dast call harvest(ctx, cred) after each account's spider/scan; each ZAP alert belongs to the account active when it first appeared (run_ctx.alerts); dast/api emit drafts once (seen_alerts). Test: passive alert raised while crawling C-0001 is tagged C-0001, not anonymous.
2. Tests: second account's spider raising EngineDown / EngineError -> no addRule before the anonymous spider, clear_headers is the last replacer call.
3. EngineError.code carries ZAP's error code. api treats only bad_external_data / url_not_found / no_implementor as "not a spec" (live ZAP answers bad_external_data for a 404 and for HTML); any other EngineError propagates (module failed). Test: internal_error -> raises.
4. run_ctx.requests: drops URLs matching login|logout|sign-?in|auth|otp|password or any run exclusion regex; masks form fields (pass|token|otp|csrf|secret|code) and the same query params as [REDACTED]. Test.
5. emit() masks every cookie value from run_ctx.sessions (>=4 chars) in all alert string fields before alert_to_draft. Test with a cookie-flag alert echoing the session.
6. Zap.new_session (so every wipe) sets spider AcceptCookies=false and core HttpStateEnabled=false; verified live both read back "false". Only the replacer Cookie identifies an account.
7. clear_quiet(): cleanup failure logs a WARNING (no values) and never replaces the original exception. Test.
8. docker-compose zap: `-notel -config start.checkForUpdates=false -config start.checkAddonUpdates=false` (the plan's `start.addonUpdates` key is not a real option: CheckAddonUpdates stayed true; `start.checkAddonUpdates` verified live via autoupdate/view: CheckOnStart false, CheckAddonUpdates false). 
   NOT FULLY RESOLVED: telemetry (tel.zaproxy.org) no longer appears, but a call to cfu.zaproxy.org:443 still shows in recent_refused about 2 min after ZAP starts (thread ZAP-cfu, ExtensionCallHome via ExtensionAutoUpdate, seen during the live active scan; idle and spider-only runs showed none earlier in the same ZAP's life). The guard refuses it ("host out of scope"), so it is harmless but noisy. Live after fix: pages 3, alerts 20, recent_refused only cfu.zaproxy.org:443, none for testtarget:80.
