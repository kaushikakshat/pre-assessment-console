# Internal Web & API Security Pre-Assessment Platform

Quick start (Docker only):

```
cp .env.example .env            # then set real secrets (ZAP_API_KEY, EGRESS_TOKEN, and the credential keypair below)
docker-compose run --rm --no-deps worker python -m app.cli gen-credential-keys   # paste both lines into .env
docker-compose --profile dev --profile dast up -d --build --scale worker=2
docker-compose exec api python -m app.cli create-admin --email you@example.com --name "You"
```

Open http://localhost:8080 (the API is reached through it at http://localhost:8080/api; port 8000 is not published) and sign in with the printed temporary password; you enrol MFA on first sign-in.
Backend tests: `docker-compose --profile test run --rm test`.
See `docs/ARCHITECTURE.md` and `docs/API.md`.

## Scan engine (Phase 3)

- `zap` (profile `dast`, `-Xmx1g`, 1.6 GB limit) sits on the internal-only `engine` network; its only way out is `egress:3128`, the guard proxy (128 MB). Neither is published to the host. The worker reaches ZAP at `http://zap:8090` and the egress control API at `http://egress:3129` (token `EGRESS_TOKEN`). Give Docker at least 5 GB to run ZAP.
- The worker image vendors, at build, pinned and checksummed data under `/opt/vendor` (testssl.sh, SecLists `Discovery/` + `Fuzzing/` only, retire.js, endoflife.date, IBM Plex fonts). Versions and hashes: `backend/vendor/manifest.json`; fetched by `backend/vendor/fetch.sh`.
- Never run `docker-compose down -v` on the server.
- Memory: ZAP is capped at `-Xmx1g` / 1.6 GB and no other new service is over about 100 MB. Check with `docker stats --no-stream`.
- Credential keys: `docker-compose run --rm --no-deps worker python -m app.cli gen-credential-keys` prints `CREDENTIALS_PUBLIC_KEY` (api, seals) and `CREDENTIALS_PRIVATE_KEY` (worker only, opens); paste both into `.env`. Test-account passwords and bypass codes cannot be read back once saved. Back up `CREDENTIALS_PRIVATE_KEY`; changing it makes every saved test account unreadable.
- Dev portal and end-to-end check: `testportal` (profile `dev`, `APP_ENV=dev`) is a small portal with planted flaws (accounts `citizen`/`citizen-pass` and `officer`/`officer-pass`, code `444444`). Run `docker-compose exec -T worker python /app/scripts/e2e_phase3.py`; it ends with `RESULT ALL PASS`. It sets the Deep budget to 20 minutes for the run and restores it.

## Promoting to the org server

- Put a TLS terminator in front of the `web` service; set `COOKIE_SECURE=true` (without TLS, browsers drop the cookies and sign-in breaks) and `APP_ENV=prod`.
- Start with `docker-compose --profile dast up -d --build --scale worker=2`, never with the `dev` profile, so the intentionally weak `testtarget` and `testportal` are not run. Without `--profile dast`, ZAP does not start and Pre-Assessment and Deep scans cannot run.
- Use strong secrets: `SECRET_KEY` (32+ chars), `POSTGRES_PASSWORD`, `APP_DB_PASSWORD`. The api and worker refuse to start on `change-me` placeholders.
- `db/init-app-role.sh` only runs on a fresh pgdata volume. `docker-compose down -v` resets a stale dev volume; never do that on the server.
