# Internal Web & API Security Pre-Assessment Platform

Quick start (Docker only):

```
cp .env.example .env            # then set real secrets
docker-compose --profile dev up -d --build --scale worker=2
docker-compose exec api python -m app.cli create-admin --email you@example.com --name "You"
```

Open http://localhost:8080 (the API is reached through it at http://localhost:8080/api; port 8000 is not published) and sign in with the printed temporary password; you enrol MFA on first sign-in.
Backend tests: `docker-compose --profile test run --rm test`.
See `docs/ARCHITECTURE.md` and `docs/API.md`.

## Promoting to the org server

- Put a TLS terminator in front of the `web` service; set `COOKIE_SECURE=true` (without TLS, browsers drop the cookies and sign-in breaks) and `APP_ENV=prod`.
- Start without the `dev` profile (`docker-compose up -d --build --scale worker=2`) so the intentionally weak `testtarget` is not run.
- Use strong secrets: `SECRET_KEY` (32+ chars), `POSTGRES_PASSWORD`, `APP_DB_PASSWORD`. The api and worker refuse to start on `change-me` placeholders.
- `db/init-app-role.sh` only runs on a fresh pgdata volume. `docker-compose down -v` resets a stale dev volume; never do that on the server.
