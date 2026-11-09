# Internal Web & API Security Pre-Assessment Platform

Quick start (Docker only):

```
cp .env.example .env            # then set real secrets
docker compose up --build --scale worker=2
docker compose exec api python -m app.cli create-admin --email you@example.com --name "You"
```

Open http://localhost:8080 and sign in with the printed temporary password; you enrol MFA on first sign-in.
Backend tests: `docker compose up -d db && docker compose run --rm api pytest`.
See `docs/ARCHITECTURE.md` and `docs/API.md`.
