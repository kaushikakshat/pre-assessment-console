import os


def validate_env():
    """Refuse to start with a missing, short or placeholder secret (api and worker call this first)."""
    key = os.environ.get("SECRET_KEY", "")
    if len(key) < 32 or "change-me" in key:
        raise SystemExit("SECRET_KEY must be set to a random value of at least 32 characters (not a change-me placeholder).")
    if "change-me" in os.environ.get("DATABASE_URL", ""):
        raise SystemExit("APP_DB_PASSWORD is still a change-me placeholder; set a real password in .env.")
