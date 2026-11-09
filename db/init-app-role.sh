#!/bin/sh
# Runs once on first db init. Table GRANTs live in the Alembic migration.
set -e
psql -v ON_ERROR_STOP=1 -v pw="$APP_DB_PASSWORD" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE app_user LOGIN PASSWORD :'pw';
SQL
