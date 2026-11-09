import os

from alembic import context
from sqlalchemy import create_engine

# Migrations run as the owner role, never app_user.
engine = create_engine(os.environ["MIGRATION_DATABASE_URL"])
with engine.connect() as conn:
    context.configure(connection=conn)
    with context.begin_transaction():
        context.run_migrations()
