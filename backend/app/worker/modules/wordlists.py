"""Vendored SecLists catalog (Discovery/ and Fuzzing/ only) and the request-count estimate."""
import os
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from app.db import SessionLocal
from app.models import Wordlist

ROOT = Path(os.environ.get("SECLISTS_DIR", "/opt/vendor/seclists"))


def seed(db, root: Path = ROOT) -> int:
    """Upsert one row per vendored file; keeps an admin's enabled flag. No tree (dev/test) -> no rows."""
    n = 0
    for p in sorted(root.rglob("*")) if root.is_dir() else []:
        rel = p.relative_to(root)
        if not p.is_file() or rel.parts[0] not in ("Discovery", "Fuzzing"):
            continue
        with p.open("rb") as f:
            lines = sum(1 for _ in f)
        db.execute(insert(Wordlist).values(key=rel.as_posix(), category=rel.parts[0].lower(), label=p.stem, lines=lines)
                   .on_conflict_do_update(index_elements=["key"], set_={"lines": lines, "label": p.stem}))
        n += 1
    db.commit()
    return n


def estimate(keys, forms=10) -> int:
    """Requests a selection needs: discovery lists once, fuzzing lists once per form."""
    with SessionLocal() as db:
        rows = db.scalars(select(Wordlist).where(Wordlist.key.in_(list(keys)))).all()
    return sum(w.lines * (forms if w.category == "fuzzing" else 1) for w in rows)
