"""Vendored SecLists catalog (Discovery/ and Fuzzing/ only) and the request-count estimate."""
import os
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert

from app.models import Wordlist

ROOT = Path(os.environ.get("SECLISTS_DIR", "/opt/vendor/seclists"))


def seed(db, root: Path = ROOT) -> int:
    """Upsert one row per vendored file; keeps an admin's enabled flag. No tree (dev/test) -> no rows."""
    files = [p for p in sorted(root.rglob("*")) if root.is_dir() and p.is_file()
             and p.relative_to(root).parts[0] in ("Discovery", "Fuzzing")]
    # shortcut: the tree is immutable per image, so a matching row count means already seeded (no line counting
    # at startup); a changed SecLists commit changes the file set. Upgrade to a stored commit marker if that stops holding.
    if len(files) == db.scalar(select(func.count()).select_from(Wordlist).where(Wordlist.key.in_(
            [p.relative_to(root).as_posix() for p in files]))) and db.scalar(select(func.count()).select_from(Wordlist)) == len(files):
        return 0
    n = 0
    for p in files:
        rel = p.relative_to(root)
        with p.open("rb") as f:
            lines = sum(1 for _ in f)
        db.execute(insert(Wordlist).values(key=rel.as_posix(), category=rel.parts[0].lower(), label=p.stem, lines=lines)
                   .on_conflict_do_update(index_elements=["key"], set_={"lines": lines, "label": p.stem}))
        n += 1
    db.commit()
    return n


def estimate(db, keys, forms=10) -> int:
    """Requests a selection needs: discovery lists once, fuzzing lists once per form."""
    rows = db.scalars(select(Wordlist).where(Wordlist.key.in_(list(keys)))).all()
    return sum(w.lines * (forms if w.category == "fuzzing" else 1) for w in rows)
