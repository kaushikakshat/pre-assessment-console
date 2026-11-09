"""Body similarity for access checks: word-shingle Jaccard on the visible text, ignoring per-request noise."""
import re

SAME = 0.9
_NOISE = [re.compile(p) for p in (r"(?is)<(script|style)\b.*?</\1>", r"<[^>]*>",
                                  r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                                  r"\b[0-9a-f]{8,}\b", r"\b[\w+/=-]{20,}\b", r"\d+")]


def _shingles(b: bytes, k: int = 3) -> set:
    t = b.decode("utf-8", "replace").lower()
    for rx in _NOISE:  # tags first: hidden CSRF inputs live inside tags
        t = rx.sub(" ", t)
    w = t.split()
    return {tuple(w[i:i + k]) for i in range(max(1, len(w) - k + 1))} if w else set()


def same_page(a: bytes, b: bytes) -> float:
    x, y = _shingles(a), _shingles(b)
    if not x and not y:
        return 1.0
    return len(x & y) / len(x | y)
