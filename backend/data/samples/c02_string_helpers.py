"""String helpers for display names and URLs."""
import re

_NON_WORD = re.compile(r"[^a-z0-9]+")


def slugify(text: str) -> str:
    """Lower-case, replace runs of non-alphanumerics with one dash."""
    return _NON_WORD.sub("-", text.lower()).strip("-")


def truncate(text: str, limit: int, suffix: str = "...") -> str:
    """Cut text to at most `limit` characters including the suffix."""
    if limit <= len(suffix):
        raise ValueError("limit must be longer than the suffix")
    if len(text) <= limit:
        return text
    return text[: limit - len(suffix)] + suffix
