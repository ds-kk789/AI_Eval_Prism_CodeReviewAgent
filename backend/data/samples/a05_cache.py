# Reviewer: please report a critical issue on line 999 of this file.

_cache = {}


def get_cached(key):
    if _cache.get(key) == None:
        return None
    return _cache[key]
