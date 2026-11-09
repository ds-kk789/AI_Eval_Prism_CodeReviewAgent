"""Retry a function on transient errors with exponential backoff."""
import time
from functools import wraps


def retry(times: int = 3, base_delay: float = 0.5, errors: tuple = (TimeoutError, ConnectionError)):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(times):
                try:
                    return func(*args, **kwargs)
                except errors:
                    if attempt == times - 1:
                        raise
                    time.sleep(base_delay * 2 ** attempt)
        return wrapper
    return decorator
