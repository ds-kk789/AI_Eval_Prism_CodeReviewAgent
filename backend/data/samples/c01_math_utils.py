"""Small numeric helpers."""
from __future__ import annotations

from statistics import mean


def clamp(value: float, low: float, high: float) -> float:
    """Return value limited to the range [low, high]."""
    if low > high:
        raise ValueError("low must not exceed high")
    return max(low, min(value, high))


def moving_average(values: list[float], window: int) -> list[float]:
    """Simple moving average; empty list when the window is larger than the data."""
    if window <= 0:
        raise ValueError("window must be positive")
    if window > len(values):
        return []
    return [mean(values[i : i + window]) for i in range(len(values) - window + 1)]
