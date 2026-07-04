"""
Prometheus-compatible metrics registry.
"""

from __future__ import annotations

import time
from typing import Any


class MetricsRegistry:
    """Lightweight Prometheus metrics without external dependency."""

    def __init__(self):
        self._counters: dict[str, float] = {}
        self._gauges: dict[str, float] = {}
        self._histograms: dict[str, list[float]] = {}

    def inc(self, name: str, value: float = 1, labels: dict[str, str] | None = None) -> None:
        key = self._key(name, labels)
        self._counters[key] = self._counters.get(key, 0) + value

    def set_gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = self._key(name, labels)
        self._gauges[key] = value

    def observe(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = self._key(name, labels)
        self._histograms.setdefault(key, []).append(value)
        if len(self._histograms[key]) > 1000:
            self._histograms[key] = self._histograms[key][-500:]

    @staticmethod
    def _key(name: str, labels: dict[str, str] | None) -> str:
        if not labels:
            return name
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    def export_prometheus(self) -> str:
        lines = []
        for key, val in sorted(self._counters.items()):
            lines.append(f"# TYPE {key.split('{')[0]} counter")
            lines.append(f"{key} {val}")
        for key, val in sorted(self._gauges.items()):
            lines.append(f"# TYPE {key.split('{')[0]} gauge")
            lines.append(f"{key} {val}")
        for key, vals in sorted(self._histograms.items()):
            base = key.split("{")[0]
            lines.append(f"# TYPE {base} histogram")
            if vals:
                lines.append(f"{key}_sum {sum(vals)}")
                lines.append(f"{key}_count {len(vals)}")
        lines.append("rocketlogai_up 1")
        lines.append(f"rocketlogai_scrape_ts {time.time()}")
        return "\n".join(lines) + "\n"

    def snapshot(self) -> dict[str, Any]:
        return {
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
            "histogram_keys": list(self._histograms.keys()),
        }