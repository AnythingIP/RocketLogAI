"""
UEBA anomaly detection engine.
"""

from __future__ import annotations

import time
from typing import Any

from .baselines import BaselineStore


class UEBADetector:
    """Detect anomalous user/entity behavior with explainable scoring."""

    def __init__(self, baselines: BaselineStore | None = None):
        self.baselines = baselines or BaselineStore()
        self._anomalies: list[dict[str, Any]] = []

    def observe(self, entity_id: str, entity_type: str, event: dict[str, Any]) -> dict[str, Any] | None:
        """Record event and return anomaly if detected."""
        metrics = {
            "log_count": 1,
            "severity_scores": [self._sev_score(event.get("severity", "low"))],
            "hours_active": [time.localtime().tm_hour],
            "source_ips": [event.get("source_ip", "")],
            "appnames": [event.get("appname", "")],
        }
        baseline = self.baselines.get(entity_id)
        self.baselines.update(entity_id, entity_type, metrics)

        if not baseline or baseline.get("sample_count", 0) < 5:
            return None

        score, reasons = self._score_anomaly(baseline["metrics"], event)
        if score < 0.6:
            return None

        anomaly = {
            "entity_id": entity_id,
            "entity_type": entity_type,
            "score": round(score, 3),
            "reasons": reasons,
            "event": event,
            "ts": time.time(),
            "explanation": self._explain(reasons, score),
        }
        self._anomalies.append(anomaly)
        if len(self._anomalies) > 500:
            self._anomalies = self._anomalies[-250:]
        return anomaly

    @staticmethod
    def _sev_score(sev: str) -> float:
        return {"low": 1, "medium": 3, "high": 7, "critical": 10}.get(sev, 2)

    def _score_anomaly(self, baseline: dict, event: dict) -> tuple[float, list[str]]:
        reasons = []
        score = 0.0

        sev = self._sev_score(event.get("severity", "low"))
        avg_sev = sum(baseline.get("severity_scores", [2])) / max(len(baseline.get("severity_scores", [1])), 1)
        if sev > avg_sev * 2:
            score += 0.35
            reasons.append(f"Severity spike: {event.get('severity')} vs baseline avg {avg_sev:.1f}")

        hour = time.localtime().tm_hour
        active_hours = baseline.get("hours_active", [])
        if active_hours and hour not in active_hours and len(set(active_hours)) < 20:
            score += 0.25
            reasons.append(f"Activity at unusual hour: {hour}:00")

        src = event.get("source_ip", "")
        known_ips = baseline.get("source_ips", [])
        if src and known_ips and src not in known_ips:
            score += 0.2
            reasons.append(f"New source IP: {src}")

        app = event.get("appname", "")
        known_apps = baseline.get("appnames", [])
        if app and known_apps and app not in known_apps:
            score += 0.15
            reasons.append(f"Unusual application: {app}")

        return min(score, 1.0), reasons

    @staticmethod
    def _explain(reasons: list[str], score: float) -> str:
        if not reasons:
            return "Behavior within normal parameters."
        level = "critical" if score >= 0.85 else "high" if score >= 0.7 else "medium"
        return f"{level.upper()} anomaly (score {score:.0%}): " + "; ".join(reasons)

    def recent_anomalies(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._anomalies[-limit:]