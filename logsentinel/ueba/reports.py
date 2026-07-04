"""
Explainable UEBA report generation.
"""

from __future__ import annotations

import time
from typing import Any


class UEBAReportGenerator:
    """Generate human-readable UEBA reports."""

    def generate_summary(self, anomalies: list[dict[str, Any]], period_hours: int = 24) -> dict[str, Any]:
        cutoff = time.time() - period_hours * 3600
        recent = [a for a in anomalies if a.get("ts", 0) >= cutoff]

        by_entity: dict[str, list] = {}
        for a in recent:
            eid = a.get("entity_id", "unknown")
            by_entity.setdefault(eid, []).append(a)

        top_entities = sorted(
            by_entity.items(),
            key=lambda x: max(a.get("score", 0) for a in x[1]),
            reverse=True,
        )[:10]

        sections = []
        for entity_id, entity_anomalies in top_entities:
            max_score = max(a.get("score", 0) for a in entity_anomalies)
            explanations = [a.get("explanation", "") for a in entity_anomalies[:3]]
            sections.append({
                "entity_id": entity_id,
                "anomaly_count": len(entity_anomalies),
                "max_score": max_score,
                "explanations": explanations,
            })

        narrative = self._build_narrative(recent, sections)
        return {
            "period_hours": period_hours,
            "total_anomalies": len(recent),
            "entities_affected": len(by_entity),
            "top_entities": sections,
            "narrative": narrative,
            "generated_at": time.time(),
        }

    @staticmethod
    def _build_narrative(anomalies: list[dict], sections: list[dict]) -> str:
        if not anomalies:
            return "No behavioral anomalies detected in this period. All monitored entities are within established baselines."

        lines = [
            f"Detected {len(anomalies)} behavioral anomalies across {len(sections)} entities.",
            "",
            "Key findings:",
        ]
        for s in sections[:5]:
            lines.append(
                f"• {s['entity_id']}: {s['anomaly_count']} anomalies (peak score {s['max_score']:.0%})"
            )
            for exp in s.get("explanations", [])[:1]:
                lines.append(f"  → {exp}")
        lines.append("")
        lines.append("Recommended actions: Review top entities, correlate with threat detections, and update baselines after investigation.")
        return "\n".join(lines)