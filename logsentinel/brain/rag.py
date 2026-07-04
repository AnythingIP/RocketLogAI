"""
RAG pipeline — ingest logs, threats, and context for unified AI retrieval.
"""

from __future__ import annotations

import logging
from typing import Any

from .vector_store import VectorStore

logger = logging.getLogger(__name__)


class RAGPipeline:
    """Retrieval-augmented generation context builder."""

    def __init__(self, vector_store: VectorStore | None = None, persist_dir: str = "./data/brain"):
        self.store = vector_store or VectorStore(persist_dir=persist_dir)

    def ingest_log_batch(self, logs: list[dict[str, Any]], source: str = "syslog") -> int:
        count = 0
        for log in logs:
            msg = log.get("message") or ""
            if not msg.strip():
                continue
            doc_id = f"log:{log.get('id', count)}"
            content = (
                f"[{log.get('timestamp', '')}] {log.get('hostname', '')}/{log.get('appname', '')} "
                f"sev={log.get('severity', '')}: {msg}"
            )
            self.store.upsert(
                doc_id,
                content,
                metadata={
                    "doc_type": "log",
                    "source": source,
                    "hostname": log.get("hostname", ""),
                    "severity": log.get("severity", ""),
                },
            )
            count += 1
        return count

    def ingest_threat(self, threat: dict[str, Any]) -> str:
        content = (
            f"Threat #{threat.get('id', '')} [{threat.get('severity', '')}]: "
            f"{threat.get('description', '')}. Action: {threat.get('recommended_action', '')}"
        )
        doc_id = f"threat:{threat.get('id', 'unknown')}"
        return self.store.upsert(
            doc_id,
            content,
            metadata={
                "doc_type": "threat",
                "severity": threat.get("severity", ""),
                "hostname": threat.get("hostname", ""),
            },
        )

    def ingest_conversation_turn(self, session_id: str, role: str, content: str) -> str:
        doc_id = f"chat:{session_id}"
        return self.store.upsert(
            doc_id,
            f"{role}: {content}",
            metadata={"doc_type": "conversation", "session_id": session_id, "role": role},
        )

    def build_context(self, query: str, limit: int = 6) -> str:
        hits = self.store.search(query, limit=limit)
        if not hits:
            return ""
        parts = []
        for i, hit in enumerate(hits, 1):
            meta = hit.get("metadata") or {}
            label = meta.get("doc_type", "context")
            parts.append(f"[{i}] ({label}, score={hit.get('score', 0):.2f}) {hit['content']}")
        return "\n".join(parts)

    def status(self) -> dict[str, Any]:
        return {"vector_store": self.store.status()}