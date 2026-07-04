"""
Vector store abstraction — Chroma (preferred) with SQLite fallback.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class VectorStore:
    """Unified vector store with Chroma or lightweight SQLite fallback."""

    def __init__(self, persist_dir: str = "./data/brain", collection: str = "rocketlogai"):
        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self.collection_name = collection
        self._backend = "sqlite"
        self._chroma = None
        self._collection = None
        self._init_backend()

    def _init_backend(self) -> None:
        try:
            import chromadb  # type: ignore

            client = chromadb.PersistentClient(path=str(self.persist_dir / "chroma"))
            self._collection = client.get_or_create_collection(
                name=self.collection_name,
                metadata={"hnsw:space": "cosine"},
            )
            self._chroma = client
            self._backend = "chroma"
            logger.info("Vector store using Chroma at %s", self.persist_dir)
        except Exception as exc:
            logger.info("Chroma unavailable (%s); using SQLite vector fallback", exc)
            self._init_sqlite()

    def _init_sqlite(self) -> None:
        db_path = self.persist_dir / "vectors.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS embeddings (
                id TEXT PRIMARY KEY,
                doc_id TEXT NOT NULL,
                content TEXT NOT NULL,
                metadata TEXT,
                vector TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_embeddings_doc ON embeddings(doc_id)")
        conn.commit()
        conn.close()
        self._sqlite_path = db_path

    @staticmethod
    def _simple_embed(text: str, dims: int = 384) -> list[float]:
        """Deterministic hash-based embedding for fallback (no external model required)."""
        vec = [0.0] * dims
        tokens = text.lower().split()
        for i, tok in enumerate(tokens):
            h = int(hashlib.sha256(tok.encode()).hexdigest(), 16)
            idx = h % dims
            vec[idx] += 1.0 / (i + 1)
        norm = sum(v * v for v in vec) ** 0.5 or 1.0
        return [v / norm for v in vec]

    @staticmethod
    def _cosine(a: list[float], b: list[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        na = sum(x * x for x in a) ** 0.5 or 1.0
        nb = sum(x * x for x in b) ** 0.5 or 1.0
        return dot / (na * nb)

    def upsert(
        self,
        doc_id: str,
        content: str,
        metadata: dict[str, Any] | None = None,
        embedding: list[float] | None = None,
    ) -> str:
        meta = metadata or {}
        emb = embedding or self._simple_embed(content)
        chunk_id = f"{doc_id}:{hashlib.md5(content.encode()).hexdigest()[:12]}"

        if self._backend == "chroma" and self._collection is not None:
            self._collection.upsert(
                ids=[chunk_id],
                documents=[content],
                metadatas=[{**meta, "doc_id": doc_id}],
                embeddings=[emb],
            )
            return chunk_id

        conn = sqlite3.connect(str(self._sqlite_path))
        conn.execute(
            """
            INSERT OR REPLACE INTO embeddings (id, doc_id, content, metadata, vector)
            VALUES (?, ?, ?, ?, ?)
            """,
            (chunk_id, doc_id, content, json.dumps(meta), json.dumps(emb)),
        )
        conn.commit()
        conn.close()
        return chunk_id

    def search(self, query: str, limit: int = 8, filter_doc_type: str | None = None) -> list[dict[str, Any]]:
        q_emb = self._simple_embed(query)

        if self._backend == "chroma" and self._collection is not None:
            where = {"doc_type": filter_doc_type} if filter_doc_type else None
            results = self._collection.query(
                query_embeddings=[q_emb],
                n_results=limit,
                where=where,
            )
            out: list[dict[str, Any]] = []
            docs = results.get("documents") or [[]]
            metas = results.get("metadatas") or [[]]
            dists = results.get("distances") or [[]]
            for doc, meta, dist in zip(docs[0], metas[0], dists[0]):
                out.append({"content": doc, "metadata": meta or {}, "score": 1.0 - (dist or 0)})
            return out

        conn = sqlite3.connect(str(self._sqlite_path))
        rows = conn.execute("SELECT content, metadata, vector FROM embeddings").fetchall()
        conn.close()

        scored: list[tuple[float, str, dict]] = []
        for content, meta_json, vec_json in rows:
            meta = json.loads(meta_json or "{}")
            if filter_doc_type and meta.get("doc_type") != filter_doc_type:
                continue
            vec = json.loads(vec_json)
            score = self._cosine(q_emb, vec)
            scored.append((score, content, meta))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [
            {"content": c, "metadata": m, "score": s}
            for s, c, m in scored[:limit]
        ]

    def delete_doc(self, doc_id: str) -> int:
        if self._backend == "chroma" and self._collection is not None:
            existing = self._collection.get(where={"doc_id": doc_id})
            ids = existing.get("ids") or []
            if ids:
                self._collection.delete(ids=ids)
            return len(ids)

        conn = sqlite3.connect(str(self._sqlite_path))
        cur = conn.execute("DELETE FROM embeddings WHERE doc_id = ?", (doc_id,))
        conn.commit()
        deleted = cur.rowcount
        conn.close()
        return deleted

    def status(self) -> dict[str, Any]:
        return {
            "backend": self._backend,
            "persist_dir": str(self.persist_dir),
            "collection": self.collection_name,
        }