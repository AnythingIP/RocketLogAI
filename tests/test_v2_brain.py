"""Tests for v2 unified AI brain."""

import tempfile
from pathlib import Path

from logsentinel.brain.vector_store import VectorStore
from logsentinel.brain.rag import RAGPipeline
from logsentinel.brain.memory import ConversationMemory


def test_vector_store_upsert_and_search():
    with tempfile.TemporaryDirectory() as tmp:
        store = VectorStore(persist_dir=tmp)
        store.upsert("doc1", "failed ssh login from 10.0.0.55", metadata={"doc_type": "log"})
        store.upsert("doc2", "nginx access log normal traffic", metadata={"doc_type": "log"})
        results = store.search("ssh brute force", limit=3)
        assert len(results) >= 1
        assert "ssh" in results[0]["content"].lower() or "login" in results[0]["content"].lower()


def test_rag_pipeline_ingest_and_context():
    with tempfile.TemporaryDirectory() as tmp:
        rag = RAGPipeline(persist_dir=tmp)
        count = rag.ingest_log_batch([
            {"id": 1, "message": "authentication failure", "hostname": "server1", "severity": "high"},
        ])
        assert count == 1
        ctx = rag.build_context("authentication failure")
        assert "authentication" in ctx.lower()


def test_conversation_memory():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "mem.db"
        mem = ConversationMemory(db_path=str(db))
        mem.get_or_create_session("sess1", user_id="admin", intent="check threats")
        mem.add_message("sess1", "user", "show open threats")
        mem.add_message("sess1", "assistant", "Found 3 open threats")
        history = mem.get_history("sess1")
        assert len(history) == 2
        assert history[0]["role"] == "user"