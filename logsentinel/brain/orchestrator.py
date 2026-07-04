"""
Agentic AI orchestrator — coordinates brain, RAG, tools, and execution results.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Awaitable

from .memory import ConversationMemory
from .rag import RAGPipeline

logger = logging.getLogger(__name__)

ToolHandler = Callable[..., Awaitable[dict[str, Any]]]


class AIOrchestrator:
    """Unified AI brain orchestrator shared across RocketLogAI products."""

    def __init__(
        self,
        rag: RAGPipeline | None = None,
        memory: ConversationMemory | None = None,
        data_dir: str = "./data/brain",
    ):
        self.rag = rag or RAGPipeline(persist_dir=data_dir)
        self.memory = memory or ConversationMemory(db_path=f"{data_dir}/memory.db")
        self._tools: dict[str, ToolHandler] = {}

    def register_tool(self, name: str, handler: ToolHandler) -> None:
        self._tools[name] = handler

    async def ask(
        self,
        session_id: str,
        query: str,
        user_id: str = "",
        llm_call: Callable[[str], Awaitable[str]] | None = None,
        tools: list[str] | None = None,
    ) -> dict[str, Any]:
        session = self.memory.get_or_create_session(session_id, user_id=user_id)
        if not session.get("intent") and query:
            self.memory.set_intent(session_id, query[:200])

        rag_context = self.rag.build_context(query)
        history = self.memory.get_history(session_id, limit=20)
        history_text = "\n".join(f"{m['role']}: {m['content']}" for m in history[-10:])

        prompt = (
            "You are RocketLogAI's unified security AI brain. Maintain conversation intent.\n"
            f"Session intent: {session.get('intent', 'general assistance')}\n\n"
            f"Retrieved context:\n{rag_context or '(none)'}\n\n"
            f"Recent conversation:\n{history_text or '(new session)'}\n\n"
            f"User: {query}\n\n"
            "Provide a helpful, actionable response grounded in the context above."
        )

        self.memory.add_message(session_id, "user", query)
        self.rag.ingest_conversation_turn(session_id, "user", query)

        execution_results: list[dict[str, Any]] = []
        tool_names = tools or []
        for tool_name in tool_names:
            handler = self._tools.get(tool_name)
            if handler:
                try:
                    result = await handler(query=query, session_id=session_id)
                    execution_results.append({"tool": tool_name, "result": result})
                except Exception as exc:
                    execution_results.append({"tool": tool_name, "error": str(exc)})

        response = ""
        if llm_call:
            try:
                response = await llm_call(prompt)
            except Exception as exc:
                logger.exception("LLM call failed")
                response = f"I encountered an error contacting the LLM: {exc}"
        else:
            response = (
                f"Received your query. Retrieved {len(rag_context.splitlines()) if rag_context else 0} "
                f"context items. Configure an LLM to get full responses."
            )

        exec_summary = ""
        if execution_results:
            exec_summary = "\n\nExecution results:\n" + "\n".join(
                f"- {r.get('tool', 'tool')}: {r.get('result') or r.get('error')}" for r in execution_results
            )
            response += exec_summary

        self.memory.add_message(session_id, "assistant", response, execution_result=exec_summary or None)
        self.rag.ingest_conversation_turn(session_id, "assistant", response)

        return {
            "response": response,
            "session_id": session_id,
            "intent": session.get("intent"),
            "rag_hits": len(rag_context.splitlines()) if rag_context else 0,
            "execution_results": execution_results,
        }

    def status(self) -> dict[str, Any]:
        return {
            "rag": self.rag.status(),
            "tools_registered": list(self._tools.keys()),
        }