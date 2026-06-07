"""
AI Assistant package for RocketLogAI.

Phase 3: Extremely powerful natural language co-pilot using Open Interpreter
as the primary execution engine, wrapped in strong safety, credential, and
learning layers.
"""

from .controller import AIAssistantController, get_ai_assistant_controller

__all__ = ["AIAssistantController", "get_ai_assistant_controller"]