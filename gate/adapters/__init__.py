"""gate Framework Adapters."""

from .base import BaseFrameworkAdapter
from .enforcement import ToolEnforcement, ToolExecutionBlocked
from .registry import FrameworkRegistry, get_registry, wrap_agent
from .langchain_adapter import LangChainAdapter
from .langgraph_adapter import LangGraphAdapter
from .openai_agents_adapter import OpenAIAgentsAdapter
from .crewai_adapter import CrewAIAdapter

__all__ = [
    "BaseFrameworkAdapter",
    "ToolEnforcement",
    "ToolExecutionBlocked",
    "FrameworkRegistry",
    "get_registry",
    "wrap_agent",
    "LangChainAdapter",
    "LangGraphAdapter",
    "OpenAIAgentsAdapter",
    "CrewAIAdapter",
]
