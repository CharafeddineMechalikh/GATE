"""
Framework Registry
Manages framework-specific adapters.
"""

import logging
from typing import Any, Dict, List, Optional

from ..core.interfaces import AgentFrameworkAdapter, SecureAgent
from ..core.config import gateConfig
from ..core.exceptions import ConfigurationError

logger = logging.getLogger(__name__)


class FrameworkRegistry:
    """Registry for framework-specific adapters."""
    
    def __init__(self) -> None:
        self._adapters: Dict[str, AgentFrameworkAdapter] = {}
        self._register_default_adapters()
    
    def _register_default_adapters(self) -> None:
        """Register default framework adapters."""
        try:
            from .langchain_adapter import LangChainAdapter
            self.register_adapter("langchain", LangChainAdapter())
            logger.info("Registered LangChain adapter")
        except ImportError:
            logger.debug("LangChain not available, skipping adapter registration")
        
        try:
            from .langgraph_adapter import LangGraphAdapter
            self.register_adapter("langgraph", LangGraphAdapter())
            logger.info("Registered LangGraph adapter")
        except ImportError:
            logger.debug("LangGraph not available, skipping adapter registration")
        
        try:
            from .openai_agents_adapter import OpenAIAgentsAdapter
            self.register_adapter("openai-agents", OpenAIAgentsAdapter())
            logger.info("Registered OpenAI Agents adapter")
        except ImportError:
            logger.debug("OpenAI Agents SDK not available, skipping adapter registration")
        
        try:
            from .crewai_adapter import CrewAIAdapter
            self.register_adapter("crewai", CrewAIAdapter())
            logger.info("Registered CrewAI adapter")
        except ImportError:
            logger.debug("CrewAI not available, skipping adapter registration")
    
    def register_adapter(
        self, framework_name: str, adapter: AgentFrameworkAdapter
    ) -> None:
        """Register a framework adapter."""
        self._adapters[framework_name.lower()] = adapter
        logger.info(f"Registered adapter for framework: {framework_name}")
    
    def get_adapter(self, framework_name: str) -> AgentFrameworkAdapter:
        """Get adapter for a framework."""
        framework_key = framework_name.lower()
        
        if framework_key not in self._adapters:
            available = ", ".join(self._adapters.keys())
            raise ConfigurationError(
                f"Framework '{framework_name}' not supported. "
                f"Available frameworks: {available}"
            )
        
        return self._adapters[framework_key]
    
    def wrap_agent(
        self, agent: Any, framework: str, config: gateConfig, **kwargs: Any
    ) -> SecureAgent:
        """Wrap an agent with gate security."""
        adapter = self.get_adapter(framework)
        return adapter.wrap_agent(agent, config, **kwargs)
    
    def list_supported_frameworks(self) -> List[str]:
        """List all supported frameworks."""
        return list(self._adapters.keys())


_registry = FrameworkRegistry()


def get_registry() -> FrameworkRegistry:
    """Get the global framework registry."""
    return _registry


def wrap_agent(
    agent: Any, framework: str, config: gateConfig, **kwargs: Any
) -> SecureAgent:
    """Convenience function to wrap an agent."""
    return _registry.wrap_agent(agent, framework, config, **kwargs)
