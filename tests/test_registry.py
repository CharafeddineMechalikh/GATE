"""Unit tests for the framework registry."""

import sys

import pytest

from gate.adapters.registry import FrameworkRegistry, get_registry, wrap_agent
from gate.core.config import AgentProfile, gateConfig
from gate.core.exceptions import ConfigurationError

_DEFAULT_MODULES = {
    "langchain": "gate.adapters.langchain_adapter",
    "langgraph": "gate.adapters.langgraph_adapter",
    "openai-agents": "gate.adapters.openai_agents_adapter",
    "crewai": "gate.adapters.crewai_adapter",
}


def _config():
    return gateConfig(
        agent_profile=AgentProfile(agent_id="a1", role="r", allowed_tools={"x"})
    )


class TestRegistryBehaviour:
    def test_registers_available_adapters(self):
        frameworks = FrameworkRegistry().list_supported_frameworks()
        assert "langchain" in frameworks
        assert "crewai" in frameworks

    def test_get_adapter_is_case_insensitive(self):
        reg = FrameworkRegistry()
        assert reg.get_adapter("LangChain") is reg.get_adapter("langchain")

    def test_register_adapter_lowcases_key(self):
        reg = FrameworkRegistry()
        sentinel = object()
        reg.register_adapter("Custom", sentinel)
        assert reg.get_adapter("custom") is sentinel

    def test_unknown_framework_raises(self):
        with pytest.raises(ConfigurationError) as exc:
            FrameworkRegistry().get_adapter("nonexistent")
        assert "not supported" in str(exc.value)

    def test_get_registry_is_singleton(self):
        assert get_registry() is get_registry()


class TestImportGracefulSkip:
    """Each default adapter import is optional; a missing dependency must not
    crash registry construction, only omit that framework."""

    @pytest.mark.parametrize("framework,module", sorted(_DEFAULT_MODULES.items()))
    def test_skips_framework_when_dependency_missing(self, framework, module, monkeypatch):
        monkeypatch.setitem(sys.modules, module, None)
        reg = FrameworkRegistry()
        assert framework not in reg.list_supported_frameworks()
        with pytest.raises(ConfigurationError):
            reg.get_adapter(framework)


def test_wrap_agent_forwards_to_adapter():
    reg = FrameworkRegistry()
    calls = {}

    class _Adapter:
        def wrap_agent(self, agent, config, **kwargs):
            calls["args"] = (agent, config, kwargs)
            return "secured"

    reg.register_adapter("dummy", _Adapter())
    assert reg.wrap_agent(object(), "dummy", _config(), extra=1) == "secured"
    assert calls["args"][2] == {"extra": 1}
