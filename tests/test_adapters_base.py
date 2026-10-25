"""Unit tests for BaseFrameworkAdapter timeout and abstract-method behaviour."""

import asyncio

import pytest

from gate.adapters.base import BaseFrameworkAdapter, TimeoutError as AdapterTimeout
from gate.core.config import AgentProfile, gateConfig
from gate.core.exceptions import AdapterError


def _config():
    return gateConfig(
        agent_profile=AgentProfile(agent_id="a1", role="r", allowed_tools={"x"}),
        timeout_seconds=12.0,
    )


@pytest.fixture
def adapter():
    return BaseFrameworkAdapter("dummy", default_timeout_seconds=5.0)


class TestAbstractMethods:
    def test_wrap_agent_not_implemented(self, adapter):
        with pytest.raises(NotImplementedError):
            adapter.wrap_agent(object(), _config())

    def test_extract_state_not_implemented(self, adapter):
        with pytest.raises(NotImplementedError):
            adapter.extract_state(object())

    def test_inject_monitoring_not_implemented(self, adapter):
        with pytest.raises(NotImplementedError):
            adapter.inject_monitoring(object(), object())

    def test_get_tool_calls_not_implemented(self, adapter):
        with pytest.raises(NotImplementedError):
            adapter.get_tool_calls(object())

    def test_get_agent_id_not_implemented(self, adapter):
        with pytest.raises(NotImplementedError):
            adapter.get_agent_id(object())


class TestValidateAgentType:
    def test_accepts_expected(self, adapter):
        adapter._validate_agent_type([], list)

    def test_rejects_wrong_type(self, adapter):
        with pytest.raises(AdapterError):
            adapter._validate_agent_type([], dict)


class TestTimeoutContext:
    def test_yields_on_platform_without_sigalrm(self, adapter):
        import signal

        if hasattr(signal, "SIGALRM"):
            pytest.skip("SIGALRM platform; behaviour covered elsewhere")
        with adapter.timeout_context(1) as value:
            assert value is None


class TestRunWithTimeout:
    def test_returns_value(self, adapter):
        assert adapter.run_with_timeout(lambda a, b=2: a + b, 3, b=4) == 7

    def test_times_out(self, adapter):
        import time

        with pytest.raises(AdapterTimeout):
            adapter.run_with_timeout(
                lambda: time.sleep(0.5), seconds=0.05, operation_name="sleeper"
            )


class TestAsyncTimeout:
    @pytest.mark.asyncio
    async def test_success(self, adapter):
        async def work():
            return 99

        assert await adapter.async_timeout_context(work(), seconds=2) == 99

    @pytest.mark.asyncio
    async def test_timeout(self, adapter):
        async def slow():
            await asyncio.sleep(1)

        with pytest.raises(AdapterTimeout):
            await adapter.async_timeout_context(slow(), seconds=0.05)


class TestTimeoutConfig:
    def test_uses_config_value(self, adapter):
        assert adapter.get_timeout_config(_config()) == 12.0

    def test_falls_back_to_default(self, adapter):
        class NoTimeout:
            pass

        assert adapter.get_timeout_config(NoTimeout()) == 5.0
