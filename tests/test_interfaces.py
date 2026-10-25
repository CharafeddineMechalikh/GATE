# tests/test_interfaces.py
"""Tests for the abstract base classes in :mod:`gate.core.interfaces`.

Every contract method is declared ``@abstractmethod`` with a ``pass`` body.
Those base bodies are only reachable through a concrete subclass that invokes
``super().method(...)``.  Each test below builds such a subclass, calls the base
implementation (covering its ``pass``), and confirms the override still returns
its own value.  Async contracts are driven with ``asyncio.run``.
"""

import asyncio

import numpy as np
import pytest

from gate.core import interfaces as ifc
from gate.core.models import ToolCall, AgentState


def _tool_call():
    return ToolCall(tool_name="t", tool_args={}, call_id="c1")


def _state():
    return AgentState(agent_id="agent-1")


# ---------------------------------------------------------------------------
# Sync contracts
# ---------------------------------------------------------------------------

class TestSemanticFirewallBase:
    def test_abstract_bodies_run(self):
        class Impl(ifc.SemanticFirewall):
            def check_semantic_safety(self, action, tool_name, agent_id):
                super().check_semantic_safety(action, tool_name, agent_id)
                return "score"

            def embed(self, text):
                super().embed(text)
                return np.zeros(3)

            def set_intent_anchor(self, user_prompt):
                super().set_intent_anchor(user_prompt)
                return True

        f = Impl()
        assert f.check_semantic_safety("a", "t", "agent") == "score"
        assert f.embed("x").shape == (3,)
        assert f.set_intent_anchor("hi") is True

    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            ifc.SemanticFirewall()  # type: ignore[abstract]


class TestSmartContractBase:
    def test_abstract_bodies_run(self):
        class Impl(ifc.SmartContract):
            def validate_precondition(self, action, state):
                super().validate_precondition(action, state)
                return True

            def validate_postcondition(self, action, result, state):
                super().validate_postcondition(action, result, state)
                return False

        c = Impl()
        assert c.validate_precondition(_tool_call(), _state()) is True
        assert c.validate_postcondition(_tool_call(), "r", _state()) is False


class TestDCBFMonitorBase:
    def test_abstract_bodies_run(self):
        class Impl(ifc.DCBFMonitor):
            def check_transition(self, current_state, proposed_action):
                super().check_transition(current_state, proposed_action)
                return (True, "ok")

            def evaluate_state(self, state):
                super().evaluate_state(state)
                return 1.0

        m = Impl()
        assert m.check_transition(_state(), _tool_call()) == (True, "ok")
        assert m.evaluate_state(_state()) == 1.0


class TestDFASupervisorBase:
    def test_abstract_bodies_run(self):
        class Impl(ifc.DFASupervisor):
            def propose_transition(self, current_state, next_phase):
                super().propose_transition(current_state, next_phase)
                return (True, "")

            def validate_action_phase(self, current_state):
                super().validate_action_phase(current_state)
                return (False, "denied")

        s = Impl()
        assert s.propose_transition(_state(), "ACTING") == (True, "")
        assert s.validate_action_phase(_state()) == (False, "denied")


class TestPrivilegeEnforcerBase:
    def test_abstract_bodies_run(self):
        class Impl(ifc.PrivilegeEnforcer):
            def check_tool_permission(self, agent_id, tool_name):
                super().check_tool_permission(agent_id, tool_name)
                return True

            def check_data_scope(self, agent_id, resource):
                super().check_data_scope(agent_id, resource)
                return True

            def check_resource_budget(self, agent_id, estimated_cost):
                super().check_resource_budget(agent_id, estimated_cost)
                return False

        p = Impl()
        assert p.check_tool_permission("a", "t") is True
        assert p.check_data_scope("a", "r") is True
        assert p.check_resource_budget("a", 1.0) is False


class TestSecureAgentBase:
    def test_abstract_bodies_run(self):
        class Impl(ifc.SecureAgent):
            def invoke(self, input, **kwargs):
                super().invoke(input, **kwargs)
                return "out"

            def get_state(self):
                super().get_state()
                return _state()

            def terminate(self):
                super().terminate()
                return None

        a = Impl()
        assert a.invoke("in") == "out"
        assert a.get_state().agent_id == "agent-1"
        a.terminate()


class TestAgentFrameworkAdapterBase:
    def test_abstract_bodies_run(self):
        class Impl(ifc.AgentFrameworkAdapter):
            def wrap_agent(self, agent, config):
                super().wrap_agent(agent, config)
                return "wrapped"

            def extract_state(self, agent):
                super().extract_state(agent)
                return _state()

            def inject_monitoring(self, agent, monitor):
                super().inject_monitoring(agent, monitor)
                return None

            def get_tool_calls(self, agent):
                super().get_tool_calls(agent)
                return [_tool_call()]

            def get_agent_id(self, agent):
                super().get_agent_id(agent)
                return "id"

        ad = Impl()
        assert ad.wrap_agent(object(), None) == "wrapped"
        assert ad.extract_state(object()).agent_id == "agent-1"
        ad.inject_monitoring(object(), object())
        assert len(ad.get_tool_calls(object())) == 1
        assert ad.get_agent_id(object()) == "id"


# ---------------------------------------------------------------------------
# Async contract
# ---------------------------------------------------------------------------

class TestSecurityMonitorBase:
    def test_abstract_bodies_run(self):
        class Impl(ifc.SecurityMonitor):
            async def validate_action(self, action, state):
                await super().validate_action(action, state)
                return "va"

            async def validate_result(self, action, result, state):
                await super().validate_result(action, result, state)
                return "vr"

            async def check_semantic_safety(self, action, tool_name, agent_id):
                await super().check_semantic_safety(action, tool_name, agent_id)
                return "cs"

            async def check_state_invariants(self, state):
                await super().check_state_invariants(state)
                return True

            async def log_event(self, event):
                await super().log_event(event)
                return None

        m = Impl()
        tc = _tool_call()
        st = _state()
        assert asyncio.run(m.validate_action(tc, st)) == "va"
        assert asyncio.run(m.validate_result(tc, "r", st)) == "vr"
        assert asyncio.run(m.check_semantic_safety("a", "t", "agent")) == "cs"
        assert asyncio.run(m.check_state_invariants(st)) is True
        assert asyncio.run(m.log_event("e")) is None
