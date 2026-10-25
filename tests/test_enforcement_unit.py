"""Unit tests for the shared adapter enforcement plumbing."""

import asyncio
from types import SimpleNamespace

import pytest

from gate.adapters.enforcement import (
    ToolEnforcement,
    ToolExecutionBlocked,
    collect_graph_tools,
    guard_tool_list,
    install_tool_guard,
    marshal_tool_args,
    schema_field_names,
)
from gate.core.config import AgentProfile, gateConfig
from gate.core.exceptions import AdapterError
from gate.core.models import ValidationResult
from gate.security.dfa_supervisor import DefaultDFASupervisor


def _config():
    return gateConfig(
        agent_profile=AgentProfile(
            agent_id="a1",
            role="r",
            allowed_tools={"add"},
            resource_budget=_budget(),
        ),
        enabled_checks={"privilege", "dfa"},
    )


def _budget():
    from gate.core.config import ResourceBudget

    return ResourceBudget(max_steps=20, max_loops_per_phase=2)


class _Approval:
    def __init__(self, approved, justification="ok"):
        self.approved = approved
        self.justification = justification
        self.request_id = "req-1"
        self.approver_id = "human-1"


class _Queue:
    def __init__(self, approved=True):
        self.approved = approved

    async def request_and_await_approval(self, **kwargs):
        return _Approval(self.approved)

    async def approve(self, request_id, approver_id, justification=""):
        return None

    async def reject(self, request_id, approver_id, reason=""):
        return None


class FakeMonitor:
    def __init__(self, decision="allow", has_result_validator=True):
        self.decision = decision
        self.dfa_supervisor = DefaultDFASupervisor(max_steps=20, max_loops_per_phase=2)
        self.calls = []
        if has_result_validator:
            self.validate_result = self._validate_result

    async def validate_action(self, action, state):
        self.calls.append(action.tool_name)
        if self.decision == "allow":
            return ValidationResult(is_allowed=True, reason="ok")
        if self.decision == "escalate":
            return ValidationResult(
                is_allowed=False, escalated=True, requires_approval=True, reason="fuzzy"
            )
        return ValidationResult(is_allowed=False, reason="denied by policy")

    async def _validate_result(self, action, output, state):
        return ValidationResult(is_allowed=True, reason="post ok")


class _IntentFirewall:
    def __init__(self):
        self.anchors = []

    def set_intent_anchor(self, text):
        self.anchors.append(text)


def _enforcement(decision="allow", queue=None, monitor=None, has_result_validator=True):
    mon = monitor or FakeMonitor(decision=decision, has_result_validator=has_result_validator)
    return ToolEnforcement(mon, _config(), approval_queue=queue), mon


# --------------------------------------------------------------------------
# Argument marshalling
# --------------------------------------------------------------------------


class TestSchemaFieldNames:
    def test_no_schema_uses_args_mapping(self):
        tool = SimpleNamespace(args={"a": int, "b": int})
        assert schema_field_names(tool) == ["a", "b"]

    def test_no_schema_args_not_mapping(self):
        tool = SimpleNamespace(args=[1, 2])
        assert schema_field_names(tool) == []

    def test_schema_mapping_properties(self):
        tool = SimpleNamespace(args_schema={"properties": {"x": {}, "y": {}}})
        assert schema_field_names(tool) == ["x", "y"]

    def test_model_fields(self):
        tool = SimpleNamespace(args_schema=SimpleNamespace(model_fields={"q": 1}))
        assert schema_field_names(tool) == ["q"]

    def test_pydantic_v1_fields(self):
        tool = SimpleNamespace(args_schema=SimpleNamespace(__fields__={"z": 1}))
        assert schema_field_names(tool) == ["z"]

    def test_unknown_schema(self):
        tool = SimpleNamespace(args_schema=object())
        assert schema_field_names(tool) == []


class TestMarshalToolArgs:
    def test_filters_control_and_underscore_kwargs(self):
        tool = SimpleNamespace(args_schema=None, args=None)
        out = marshal_tool_args(
            tool, (), {"a": 1, "run_manager": object(), "_private": 2}
        )
        assert out == {"a": 1}

    def test_single_positional_mapping(self):
        tool = SimpleNamespace(args_schema=None, args=None)
        out = marshal_tool_args(tool, ({"a": 1, "b": 2},), {})
        assert out == {"a": 1, "b": 2}

    def test_single_positional_scalar(self):
        tool = SimpleNamespace(args_schema=None, args=None)
        out = marshal_tool_args(tool, ("query text",), {})
        assert out == {"input": "query text"}

    def test_single_positional_model_dump(self):
        model = SimpleNamespace(model_dump=lambda: {"a": 5})
        tool = SimpleNamespace(args_schema=None, args=None)
        out = marshal_tool_args(tool, (model,), {})
        assert out == {"a": 5}

    def test_multiple_positional_uses_names(self):
        tool = SimpleNamespace(args_schema={"properties": {"a": {}, "b": {}}})
        out = marshal_tool_args(tool, (1, 2), {})
        assert out == {"a": 1, "b": 2}

    def test_multiple_positional_overflow(self):
        tool = SimpleNamespace(args_schema={"properties": {"a": {}}})
        out = marshal_tool_args(tool, (1, 2, 3), {})
        assert out == {"arg0": 1, "arg1": 2, "arg2": 3}

    def test_kwargs_merge_over_args(self):
        tool = SimpleNamespace(args_schema={"properties": {"a": {}}})
        out = marshal_tool_args(tool, (1,), {"a": 9})
        # single positional becomes "input", then clean kwargs override by name
        assert out == {"input": 1, "a": 9}


# --------------------------------------------------------------------------
# ToolEnforcement lifecycle
# --------------------------------------------------------------------------


class TestLifecycle:
    def test_begin_run_sets_anchor(self):
        mon = FakeMonitor()
        mon.semantic_firewall = _IntentFirewall()
        enf, _ = _enforcement(monitor=mon)
        enf.begin_run("do a thing")
        assert mon.semantic_firewall.anchors == ["do a thing"]

    def test_finish_run(self):
        enf, _ = _enforcement()
        enf.finish_run()
        assert enf.state.current_phase == "ANSWERING"

    def test_abort(self):
        enf, _ = _enforcement()
        enf.abort("timeout")
        assert enf._aborted_reason == "timeout"

    @pytest.mark.asyncio
    async def test_advance_after_finish_raises(self):
        enf, _ = _enforcement()
        enf.finish_run()
        with pytest.raises(ToolExecutionBlocked) as exc:
            await enf.before_call("add", {"a": 1})
        assert "already completed" in str(exc.value)

    @pytest.mark.asyncio
    async def test_transition_to_acting(self):
        enf, mon = _enforcement()
        action = await enf.before_call("add", {"a": 1})
        assert action.tool_name == "add"
        assert enf.state.current_phase == "ACTING"

    @pytest.mark.asyncio
    async def test_acting_self_loop(self):
        enf, _ = _enforcement()
        await enf.before_call("add", {"a": 1})
        await enf.after_call(_action(), 2)
        enf.state.current_phase = "ACTING"
        await enf.before_call("add", {"a": 2})
        assert enf.state.loop_count.get("ACTING", 0) >= 1

    @pytest.mark.asyncio
    async def test_dfa_refused_raises(self):
        enf, _ = _enforcement()
        enf.dfa = enf.monitor.dfa_supervisor
        enf.dfa.remove_transition("IDLE", "PLANNING")
        with pytest.raises(ToolExecutionBlocked):
            await enf.before_call("add", {"a": 1})

    @pytest.mark.asyncio
    async def test_acting_loop_exhausted_raises(self):
        enf, _ = _enforcement()
        enf.state.current_phase = "ACTING"
        enf.state.loop_count["ACTING"] = 2
        with pytest.raises(ToolExecutionBlocked) as exc:
            await enf.before_call("add", {"a": 1})
        assert "ACTING loop" in str(exc.value)


def _action(name="add"):
    from gate.core.models import ToolCall

    return ToolCall(tool_name=name, tool_args={"a": 1}, call_id="c")


# --------------------------------------------------------------------------
# before_call decisions and after_call postconditions
# --------------------------------------------------------------------------


class TestDecisions:
    @pytest.mark.asyncio
    async def test_block_raises(self):
        enf, _ = _enforcement(decision="block")
        with pytest.raises(ToolExecutionBlocked):
            await enf.before_call("add", {"a": 1})

    @pytest.mark.asyncio
    async def test_escalate_without_queue(self):
        enf, _ = _enforcement(decision="escalate")
        with pytest.raises(ToolExecutionBlocked):
            await enf.before_call("add", {"a": 1})

    @pytest.mark.asyncio
    async def test_escalate_with_approval(self):
        enf, _ = _enforcement(decision="escalate", queue=_Queue(approved=True))
        action = await enf.before_call("add", {"a": 1})
        assert action.metadata["hitl_approval"]["approver_id"] == "human-1"

    @pytest.mark.asyncio
    async def test_escalate_denied(self):
        enf, _ = _enforcement(decision="escalate", queue=_Queue(approved=False))
        with pytest.raises(ToolExecutionBlocked) as exc:
            await enf.before_call("add", {"a": 1})
        assert exc.value.result is not None

    @pytest.mark.asyncio
    async def test_after_call_without_validator(self):
        enf, _ = _enforcement(has_result_validator=False)
        out = await enf.after_call(_action(), 42)
        assert out == 42
        assert enf.state.current_phase == "OBSERVING"

    @pytest.mark.asyncio
    async def test_after_call_postcondition_fail(self):
        mon = FakeMonitor()

        async def fail(action, output, state):
            return ValidationResult(is_allowed=False, reason="bad output")

        mon.validate_result = fail
        enf, _ = _enforcement(monitor=mon)
        with pytest.raises(ToolExecutionBlocked) as exc:
            await enf.after_call(_action(), 1)
        assert exc.value.post_execution is True


# --------------------------------------------------------------------------
# Cross-thread approval API
# --------------------------------------------------------------------------


class TestApprovalApi:
    def test_approve_without_queue(self):
        enf, _ = _enforcement()
        with pytest.raises(AdapterError):
            enf.approve("req", "human")

    def test_reject_without_queue(self):
        enf, _ = _enforcement()
        with pytest.raises(AdapterError):
            enf.reject("req", "human")

    def test_resolve_without_pending(self):
        enf, _ = _enforcement(queue=_Queue())
        with pytest.raises(AdapterError):
            enf.approve("req", "human")


# --------------------------------------------------------------------------
# Guard installation
# --------------------------------------------------------------------------


class _PlainTool:
    def __init__(self, name="add"):
        self.name = name
        self.executed = []

    def _run(self, a=0, b=0):
        self.executed.append((a, b))
        return a + b


class _AsyncTool:
    def __init__(self, name="add"):
        self.name = name
        self.executed = []

    def _run(self, a=0, b=0):
        self.executed.append((a, b))
        return a + b

    async def _arun(self, a=0, b=0):
        self.executed.append((a, b))
        return a + b

    coroutine = _arun


def test_install_blocks_unauthorized_and_runs_body():
    enf, _ = _enforcement(decision="allow")
    tool = _PlainTool()
    install_tool_guard(tool, enf)
    assert tool._run(a=2, b=3) == 5
    enf.close()


def test_install_tool_guard_denied_does_not_run_body():
    enf, _ = _enforcement(decision="block")
    tool = _PlainTool()
    install_tool_guard(tool, enf)
    with pytest.raises(ToolExecutionBlocked):
        tool._run(a=1, b=1)
    assert tool.executed == []
    enf.close()


def test_install_same_enforcement_is_idempotent():
    enf, _ = _enforcement()
    tool = _PlainTool()
    tool._gate_enforcement = enf
    assert install_tool_guard(tool, enf) is tool
    enf.close()


def test_install_other_enforcement_raises():
    enf1, _ = _enforcement()
    enf2, _ = _enforcement()
    tool = _PlainTool()
    tool._gate_enforcement = enf1
    with pytest.raises(AdapterError):
        install_tool_guard(tool, enf2)
    enf1.close()
    enf2.close()


def test_install_without_run_raises():
    enf, _ = _enforcement()
    tool = SimpleNamespace(name="broken")
    with pytest.raises(AdapterError):
        install_tool_guard(tool, enf)
    enf.close()


def test_guarded_arun_native_async():
    enf, _ = _enforcement()
    tool = _AsyncTool()
    install_tool_guard(tool, enf, native_async=True)
    result = asyncio.run(tool._arun(a=4, b=5))
    assert result == 9
    assert tool.executed == [(4, 5)]
    enf.close()


def test_guarded_arun_falls_back_to_thread():
    enf, _ = _enforcement()
    tool = _AsyncTool()
    install_tool_guard(tool, enf, native_async=False)
    # With native_async False the sync body runs on a worker thread.
    result = asyncio.run(tool._arun(a=1, b=2))
    assert result == 3
    enf.close()


def test_guard_tool_list_skips_empty():
    enf, _ = _enforcement()
    guard_tool_list([], enf)  # no-op
    tools = [_PlainTool("add")]
    guard_tool_list(tools, enf, native_async=False)
    assert getattr(tools[0], "_gate_enforcement") is enf
    enf.close()


# --------------------------------------------------------------------------
# Graph tool discovery
# --------------------------------------------------------------------------


class _ToolNode:
    def __init__(self, tools):
        self.tools_by_name = {t.name: t for t in tools}


def test_collect_graph_tools_from_builder():
    tool = _PlainTool("add")
    node = _ToolNode([tool])
    graph = SimpleNamespace(
        builder=SimpleNamespace(nodes={"tools": SimpleNamespace(runnable=node)}),
        nodes=None,
    )
    assert collect_graph_tools(graph) == [tool]


def test_collect_graph_tools_from_compiled_nodes():
    tool = _PlainTool("add")
    node = _ToolNode([tool])
    graph = SimpleNamespace(
        builder=None,
        nodes={"tools": SimpleNamespace(bound=node)},
    )
    assert collect_graph_tools(graph) == [tool]


def test_collect_graph_tools_dedups():
    tool = _PlainTool("add")
    node = _ToolNode([tool])
    graph = SimpleNamespace(
        builder=SimpleNamespace(
            nodes={
                "a": SimpleNamespace(runnable=node),
                "b": SimpleNamespace(runnable=node),
            }
        ),
        nodes=None,
    )
    assert collect_graph_tools(graph) == [tool]


def test_collect_graph_tools_ignores_non_tool_nodes():
    graph = SimpleNamespace(
        builder=SimpleNamespace(nodes={"x": SimpleNamespace(runnable=object())}),
        nodes=None,
    )
    assert collect_graph_tools(graph) == []
