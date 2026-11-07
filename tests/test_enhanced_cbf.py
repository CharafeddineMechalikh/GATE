"""Tests for Enhanced D-CBF Monitor."""

import pytest
import numpy as np
from gate.core.models import AgentState, ToolCall, ResourceMetrics
from gate.security.dcbf_monitor import EnhancedDCBFMonitor, ClassKFunction


class TestClassKFunction:
    """Tests for class-K function."""
    
    def test_initialization(self):
        alpha = ClassKFunction(kappa=0.5, power=1.0)
        assert alpha.kappa == 0.5
        assert alpha.power == 1.0
    
    def test_invalid_kappa(self):
        with pytest.raises(ValueError):
            ClassKFunction(kappa=1.5)
        
        with pytest.raises(ValueError):
            ClassKFunction(kappa=0.0)
    
    def test_invalid_power(self):
        with pytest.raises(ValueError):
            ClassKFunction(power=0.5)
    
    def test_evaluation(self):
        alpha = ClassKFunction(kappa=0.5, power=1.0)
        
        assert alpha(0.0) == 0.0
        assert alpha(1.0) == 0.5
        assert alpha(2.0) == 1.0
        assert alpha(-1.0) == 0.0


class TestEnhancedDCBFMonitor:
    """Tests for enhanced D-CBF monitor."""
    
    def setup_method(self):
        self.monitor = EnhancedDCBFMonitor(
            safety_margin=0.1,
            privacy_budget=0.5,
            resource_limit=10.0,
            max_drift=0.8,
            step_budget=50,
        )
    
    def test_initialization(self):
        assert len(self.monitor.barriers) == 5
        assert "safety" in self.monitor.barriers
        assert "privacy" in self.monitor.barriers
        assert "resource" in self.monitor.barriers
        assert "scope" in self.monitor.barriers
        assert "stability" in self.monitor.barriers
    
    def test_evaluate_state(self):
        state = AgentState(
            agent_id="test",
            step_count=5,
            trust_level=0.8,
            current_phase="ACTING",
            resource_usage=ResourceMetrics(tokens_used=1000, api_calls=5, cost_usd=0.5),
        )
        
        h_value = self.monitor.evaluate_state(state)
        assert isinstance(h_value, float)
    
    def test_check_transition(self):
        current_state = AgentState(
            agent_id="test",
            step_count=5,
            current_phase="PLANNING",
        )
        
        action = ToolCall(
            tool_name="search",
            tool_args={"query": "test"},
            call_id="test-1",
        )
        
        is_safe, reason = self.monitor.check_transition(current_state, action)
        assert isinstance(is_safe, bool)
        assert isinstance(reason, str)
    
    def test_add_custom_barrier(self):
        def custom_barrier(state: AgentState) -> float:
            return 1.0 - state.step_count / 100.0
        
        self.monitor.add_barrier("custom", custom_barrier, weight=0.5, margin=0.1)
        
        assert "custom" in self.monitor.barriers
        assert self.monitor.barriers["custom"].weight == 0.5
    
    def test_remove_barrier(self):
        self.monitor.remove_barrier("safety")
        assert "safety" not in self.monitor.barriers
    
    def test_get_barrier_values(self):
        state = AgentState(
            agent_id="test",
            step_count=5,
            current_phase="ACTING",
        )
        
        values = self.monitor.get_barrier_values(state)
        
        assert isinstance(values, dict)
        assert len(values) == 5
        assert all(isinstance(v, float) for v in values.values())
    
    def test_verify_forward_invariance(self):
        states = [
            AgentState(agent_id="test", step_count=i, current_phase="ACTING")
            for i in range(5)
        ]
        
        actions = [
            ToolCall(tool_name="search", tool_args={}, call_id=f"test-{i}")
            for i in range(5)
        ]
        
        result = self.monitor.verify_forward_invariance(states, actions)
        
        assert "total_checks" in result
        assert "violations" in result
        assert "violation_rate" in result
        assert "forward_invariant" in result
        assert result["total_checks"] == 5

    def test_single_breached_barrier_blocks(self):
        """A single negative barrier (privacy) blocks even when the weighted
        composite stays positive. The safe set is the INTERSECTION {h_i >= 0},
        not a scalar average, so a lone breached barrier leaves the safe set."""
        # Drain the privacy budget (0.5) with 4 outbound sends => h_privacy < 0.
        history = [
            ToolCall(tool_name="send_email", tool_args={}, call_id=f"h{i}")
            for i in range(4)
        ]
        unsafe_state = AgentState(
            agent_id="test",
            step_count=1,
            current_phase="PLANNING",
            tool_history=history,
        )
        action = ToolCall(
            tool_name="send_email", tool_args={}, call_id="probe"
        )

        is_safe, reason = self.monitor.check_transition(unsafe_state, action)
        assert is_safe is False
        assert "privacy" in reason

    def test_healthy_state_passes(self):
        """A clean state (no breached barrier) passes the transition check."""
        healthy = AgentState(agent_id="test", step_count=1, current_phase="PLANNING")
        action = ToolCall(tool_name="search", tool_args={}, call_id="ok")
        is_safe, _ = self.monitor.check_transition(healthy, action)
        assert is_safe is True

    def test_successor_model_appends_call_without_mutating(self):
        """The successor predicts history, step and cost; the input state is
        left untouched so a rejected call leaves no trace."""
        state = AgentState(
            agent_id="test",
            step_count=3,
            tool_history=[ToolCall("search", {}, "h0")],
        )
        state.resource_usage.cost_usd = 1.0
        action = ToolCall("http_request", {}, "probe")

        nxt = self.monitor._simulate_next_state(state, action)

        assert [tc.tool_name for tc in nxt.tool_history] == ["search", "http_request"]
        assert nxt.step_count == 4
        assert nxt.resource_usage.cost_usd == pytest.approx(1.01)
        assert state.step_count == 3
        assert len(state.tool_history) == 1
        assert state.resource_usage.cost_usd == pytest.approx(1.0)

    def test_successor_condition_blocks_third_outbound(self):
        """Two outbound calls leave h_privacy = 0.1 > 0, so the state is inside
        the safe set. The successor of a third outbound call has h = -0.1, which
        violates h(x_{k+1}) - h(x_k) >= -alpha(h(x_k)); the call must be refused
        by the forward test, not by the membership test."""
        history = [
            ToolCall(tool_name="send_email", tool_args={}, call_id=f"h{i}")
            for i in range(2)
        ]
        state = AgentState(
            agent_id="test",
            step_count=2,
            current_phase="PLANNING",
            tool_history=history,
        )
        values = self.monitor.get_barrier_values(state)
        assert values["privacy"] == pytest.approx(0.1)
        assert all(v >= 0 for v in values.values())

        is_safe, reason = self.monitor.check_transition(
            state, ToolCall("send_email", {}, "probe")
        )
        assert is_safe is False
        assert "privacy" in reason
        assert "CBF condition" in reason

    def test_successor_condition_blocks_completed_dangerous_pair(self):
        """A history holding one half of a dangerous pair is safe; appending the
        other half completes the pair in the successor and must be refused."""
        state = AgentState(
            agent_id="test",
            step_count=1,
            current_phase="PLANNING",
            tool_history=[ToolCall("sql_query", {}, "h0")],
        )
        is_safe, reason = self.monitor.check_transition(
            state, ToolCall("http_request", {}, "probe")
        )
        assert is_safe is False
        assert "safety" in reason

    def test_successor_condition_blocks_overrun(self):
        """The forward condition refuses the call that crosses each budget."""
        # Stability: one step past a three-step budget.
        stability_state = AgentState(agent_id="test", step_count=3, current_phase="ACTING")
        tight = EnhancedDCBFMonitor(step_budget=3)
        is_safe, reason = tight.check_transition(
            stability_state, ToolCall("search", {}, "probe")
        )
        assert is_safe is False
        assert "stability" in reason

        # Resource: a declared cost that exceeds the remaining budget.
        resource_state = AgentState(agent_id="test", step_count=1, current_phase="ACTING")
        resource_state.resource_usage.cost_usd = 9.9
        action = ToolCall("search", {}, "probe", metadata={"estimated_cost": 0.2})
        is_safe, reason = self.monitor.check_transition(resource_state, action)
        assert is_safe is False
        assert "resource" in reason

    def test_forward_invariance_over_accepted_sequence(self):
        """Any sequence the monitor admits stays inside the safe set, so the
        forward-invariance property holds by construction of the check."""
        state = AgentState(agent_id="test", current_phase="PLANNING", step_count=0,
                           loop_count={})
        proposals = [
            ToolCall("sql_query", {}, "a"),
            ToolCall("web_search", {}, "b"),
            ToolCall("http_request", {}, "c"),
            ToolCall("send_email", {}, "d"),
            ToolCall("send_email", {}, "e"),
        ]
        accepted = 0
        for action in proposals:
            is_safe, _ = self.monitor.check_transition(state, action)
            if is_safe:
                accepted += 1
                state.tool_history.append(action)
                state.step_count += 1
                assert all(
                    v >= 0 for v in self.monitor.get_barrier_values(state).values()
                )
        assert accepted < len(proposals)
