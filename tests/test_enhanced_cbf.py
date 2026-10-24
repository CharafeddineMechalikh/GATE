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
