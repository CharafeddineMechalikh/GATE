"""Tests for Neural CBF."""

import pytest
import numpy as np
from gate.core.models import AgentState, ResourceMetrics
from gate.security.neural_cbf import NeuralCBF


class TestNeuralCBF:
    """Tests for Neural CBF."""
    
    def setup_method(self):
        self.cbf = NeuralCBF(state_dim=10, hidden_dims=[32, 32])
    
    def test_initialization(self):
        assert self.cbf.state_dim == 10
        assert self.cbf.hidden_dims == [32, 32]
        assert self.cbf._model is not None
    
    def test_evaluate_state(self):
        state = AgentState(
            agent_id="test",
            step_count=5,
            trust_level=0.8,
            current_phase="ACTING",
            resource_usage=ResourceMetrics(tokens_used=1000, api_calls=5, cost_usd=0.5),
        )
        
        h_value = self.cbf.evaluate_state(state)
        assert isinstance(h_value, float)
        assert -1.0 <= h_value <= 1.0
    
    def test_check_transition(self):
        from gate.core.models import ToolCall
        
        current_state = AgentState(
            agent_id="test",
            step_count=5,
            trust_level=0.8,
            current_phase="PLANNING",
        )
        
        action = ToolCall(
            tool_name="search",
            tool_args={"query": "test"},
            call_id="test-1",
        )
        
        is_safe, reason = self.cbf.check_transition(current_state, action)
        assert isinstance(is_safe, bool)
        assert isinstance(reason, str)
    
    def test_save_and_load(self, tmp_path):
        model_path = tmp_path / "test_model.pt"
        
        self.cbf.save_model(str(model_path))
        assert model_path.exists()
        
        new_cbf = NeuralCBF(state_dim=10, hidden_dims=[32, 32])
        new_cbf.load_model(str(model_path))
        
        state = AgentState(agent_id="test", step_count=5)
        h1 = self.cbf.evaluate_state(state)
        h2 = new_cbf.evaluate_state(state)
        
        assert abs(h1 - h2) < 1e-5
    
    def test_verify_barrier(self):
        states = [
            AgentState(agent_id="test", step_count=i, trust_level=0.8)
            for i in range(10)
        ]
        expected_safe = [True] * 10
        
        metrics = self.cbf.verify_barrier(states, expected_safe)
        
        assert "accuracy" in metrics
        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1" in metrics
        assert 0.0 <= metrics["accuracy"] <= 1.0
