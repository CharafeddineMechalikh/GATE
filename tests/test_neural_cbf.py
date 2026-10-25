"""Tests for Neural CBF."""

import pytest
import numpy as np
from gate.core.models import AgentState, ResourceMetrics, ToolCall
from gate.security.neural_cbf import NeuralCBF


def _state(step=5, trust=0.8, phase="ACTING", tokens=1000, api=5, cost=0.5,
           context=None, action=None):
    return AgentState(
        agent_id="test",
        step_count=step,
        trust_level=trust,
        current_phase=phase,
        resource_usage=ResourceMetrics(
            tokens_used=tokens, api_calls=api, cost_usd=cost
        ),
        context_embedding=context,
        action_embedding=action,
    )


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


class TestStateVector:
    def setup_method(self):
        self.cbf = NeuralCBF(state_dim=12, hidden_dims=[16, 16])

    def test_with_embeddings_and_padding(self):
        vec = self.cbf._extract_state_vector(
            _state(context=np.array([0.1, 0.2, 0.3]), action=np.array([0.4, 0.5, 0.6]))
        )
        assert len(vec) == 12
        assert vec.dtype == np.float32

    def test_without_embeddings(self):
        vec = self.cbf._extract_state_vector(_state())
        assert len(vec) == 12
        assert vec[-1] == 0.0

    def test_evaluate_when_model_missing(self):
        self.cbf._model = None
        with pytest.raises(RuntimeError):
            self.cbf.evaluate_state(_state())


class TestTrain:
    def test_train_populates_history(self):
        cbf = NeuralCBF(state_dim=10, hidden_dims=[16, 16])
        safe = [_state(step=i, phase="IDLE") for i in range(3)]
        unsafe = [_state(step=i, phase="ACTING", tokens=90000, cost=9.0) for i in range(3)]
        transitions = [
            (safe[0], ToolCall(tool_name="x", tool_args={}, call_id="c1"), unsafe[0])
        ]
        history = cbf.train(
            safe, unsafe, transitions=transitions, epochs=2, batch_size=2
        )
        assert cbf._is_trained is True
        assert len(history["total_loss"]) == 2
        assert len(history["classification_loss"]) == 2
        assert len(history["cbf_loss"]) == 2

    def test_train_without_transitions(self):
        cbf = NeuralCBF(state_dim=10, hidden_dims=[16, 16])
        safe = [_state(step=i) for i in range(2)]
        history = cbf.train(safe, safe, epochs=1, batch_size=2)
        assert history["cbf_loss"][0] == pytest.approx(0.0, abs=1e-6)

    def test_train_missing_model(self):
        cbf = NeuralCBF(state_dim=10, hidden_dims=[16, 16])
        cbf._model = None
        with pytest.raises(RuntimeError):
            cbf.train([_state()], [_state()])


class TestTransitionBranches:
    def test_current_state_unsafe(self):
        cbf = NeuralCBF(state_dim=10, hidden_dims=[16, 16], safety_margin=0.1)
        cbf.evaluate_state = lambda state: -0.9
        ok, reason = cbf.check_transition(_state(), ToolCall("x", {}, "c"))
        assert ok is False
        assert "Current state unsafe" in reason

    def test_cbf_condition_violated(self):
        cbf = NeuralCBF(state_dim=10, hidden_dims=[16, 16])
        values = iter([0.5, -0.9])  # h_current, h_next
        cbf.evaluate_state = lambda state: next(values)
        ok, reason = cbf.check_transition(_state(), ToolCall("x", {}, "c"))
        assert ok is False
        assert "CBF condition violated" in reason

    def test_simulate_next_state_copies_embedding(self):
        cbf = NeuralCBF(state_dim=10, hidden_dims=[16, 16])
        nxt = cbf._simulate_next_state(
            _state(context=np.array([0.5, 0.5, 0.5])), ToolCall("x", {}, "c")
        )
        assert nxt.step_count == 6
        assert nxt.context_embedding is not None


class TestPersistenceGuards:
    def test_save_without_model(self, tmp_path):
        cbf = NeuralCBF(state_dim=10, hidden_dims=[16, 16])
        cbf._model = None
        with pytest.raises(RuntimeError):
            cbf.save_model(str(tmp_path / "m.pt"))

    def test_load_without_model(self, tmp_path):
        cbf = NeuralCBF(state_dim=10, hidden_dims=[16, 16])
        cbf._model = None
        with pytest.raises(RuntimeError):
            cbf.load_model(str(tmp_path / "m.pt"))

    def test_init_from_pretrained_path(self, tmp_path):
        cbf = NeuralCBF(state_dim=10, hidden_dims=[16, 16])
        path = tmp_path / "m.pt"
        cbf.save_model(str(path))
        loaded = NeuralCBF(state_dim=10, hidden_dims=[16, 16], model_path=str(path))
        assert loaded._is_trained is True


class TestVerifyBarrierBranches:
    def test_length_mismatch(self):
        cbf = NeuralCBF(state_dim=10, hidden_dims=[16, 16])
        with pytest.raises(ValueError):
            cbf.verify_barrier([_state()], [True, False])

    def test_confusion_counts(self):
        cbf = NeuralCBF(state_dim=10, hidden_dims=[16, 16])
        # First two safe, last two unsafe; predictions match exactly.
        cbf.evaluate_state = lambda state: 0.5 if state.step_count < 2 else -0.5
        states = [_state(step=i) for i in range(4)]
        expected = [True, True, False, False]
        metrics = cbf.verify_barrier(states, expected)
        assert metrics["true_positives"] == 2
        assert metrics["true_negatives"] == 2
        assert metrics["accuracy"] == 1.0

    def test_false_positives_and_negatives(self):
        cbf = NeuralCBF(state_dim=10, hidden_dims=[16, 16])
        # step0 safe/correct, step1 unsafe-but-expected-safe (FN), step2 safe-but-expected-unsafe (FP).
        cbf.evaluate_state = lambda state: -0.5 if state.step_count == 1 else 0.5
        states = [_state(step=i) for i in range(3)]
        expected = [True, True, False]
        metrics = cbf.verify_barrier(states, expected)
        assert metrics["true_positives"] == 1
        assert metrics["false_positives"] == 1
        assert metrics["false_negatives"] == 1
        assert metrics["accuracy"] == pytest.approx(1 / 3)
