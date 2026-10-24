"""
Neural Control Barrier Function
Learned barrier function using neural networks for complex state spaces.
"""

import logging
from typing import Any, Callable, Dict, List, Optional, Tuple
import numpy as np

from ..core.interfaces import DCBFMonitor
from ..core.models import ToolCall, AgentState

logger = logging.getLogger(__name__)


class NeuralCBF(DCBFMonitor):
    """
    Neural Control Barrier Function.
    
    Uses a neural network to learn a barrier function h(x) from data.
    The network is trained to satisfy:
    - h(x) > 0 for safe states
    - h(x) < 0 for unsafe states
    - h(x_{k+1}) - h(x_k) >= -alpha(h(x_k)) (CBF condition)
    
    This is a drop-in replacement for hand-crafted barrier functions.
    """
    
    def __init__(
        self,
        state_dim: int = 10,
        hidden_dims: Optional[List[int]] = None,
        alpha_kappa: float = 0.5,
        safety_margin: float = 0.1,
        model_path: Optional[str] = None,
        device: str = "cpu",
    ) -> None:
        """
        Initialize Neural CBF.
        
        Args:
            state_dim: Dimension of the state vector.
            hidden_dims: Hidden layer dimensions. Defaults to [64, 64].
            alpha_kappa: Kappa parameter for class-K function alpha(h) = kappa * h.
            safety_margin: Safety margin for barrier verification.
            model_path: Path to pre-trained model. If None, initializes randomly.
            device: Device for computation ('cpu' or 'cuda').
        """
        self.state_dim = state_dim
        self.hidden_dims = hidden_dims or [64, 64]
        self.alpha_kappa = alpha_kappa
        self.safety_margin = safety_margin
        self.device = device
        
        self._model = None
        self._is_trained = False
        
        self._initialize_model(model_path)
    
    def _initialize_model(self, model_path: Optional[str]) -> None:
        """Initialize the neural network model."""
        try:
            import torch
            import torch.nn as nn
            
            class CBFNetwork(nn.Module):
                def __init__(
                    self,
                    input_dim: int,
                    hidden_dims: List[int],
                ) -> None:
                    super().__init__()
                    
                    layers = []
                    prev_dim = input_dim
                    
                    for hidden_dim in hidden_dims:
                        layers.append(nn.Linear(prev_dim, hidden_dim))
                        layers.append(nn.ReLU())
                        layers.append(nn.Dropout(0.1))
                        prev_dim = hidden_dim
                    
                    layers.append(nn.Linear(prev_dim, 1))
                    layers.append(nn.Tanh())
                    
                    self.network = nn.Sequential(*layers)
                
                def forward(self, x: torch.Tensor) -> torch.Tensor:
                    return self.network(x)
            
            self._model = CBFNetwork(self.state_dim, self.hidden_dims).to(self.device)
            
            if model_path:
                self.load_model(model_path)
                self._is_trained = True
                logger.info(f"Loaded pre-trained Neural CBF from {model_path}")
            else:
                logger.info("Initialized Neural CBF with random weights")
        
        except ImportError as e:
            raise ImportError(
                "PyTorch is required for NeuralCBF. "
                "Install with: pip install torch"
            ) from e
    
    def _state_to_tensor(self, state: AgentState) -> "torch.Tensor":
        """Convert agent state to tensor."""
        import torch
        
        state_vector = self._extract_state_vector(state)
        return torch.tensor(state_vector, dtype=torch.float32).to(self.device)
    
    def _extract_state_vector(self, state: AgentState) -> np.ndarray:
        """Extract numerical state vector from AgentState.

        Features are normalized to a bounded range: raw resource counters
        (tokens_used up to 1e5+) saturate the tanh output head at init,
        which zeroes gradients and makes training impossible.
        """
        vector = []

        vector.append(float(state.step_count) / 50.0)
        vector.append(float(state.trust_level))

        phase_map = {"IDLE": 0, "PLANNING": 1, "ACTING": 2, "OBSERVING": 3, "ANSWERING": 4}
        vector.append(float(phase_map.get(state.current_phase, 0)) / 4.0)

        vector.append(float(state.resource_usage.tokens_used) / 100000.0)
        vector.append(float(state.resource_usage.api_calls) / 100.0)
        vector.append(float(state.resource_usage.cost_usd) / 10.0)
        
        if state.context_embedding is not None:
            vector.extend(state.context_embedding[:3].tolist())
        else:
            vector.extend([0.0, 0.0, 0.0])
        
        if state.action_embedding is not None:
            vector.extend(state.action_embedding[:3].tolist())
        else:
            vector.extend([0.0, 0.0, 0.0])
        
        while len(vector) < self.state_dim:
            vector.append(0.0)
        
        return np.array(vector[:self.state_dim], dtype=np.float32)
    
    def evaluate_state(self, state: AgentState) -> float:
        """
        Evaluate the barrier function h(x) for a state.
        
        Returns:
            Barrier value. h(x) >= 0 means safe, h(x) < 0 means unsafe.
        """
        if self._model is None:
            raise RuntimeError("Neural CBF model not initialized")
        
        import torch
        
        self._model.eval()
        with torch.no_grad():
            state_tensor = self._state_to_tensor(state)
            h_value = self._model(state_tensor.unsqueeze(0)).item()
        
        return h_value
    
    def check_transition(
        self, current_state: AgentState, proposed_action: ToolCall
    ) -> Tuple[bool, str]:
        """
        Check if a state transition satisfies the D-CBF condition.
        
        Verifies: h(x_{k+1}) - h(x_k) >= -alpha(h(x_k))
        where alpha(h) = kappa * h (class-K function)
        """
        h_current = self.evaluate_state(current_state)
        
        if h_current < -self.safety_margin:
            return False, f"Current state unsafe: h(x)={h_current:.3f}"
        
        next_state = self._simulate_next_state(current_state, proposed_action)
        h_next = self.evaluate_state(next_state)
        
        alpha_h = self.alpha_kappa * max(0, h_current)
        cbf_condition = h_next - h_current >= -alpha_h
        
        if not cbf_condition:
            return False, (
                f"CBF condition violated: h(x_next) - h(x) = {h_next - h_current:.3f}, "
                f"required >= {-alpha_h:.3f}"
            )
        
        return True, ""
    
    def _simulate_next_state(
        self, current_state: AgentState, action: ToolCall
    ) -> AgentState:
        """
        Simulate the next state after executing an action.
        
        This is a simplified simulation. In production, you might use
        a learned dynamics model or rollout the actual agent.
        """
        from ..core.models import AgentState, ResourceMetrics
        
        next_state = AgentState(
            agent_id=current_state.agent_id,
            resource_usage=ResourceMetrics(
                tokens_used=current_state.resource_usage.tokens_used + 100,
                api_calls=current_state.resource_usage.api_calls + 1,
                cost_usd=current_state.resource_usage.cost_usd + 0.01,
            ),
            step_count=current_state.step_count + 1,
            current_phase="ACTING",
            trust_level=current_state.trust_level,
        )
        
        if current_state.context_embedding is not None:
            next_state.context_embedding = current_state.context_embedding.copy()
        
        return next_state
    
    def train(
        self,
        safe_states: List[AgentState],
        unsafe_states: List[AgentState],
        transitions: Optional[List[Tuple[AgentState, ToolCall, AgentState]]] = None,
        epochs: int = 100,
        batch_size: int = 32,
        learning_rate: float = 1e-3,
        cbf_weight: float = 1.0,
        classification_weight: float = 1.0,
    ) -> Dict[str, List[float]]:
        """
        Train the Neural CBF on safe and unsafe states.
        
        Args:
            safe_states: List of safe agent states.
            unsafe_states: List of unsafe agent states.
            transitions: Optional list of (state, action, next_state) tuples.
            epochs: Number of training epochs.
            batch_size: Batch size for training.
            learning_rate: Learning rate.
            cbf_weight: Weight for CBF condition loss.
            classification_weight: Weight for classification loss.
        
        Returns:
            Dictionary of training metrics.
        """
        import torch
        import torch.nn as nn
        import torch.optim as optim
        
        if self._model is None:
            raise RuntimeError("Model not initialized")
        
        optimizer = optim.Adam(self._model.parameters(), lr=learning_rate)
        
        history = {
            "total_loss": [],
            "classification_loss": [],
            "cbf_loss": [],
        }
        
        for epoch in range(epochs):
            self._model.train()
            
            epoch_losses = {"total": 0.0, "classification": 0.0, "cbf": 0.0}
            num_batches = 0
            
            for i in range(0, len(safe_states), batch_size):
                safe_batch = safe_states[i:i + batch_size]
                unsafe_batch = unsafe_states[i:i + batch_size] if i < len(unsafe_states) else []
                
                optimizer.zero_grad()
                
                safe_tensors = torch.stack([self._state_to_tensor(s) for s in safe_batch])
                safe_h = self._model(safe_tensors).squeeze()
                
                classification_loss = torch.mean(torch.relu(-safe_h + self.safety_margin))
                
                if unsafe_batch:
                    unsafe_tensors = torch.stack([self._state_to_tensor(s) for s in unsafe_batch])
                    unsafe_h = self._model(unsafe_tensors).squeeze()
                    classification_loss += torch.mean(torch.relu(unsafe_h + self.safety_margin))
                
                cbf_loss = torch.tensor(0.0, device=self.device)
                if transitions:
                    transition_batch = transitions[i:i + batch_size] if i < len(transitions) else []
                    for state, action, next_state in transition_batch:
                        h_current = self._model(self._state_to_tensor(state).unsqueeze(0)).squeeze()
                        h_next = self._model(self._state_to_tensor(next_state).unsqueeze(0)).squeeze()
                        
                        alpha_h = self.alpha_kappa * torch.relu(h_current)
                        cbf_violation = torch.relu(-alpha_h - (h_next - h_current))
                        cbf_loss = cbf_loss + cbf_violation
                    
                    if transition_batch:
                        cbf_loss = cbf_loss / len(transition_batch)
                
                total_loss = (
                    classification_weight * classification_loss +
                    cbf_weight * cbf_loss
                )
                
                total_loss.backward()
                optimizer.step()
                
                epoch_losses["total"] += total_loss.item()
                epoch_losses["classification"] += classification_loss.item()
                epoch_losses["cbf"] += cbf_loss.item()
                num_batches += 1
            
            if num_batches > 0:
                history["total_loss"].append(epoch_losses["total"] / num_batches)
                history["classification_loss"].append(epoch_losses["classification"] / num_batches)
                history["cbf_loss"].append(epoch_losses["cbf"] / num_batches)
            
            if (epoch + 1) % 10 == 0:
                logger.info(
                    f"Epoch {epoch + 1}/{epochs}: "
                    f"loss={history['total_loss'][-1]:.4f}, "
                    f"class={history['classification_loss'][-1]:.4f}, "
                    f"cbf={history['cbf_loss'][-1]:.4f}"
                )
        
        self._is_trained = True
        logger.info("Neural CBF training complete")
        
        return history
    
    def save_model(self, path: str) -> None:
        """Save the trained model to disk."""
        import torch
        
        if self._model is None:
            raise RuntimeError("Model not initialized")
        
        torch.save({
            "model_state_dict": self._model.state_dict(),
            "state_dim": self.state_dim,
            "hidden_dims": self.hidden_dims,
            "alpha_kappa": self.alpha_kappa,
            "safety_margin": self.safety_margin,
            "is_trained": self._is_trained,
        }, path)
        
        logger.info(f"Saved Neural CBF model to {path}")
    
    def load_model(self, path: str) -> None:
        """Load a trained model from disk."""
        import torch
        
        if self._model is None:
            raise RuntimeError("Model not initialized")
        
        checkpoint = torch.load(path, map_location=self.device, weights_only=False)
        self._model.load_state_dict(checkpoint["model_state_dict"])
        self._is_trained = checkpoint.get("is_trained", False)
        
        logger.info(f"Loaded Neural CBF model from {path}")
    
    def verify_barrier(
        self,
        test_states: List[AgentState],
        expected_safe: List[bool],
    ) -> Dict[str, float]:
        """
        Verify the barrier function on test states.
        
        Args:
            test_states: List of test states.
            expected_safe: List of booleans indicating expected safety.
        
        Returns:
            Dictionary with accuracy metrics.
        """
        if len(test_states) != len(expected_safe):
            raise ValueError("test_states and expected_safe must have same length")
        
        correct = 0
        true_positives = 0
        true_negatives = 0
        false_positives = 0
        false_negatives = 0
        
        for state, expected in zip(test_states, expected_safe):
            h_value = self.evaluate_state(state)
            predicted_safe = h_value >= 0
            
            if predicted_safe == expected:
                correct += 1
                if expected:
                    true_positives += 1
                else:
                    true_negatives += 1
            else:
                if predicted_safe:
                    false_positives += 1
                else:
                    false_negatives += 1
        
        accuracy = correct / len(test_states) if test_states else 0.0
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        
        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "true_positives": true_positives,
            "true_negatives": true_negatives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
        }
