"""
Discrete Control Barrier Function Monitor
Enhanced implementation with proper class-K functions, state tracking,
and forward invariance verification.
"""

import copy
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import numpy as np

from ..core.interfaces import DCBFMonitor
from ..core.models import ToolCall, AgentState

logger = logging.getLogger(__name__)


class ClassKFunction:
    """
    Class-K function for D-CBF condition.
    
    A function α: [0, ∞) → [0, ∞) is class-K if:
    - α(0) = 0
    - α is strictly increasing
    - α is continuous
    
    We use α(h) = κ * h^p for κ ∈ (0, 1] and p ≥ 1. With κ = 1 the condition
    h(x_{k+1}) - h(x_k) >= -α(h(x_k)) reduces to h(x_{k+1}) >= 0, i.e. the
    successor must stay inside the safe set. Smaller κ demands a margin that
    shrinks with distance from the boundary.
    """
    
    def __init__(self, kappa: float = 1.0, power: float = 1.0) -> None:
        """
        Initialize class-K function.
        
        Args:
            kappa: Scaling parameter (0 < kappa <= 1).
            power: Power parameter (power >= 1).
        """
        if not 0 < kappa <= 1:
            raise ValueError(f"kappa must be in (0, 1], got {kappa}")
        if power < 1:
            raise ValueError(f"power must be >= 1, got {power}")
        
        self.kappa = kappa
        self.power = power
    
    def __call__(self, h: float) -> float:
        """Evaluate α(h)."""
        return self.kappa * (max(0, h) ** self.power)
    
    def __repr__(self) -> str:
        return f"ClassKFunction(kappa={self.kappa}, power={self.power})"


class BarrierFunction:
    """
    Individual barrier function with metadata.
    """
    
    def __init__(
        self,
        name: str,
        func: Callable[[AgentState], float],
        weight: float = 1.0,
        margin: float = 0.0,
    ) -> None:
        """
        Initialize barrier function.
        
        Args:
            name: Name of the barrier.
            func: Function that takes AgentState and returns barrier value.
            weight: Weight in composite barrier (higher = more important).
            margin: Safety margin (barrier must be >= margin to be safe).
        """
        self.name = name
        self.func = func
        self.weight = weight
        self.margin = margin
    
    def evaluate(self, state: AgentState) -> float:
        """Evaluate the barrier function."""
        try:
            value = self.func(state)
            return value - self.margin
        except Exception as e:
            logger.error(f"Barrier {self.name} evaluation failed: {e}")
            return -1.0
    
    def __repr__(self) -> str:
        return f"BarrierFunction(name={self.name}, weight={self.weight}, margin={self.margin})"


class EnhancedDCBFMonitor(DCBFMonitor):
    """
    Enhanced Discrete Control Barrier Function Monitor.

    The safe set is the intersection of the per-barrier superlevel sets. A
    proposed call is admitted only if the current state is inside it and every
    barrier satisfies the discrete forward-invariance condition on the successor
    predicted by the executable-call model (see `_simulate_next_state`).

    Features:
    - Proper class-K functions for D-CBF condition
    - Explicit successor model over history, step count and declared cost
    - Forward invariance verification
    - Configurable barrier margins and weights
    - Support for custom barrier functions
    """
    
    def __init__(
        self,
        alpha_function: Optional[ClassKFunction] = None,
        safety_margin: float = 0.1,
        privacy_budget: float = 0.5,
        resource_limit: float = 10.0,
        max_drift: float = 0.8,
        step_budget: int = 50,
        enable_verification: bool = True,
        per_call_cost_usd: float = 0.01,
    ) -> None:
        """
        Initialize enhanced D-CBF monitor.
        
        Args:
            alpha_function: Class-K function for D-CBF condition.
            safety_margin: Margin for safety barrier.
            privacy_budget: Budget for privacy barrier.
            resource_limit: Limit for resource barrier.
            max_drift: Maximum allowed semantic drift.
            step_budget: Maximum number of steps.
            enable_verification: Enable forward invariance verification.
            per_call_cost_usd: Cost charged in the successor model when the
                proposed action declares no `estimated_cost` metadata.
        """
        self.alpha = alpha_function or ClassKFunction(kappa=1.0, power=1.0)
        self.enable_verification = enable_verification
        # The corpus envelopes write 0.0 to mean "unset", not a zero budget.
        self.privacy_budget = privacy_budget if privacy_budget > 0 else 0.5
        self.per_call_cost_usd = per_call_cost_usd

        self.barriers: Dict[str, BarrierFunction] = {}
        self._state_history: List[Tuple[AgentState, float]] = []
        
        self._register_default_barriers(
            safety_margin, privacy_budget, resource_limit, max_drift, step_budget
        )
        
        logger.info(f"EnhancedDCBFMonitor initialized with alpha={self.alpha}")
    
    def _register_default_barriers(
        self,
        safety_margin: float,
        privacy_budget: float,
        resource_limit: float,
        max_drift: float,
        step_budget: int,
    ) -> None:
        """Register default barrier functions."""
        self.add_barrier(
            "safety",
            lambda state: self._h_safety(state),
            weight=1.0,
            margin=safety_margin,
        )
        
        self.add_barrier(
            "privacy",
            lambda state: self._h_privacy(state),
            weight=1.5,
            margin=0.0,
        )
        
        self.add_barrier(
            "resource",
            lambda state: self._h_resource(state, resource_limit),
            weight=1.0,
            margin=0.0,
        )
        
        self.add_barrier(
            "scope",
            lambda state: self._h_scope(state, max_drift),
            weight=1.2,
            margin=0.0,
        )
        
        self.add_barrier(
            "stability",
            lambda state: self._h_stability(state, step_budget),
            weight=1.0,
            margin=0.0,
        )
    
    def add_barrier(
        self,
        name: str,
        func: Callable[[AgentState], float],
        weight: float = 1.0,
        margin: float = 0.0,
    ) -> None:
        """Add a custom barrier function."""
        self.barriers[name] = BarrierFunction(name, func, weight, margin)
        logger.debug(f"Added barrier: {name} (weight={weight}, margin={margin})")
    
    def remove_barrier(self, name: str) -> None:
        """Remove a barrier function."""
        if name in self.barriers:
            del self.barriers[name]
            logger.debug(f"Removed barrier: {name}")
    
    def evaluate_state(self, state: AgentState) -> float:
        """
        Evaluate the composite barrier function for a state.
        
        Returns weighted minimum of all barrier values.
        """
        if not self.barriers:
            return 0.0
        
        barrier_values = []
        weights = []
        
        for name, barrier in self.barriers.items():
            value = barrier.evaluate(state)
            barrier_values.append(value)
            weights.append(barrier.weight)
            
            logger.debug(f"Barrier {name}: h={value:.3f}")
        
        weights_array = np.array(weights)
        values_array = np.array(barrier_values)
        
        composite = np.average(values_array, weights=weights_array)
        
        self._state_history.append((state, composite))
        if len(self._state_history) > 100:
            self._state_history.pop(0)
        
        return float(composite)
    
    def check_transition(
        self, current_state: AgentState, proposed_action: ToolCall
    ) -> Tuple[bool, str]:
        """Check if a state transition satisfies the D-CBF condition.

        The safe set is the intersection C = {x : h_i(x) >= 0 for all barriers i}
        (Ames et al. 2019; Agrawal & Sreenath 2017). A transition is admitted only
        if (a) the current state lies inside C (every per-barrier value h_i >= 0)
        and (b) each barrier satisfies the discrete forward-invariance condition
            h_i(x_{k+1}) - h_i(x_k) >= -alpha(h_i(x_k)).
        Enforcing per-barrier (rather than on a weighted composite) is the
        standard multi-barrier formulation: a single breached barrier means the
        state has left the safe set regardless of how healthy the others are.
        """
        values_now = self.get_barrier_values(current_state)

        # (a) Current state must be inside the safe set: every h_i >= 0.
        breached = sorted(k for k, v in values_now.items() if v < 0.0)
        if breached:
            return False, (
                f"Current state unsafe: barrier(s) {breached} < 0 "
                f"({', '.join(f'{k}={values_now[k]:.3f}' for k in breached)})"
            )

        if not self.enable_verification:
            return True, ""

        # (b) Per-barrier discrete forward-invariance condition on the successor
        # predicted by the declared model: the proposed call is appended to the
        # tool history, the step count advances by one, and the cost advances by
        # the action's declared estimate (or the configured per-call cost). Every
        # barrier is a function of these components, so the prediction is exact
        # up to the cost estimate; at alpha(h) = h the condition reduces to
        # h_i(x_{k+1}) >= 0.
        next_state = self._simulate_next_state(current_state, proposed_action)
        values_next = self.get_barrier_values(next_state)

        for name in values_now:
            h_i = values_now[name]
            hn_i = values_next[name]
            alpha_h = self.alpha(h_i)
            delta = hn_i - h_i
            if delta < -alpha_h - 1e-9:
                return False, (
                    f"CBF condition violated on barrier '{name}': "
                    f"delta_h={delta:.3f}, required >= -alpha(h)={-alpha_h:.3f}"
                )

        logger.debug(
            "Per-barrier CBF condition satisfied: %s",
            ", ".join(f"{k}={v:.3f}" for k, v in values_now.items()),
        )
        return True, ""
    
    def _simulate_next_state(
        self, current_state: AgentState, action: ToolCall
    ) -> AgentState:
        """Predict the successor state under the executable-call model.

        The barriers depend on the tool history, the step count, the cumulative
        cost and the embeddings. The model is exact on the first three: the call
        is appended to the history, the step advances by one, and the cost
        advances by the declared estimate (a call that declares none is charged
        `per_call_cost_usd`). Embeddings are carried unchanged because the
        outbound content is unknown before execution.
        """
        cost = float(action.metadata.get("estimated_cost", self.per_call_cost_usd))

        next_state = copy.copy(current_state)
        next_state.tool_history = list(current_state.tool_history) + [action]
        next_state.resource_usage = copy.copy(current_state.resource_usage)
        next_state.resource_usage.cost_usd = current_state.resource_usage.cost_usd + cost
        next_state.step_count = current_state.step_count + 1
        next_state.loop_count = dict(current_state.loop_count)
        next_state.current_phase = "ACTING"
        return next_state
    
    def verify_forward_invariance(
        self,
        test_states: List[AgentState],
        test_actions: List[ToolCall],
    ) -> Dict[str, Any]:
        """
        Verify forward invariance on test data.
        
        Args:
            test_states: List of test states.
            test_actions: List of corresponding actions.
        
        Returns:
            Dictionary with verification metrics.
        """
        if len(test_states) != len(test_actions):
            raise ValueError("test_states and test_actions must have same length")
        
        violations = 0
        total_checks = 0

        for state, action in zip(test_states, test_actions):
            values_now = self.get_barrier_values(state)
            # Only transitions starting inside the safe set are informative:
            # a violated invariant cannot be "preserved" by the successor.
            if any(v < 0 for v in values_now.values()):
                continue

            values_next = self.get_barrier_values(
                self._simulate_next_state(state, action)
            )
            if any(
                values_next[name] - h < -self.alpha(h) - 1e-9
                for name, h in values_now.items()
            ):
                violations += 1

            total_checks += 1
        
        violation_rate = violations / total_checks if total_checks > 0 else 0.0
        
        return {
            "total_checks": total_checks,
            "violations": violations,
            "violation_rate": violation_rate,
            "forward_invariant": violations == 0,
        }
    
    def _h_safety(self, state: AgentState) -> float:
        """Safety barrier: distance from dangerous tool combos."""
        recent_tools = [tc.tool_name for tc in state.get_recent_tool_calls(5)]
        
        dangerous_combos = [
            {"sql_query", "http_request"},
            {"file_read", "send_email"},
            {"database_query", "webhook_post"},
        ]
        
        risk = 0.0
        for combo in dangerous_combos:
            if combo.issubset(set(recent_tools)):
                risk += 1.0
        
        return 1.0 - risk
    
    def _h_privacy(self, state: AgentState) -> float:
        """Privacy barrier: PII exposure risk.

        The budget is applied exactly once, here, and the barrier is registered
        with a zero margin so it is not subtracted twice. Exposure is 0.2 per
        outbound call, so with the default budget of 0.5 the first two outbound
        actions are admitted and the third breaches.
        """
        pii_exposure = 0.0

        for tool_call in state.tool_history:
            if tool_call.tool_name in ["send_email", "http_request"]:
                pii_exposure += 0.2

        return self.privacy_budget - pii_exposure
    
    def _h_resource(self, state: AgentState, resource_limit: float) -> float:
        """Resource barrier: budget remaining."""
        cost = state.resource_usage.cost_usd
        return resource_limit - cost
    
    def _h_scope(self, state: AgentState, max_drift: float) -> float:
        """Scope barrier: semantic drift from original intent."""
        if state.context_embedding is None or state.action_embedding is None:
            return max_drift
        
        drift = np.linalg.norm(state.action_embedding - state.context_embedding)
        return max_drift - drift
    
    def _h_stability(self, state: AgentState, step_budget: int) -> float:
        """Stability barrier: loop detection."""
        return float(step_budget - state.step_count)
    
    def get_barrier_values(self, state: AgentState) -> Dict[str, float]:
        """Get individual barrier values for a state."""
        return {name: barrier.evaluate(state) for name, barrier in self.barriers.items()}
    
    def get_state_history(self) -> List[Tuple[AgentState, float]]:
        """Get the state history with composite barrier values."""
        return self._state_history.copy()
