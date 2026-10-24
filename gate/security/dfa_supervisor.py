"""
DFA Supervisor Implementation
Enhanced with configurable transitions and detailed state tracking.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple

from ..core.interfaces import DFASupervisor
from ..core.models import AgentState
from ..core.exceptions import DFAViolation

logger = logging.getLogger(__name__)


class DefaultDFASupervisor(DFASupervisor):
    """Default implementation of DFA supervisor."""
    
    DEFAULT_VALID_TRANSITIONS: Set[Tuple[str, str]] = {
        ("IDLE", "PLANNING"),
        ("PLANNING", "ACTING"),
        ("PLANNING", "ANSWERING"),
        ("ACTING", "OBSERVING"),
        ("OBSERVING", "PLANNING"),
        ("OBSERVING", "ANSWERING"),
    }
    
    TERMINAL_STATES: Set[str] = {"ANSWERING", "REJECTED", "EXHAUSTED"}
    
    def __init__(
        self,
        max_steps: int = 50,
        max_loops_per_phase: int = 3,
        valid_transitions: Optional[Set[Tuple[str, str]]] = None,
    ) -> None:
        self.max_steps = max_steps
        self.max_loops_per_phase = max_loops_per_phase
        self.valid_transitions = valid_transitions or self.DEFAULT_VALID_TRANSITIONS
        
        self._transition_history: List[Tuple[str, str, float]] = []
        
        logger.info(f"DFASupervisor initialized: max_steps={max_steps}")
    
    def propose_transition(
        self, current_state: AgentState, next_phase: str
    ) -> Tuple[bool, str]:
        """Propose a state transition."""
        current_phase = current_state.current_phase
        
        if current_state.step_count >= self.max_steps:
            return False, f"Step budget exhausted: {current_state.step_count}/{self.max_steps}"
        
        if current_phase in self.TERMINAL_STATES:
            return False, f"Cannot transition from terminal state: {current_phase}"
        
        loop_count = current_state.loop_count.get(next_phase, 0)
        if current_phase == next_phase and loop_count >= self.max_loops_per_phase:
            return False, f"Too many loops in {next_phase}: {loop_count}/{self.max_loops_per_phase}"
        
        if (current_phase, next_phase) not in self.valid_transitions:
            return False, f"Invalid transition: {current_phase} → {next_phase}"
        
        import time
        self._transition_history.append((current_phase, next_phase, time.time()))
        
        logger.debug(f"Transition allowed: {current_phase} → {next_phase}")
        return True, ""
    
    def validate_action_phase(
        self, current_state: AgentState
    ) -> Tuple[bool, str]:
        """Check whether executing a tool now is consistent with the phase machine.

        Walks the shortest legal transition path from the current phase to
        ACTING (e.g. IDLE → PLANNING → ACTING) instead of requiring a single
        direct edge, while still enforcing the step budget, terminal states,
        and per-phase loop limits. No state is mutated and no transition is
        recorded: the agent runtime owns actual phase advancement.
        """
        current_phase = current_state.current_phase

        if current_state.step_count >= self.max_steps:
            return False, f"Step budget exhausted: {current_state.step_count}/{self.max_steps}"

        if current_phase in self.TERMINAL_STATES:
            return False, f"Cannot transition from terminal state: {current_phase}"

        if current_phase == "ACTING":
            loop_count = current_state.loop_count.get("ACTING", 0)
            if loop_count >= self.max_loops_per_phase:
                return False, f"Too many loops in ACTING: {loop_count}/{self.max_loops_per_phase}"
            return True, ""

        if self._shortest_path(current_phase, "ACTING") is None:
            return False, f"No legal transition path: {current_phase} → ACTING"

        return True, ""

    def _shortest_path(self, start_phase: str, target_phase: str) -> Optional[List[str]]:
        """BFS shortest hop sequence between phases, or None if unreachable."""
        from collections import deque

        if start_phase == target_phase:
            return []

        queue = deque([(start_phase, [])])
        visited = {start_phase}
        while queue:
            phase, path = queue.popleft()
            for src, dst in self.valid_transitions:
                if src != phase or dst in visited:
                    continue
                if dst == target_phase:
                    return path + [dst]
                queue.append((dst, path + [dst]))
                visited.add(dst)
        return None

    def add_transition(self, from_phase: str, to_phase: str) -> None:
        """Add a custom valid transition."""
        self.valid_transitions.add((from_phase, to_phase))
        logger.debug(f"Added transition: {from_phase} → {to_phase}")
    
    def remove_transition(self, from_phase: str, to_phase: str) -> None:
        """Remove a valid transition."""
        self.valid_transitions.discard((from_phase, to_phase))
        logger.debug(f"Removed transition: {from_phase} → {to_phase}")
    
    def get_transition_history(self) -> List[Tuple[str, str, float]]:
        """Get the transition history."""
        return self._transition_history.copy()
    
    def reset_history(self) -> None:
        """Reset the transition history."""
        self._transition_history = []
