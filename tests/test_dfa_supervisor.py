"""Tests for DFA supervisor."""

import pytest
from gate.core.models import AgentState
from gate.security.dfa_supervisor import DefaultDFASupervisor


class TestDFASupervisor:
    """Tests for DFA supervisor."""
    
    def setup_method(self):
        self.supervisor = DefaultDFASupervisor(max_steps=10, max_loops_per_phase=2)
    
    def test_allows_valid_transition(self):
        state = AgentState(agent_id="test", current_phase="IDLE")
        allowed, reason = self.supervisor.propose_transition(state, "PLANNING")
        assert allowed is True
    
    def test_blocks_invalid_transition(self):
        state = AgentState(agent_id="test", current_phase="IDLE")
        allowed, reason = self.supervisor.propose_transition(state, "ACTING")
        assert allowed is False
        assert "Invalid transition" in reason
    
    def test_blocks_when_step_budget_exhausted(self):
        state = AgentState(agent_id="test", current_phase="PLANNING", step_count=10)
        allowed, reason = self.supervisor.propose_transition(state, "ACTING")
        assert allowed is False
        assert "Step budget exhausted" in reason
    
    def test_blocks_excessive_loops(self):
        state = AgentState(
            agent_id="test",
            current_phase="ACTING",
            loop_count={"ACTING": 2},
        )
        allowed, reason = self.supervisor.propose_transition(state, "ACTING")
        assert allowed is False
        assert "Too many loops" in reason
    
    def test_allows_observing_to_planning(self):
        state = AgentState(agent_id="test", current_phase="OBSERVING")
        allowed, reason = self.supervisor.propose_transition(state, "PLANNING")
        assert allowed is True
    
    def test_allows_planning_to_answering(self):
        state = AgentState(agent_id="test", current_phase="PLANNING")
        allowed, reason = self.supervisor.propose_transition(state, "ANSWERING")
        assert allowed is True

    def test_blocks_transition_from_terminal_state(self):
        state = AgentState(agent_id="test", current_phase="ANSWERING")
        allowed, reason = self.supervisor.propose_transition(state, "ACTING")
        assert allowed is False
        assert "terminal state" in reason


class TestValidateActionPhase:
    def setup_method(self):
        self.supervisor = DefaultDFASupervisor(max_steps=10, max_loops_per_phase=2)

    def test_idle_can_reach_acting(self):
        state = AgentState(agent_id="test", current_phase="IDLE")
        allowed, reason = self.supervisor.validate_action_phase(state)
        assert allowed is True

    def test_acting_ok_when_under_loop_limit(self):
        state = AgentState(
            agent_id="test", current_phase="ACTING", loop_count={"ACTING": 1}
        )
        allowed, _ = self.supervisor.validate_action_phase(state)
        assert allowed is True

    def test_acting_blocked_when_loops_exceeded(self):
        state = AgentState(
            agent_id="test", current_phase="ACTING", loop_count={"ACTING": 2}
        )
        allowed, reason = self.supervisor.validate_action_phase(state)
        assert allowed is False
        assert "Too many loops" in reason

    def test_terminal_state_blocked(self):
        state = AgentState(agent_id="test", current_phase="ANSWERING")
        allowed, reason = self.supervisor.validate_action_phase(state)
        assert allowed is False
        assert "terminal state" in reason

    def test_step_budget_blocked(self):
        state = AgentState(agent_id="test", current_phase="PLANNING", step_count=10)
        allowed, reason = self.supervisor.validate_action_phase(state)
        assert allowed is False
        assert "Step budget exhausted" in reason

    def test_unreachable_phase_blocked(self):
        state = AgentState(agent_id="test", current_phase="OBSERVING")
        # Remove the OBSERVING->PLANNING edge so no path to ACTING exists.
        self.supervisor.remove_transition("OBSERVING", "PLANNING")
        allowed, reason = self.supervisor.validate_action_phase(state)
        assert allowed is False
        assert "No legal transition path" in reason


class TestTransitionsAndHistory:
    def setup_method(self):
        self.supervisor = DefaultDFASupervisor(max_steps=10, max_loops_per_phase=2)

    def test_add_custom_transition(self):
        self.supervisor.add_transition("IDLE", "ACTING")
        state = AgentState(agent_id="test", current_phase="IDLE")
        allowed, _ = self.supervisor.propose_transition(state, "ACTING")
        assert allowed is True

    def test_remove_transition(self):
        self.supervisor.remove_transition("PLANNING", "ACTING")
        assert ("PLANNING", "ACTING") not in self.supervisor.valid_transitions

    def test_history_records_allowed_transition(self):
        state = AgentState(agent_id="test", current_phase="IDLE")
        self.supervisor.propose_transition(state, "PLANNING")
        history = self.supervisor.get_transition_history()
        assert len(history) == 1
        assert history[0][0] == "IDLE"
        assert history[0][1] == "PLANNING"

    def test_reset_history(self):
        state = AgentState(agent_id="test", current_phase="IDLE")
        self.supervisor.propose_transition(state, "PLANNING")
        self.supervisor.reset_history()
        assert self.supervisor.get_transition_history() == []
