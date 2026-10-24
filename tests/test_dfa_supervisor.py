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
