"""
gate Core Interfaces
Abstract base classes defining the contracts for all components.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from .models import ToolCall, AgentState, ValidationResult, SemanticScore


class SemanticFirewall(ABC):
    """Interface for semantic safety checking."""
    
    @abstractmethod
    def check_semantic_safety(self, action: str, tool_name: str, 
                             agent_id: str) -> SemanticScore:
        """
        Check if an action is semantically safe.
        
        Args:
            action: Natural language description of the action
            tool_name: Name of the tool being called
            agent_id: ID of the agent proposing the action
            
        Returns:
            SemanticScore with safety assessment
        """
        pass
    
    @abstractmethod
    def embed(self, text: str) -> np.ndarray:
        """
        Embed text into vector space.
        
        Args:
            text: Text to embed
            
        Returns:
            Embedding vector
        """
        pass
    
    @abstractmethod
    def set_intent_anchor(self, user_prompt: str):
        """
        Set the user's original intent as the anchor for drift detection.
        
        Args:
            user_prompt: The user's original request
        """
        pass


class SmartContract(ABC):
    """Interface for smart contract validation."""
    
    @abstractmethod
    def validate_precondition(self, action: ToolCall, state: AgentState) -> bool:
        """
        Validate precondition before tool execution.
        
        Args:
            action: Tool call to validate
            state: Current agent state
            
        Returns:
            True if precondition is satisfied
        """
        pass
    
    @abstractmethod
    def validate_postcondition(self, action: ToolCall, result: Any, 
                              state: AgentState) -> bool:
        """
        Validate postcondition after tool execution.
        
        Args:
            action: Tool call that was executed
            result: Result from tool execution
            state: Current agent state
            
        Returns:
            True if postcondition is satisfied
        """
        pass


class DCBFMonitor(ABC):
    """Interface for Discrete Control Barrier Function monitoring."""
    
    @abstractmethod
    def check_transition(self, current_state: AgentState, 
                        proposed_action: ToolCall) -> Tuple[bool, str]:
        """
        Check if a state transition is safe according to D-CBF.
        
        Args:
            current_state: Current agent state
            proposed_action: Proposed action
            
        Returns:
            Tuple of (is_safe, reason_if_unsafe)
        """
        pass
    
    @abstractmethod
    def evaluate_state(self, state: AgentState) -> float:
        """
        Evaluate the composite barrier function for a state.
        
        Args:
            state: Agent state to evaluate
            
        Returns:
            Composite barrier value (>= 0 means safe)
        """
        pass


class DFASupervisor(ABC):
    """Interface for DFA-based state machine supervision."""
    
    @abstractmethod
    def propose_transition(self, current_state: AgentState, 
                          next_phase: str) -> Tuple[bool, str]:
        """
        Propose a state transition.
        
        Args:
            current_state: Current agent state
            next_phase: Proposed next phase
            
        Returns:
            Tuple of (is_allowed, reason_if_denied)
        """
        pass

    @abstractmethod
    def validate_action_phase(self, current_state: AgentState) -> Tuple[bool, str]:
        """
        Check whether executing a tool is consistent with the phase machine.

        Unlike propose_transition (a single edge), this accepts a legal
        multi-hop path from the current phase to ACTING, so an agent that has
        not explicitly advanced its own phase can still act.

        Args:
            current_state: Current agent state

        Returns:
            Tuple of (is_allowed, reason_if_denied)
        """
        pass


class PrivilegeEnforcer(ABC):
    """Interface for privilege and capability enforcement."""
    
    @abstractmethod
    def check_tool_permission(self, agent_id: str, tool_name: str) -> bool:
        """
        Check if agent is allowed to use a tool.
        
        Args:
            agent_id: Agent identifier
            tool_name: Name of the tool
            
        Returns:
            True if allowed
        """
        pass
    
    @abstractmethod
    def check_data_scope(self, agent_id: str, resource: str) -> bool:
        """
        Check if agent can access a data resource.
        
        Args:
            agent_id: Agent identifier
            resource: Data resource identifier
            
        Returns:
            True if allowed
        """
        pass
    
    @abstractmethod
    def check_resource_budget(self, agent_id: str, 
                             estimated_cost: float) -> bool:
        """
        Check if agent is within resource budget.
        
        Args:
            agent_id: Agent identifier
            estimated_cost: Estimated cost of the action
            
        Returns:
            True if within budget
        """
        pass


class SecurityMonitor(ABC):
    """Main interface for the security monitoring layer."""
    
    @abstractmethod
    async def validate_action(self, action: ToolCall, state: AgentState) -> ValidationResult:
        """
        Validate an action against all security checks.
        
        Args:
            action: Tool call to validate
            state: Current agent state
            
        Returns:
            ValidationResult with decision and details
        """
        pass

    @abstractmethod
    async def validate_result(self, action: ToolCall, result: Any,
                              state: AgentState) -> ValidationResult:
        """
        Validate an executed tool's output against its postconditions.

        Args:
            action: Tool call that produced the output
            result: Tool output
            state: Current agent state

        Returns:
            ValidationResult with decision and details
        """
        pass
    
    @abstractmethod
    async def check_semantic_safety(self, action: str, tool_name: str, 
                             agent_id: str) -> SemanticScore:
        """
        Check semantic safety of an action.
        
        Args:
            action: Natural language description
            tool_name: Tool name
            agent_id: Agent ID
            
        Returns:
            SemanticScore
        """
        pass
    
    @abstractmethod
    async def check_state_invariants(self, state: AgentState) -> bool:
        """
        Check all state invariants.
        
        Args:
            state: Agent state
            
        Returns:
            True if all invariants hold
        """
        pass
    
    @abstractmethod
    async def log_event(self, event: Any):
        """
        Log a security event.
        
        Args:
            event: Event to log
        """
        pass


class SecureAgent(ABC):
    """Interface for a secured agent wrapper."""
    
    @abstractmethod
    def invoke(self, input: Any, **kwargs) -> Any:
        """
        Invoke the agent with security enforcement.
        
        Args:
            input: Agent input
            **kwargs: Additional arguments
            
        Returns:
            Agent output
        """
        pass
    
    @abstractmethod
    def get_state(self) -> AgentState:
        """
        Get current agent state.
        
        Returns:
            AgentState
        """
        pass
    
    @abstractmethod
    def terminate(self):
        """Terminate the agent."""
        pass


class AgentFrameworkAdapter(ABC):
    """Interface for framework-specific adapters."""
    
    @abstractmethod
    def wrap_agent(self, agent: Any, config: "gateConfig") -> SecureAgent:
        """
        Wrap a framework-specific agent with gate security.
        
        Args:
            agent: Framework-specific agent object
            config: gate configuration
            
        Returns:
            SecureAgent wrapper
        """
        pass
    
    @abstractmethod
    def extract_state(self, agent: Any) -> AgentState:
        """
        Extract agent state from framework-specific agent.
        
        Args:
            agent: Framework-specific agent object
            
        Returns:
            AgentState
        """
        pass
    
    @abstractmethod
    def inject_monitoring(self, agent: Any, monitor: SecurityMonitor):
        """
        Inject security monitoring into framework-specific agent.
        
        Args:
            agent: Framework-specific agent object
            monitor: SecurityMonitor instance
        """
        pass
    
    @abstractmethod
    def get_tool_calls(self, agent: Any) -> List[ToolCall]:
        """
        Extract tool calls from framework-specific agent.
        
        Args:
            agent: Framework-specific agent object
            
        Returns:
            List of ToolCall objects
        """
        pass
    
    @abstractmethod
    def get_agent_id(self, agent: Any) -> str:
        """
        Get agent ID from framework-specific agent.
        
        Args:
            agent: Framework-specific agent object
            
        Returns:
            Agent ID string
        """
        pass
