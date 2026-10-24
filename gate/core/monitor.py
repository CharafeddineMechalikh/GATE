"""
gate Monitor Implementation
Main security monitoring layer that orchestrates all security checks.
Now supports Neural CBF, Enhanced D-CBF, trajectory tracking, and timeouts.
"""

import logging
from typing import Any, Dict, List, Optional
from datetime import datetime

from .interfaces import (
    SecurityMonitor,
    SemanticFirewall,
    SmartContract,
    DCBFMonitor,
    DFASupervisor,
    PrivilegeEnforcer,
)
from .config import gateConfig
from .models import ToolCall, AgentState, ValidationResult, SemanticScore
from .exceptions import (
    SecurityViolation,
    SemanticSafetyViolation,
    SemanticEscalation,
    ContractViolation,
    DCBFViolation,
    PrivilegeViolation,
    DataScopeViolation,
    ResourceBudgetExceeded,
    DFAViolation,
)
from ..audit.encrypted_logger import EncryptedAuditLogger, SecurityEvent

logger = logging.getLogger(__name__)


def _looks_like_data_resource(value: str) -> bool:
    """Identify tool arguments that name a data resource (db.table style).

    Free text (queries, message bodies) contains whitespace, and email
    addresses carry an "@"; both are judged by the tool-contract layer
    instead of the data-scope check.
    """
    if "@" in value or any(ch.isspace() for ch in value):
        return False
    return "." in value


class gateMonitor(SecurityMonitor):
    """
    Main security monitor that orchestrates all security checks.
    
    Implements the Agent Reference Monitor (ARM) pattern from the architecture.
    Supports both hand-crafted D-CBF and Neural CBF.
    """
    
    def __init__(
        self,
        config: gateConfig,
        semantic_firewall: Optional[SemanticFirewall] = None,
        contract_registry: Optional[Any] = None,
        dcbf_monitor: Optional[DCBFMonitor] = None,
        dfa_supervisor: Optional[DFASupervisor] = None,
        privilege_enforcer: Optional[PrivilegeEnforcer] = None,
        audit_logger: Optional[EncryptedAuditLogger] = None,
    ) -> None:
        self.config = config
        self.semantic_firewall = semantic_firewall
        self.contract_registry = contract_registry
        self.dcbf_monitor = dcbf_monitor
        self.dfa_supervisor = dfa_supervisor
        self.privilege_enforcer = privilege_enforcer
        self.audit_logger = audit_logger
        
        self._initialize_components()
        
        logger.info(f"gateMonitor initialized for agent: {config.agent_profile.agent_id}")
    
    def _initialize_components(self) -> None:
        """Initialize default components if not provided."""
        if self.config.is_check_enabled("semantic") and self.semantic_firewall is None:
            from ..security.semantic_firewall import DefaultSemanticFirewall
            self.semantic_firewall = DefaultSemanticFirewall(self.config)
        
        if self.config.is_check_enabled("contracts") and self.contract_registry is None:
            from ..security.smart_contracts import ContractRegistry
            self.contract_registry = ContractRegistry()
        
        if self.config.is_check_enabled("dcbf") and self.dcbf_monitor is None:
            if self.config.neural_cbf_config.enabled:
                from ..security.neural_cbf import NeuralCBF
                ncbf_config = self.config.neural_cbf_config
                self.dcbf_monitor = NeuralCBF(
                    state_dim=ncbf_config.state_dim,
                    hidden_dims=ncbf_config.hidden_dims,
                    alpha_kappa=ncbf_config.alpha_kappa,
                    safety_margin=ncbf_config.safety_margin,
                    model_path=ncbf_config.model_path,
                    device=ncbf_config.device,
                )
            else:
                from ..security.dcbf_monitor import EnhancedDCBFMonitor
                self.dcbf_monitor = EnhancedDCBFMonitor(
                    enable_verification=self.config.enable_forward_invariance_verification,
                )
        
        if self.config.is_check_enabled("dfa") and self.dfa_supervisor is None:
            from ..security.dfa_supervisor import DefaultDFASupervisor
            self.dfa_supervisor = DefaultDFASupervisor(
                max_steps=self.config.agent_profile.resource_budget.max_steps,
                max_loops_per_phase=self.config.agent_profile.resource_budget.max_loops_per_phase,
            )
        
        if self.config.is_check_enabled("privilege") and self.privilege_enforcer is None:
            from ..security.privilege_enforcer import DefaultPrivilegeEnforcer
            self.privilege_enforcer = DefaultPrivilegeEnforcer()
            self.privilege_enforcer.register_profile(self.config.agent_profile)
    
    async def validate_action(self, action: ToolCall, state: AgentState) -> ValidationResult:
        """
        Validate an action against all security checks.
        
        Runs checks in order:
        1. Privilege check
        2. DFA supervisor
        3. Smart contracts
        4. Semantic firewall
        5. D-CBF monitor
        """
        checks_passed: List[str] = []
        checks_failed: List[str] = []
        
        # 1. Privilege check
        if self.config.is_check_enabled("privilege") and self.privilege_enforcer:
            try:
                await self._check_privileges(action, state)
                checks_passed.append("privilege")
            except SecurityViolation as e:
                logger.warning(f"Privilege check failed: {e}")
                checks_failed.append("privilege")
                await self._log_violation(action, state, "PRIVILEGE_VIOLATION", str(e))
                return ValidationResult(
                    is_allowed=False,
                    reason=f"Privilege violation: {e.message}",
                    details=e.details,
                    checks_passed=checks_passed,
                    checks_failed=checks_failed,
                )
        
        # 2. DFA supervisor
        if self.config.is_check_enabled("dfa") and self.dfa_supervisor:
            try:
                await self._check_dfa_transition(action, state)
                checks_passed.append("dfa")
            except DFAViolation as e:
                logger.warning(f"DFA check failed: {e}")
                checks_failed.append("dfa")
                await self._log_violation(action, state, "DFA_VIOLATION", str(e))
                return ValidationResult(
                    is_allowed=False,
                    reason=f"DFA violation: {e.message}",
                    details=e.details,
                    checks_passed=checks_passed,
                    checks_failed=checks_failed,
                )
        
        # 3. Smart contracts
        if self.config.is_check_enabled("contracts") and self.contract_registry:
            try:
                await self._check_contracts(action, state)
                checks_passed.append("contracts")
            except ContractViolation as e:
                logger.warning(f"Contract check failed: {e}")
                checks_failed.append("contracts")
                await self._log_violation(action, state, "CONTRACT_VIOLATION", str(e))
                return ValidationResult(
                    is_allowed=False,
                    reason=f"Contract violation: {e.message}",
                    details=e.details,
                    checks_passed=checks_passed,
                    checks_failed=checks_failed,
                )
        
        # 4. Semantic firewall
        semantic_score = None
        if self.config.is_check_enabled("semantic") and self.semantic_firewall:
            try:
                semantic_score = await self._check_semantic_safety(action, state)
                checks_passed.append("semantic")
            except SemanticSafetyViolation as e:
                logger.warning(f"Semantic check failed: {e}")
                checks_failed.append("semantic")
                await self._log_violation(action, state, "SEMANTIC_VIOLATION", str(e))
                return ValidationResult(
                    is_allowed=False,
                    reason=f"Semantic safety violation: {e.message}",
                    details=e.details,
                    semantic_score=e.semantic_score or semantic_score,
                    checks_passed=checks_passed,
                    checks_failed=checks_failed,
                )
            if semantic_score.decision == "ESCALATE":
                # Fuzzy band: the call must not execute silently. It is
                # withheld and routed to the HITL approval queue (deny by
                # default until a human approves). Not a stage failure, so
                # it is not added to checks_failed and stays unattributed.
                logger.info(
                    f"Semantic escalation: SSS={semantic_score.sss_value:.4f} "
                    "in escalate band; routing to HITL approval queue"
                )
                await self._log_violation(
                    action, state, "SEMANTIC_ESCALATION",
                    f"SSS={semantic_score.sss_value:.4f} in escalate band; "
                    "withheld pending human approval",
                )
                return ValidationResult(
                    is_allowed=False,
                    escalated=True,
                    requires_approval=True,
                    reason=(
                        f"Semantic escalation: SSS={semantic_score.sss_value:.4f} "
                        "is in the escalate band; awaiting human approval"
                    ),
                    details={"needs_user_approval": True},
                    semantic_score=semantic_score,
                    checks_passed=checks_passed,
                    checks_failed=checks_failed,
                )
        
        # 5. D-CBF monitor
        if self.config.is_check_enabled("dcbf") and self.dcbf_monitor:
            try:
                await self._check_dcbf(action, state)
                checks_passed.append("dcbf")
            except DCBFViolation as e:
                logger.warning(f"D-CBF check failed: {e}")
                checks_failed.append("dcbf")
                await self._log_violation(action, state, "DCBF_VIOLATION", str(e))
                return ValidationResult(
                    is_allowed=False,
                    reason=f"D-CBF violation: {e.message}",
                    details=e.details,
                    semantic_score=semantic_score,
                    checks_passed=checks_passed,
                    checks_failed=checks_failed,
                )
        
        # All checks passed
        await self._log_action_approved(action, state)
        
        return ValidationResult(
            is_allowed=True,
            reason="All security checks passed",
            semantic_score=semantic_score,
            checks_passed=checks_passed,
            checks_failed=checks_failed,
        )
    
    async def validate_result(
        self, action: ToolCall, result: Any, state: AgentState
    ) -> ValidationResult:
        """Validate an executed tool's output against its contract postconditions.

        Runs after dispatch; a failed postcondition withholds the output from
        the agent. Contract evaluation errors fail closed, as in the
        pre-execution stages.
        """
        if not (self.config.is_check_enabled("contracts") and self.contract_registry):
            return ValidationResult(is_allowed=True, reason="Postcondition checks disabled")

        contract = self.contract_registry.get_contract(action.tool_name)
        if contract is None:
            return ValidationResult(is_allowed=True, reason="No contract for tool")

        try:
            is_valid = contract.validate_postcondition(action, result, state)
        except ContractViolation as e:
            logger.warning(f"Postcondition failed: {e}")
            await self._log_violation(
                action, state, "CONTRACT_POSTCONDITION_VIOLATION", str(e)
            )
            return ValidationResult(
                is_allowed=False,
                reason=f"Postcondition violation: {e.message}",
                details=e.details,
                checks_failed=["postcondition"],
            )
        except Exception as e:
            logger.error(f"Postcondition evaluation error: {e}", exc_info=True)
            await self._log_violation(
                action, state, "CONTRACT_POSTCONDITION_ERROR", str(e)
            )
            return ValidationResult(
                is_allowed=False,
                reason=f"Postcondition evaluation error: {e}",
                checks_failed=["postcondition"],
            )

        if not is_valid:
            await self._log_violation(
                action, state, "CONTRACT_POSTCONDITION_VIOLATION", "postcondition false"
            )
            return ValidationResult(
                is_allowed=False,
                reason=f"Postcondition failed for tool {action.tool_name}",
                checks_failed=["postcondition"],
            )

        return ValidationResult(
            is_allowed=True,
            reason="All postconditions passed",
            checks_passed=["postcondition"],
        )

    async def check_semantic_safety(
        self, action: str, tool_name: str, agent_id: str
    ) -> SemanticScore:
        """Check semantic safety of an action."""
        if not self.semantic_firewall:
            raise ValueError("Semantic firewall not configured")
        return self.semantic_firewall.check_semantic_safety(action, tool_name, agent_id)
    
    async def check_state_invariants(self, state: AgentState) -> bool:
        """Check all state invariants."""
        if not self.dcbf_monitor:
            return True
        
        barrier_value = self.dcbf_monitor.evaluate_state(state)
        return barrier_value >= 0
    
    async def log_event(self, event: SecurityEvent) -> None:
        """Log a security event."""
        if self.audit_logger:
            await self.audit_logger.log_event(event)
    
    async def _check_privileges(self, action: ToolCall, state: AgentState) -> None:
        """Check privilege enforcement."""
        agent_id = state.agent_id
        
        if not self.privilege_enforcer.check_tool_permission(agent_id, action.tool_name):
            raise PrivilegeViolation(
                f"Agent {agent_id} not authorized to use tool {action.tool_name}",
                agent_id=agent_id,
                resource=action.tool_name,
            )
        
        for key, value in action.tool_args.items():
            if isinstance(value, str) and _looks_like_data_resource(value):
                if not self.privilege_enforcer.check_data_scope(agent_id, value):
                    raise DataScopeViolation(
                        f"Agent {agent_id} not authorized to access {value}",
                        agent_id=agent_id,
                        data_resource=value,
                    )
        
        estimated_cost = action.metadata.get("estimated_cost", 0.0)
        if not self.privilege_enforcer.check_resource_budget(agent_id, estimated_cost):
            raise ResourceBudgetExceeded(
                f"Agent {agent_id} exceeded resource budget",
                agent_id=agent_id,
                resource_type="cost",
                limit=self.config.agent_profile.resource_budget.max_cost_usd,
                current=state.resource_usage.cost_usd + estimated_cost,
            )
    
    async def _check_dfa_transition(self, action: ToolCall, state: AgentState) -> None:
        """Check DFA state transition."""
        is_allowed, reason = self.dfa_supervisor.validate_action_phase(state)

        if not is_allowed:
            raise DFAViolation(
                f"DFA supervisor rejected action in phase {state.current_phase}: {reason}",
                current_state=state.current_phase,
                proposed_state="ACTING",
            )
    
    async def _check_contracts(self, action: ToolCall, state: AgentState) -> None:
        """Check smart contract preconditions."""
        contract = self.contract_registry.get_contract(action.tool_name)
        
        if contract:
            if not contract.validate_precondition(action, state):
                raise ContractViolation(
                    f"Precondition failed for tool {action.tool_name}",
                    contract_name=contract.__class__.__name__,
                    violation_type="PRECONDITION_FAILED",
                )
    
    async def _check_semantic_safety(
        self, action: ToolCall, state: AgentState
    ) -> SemanticScore:
        """Check semantic safety."""
        action_description = action.get_action_description()
        score = self.semantic_firewall.check_semantic_safety(
            action_description, action.tool_name, state.agent_id
        )
        
        if score.decision == "BLOCK":
            raise SemanticSafetyViolation(
                f"Action semantically unsafe: SSS={score.sss_value:.3f}",
                sss_score=score.sss_value,
                threshold=self.config.semantic_thresholds.sss_block_threshold,
                semantic_score=score,
            )
        
        return score
    
    async def _check_dcbf(self, action: ToolCall, state: AgentState) -> None:
        """Check D-CBF state invariants."""
        is_safe, reason = self.dcbf_monitor.check_transition(state, action)
        
        if not is_safe:
            barrier_value = self.dcbf_monitor.evaluate_state(state)
            raise DCBFViolation(
                f"D-CBF invariant violated: {reason}",
                barrier_value=barrier_value,
                barrier_name="composite",
            )
    
    async def _log_violation(
        self, action: ToolCall, state: AgentState, event_type: str, details: str
    ) -> None:
        """Log a security violation."""
        if self.audit_logger:
            event = SecurityEvent(
                event_type=event_type,
                agent_id=state.agent_id,
                tenant_id=self.config.tenant_id,
                tool_name=action.tool_name,
                tool_args=action.tool_args,
                violation_details={"reason": details},
            )
            await self.audit_logger.log_event(event)
    
    async def _log_action_approved(self, action: ToolCall, state: AgentState) -> None:
        """Log an approved action."""
        if self.audit_logger:
            event = SecurityEvent(
                event_type="ACTION_APPROVED",
                agent_id=state.agent_id,
                tenant_id=self.config.tenant_id,
                tool_name=action.tool_name,
                tool_args=action.tool_args,
            )
            await self.audit_logger.log_event(event)
