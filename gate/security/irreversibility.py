"""
Irreversibility Handler
Classifies actions by reversibility and enforces dry-run + HITL workflows.
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from ..core.models import ToolCall, AgentState
from ..core.exceptions import SecurityViolation

logger = logging.getLogger(__name__)


class ActionClassification(str, Enum):
    """Classification of action reversibility and risk."""
    REVERSIBLE = "REVERSIBLE"
    IRREVERSIBLE_LOW_RISK = "IRREVERSIBLE_LOW_RISK"
    IRREVERSIBLE_HIGH_RISK = "IRREVERSIBLE_HIGH_RISK"
    CRITICAL = "CRITICAL"


@dataclass
class ImpactEstimate:
    """Estimate of an action's impact."""
    affected_entities: int = 0
    data_volume_bytes: int = 0
    external_communications: int = 0
    financial_impact_usd: float = 0.0
    estimated_duration_seconds: float = 0.0


@dataclass
class DryRunResult:
    """Result of executing an action in dry-run mode."""
    success: bool
    impact: ImpactEstimate
    risks_identified: List[str]
    warnings: List[str]
    shadow_output: Any = None
    transaction_id: str = ""


@dataclass
class ApprovalResult:
    """Result of human approval request."""
    approved: bool
    approver_id: Optional[str]
    justification: Optional[str]
    request_id: str
    timestamp: float


class IrreversibilityHandler:
    """
    Handles actions that cannot be easily undone.
    
    Workflow:
    1. Classify action (reversible vs irreversible)
    2. For irreversible: execute in dry-run mode first
    3. For high-risk/critical: require human approval
    4. Log everything with impact estimates
    """
    
    DEFAULT_CLASSIFICATIONS: Dict[str, ActionClassification] = {
        "search": ActionClassification.REVERSIBLE,
        "query": ActionClassification.REVERSIBLE,
        "read": ActionClassification.REVERSIBLE,
        "get": ActionClassification.REVERSIBLE,
        "update": ActionClassification.IRREVERSIBLE_LOW_RISK,
        "insert": ActionClassification.IRREVERSIBLE_LOW_RISK,
        "create": ActionClassification.IRREVERSIBLE_LOW_RISK,
        "send_email": ActionClassification.IRREVERSIBLE_HIGH_RISK,
        "send_message": ActionClassification.IRREVERSIBLE_HIGH_RISK,
        "delete": ActionClassification.IRREVERSIBLE_HIGH_RISK,
        "drop": ActionClassification.CRITICAL,
        "truncate": ActionClassification.CRITICAL,
        "process_payment": ActionClassification.CRITICAL,
        "transfer_funds": ActionClassification.CRITICAL,
        "refund": ActionClassification.CRITICAL,
    }
    
    RISK_ORDER = [
        ActionClassification.REVERSIBLE,
        ActionClassification.IRREVERSIBLE_LOW_RISK,
        ActionClassification.IRREVERSIBLE_HIGH_RISK,
        ActionClassification.CRITICAL,
    ]
    
    def __init__(
        self,
        custom_classifications: Optional[Dict[str, ActionClassification]] = None,
        dry_run_executor: Optional[Callable] = None,
        hitl_queue: Optional[Any] = None,
        require_approval_threshold: ActionClassification = ActionClassification.IRREVERSIBLE_HIGH_RISK,
    ):
        self.classifications: Dict[str, ActionClassification] = dict(self.DEFAULT_CLASSIFICATIONS)
        if custom_classifications:
            self.classifications.update(custom_classifications)
        
        self.dry_run_executor = dry_run_executor
        self.hitl_queue = hitl_queue
        self.require_approval_threshold = require_approval_threshold
    
    def classify_action(self, action: ToolCall) -> ActionClassification:
        """Classify an action by its reversibility and risk level."""
        tool_name = action.tool_name.lower()
        
        if tool_name in self.classifications:
            return self.classifications[tool_name]
        
        for keyword, classification in self.classifications.items():
            if keyword in tool_name:
                return classification
        
        if any(kw in tool_name for kw in ["write", "post", "put", "patch"]):
            return ActionClassification.IRREVERSIBLE_LOW_RISK
        
        return ActionClassification.REVERSIBLE
    
    async def execute_with_safeguards(
        self,
        action: ToolCall,
        state: AgentState,
        real_executor: Callable,
    ) -> Dict[str, Any]:
        """
        Execute an action with appropriate safeguards based on classification.
        """
        classification = self.classify_action(action)
        logger.info(f"Action {action.tool_name} classified as {classification.value}")
        
        result: Dict[str, Any] = {
            "classification": classification,
            "dry_run_result": None,
            "approval_result": None,
            "execution_result": None,
        }
        
        if classification == ActionClassification.REVERSIBLE:
            result["execution_result"] = await real_executor(action)
            return result
        
        if self.dry_run_executor:
            dry_run = await self.dry_run_executor(action)
            result["dry_run_result"] = dry_run
            
            if not dry_run.success:
                raise SecurityViolation(
                    f"Dry-run failed for {action.tool_name}",
                    details={"risks": dry_run.risks_identified, "warnings": dry_run.warnings},
                )
        
        if self._requires_approval(classification):
            if not self.hitl_queue:
                raise SecurityViolation(
                    f"Action {action.tool_name} requires human approval but no HITL queue configured",
                    details={"classification": classification.value},
                )
            
            approval = await self.hitl_queue.request_and_await_approval(
                action=action,
                agent_id=state.agent_id,
                risk_level=classification.value,
                dry_run_result=result["dry_run_result"],
            )
            result["approval_result"] = approval
            
            if not approval.approved:
                raise SecurityViolation(
                    f"Human approval denied for {action.tool_name}",
                    details={"reason": approval.justification},
                )
        
        result["execution_result"] = await real_executor(action)
        return result
    
    def _requires_approval(self, classification: ActionClassification) -> bool:
        """Check if classification requires human approval."""
        return self.RISK_ORDER.index(classification) >= self.RISK_ORDER.index(
            self.require_approval_threshold
        )
