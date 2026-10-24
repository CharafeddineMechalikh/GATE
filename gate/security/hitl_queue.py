"""
Human-in-the-Loop Approval Queue
Queue for human approval of high-risk actions.
"""

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum

from ..core.models import ToolCall

logger = logging.getLogger(__name__)


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


@dataclass
class ApprovalRequest:
    """A request for human approval."""
    request_id: str
    agent_id: str
    tenant_id: str
    action: ToolCall
    risk_level: str
    dry_run_result: Optional[Any]
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    approver_id: Optional[str] = None
    justification: Optional[str] = None
    sla_timeout_seconds: int = 300


@dataclass
class ApprovalResult:
    """Result of an approval request."""
    approved: bool
    approver_id: Optional[str]
    justification: Optional[str]
    request_id: str
    timestamp: datetime


def _post_json(url: str, payload: Dict[str, Any], timeout: float = 10.0) -> bool:
    """Blocking JSON POST; returns True on 2xx."""
    import json
    import urllib.request
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return 200 <= resp.status < 300


class NotificationChannel:
    """Abstract notification channel for approval requests."""
    
    async def send(self, request: ApprovalRequest) -> bool:
        raise NotImplementedError


class SlackNotificationChannel(NotificationChannel):
    """Send approval requests to Slack via incoming webhook."""
    
    def __init__(self, webhook_url: str, channel: str) -> None:
        self.webhook_url = webhook_url
        self.channel = channel
    
    async def send(self, request: ApprovalRequest) -> bool:
        logger.info(f"[Slack] Approval request {request.request_id} -> {self.channel}")
        payload = {
            "channel": self.channel,
            "text": (
                f"gate approval needed [{request.risk_level}] "
                f"agent={request.agent_id} tenant={request.tenant_id} "
                f"tool={request.action.tool_name} id={request.request_id}"
            ),
        }
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, _post_json, self.webhook_url, payload)
        except Exception as e:
            logger.error(f"[Slack] notification failed: {e}")
            return False


class PagerDutyNotificationChannel(NotificationChannel):
    """Send critical approval requests to PagerDuty (Events API v2)."""
    
    EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"
    
    def __init__(self, integration_key: str) -> None:
        self.integration_key = integration_key
    
    async def send(self, request: ApprovalRequest) -> bool:
        logger.info(f"[PagerDuty] Critical approval: {request.request_id}")
        payload = {
            "routing_key": self.integration_key,
            "event_action": "trigger",
            "dedup_key": request.request_id,
            "payload": {
                "summary": (
                    f"gate critical approval: {request.action.tool_name} "
                    f"by {request.agent_id}"
                ),
                "source": "gate",
                "severity": "critical",
                "custom_details": {"tenant_id": request.tenant_id,
                                   "risk_level": request.risk_level},
            },
        }
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, _post_json, self.EVENTS_URL, payload)
        except Exception as e:
            logger.error(f"[PagerDuty] notification failed: {e}")
            return False


class HumanApprovalQueue:
    """
    Queue for human approval of high-risk actions.
    """
    
    def __init__(
        self,
        notification_channels: Optional[List[NotificationChannel]] = None,
        default_sla_seconds: int = 300,
        max_pending_requests: int = 100,
    ) -> None:
        self.notification_channels = notification_channels or []
        self.default_sla = default_sla_seconds
        self.max_pending = max_pending_requests
        
        self._pending: Dict[str, ApprovalRequest] = {}
        self._events: Dict[str, asyncio.Event] = {}
        self._results: Dict[str, ApprovalResult] = {}
        self._audit_log: List[ApprovalRequest] = []
    
    async def request_and_await_approval(
        self,
        action: ToolCall,
        agent_id: str,
        risk_level: str,
        dry_run_result: Optional[Any] = None,
        tenant_id: str = "default",
        sla_seconds: Optional[int] = None,
    ) -> ApprovalResult:
        """
        Request human approval and wait for response.
        Raises TimeoutError if SLA is exceeded.
        """
        request_id = str(uuid.uuid4())
        sla = sla_seconds or self.default_sla
        
        request = ApprovalRequest(
            request_id=request_id,
            agent_id=agent_id,
            tenant_id=tenant_id,
            action=action,
            risk_level=risk_level,
            dry_run_result=dry_run_result,
            sla_timeout_seconds=sla,
        )
        
        if len(self._pending) >= self.max_pending:
            logger.error("Approval queue full, rejecting request")
            return ApprovalResult(
                approved=False,
                approver_id="system",
                justification="Approval queue full",
                request_id=request_id,
                timestamp=datetime.utcnow(),
            )
        
        self._pending[request_id] = request
        self._events[request_id] = asyncio.Event()
        
        await self._notify(request)
        
        logger.info(f"Approval requested: {request_id} for {action.tool_name} ({risk_level})")
        
        try:
            await asyncio.wait_for(self._events[request_id].wait(), timeout=sla)
        except asyncio.TimeoutError:
            logger.warning(f"Approval SLA exceeded: {request_id}")
            request.status = ApprovalStatus.EXPIRED
            request.resolved_at = datetime.utcnow()
            self._audit_log.append(request)
            del self._pending[request_id]
            del self._events[request_id]
            return ApprovalResult(
                approved=False,
                approver_id="system",
                justification=f"SLA timeout ({sla}s)",
                request_id=request_id,
                timestamp=datetime.utcnow(),
            )
        
        result = self._results.pop(request_id)
        del self._pending[request_id]
        del self._events[request_id]
        self._audit_log.append(request)
        
        return result
    
    async def approve(
        self,
        request_id: str,
        approver_id: str,
        justification: str = "",
    ) -> None:
        """Approve a pending request."""
        if request_id not in self._pending:
            raise ValueError(f"Unknown or expired request: {request_id}")
        
        request = self._pending[request_id]
        request.status = ApprovalStatus.APPROVED
        request.resolved_at = datetime.utcnow()
        request.approver_id = approver_id
        request.justification = justification
        
        self._results[request_id] = ApprovalResult(
            approved=True,
            approver_id=approver_id,
            justification=justification,
            request_id=request_id,
            timestamp=datetime.utcnow(),
        )
        
        self._events[request_id].set()
        logger.info(f"Request {request_id} approved by {approver_id}")
    
    async def reject(
        self,
        request_id: str,
        approver_id: str,
        reason: str = "",
    ) -> None:
        """Reject a pending request."""
        if request_id not in self._pending:
            raise ValueError(f"Unknown or expired request: {request_id}")
        
        request = self._pending[request_id]
        request.status = ApprovalStatus.REJECTED
        request.resolved_at = datetime.utcnow()
        request.approver_id = approver_id
        request.justification = reason
        
        self._results[request_id] = ApprovalResult(
            approved=False,
            approver_id=approver_id,
            justification=reason,
            request_id=request_id,
            timestamp=datetime.utcnow(),
        )
        
        self._events[request_id].set()
        logger.info(f"Request {request_id} rejected by {approver_id}: {reason}")
    
    async def _notify(self, request: ApprovalRequest) -> None:
        """Send notifications through all configured channels."""
        for channel in self.notification_channels:
            try:
                await channel.send(request)
            except Exception as e:
                logger.error(f"Notification failed: {e}")
    
    def get_pending_requests(self) -> List[ApprovalRequest]:
        """Get all pending approval requests."""
        return list(self._pending.values())
    
    def get_audit_log(self) -> List[ApprovalRequest]:
        """Get the full audit log of approval decisions."""
        return self._audit_log.copy()
