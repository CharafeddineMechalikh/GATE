"""Unit tests for the human-in-the-loop approval queue.

The notification channels are exercised through a monkeypatched transport so no
HTTP request leaves the process; the Slack and PagerDuty classes are still run
for their payload building and error handling.
"""

import asyncio

import pytest

from gate.core.models import ToolCall
from gate.security import hitl_queue
from gate.security.hitl_queue import (
    ApprovalStatus,
    HumanApprovalQueue,
    NotificationChannel,
    PagerDutyNotificationChannel,
    SlackNotificationChannel,
)


def _action(name="send_email"):
    return ToolCall(tool_name=name, tool_args={"to": "all@corp"}, call_id="c1")


async def _await_pending(queue):
    for _ in range(200):
        pending = queue.get_pending_requests()
        if pending:
            return pending[0].request_id
        await asyncio.sleep(0)
    raise AssertionError("request never became pending")


@pytest.mark.asyncio
async def test_approve_resolves_request():
    queue = HumanApprovalQueue(default_sla_seconds=5)
    task = asyncio.create_task(queue.request_and_await_approval(_action(), "a1", "high"))
    rid = await _await_pending(queue)
    await queue.approve(rid, "alice", "looks fine")
    result = await task
    assert result.approved is True
    assert result.approver_id == "alice"
    assert result.justification == "looks fine"
    assert queue.get_pending_requests() == []
    log = queue.get_audit_log()
    assert log and log[-1].status == ApprovalStatus.APPROVED


@pytest.mark.asyncio
async def test_reject_resolves_request():
    queue = HumanApprovalQueue(default_sla_seconds=5)
    task = asyncio.create_task(queue.request_and_await_approval(_action(), "a1", "high"))
    rid = await _await_pending(queue)
    await queue.reject(rid, "bob", "wrong customer")
    result = await task
    assert result.approved is False
    assert result.justification == "wrong customer"
    assert queue.get_audit_log()[-1].status == ApprovalStatus.REJECTED


@pytest.mark.asyncio
async def test_sla_expiry_marks_expired():
    queue = HumanApprovalQueue(default_sla_seconds=1)
    result = await queue.request_and_await_approval(_action(), "a1", "high", sla_seconds=1)
    assert result.approved is False
    assert "SLA timeout" in result.justification
    assert queue.get_audit_log()[-1].status == ApprovalStatus.EXPIRED
    assert queue.get_pending_requests() == []


@pytest.mark.asyncio
async def test_full_queue_rejects_immediately():
    queue = HumanApprovalQueue(max_pending_requests=0)
    result = await queue.request_and_await_approval(_action(), "a1", "high")
    assert result.approved is False
    assert result.justification == "Approval queue full"


@pytest.mark.asyncio
async def test_approve_unknown_request_raises():
    queue = HumanApprovalQueue()
    with pytest.raises(ValueError):
        await queue.approve("does-not-exist", "alice")
    with pytest.raises(ValueError):
        await queue.reject("does-not-exist", "alice")


class _RecordingChannel(NotificationChannel):
    def __init__(self, fail=False):
        self.sent = []
        self.fail = fail

    async def send(self, request):
        if self.fail:
            raise RuntimeError("channel down")
        self.sent.append(request.request_id)
        return True


@pytest.mark.asyncio
async def test_custom_channel_notified():
    channel = _RecordingChannel()
    queue = HumanApprovalQueue(notification_channels=[channel], default_sla_seconds=5)
    task = asyncio.create_task(queue.request_and_await_approval(_action(), "a1", "high"))
    rid = await _await_pending(queue)
    await queue.approve(rid, "alice")
    await task
    assert rid in channel.sent


@pytest.mark.asyncio
async def test_failing_channel_does_not_break_request():
    channel = _RecordingChannel(fail=True)
    queue = HumanApprovalQueue(notification_channels=[channel], default_sla_seconds=5)
    task = asyncio.create_task(queue.request_and_await_approval(_action(), "a1", "high"))
    rid = await _await_pending(queue)
    await queue.approve(rid, "alice")
    result = await task
    assert result.approved is True


def test_base_channel_is_abstract():
    with pytest.raises(NotImplementedError):
        asyncio.run(NotificationChannel().send(object()))


@pytest.mark.asyncio
async def test_slack_channel_success(monkeypatch):
    calls = {}

    def fake_post(url, payload, timeout=10.0):
        calls["url"] = url
        calls["payload"] = payload
        return True

    monkeypatch.setattr(hitl_queue, "_post_json", fake_post)
    channel = SlackNotificationChannel("https://hooks.slack.test/x", "#approvals")
    ok = await channel.send(_req())
    assert ok is True
    assert calls["payload"]["channel"] == "#approvals"


@pytest.mark.asyncio
async def test_slack_channel_failure_returns_false(monkeypatch):
    def boom(url, payload, timeout=10.0):
        raise OSError("network down")

    monkeypatch.setattr(hitl_queue, "_post_json", boom)
    channel = SlackNotificationChannel("https://hooks.slack.test/x", "#approvals")
    assert await channel.send(_req()) is False


@pytest.mark.asyncio
async def test_pagerduty_channel_success(monkeypatch):
    seen = {}

    def fake_post(url, payload, timeout=10.0):
        seen["url"] = url
        seen["payload"] = payload
        return True

    monkeypatch.setattr(hitl_queue, "_post_json", fake_post)
    channel = PagerDutyNotificationChannel("integration-key")
    assert await channel.send(_req()) is True
    assert seen["payload"]["routing_key"] == "integration-key"
    assert seen["url"] == PagerDutyNotificationChannel.EVENTS_URL


@pytest.mark.asyncio
async def test_pagerduty_channel_failure_returns_false(monkeypatch):
    monkeypatch.setattr(hitl_queue, "_post_json", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    channel = PagerDutyNotificationChannel("k")
    assert await channel.send(_req()) is False


def _req():
    from gate.security.hitl_queue import ApprovalRequest

    return ApprovalRequest(
        request_id="r1", agent_id="a1", tenant_id="t1", action=_action(),
        risk_level="high", dry_run_result=None,
    )
