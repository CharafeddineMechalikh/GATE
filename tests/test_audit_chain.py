"""Hash-chain integrity tests for the encrypted audit logger."""

import asyncio
import json

import pytest

from gate.audit.encrypted_logger import EncryptedAuditLogger, SecurityEvent


def _event(i: int) -> SecurityEvent:
    return SecurityEvent(
        event_type="tool_call",
        agent_id="a1",
        tenant_id="t1",
        tool_name="send_email",
        tool_args={"to": f"user{i}@corp"},
    )


async def _write(logger: EncryptedAuditLogger, count: int) -> None:
    await logger.start()
    for i in range(count):
        await logger.log_event(_event(i))
    await logger.stop()


@pytest.mark.asyncio
async def test_chain_links_and_verifies(tmp_path):
    logger = EncryptedAuditLogger(str(tmp_path / "logs"), tenant_id="t1", batch_size=10)
    await _write(logger, 3)
    log_file = next((tmp_path / "logs" / "t1").glob("*.log.enc"))
    rows = [json.loads(line) for line in log_file.read_text().splitlines()]
    assert len(rows) == 3
    assert rows[1]["prev_hash"] == rows[0]["entry_hash"]
    assert rows[2]["prev_hash"] == rows[1]["entry_hash"]
    result = EncryptedAuditLogger.verify_chain(str(log_file))
    assert result["ok"] is True
    assert result["records"] == 3
    assert result["head"] == rows[-1]["entry_hash"]


@pytest.mark.asyncio
async def test_tampering_a_record_breaks_the_chain(tmp_path):
    logger = EncryptedAuditLogger(str(tmp_path / "logs"), tenant_id="t1", batch_size=10)
    await _write(logger, 3)
    log_file = next((tmp_path / "logs" / "t1").glob("*.log.enc"))
    rows = [json.loads(line) for line in log_file.read_text().splitlines()]
    rows[1]["agent_id"] = "someone-else"
    log_file.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    result = EncryptedAuditLogger.verify_chain(str(log_file))
    assert result["ok"] is False
    assert result["line"] == 2
    assert "entry_hash" in result["reason"]


@pytest.mark.asyncio
async def test_deleting_a_record_breaks_the_link(tmp_path):
    logger = EncryptedAuditLogger(str(tmp_path / "logs"), tenant_id="t1", batch_size=10)
    await _write(logger, 3)
    log_file = next((tmp_path / "logs" / "t1").glob("*.log.enc"))
    rows = [json.loads(line) for line in log_file.read_text().splitlines()]
    log_file.write_text("\n".join(json.dumps(r) for r in [rows[0], rows[2]]) + "\n")
    result = EncryptedAuditLogger.verify_chain(str(log_file))
    assert result["ok"] is False
    assert "prev_hash" in result["reason"]


@pytest.mark.asyncio
async def test_chain_continues_after_restart(tmp_path):
    first = EncryptedAuditLogger(str(tmp_path / "logs"), tenant_id="t1", batch_size=10)
    await _write(first, 2)
    second = EncryptedAuditLogger(str(tmp_path / "logs"), tenant_id="t1", batch_size=10)
    await _write(second, 2)
    log_file = next((tmp_path / "logs" / "t1").glob("*.log.enc"))
    result = EncryptedAuditLogger.verify_chain(str(log_file))
    assert result["ok"] is True
    assert result["records"] == 4
