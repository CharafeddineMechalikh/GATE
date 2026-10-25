"""Unit tests for the encrypted audit logger.

Covers PII masking, the local KMS round-trip, the async writer loop, log
rotation with compression, retention purging, and the stats view. The vault and
aws backends are only exercised up to their environment guard so no network or
cloud credential is required.
"""

import asyncio
import base64
import json
import os
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from gate.audit.encrypted_logger import (
    EncryptedAuditLogger,
    EncryptedEvent,
    KMSClient,
    PIIMasker,
    RetentionPolicy,
    SecurityEvent,
)


# --- SecurityEvent / EncryptedEvent dataclasses ---

def test_security_event_defaults():
    e = SecurityEvent(event_type="block", agent_id="a1", tenant_id="t1")
    assert e.tool_name is None
    assert e.metadata == {}
    assert isinstance(e.timestamp, datetime)


def test_encrypted_event_is_a_plain_record():
    ev = EncryptedEvent(
        event_id="id", tenant_id="t", encrypted_payload="x", payload_hash="h",
        encryption_key_id="k", timestamp=datetime.utcnow(), event_type="et", agent_id="a",
    )
    assert ev.event_id == "id"


# --- PIIMasker ---

def test_pii_masker_masks_every_pattern():
    m = PIIMasker()
    assert "***@***.***" in m.mask("mail me at bob@example.com")
    assert "***-***-****" in m.mask("call 555-123-4567")
    assert "***-**-****" in m.mask("ssn 123-45-6789")
    assert "****-****-****-****" in m.mask("card 4111-1111-1111-1111")
    assert "***.***.***.***" in m.mask("host 192.168.0.1")
    assert "***REDACTED***" in m.mask("api_key=abcdefghij1234567890XYZ")


def test_pii_masker_recurses_structures():
    m = PIIMasker()
    masked = m.mask({"user": ["a@b.com", 5, {"k": "555-123-4567"}], "n": 7})
    assert "***@***.***" in masked["user"][0]
    assert masked["user"][1] == 5
    assert "***-***-****" in masked["user"][2]["k"]
    assert masked["n"] == 7


# --- RetentionPolicy.should_rotate ---

def test_should_rotate_false_for_missing_file(tmp_path):
    assert RetentionPolicy().should_rotate(tmp_path / "nope.log.enc") is False


def test_should_rotate_on_size(tmp_path):
    p = tmp_path / "big.log.enc"
    p.write_bytes(b"x" * 2048)
    assert RetentionPolicy(max_file_size_mb=0.001).should_rotate(p) is True


def test_should_rotate_daily_on_old_mtime(tmp_path):
    p = tmp_path / "old.log.enc"
    p.write_text("data")
    two_days_ago = (datetime.utcnow() - timedelta(days=2)).timestamp()
    os.utime(p, (two_days_ago, two_days_ago))
    assert RetentionPolicy(rotation_frequency="daily").should_rotate(p) is True


def test_no_rotation_when_recent(tmp_path):
    p = tmp_path / "new.log.enc"
    p.write_text("data")
    assert RetentionPolicy(max_file_size_mb=100, rotation_frequency="weekly").should_rotate(p) is False


# --- KMSClient ---

def test_local_kms_roundtrip():
    kms = KMSClient(backend="local")
    ct = kms.encrypt(b"secret payload")
    assert ct != b"secret payload"
    assert kms.decrypt(ct) == b"secret payload"


def test_local_kms_caches_key_per_id():
    kms = KMSClient(backend="local")
    k1 = kms._get_or_create_local_key("a")
    k2 = kms._get_or_create_local_key("a")
    assert k1 == k2
    assert kms._get_or_create_local_key("b") != k1


def test_xor_encrypt_is_symmetric():
    kms = KMSClient()
    key = b"0123456789"
    data = b"hello world this is gate"
    assert kms._xor_encrypt(kms._xor_encrypt(data, key), key) == data


def test_unknown_backend_raises():
    kms = KMSClient(backend="moon")
    with pytest.raises(ValueError):
        kms.encrypt(b"x")
    with pytest.raises(ValueError):
        kms.decrypt(b"x")


def test_vault_backend_requires_token(monkeypatch):
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    kms = KMSClient(backend="vault")
    with pytest.raises(RuntimeError):
        kms.encrypt(b"x")


# --- EncryptedAuditLogger: masking + encryption round-trip ---

def test_mask_and_encrypt_roundtrip(tmp_path):
    log = EncryptedAuditLogger(log_path=str(tmp_path))
    event = SecurityEvent(
        event_type="call", agent_id="a", tenant_id="t",
        tool_name="email", tool_args={"to": "victim@corp.com"},
    )
    enc = log._mask_and_encrypt(event)
    assert isinstance(enc, EncryptedEvent)
    assert enc.tenant_id == "t"
    plaintext = json.loads(log.kms_client.decrypt(base64.b64decode(enc.encrypted_payload)))
    assert "***@***.***" in json.dumps(plaintext)


def test_get_current_log_path_is_tenant_scoped(tmp_path):
    log = EncryptedAuditLogger(log_path=str(tmp_path))
    p = log._get_current_log_path("acme")
    assert p.parent.name == "acme"
    assert p.suffix == ".enc"


# --- async writer loop persists and masks ---

@pytest.mark.asyncio
async def test_writer_flushes_events_to_disk(tmp_path):
    log = EncryptedAuditLogger(
        log_path=str(tmp_path), tenant_id="t", batch_size=1, flush_interval_seconds=0.05
    )
    await log.start()
    await log.log_event(
        SecurityEvent(event_type="x", agent_id="a", tenant_id="t",
                      result={"note": "pan 4111 1111 1111 1111"})
    )
    await asyncio.sleep(0.1)
    await log.stop()

    files = list((tmp_path / "t").glob("*.log.enc"))
    assert files, "expected a written log file"
    lines = files[0].read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    decoded = log.kms_client.decrypt(base64.b64decode(record["encrypted_payload"]))
    assert "****-****-****-****" in decoded.decode()  # pan/card pattern masked


@pytest.mark.asyncio
async def test_queue_full_drops_event(tmp_path):
    log = EncryptedAuditLogger(log_path=str(tmp_path), queue_max_size=1)
    await log.log_event(SecurityEvent(event_type="e", agent_id="a", tenant_id="t"))
    # queue now holds one item and is full; the next event must be dropped, not raise
    await log.log_event(SecurityEvent(event_type="e2", agent_id="a", tenant_id="t"))


# --- rotation and purge ---

@pytest.mark.asyncio
async def test_rotate_logs_compresses(tmp_path):
    tenant = tmp_path / "t"
    tenant.mkdir()
    log_file = tenant / "day.log.enc"
    log_file.write_text("line\n")
    policy = RetentionPolicy(max_file_size_mb=0, compress_rotated=True)
    log = EncryptedAuditLogger(log_path=str(tmp_path), retention_policy=policy)
    await log._rotate_logs()
    gz = list(tenant.glob("*.gz"))
    assert gz, "rotated+compressed file should exist"
    assert not log_file.exists()


@pytest.mark.asyncio
async def test_purge_old_logs_deletes_expired(tmp_path):
    tenant = tmp_path / "t"
    tenant.mkdir()
    old = tenant / "old.log.enc"
    old.write_text("x")
    long_ago = (datetime.utcnow() - timedelta(days=400)).timestamp()
    os.utime(old, (long_ago, long_ago))
    policy = RetentionPolicy(retention_days=30)
    log = EncryptedAuditLogger(log_path=str(tmp_path), retention_policy=policy)
    await log._purge_old_logs()
    assert not old.exists()


@pytest.mark.asyncio
async def test_purge_keeps_recent_logs(tmp_path):
    tenant = tmp_path / "t"
    tenant.mkdir()
    recent = tenant / "recent.log.enc"
    recent.write_text("x")
    log = EncryptedAuditLogger(log_path=str(tmp_path), retention_policy=RetentionPolicy(retention_days=365))
    await log._purge_old_logs()
    assert recent.exists()


def test_get_log_stats(tmp_path):
    tenant = tmp_path / "t"
    tenant.mkdir()
    (tenant / "a.log.enc").write_text("hello")
    log = EncryptedAuditLogger(log_path=str(tmp_path))
    stats = log.get_log_stats()
    assert stats["total_files"] == 1
    assert "t" in stats["by_tenant"]
    assert stats["by_tenant"]["t"]["files"] == 1
