"""
Encrypted Audit Logger
Enhanced with log rotation, retention policies, and GDPR compliance.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import glob
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class SecurityEvent:
    """A security-relevant event to be logged."""
    event_type: str
    agent_id: str
    tenant_id: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    tool_name: Optional[str] = None
    tool_args: Optional[Dict[str, Any]] = None
    result: Optional[Any] = None
    violation_details: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EncryptedEvent:
    """An encrypted, PII-masked audit event."""
    event_id: str
    tenant_id: str
    encrypted_payload: str
    payload_hash: str
    encryption_key_id: str
    timestamp: datetime
    event_type: str
    agent_id: str


@dataclass
class RetentionPolicy:
    """Log retention policy for compliance."""
    retention_days: int = 365
    max_file_size_mb: int = 100
    max_total_size_mb: int = 10000
    rotation_frequency: str = "daily"  # daily, weekly, monthly
    compress_rotated: bool = True
    
    def should_rotate(self, file_path: Path) -> bool:
        """Check if file should be rotated."""
        if not file_path.exists():
            return False
        
        file_size_mb = file_path.stat().st_size / (1024 * 1024)
        if file_size_mb >= self.max_file_size_mb:
            return True
        
        if self.rotation_frequency == "daily":
            mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
            if (datetime.utcnow() - mtime).days >= 1:
                return True
        
        return False


class PIIMasker:
    """Detects and masks PII in audit log data."""
    
    PATTERNS = {
        "email": (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "***@***.***"),
        "phone": (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "***-***-****"),
        "ssn": (r"\b\d{3}-\d{2}-\d{4}\b", "***-**-****"),
        "credit_card": (r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", "****-****-****-****"),
        "ipv4": (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "***.***.***.***"),
        "api_key": (r"(?i)(api[_-]?key|apikey|token|secret)\s*[:=]\s*['\"]?[\w-]{20,}", "***REDACTED***"),
    }
    
    def mask(self, data: Any) -> Any:
        """Recursively mask PII in any data structure."""
        if isinstance(data, str):
            return self._mask_string(data)
        elif isinstance(data, dict):
            return {k: self.mask(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.mask(item) for item in data]
        return data
    
    def _mask_string(self, text: str) -> str:
        """Mask PII patterns in a string."""
        masked = text
        for pattern_name, (pattern, replacement) in self.PATTERNS.items():
            masked = re.sub(pattern, replacement, masked)
        return masked


class KMSClient:
    """Abstraction over key management systems."""
    
    def __init__(self, backend: str = "local", key_id: Optional[str] = None) -> None:
        if backend == "local":
            logger.warning(
                "Using LOCAL encryption backend. This is for development only. "
                "Configure AWS KMS or Vault for production."
            )
        self.backend = backend
        self.key_id = key_id or "default-key"
        self._local_keys: Dict[str, bytes] = {}
    
    def encrypt(self, plaintext: bytes, key_id: Optional[str] = None) -> bytes:
        """Encrypt data."""
        kid = key_id or self.key_id
        
        if self.backend == "local":
            key = self._get_or_create_local_key(kid)
            return self._xor_encrypt(plaintext, key)
        elif self.backend == "aws_kms":
            import boto3
            kms = boto3.client("kms")
            response = kms.encrypt(KeyId=kid, Plaintext=plaintext)
            return response["CiphertextBlob"]
        elif self.backend == "vault":
            result = self._vault_request(
                f"transit/encrypt/{kid}",
                {"plaintext": base64.b64encode(plaintext).decode("ascii")},
            )
            return result["data"]["ciphertext"].encode("utf-8")
        else:
            raise ValueError(f"Unknown KMS backend: {self.backend}")
    
    def _vault_request(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Call the HashiCorp Vault HTTP API (transit engine). Uses VAULT_ADDR/VAULT_TOKEN."""
        import urllib.request
        addr = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200").rstrip("/")
        token = os.environ.get("VAULT_TOKEN")
        if not token:
            raise RuntimeError("VAULT_TOKEN environment variable is required for vault backend")
        req = urllib.request.Request(
            f"{addr}/v1/{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"X-Vault-Token": token, "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    
    def decrypt(self, ciphertext: bytes, key_id: Optional[str] = None) -> bytes:
        """Decrypt data."""
        kid = key_id or self.key_id
        
        if self.backend == "local":
            key = self._get_or_create_local_key(kid)
            return self._xor_encrypt(ciphertext, key)
        elif self.backend == "aws_kms":
            import boto3
            kms = boto3.client("kms")
            response = kms.decrypt(CiphertextBlob=ciphertext)
            return response["Plaintext"]
        elif self.backend == "vault":
            result = self._vault_request(
                f"transit/decrypt/{kid}", {"ciphertext": ciphertext.decode("utf-8")}
            )
            return base64.b64decode(result["data"]["plaintext"])
        else:
            raise ValueError(f"Unknown KMS backend: {self.backend}")
    
    def _get_or_create_local_key(self, key_id: str) -> bytes:
        if key_id not in self._local_keys:
            self._local_keys[key_id] = os.urandom(32)
        return self._local_keys[key_id]
    
    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


class EncryptedAuditLogger:
    """
    Audit logger with:
    - PII masking before logging
    - Encryption at rest via KMS
    - Async writes to avoid blocking
    - Tenant isolation
    - Integrity verification via hashing
    - Log rotation and retention policies (NEW)
    """
    
    def __init__(
        self,
        log_path: str,
        kms_client: Optional[KMSClient] = None,
        tenant_id: str = "default",
        queue_max_size: int = 10000,
        batch_size: int = 100,
        flush_interval_seconds: float = 1.0,
        retention_policy: Optional[RetentionPolicy] = None,
    ) -> None:
        self.log_path = Path(log_path)
        self.log_path.mkdir(parents=True, exist_ok=True)
        
        self.kms_client = kms_client or KMSClient()
        self.tenant_id = tenant_id
        self.pii_masker = PIIMasker()
        self.retention_policy = retention_policy or RetentionPolicy()
        
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=queue_max_size)
        self._batch_size = batch_size
        self._flush_interval = flush_interval_seconds
        self._writer_task: Optional[asyncio.Task] = None
        self._rotation_task: Optional[asyncio.Task] = None
        self._running = False
        
        logger.info(
            f"EncryptedAuditLogger initialized: path={log_path}, "
            f"tenant={tenant_id}, retention={self.retention_policy.retention_days}d"
        )
    
    async def start(self) -> None:
        """Start the async writer and rotation tasks."""
        if self._running:
            return
        self._running = True
        self._writer_task = asyncio.create_task(self._async_writer_loop())
        self._rotation_task = asyncio.create_task(self._rotation_loop())
        logger.info("Audit logger tasks started")
    
    async def stop(self) -> None:
        """Stop the writer and flush remaining events."""
        self._running = False
        if self._writer_task:
            await self._writer_task
        if self._rotation_task:
            self._rotation_task.cancel()
            try:
                await self._rotation_task
            except asyncio.CancelledError:
                pass
        logger.info("Audit logger stopped")
    
    async def log_event(self, event: SecurityEvent) -> None:
        """Log a security event. Non-blocking: enqueues for async writing."""
        encrypted = self._mask_and_encrypt(event)
        
        try:
            self._queue.put_nowait(encrypted)
        except asyncio.QueueFull:
            logger.error("Audit log queue full! Event dropped.")
    
    def _mask_and_encrypt(self, event: SecurityEvent) -> EncryptedEvent:
        """Mask PII and encrypt the event."""
        masked_args = self.pii_masker.mask(event.tool_args) if event.tool_args else None
        masked_result = self.pii_masker.mask(event.result) if event.result else None
        masked_violation = (
            self.pii_masker.mask(event.violation_details) if event.violation_details else None
        )
        
        payload = {
            "event_type": event.event_type,
            "agent_id": event.agent_id,
            "tenant_id": event.tenant_id,
            "timestamp": event.timestamp.isoformat(),
            "tool_name": event.tool_name,
            "tool_args": masked_args,
            "result": masked_result,
            "violation_details": masked_violation,
            "metadata": event.metadata,
        }
        
        payload_json = json.dumps(payload, default=str).encode("utf-8")
        payload_hash = hashlib.sha256(payload_json).hexdigest()
        encrypted_payload = self.kms_client.encrypt(payload_json)
        encrypted_b64 = base64.b64encode(encrypted_payload).decode("utf-8")
        
        return EncryptedEvent(
            event_id=f"{event.tenant_id}:{event.timestamp.timestamp()}:{hash(payload_json) % 1000000:06d}",
            tenant_id=event.tenant_id,
            encrypted_payload=encrypted_b64,
            payload_hash=payload_hash,
            encryption_key_id=self.kms_client.key_id,
            timestamp=event.timestamp,
            event_type=event.event_type,
            agent_id=event.agent_id,
        )
    
    async def _async_writer_loop(self) -> None:
        """Background task that batches and writes events to disk."""
        batch: List[EncryptedEvent] = []
        last_flush = asyncio.get_event_loop().time()
        
        while self._running or not self._queue.empty():
            try:
                try:
                    event = await asyncio.wait_for(self._queue.get(), timeout=0.1)
                    batch.append(event)
                except asyncio.TimeoutError:
                    pass
                
                now = asyncio.get_event_loop().time()
                
                if len(batch) >= self._batch_size or (
                    batch and now - last_flush >= self._flush_interval
                ):
                    await self._flush_batch(batch)
                    batch = []
                    last_flush = now
            
            except Exception as e:
                logger.error(f"Error in audit writer loop: {e}", exc_info=True)
        
        if batch:
            await self._flush_batch(batch)
    
    async def _rotation_loop(self) -> None:
        """Background task that handles log rotation and retention."""
        while self._running:
            try:
                await asyncio.sleep(3600)  # Check every hour
                await self._rotate_logs()
                await self._purge_old_logs()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in rotation loop: {e}", exc_info=True)
    
    async def _flush_batch(self, batch: List[EncryptedEvent]) -> None:
        """Write a batch of events to disk."""
        try:
            by_tenant: Dict[str, List[EncryptedEvent]] = {}
            for event in batch:
                by_tenant.setdefault(event.tenant_id, []).append(event)
            
            for tenant_id, events in by_tenant.items():
                tenant_log = self._get_current_log_path(tenant_id)
                tenant_log.parent.mkdir(parents=True, exist_ok=True)
                
                with open(tenant_log, "a") as f:
                    for event in events:
                        record = {
                            "event_id": event.event_id,
                            "encrypted_payload": event.encrypted_payload,
                            "payload_hash": event.payload_hash,
                            "encryption_key_id": event.encryption_key_id,
                            "timestamp": event.timestamp.isoformat(),
                            "event_type": event.event_type,
                            "agent_id": event.agent_id,
                        }
                        f.write(json.dumps(record) + "\n")
            
            logger.debug(f"Flushed {len(batch)} audit events to disk")
        
        except Exception as e:
            logger.error(f"Failed to flush audit batch: {e}", exc_info=True)
    
    def _get_current_log_path(self, tenant_id: str) -> Path:
        """Get the current log file path for a tenant."""
        date_str = datetime.utcnow().strftime("%Y-%m-%d")
        return self.log_path / tenant_id / f"{date_str}.log.enc"
    
    async def _rotate_logs(self) -> None:
        """Rotate logs based on retention policy."""
        try:
            for tenant_dir in self.log_path.iterdir():
                if not tenant_dir.is_dir():
                    continue
                
                for log_file in tenant_dir.glob("*.log.enc"):
                    if self.retention_policy.should_rotate(log_file):
                        await self._rotate_file(log_file)
        except Exception as e:
            logger.error(f"Log rotation failed: {e}", exc_info=True)
    
    async def _rotate_file(self, file_path: Path) -> None:
        """Rotate a single log file."""
        try:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            rotated_name = f"{file_path.stem}_{timestamp}{file_path.suffix}"
            rotated_path = file_path.parent / rotated_name
            
            file_path.rename(rotated_path)
            
            if self.retention_policy.compress_rotated:
                import gzip
                with open(rotated_path, "rb") as f_in:
                    with gzip.open(f"{rotated_path}.gz", "wb") as f_out:
                        f_out.writelines(f_in)
                rotated_path.unlink()
            
            logger.info(f"Rotated log file: {file_path.name} -> {rotated_path.name}")
        
        except Exception as e:
            logger.error(f"Failed to rotate file {file_path}: {e}")
    
    async def _purge_old_logs(self) -> None:
        """Purge logs older than retention period."""
        try:
            cutoff = datetime.utcnow() - timedelta(days=self.retention_policy.retention_days)
            
            for tenant_dir in self.log_path.iterdir():
                if not tenant_dir.is_dir():
                    continue
                
                for log_file in tenant_dir.glob("*.log.enc*"):
                    mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
                    if mtime < cutoff:
                        log_file.unlink()
                        logger.info(f"Purged old log: {log_file.name}")
        
        except Exception as e:
            logger.error(f"Log purge failed: {e}", exc_info=True)
    
    def get_log_stats(self) -> Dict[str, Any]:
        """Get statistics about log files."""
        stats = {
            "total_files": 0,
            "total_size_mb": 0.0,
            "by_tenant": {},
        }
        
        for tenant_dir in self.log_path.iterdir():
            if not tenant_dir.is_dir():
                continue
            
            tenant_stats = {"files": 0, "size_mb": 0.0}
            
            for log_file in tenant_dir.glob("*.log.enc*"):
                tenant_stats["files"] += 1
                tenant_stats["size_mb"] += log_file.stat().st_size / (1024 * 1024)
                stats["total_files"] += 1
                stats["total_size_mb"] += log_file.stat().st_size / (1024 * 1024)
            
            stats["by_tenant"][tenant_dir.name] = tenant_stats
        
        return stats
