# gate/audit_log.py
"""Encrypted audit logger for gate.

If a file named ``audit_key.key`` exists in the same directory, its contents are
interpreted as a Fernet key (base64 url‑safe).  If the file does not exist, a
new key is generated and saved – this mimics a KMS‑provided symmetric key.

Each log entry is a JSON object (timestamp, tool, args, result, allowed) that
is encrypted with the key and written as a base64 string on its own line.

The function ``log_execution`` mirrors the previous plaintext version, so the
rest of the code base does not need to change.
"""

import json
import time
from pathlib import Path
from typing import Any

try:
    from cryptography.fernet import Fernet
except ImportError as exc:
    raise ImportError(
        "The encrypted audit log requires the 'cryptography' package. "
        "Install with `pip install cryptography`."
    ) from exc

# ----------------------------------------------------------------------
# Key management – a persistent key file mimics a KMS‑managed secret.
# ----------------------------------------------------------------------
_KEY_PATH = Path(__file__).with_name('audit_key.key')

def _load_or_create_key() -> bytes:
    if _KEY_PATH.exists():
        return _KEY_PATH.read_bytes()
    key = Fernet.generate_key()
    _KEY_PATH.write_bytes(key)
    return key

_FERNET = Fernet(_load_or_create_key())

# ----------------------------------------------------------------------
# Public API – encrypt and append a single log line.
# ----------------------------------------------------------------------
def log_execution(tool_name: str, args: dict, result: Any, allowed: bool) -> None:
    """Write an **encrypted** audit record.

    The log file ``audit.log`` stores one base64‑encoded ciphertext per line.
    Decryption is straightforward with the stored key, enabling post‑mortem
    forensic analysis while keeping the on‑disk format unintelligible to an
    attacker.
    """
    entry = {
        "ts": time.time(),
        "tool": tool_name,
        "args": args,
        "result": result,
        "allowed": allowed,
    }
    plaintext = json.dumps(entry).encode('utf-8')
    ciphertext = _FERNET.encrypt(plaintext)
    log_path = Path(__file__).with_name('audit.log')
    with log_path.open('ab') as f:
        f.write(ciphertext + b"\n")
