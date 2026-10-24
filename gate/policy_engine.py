# gate/policy_engine.py
"""Simple policy engine for gate.

The real implementation would be much more sophisticated (embedding‑based
semantic firewalls, formal contracts, etc.). For the purpose of the
framework we provide a lightweight, yaml‑driven allow/deny check that
the adapter base calls before executing any tool.

Policy file format (YAML)::

    permissions:
      # permission -> list of allowed tool names (or "*" for any)
      fs:read: [*]
      fs:write: [write_file]
      network:outbound: [http_get, http_post]

If a permission is missing it defaults to deny.
"""

import yaml
from pathlib import Path
from typing import Dict, List

# Default location – can be overridden by passing a Path to ``load_policy``
DEFAULT_POLICY_PATH = Path(__file__).with_name("policy.yaml")


def load_policy(path: Path = DEFAULT_POLICY_PATH) -> Dict[str, List[str]]:
    """Load the yaml policy file and return a mapping ``permission -> allowed tools``.

    The file is small, so we read it synchronously.
    """
    if not path.exists():
        # If no file, deny everything – safest default.
        return {}
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get("permissions", {})


def is_allowed(permission: str, tool_name: str, policy: Dict[str, List[str]]) -> bool:
    """Return ``True`` if ``tool_name`` is permitted for ``permission``.

    ``*`` means any tool is allowed for that permission.
    """
    allowed = policy.get(permission, [])
    if "*" in allowed:
        return True
    return tool_name in allowed


# Load once at import time – the framework can also expose a ``reload`` function.
_POLICY_CACHE = load_policy()


def check_permission(contract, tool_name: str) -> bool:
    """Check the contract's permission list against the loaded policy.

    ``contract`` is an instance of ``ToolContract`` defined in ``adapter_base``.
    """
    for perm in contract.permissions:
        if not is_allowed(perm, tool_name, _POLICY_CACHE):
            return False
    return True
