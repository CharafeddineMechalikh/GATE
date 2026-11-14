"""Taxonomy data model for the GATE Zero-Trust benchmark (Phase 1).

Design rules enforced here:
  * every subtype belongs to exactly one of the 11 categories A-K;
  * every subtype declares the execution levels it can legitimately appear at;
  * every subtype declares the single layer that must stop it (its designated
    enforcing layer) - the benchmark never requires two layers to fire for the
    same instance;
  * every variant names a concrete tool, operation, argument set, target
    resource and policy id - nothing is inferred from prose at evaluation time.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

SCHEMA_VERSION = "1.2"
GENERATOR_VERSION = "1.2.0"

CATEGORIES: Dict[str, str] = {
    "A": "Reconnaissance and information gathering",
    "B": "Unauthorized access and identity abuse",
    "C": "Data-related attacks",
    "D": "Filesystem and operating-system attacks",
    "E": "Network and infrastructure attacks",
    "F": "Web application and API attacks",
    "G": "Email, communication and social engineering",
    "H": "Financial and transactional attacks",
    "I": "Cloud and DevOps attacks",
    "J": "Persistence and security-control interference",
    "K": "AI-agent-specific attacks",
    "X": "Externally sourced cases (GATE-Union)",
}

LAYERS: Tuple[str, ...] = (
    "capability", "workflow", "semantic", "ifc", "contracts", "dcbf", "hitl",
)

# Tool catalog: name -> (operations, argument keys the layer must inspect).
# This is the vocabulary the generator and the Phase-2 monitor share.
TOOL_CATALOG: Dict[str, Dict[str, Any]] = {
    "file_read":        {"ops": ["read"], "args": ["path"], "resource_type": "file"},
    "file_write":       {"ops": ["write", "append", "delete", "create"], "args": ["path", "content"], "resource_type": "file"},
    "code_execute":     {"ops": ["execute"], "args": ["command"], "resource_type": "directory"},
    "web_search":       {"ops": ["search"], "args": ["query"], "resource_type": "api_endpoint"},
    "http_request":     {"ops": ["get", "post", "put", "delete"], "args": ["url", "body"], "resource_type": "api_endpoint"},
    "sql_query":        {"ops": ["select", "insert", "update", "delete", "ddl"], "args": ["query", "database"], "resource_type": "database_table"},
    "database_query":   {"ops": ["select", "insert", "update", "delete"], "args": ["table", "filter", "values"], "resource_type": "database_table"},
    "data_analysis":    {"ops": ["read", "compute", "export"], "args": ["dataset", "operation"], "resource_type": "database_table"},
    "send_email":       {"ops": ["send", "forward", "reply"], "args": ["to", "subject", "body", "attachment"], "resource_type": "email_account"},
    "format_template":  {"ops": ["render"], "args": ["template", "data"], "resource_type": "file"},
    "admin_tool":       {"ops": ["read", "write", "config"], "args": ["target", "setting", "value"], "resource_type": "cloud_resource"},
    "cloud_api":        {"ops": ["provision", "modify", "delete", "snapshot"], "args": ["resource", "region", "spec"], "resource_type": "cloud_resource"},
    "k8s_api":          {"ops": ["get", "apply", "delete", "exec"], "args": ["namespace", "object", "manifest"], "resource_type": "kubernetes_object"},
    "ci_pipeline":      {"ops": ["trigger", "modify", "deploy", "publish"], "args": ["pipeline", "branch", "artifact"], "resource_type": "ci_artifact"},
    "memory_write":     {"ops": ["write", "delete"], "args": ["key", "value"], "resource_type": "memory_entry"},
    "agent_delegate":   {"ops": ["spawn", "delegate", "message"], "args": ["agent", "task", "scope"], "resource_type": "agent"},
    "payment_api":      {"ops": ["charge", "transfer", "refund"], "args": ["account", "amount", "recipient"], "resource_type": "financial_account"},
    "calendar_api":     {"ops": ["read", "write", "delete"], "args": ["calendar", "event", "action"], "resource_type": "calendar"},
}


@dataclass(frozen=True)
class Variant:
    """One concrete way to instantiate a subtype."""
    args: Dict[str, Any]
    target: str
    policy: str
    reason: str
    severity: str = "high"
    confidentiality: str = "none"
    integrity: str = "none"
    availability: str = "none"
    autonomy: bool = False
    destination: Optional[Dict[str, str]] = None
    difficulty: str = "easy"
    initial_state: Dict[str, Any] = field(default_factory=dict)
    labels: Tuple[str, ...] = ()
    decision: Optional[str] = None


@dataclass(frozen=True)
class Subtype:
    code: str
    name: str
    category: str
    levels: Tuple[int, ...]
    tool: str
    operation: str
    layer: str
    description: str
    variants: Tuple[Variant, ...]
    threat_model: str = "malicious or compromised agent acting through its own tool grants"


SPECS: list[Subtype] = []


def S(code: str, name: str, category: str, levels: Tuple[int, ...], tool: str,
      operation: str, layer: str, description: str, variants: list[Variant],
      threat_model: str = "malicious or compromised agent acting through its own tool grants",
      ) -> None:
    """Register one subtype. Fails fast on malformed references."""
    assert category in CATEGORIES, category
    assert code.startswith(category), f"{code} not in category {category}"
    assert layer in LAYERS, layer
    assert tool in TOOL_CATALOG, tool
    assert operation in TOOL_CATALOG[tool]["ops"], (tool, operation)
    assert levels and set(levels) <= {1, 2, 3}, levels
    assert variants, f"{code} has no variants"
    for v in variants:
        missing = [k for k in TOOL_CATALOG[tool]["args"] if k not in v.args]
        assert not missing, f"{code} variant missing args {missing}"
        assert v.severity in ("low", "medium", "high", "critical")
    SPECS.append(Subtype(code, name, category, levels, tool, operation, layer,
                         description, tuple(variants), threat_model))


def V(args: Dict[str, Any], target: str, policy: str, reason: str,
      severity: str = "high", confidentiality: str = "none", integrity: str = "none",
      availability: str = "none", autonomy: bool = False,
      destination: Optional[Dict[str, str]] = None,
      difficulty: str = "easy",
      initial_state: Optional[Dict[str, Any]] = None,
      labels: Tuple[str, ...] = (),
      decision: Optional[str] = None) -> Variant:
    return Variant(args=args, target=target, policy=policy, reason=reason,
                   severity=severity, confidentiality=confidentiality,
                   integrity=integrity, availability=availability,
                   autonomy=autonomy, destination=destination,
                   difficulty=difficulty, initial_state=initial_state or {},
                   labels=labels, decision=decision)


def load_specs() -> list[Subtype]:
    """Import spec modules exactly once and return the registry."""
    if SPECS:
        return SPECS
    from . import specs_ad, specs_eh, specs_ik  # noqa: F401
    return SPECS
