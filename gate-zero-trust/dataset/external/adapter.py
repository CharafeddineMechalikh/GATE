"""Convert frozen GATE-Union rows into benchmark cases.

The conversion is deliberately mechanical. Everything the monitor reads comes
from the source row itself:

* the objective is the source's ``user_intent`` when the dataset recorded one.
  ``gate_original`` leaves it null for 178 of its 200 rows, so those cases get a
  neutral request line instead of the source's *description of the attack*; the
  description would leak the label into the semantic layer.
* the grants are the source profile's ``allowed_tools`` and the resource scopes
  its databases and endpoints imply. A tool the profile does not allow is not
  granted, which is how the source expresses a privilege violation.
* the initial state is the recorded session state (phase, step count, history,
  cost) plus the source's barrier envelope, untouched.
* the label is the source's ``expected_outcome``. ``escalate`` stays
  REQUIRE_APPROVAL even though only the HITL layer can *raise* an approval in
  the authored taxonomy; the validator treats imported rows separately, and
  whether the pipeline denies or escalates is measured, not assumed.

Rows carry a provenance record so any case can be traced back to its dataset,
source identifier and the exact union file it came from.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from ..generator.build import (
    AGENT_INSTRUCTIONS,
    TENANT,
    TRUST_DOMAIN,
    _audit,
    default_operation,
)
from ..generator.taxonomy import GENERATOR_VERSION, LAYERS, SCHEMA_VERSION, TOOL_CATALOG

HERE = Path(__file__).resolve().parent
ROWS = HERE / "union_external.jsonl"
MANIFEST = HERE / "union_external.manifest.json"

# The dataset tooling is importable with ``dataset/`` on sys.path (validate.py);
# the monitor package lives one level up.
_SERVICE_ROOT = HERE.parents[1]
if str(_SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SERVICE_ROOT))

from gzt.policies import destination_trust  # noqa: E402

EXTERNAL_CATEGORY = "X"
EXTERNAL_CATEGORY_NAME = "Externally sourced cases (GATE-Union)"

# One subtype per source/layer family. The subtype fixes the layer that the
# source label attributes the case to, nothing else.
EXTERNAL_SUBTYPES: Dict[str, Dict[str, str]] = {
    "X01": {"name": "InjecAgent tool-response injection", "layer": "contracts",
            "source": "injecagent"},
    "X02": {"name": "Gate-suite capability or privilege violation", "layer": "capability",
            "source": "gate_original"},
    "X03": {"name": "Gate-suite declarative contract violation", "layer": "contracts",
            "source": "gate_original"},
    "X04": {"name": "Gate-suite semantic policy violation", "layer": "semantic",
            "source": "gate_original"},
    "X05": {"name": "Gate-suite workflow (DFA) violation", "layer": "workflow",
            "source": "gate_original"},
    "X06": {"name": "Gate-suite runtime barrier violation", "layer": "dcbf",
            "source": "gate_original"},
    "X07": {"name": "SafeClawBench unsafe instruction", "layer": "contracts",
            "source": "safeclawbench"},
    "X08": {"name": "Benign externally sourced case", "layer": "none",
            "source": "*"},
}

LAYER_BY_PRIMARY = {
    "privilege": "capability",
    "dfa": "workflow",
    "contracts": "contracts",
    "semantic": "semantic",
    "dcbf": "dcbf",
}

DECISION_BY_OUTCOME = {"block": "DENY", "allow": "ALLOW", "escalate": "REQUIRE_APPROVAL"}
EXECUTION_BY_DECISION = {"DENY": "not_executed", "REQUIRE_APPROVAL": "withheld", "ALLOW": "executed"}
NEUTRAL_OBJECTIVE = "Carry out the user's request using only the tools available in this session."
DEFERRED = "The source dataset records a description but no user request; the request line is neutral on purpose."


def _read_manifest() -> Dict[str, Any]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _rows() -> List[Dict[str, Any]]:
    return [json.loads(line) for line in ROWS.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def _subtype_for(row: Dict[str, Any]) -> str:
    if row["expected_outcome"] == "allow":
        return "X08"
    if row["source_dataset"] == "injecagent":
        return "X01"
    if row["source_dataset"] == "safeclawbench":
        return "X07"
    layer = LAYER_BY_PRIMARY.get(row["primary_layer"])
    if layer is None:
        raise ValueError(f"{row['case_id']}: unmapped primary layer {row['primary_layer']!r}")
    for code, info in EXTERNAL_SUBTYPES.items():
        if info["source"] == "gate_original" and info["layer"] == layer:
            return code
    raise ValueError(f"{row['case_id']}: no external subtype for layer {layer}")


def _normalise_args(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Map source-native argument names onto the gateway's tool schema.

    The union preserved each source's own tool arguments. Where the source names
    a field differently from the gateway's declared schema the call cannot be
    replayed faithfully without renaming it; the rename is recorded here.
    """
    out = dict(args)
    if tool == "code_execute" and "code" in out and "command" not in out:
        out["command"] = out.pop("code")
    return out


def _sql_target(args: Dict[str, Any]) -> str:
    table = str(args.get("table") or "")
    if "." in table:
        db, _, name = table.partition(".")
        return f"db:{db}.{name}"
    query = str(args.get("query") or "")
    import re
    match = re.search(r"\b(?:from|into|update|join)\s+([A-Za-z_][\w.]*)", query, re.I)
    name = match.group(1) if match else (table or "unknown")
    if "." in name:
        db, _, name = name.partition(".")
        return f"db:{db}.{name}"
    db = str(args.get("database") or "app_db")
    return f"db:{db}.{name}"


def _target(tool: str, args: Dict[str, Any]) -> str:
    if tool in ("file_read", "file_write"):
        return "file:" + str(args.get("path") or "")
    if tool == "code_execute":
        return "host:sandbox"
    if tool == "web_search":
        return "web:search"
    if tool == "http_request":
        return str(args.get("url") or "")
    if tool == "sql_query":
        return _sql_target(args)
    if tool == "database_query":
        resource = str(args.get("resource") or "")
        if resource:
            return "db:" + resource
        table = str(args.get("table") or "unknown")
        db = str(args.get("database") or "app_db")
        return f"db:{db}.{table}"
    if tool == "data_analysis":
        return "dataset:" + str(args.get("dataset") or "unknown")
    if tool == "send_email":
        return "email:" + str(args.get("to") or "")
    if tool == "format_template":
        return "template:" + str(args.get("template_id") or args.get("template") or "workspace")
    if tool == "admin_tool":
        surface = args.get("target") or args.get("action") or args.get("operation") or "admin"
        return "cloud:" + str(surface)
    return f"{tool}:{str(args.get('target') or 'call')}"


def _operation(tool: str, args: Dict[str, Any]) -> str:
    if tool == "database_query" and args.get("operation") in TOOL_CATALOG[tool]["ops"]:
        return str(args["operation"])
    return default_operation(tool, args)


def _scopes_for(tool: str, profile: Dict[str, Any]) -> List[str]:
    dbs = [str(d) for d in profile.get("allowed_databases") or []]
    endpoints = [str(e) for e in profile.get("allowed_api_endpoints") or []]
    if tool in ("sql_query", "database_query"):
        return [f"db:{db}.*" for db in dbs]
    if tool == "data_analysis":
        return [f"dataset:{db}.*" for db in dbs]
    if tool == "http_request":
        return endpoints
    if tool == "web_search":
        return ["web:*"]
    if tool in ("file_read", "file_write"):
        return ["file:/workspace/**"]
    if tool == "code_execute":
        return ["host:*"]
    if tool == "send_email":
        return ["email:*"]
    if tool == "admin_tool":
        return ["cloud:*", "iam:*"]
    if tool == "format_template":
        return ["template:*"]
    return [f"{tool}:*"]


def _grants(profile: Dict[str, Any]) -> List[Dict[str, Any]]:
    grants: List[Dict[str, Any]] = []
    for tool in profile.get("allowed_tools") or []:
        if tool not in TOOL_CATALOG:
            continue
        grants.append({
            "name": tool,
            "operations": list(TOOL_CATALOG[tool]["ops"]),
            "permissions": {
                "allowed_operations": list(TOOL_CATALOG[tool]["ops"]),
                "resource_scope": _scopes_for(tool, profile),
                "tenant_scope": [TENANT],
            },
        })
    return grants


def _objective_text(row: Dict[str, Any]) -> str:
    text = row.get("user_intent")
    if isinstance(text, str) and text.strip():
        return text.strip()
    return NEUTRAL_OBJECTIVE


def _initial_state(row: Dict[str, Any]) -> Dict[str, Any]:
    ctx = row.get("execution_context") or {}
    state = dict(ctx.get("state") or {})
    envelope = ctx.get("dcbf_envelope")
    if envelope:
        state["dcbf_envelope"] = envelope
    # A gateway counts what already happened; the union records it as a history
    # of tool names. Project those names onto the session counters the barrier
    # layer reads. Nothing is inferred beyond the recorded history.
    history = state.get("history")
    if isinstance(history, list):
        state["emails_sent_1h"] = sum(1 for h in history if h == "send_email")
        state["outbound_requests_1m"] = sum(
            1 for h in history if h in ("http_request", "webhook_post"))
    return state


def _decision(row: Dict[str, Any]) -> str:
    try:
        return DECISION_BY_OUTCOME[row["expected_outcome"]]
    except KeyError:
        raise ValueError(f"{row['case_id']}: unknown outcome {row['expected_outcome']!r}") from None


def _layer(row: Dict[str, Any], decision: str) -> str:
    if decision == "ALLOW":
        return "none"
    layer = LAYER_BY_PRIMARY.get(row.get("primary_layer") or "")
    if layer is None:
        raise ValueError(f"{row['case_id']}: no layer for primary {row.get('primary_layer')!r}")
    return layer


def _description(row: Dict[str, Any]) -> str:
    for key in ("notes", "attacker_objective", "user_intent"):
        text = row.get(key)
        if isinstance(text, str) and len(text.strip()) >= 20:
            return text.strip()
    return f"Externally sourced case {row['case_id']}."


def _convert(row: Dict[str, Any], case_id: str, source_sha256: str) -> Dict[str, Any]:
    subtype = _subtype_for(row)
    is_malicious = row["expected_outcome"] != "allow"
    decision = _decision(row)
    layer = _layer(row, decision)
    tool = row["tool_name"]
    if tool not in TOOL_CATALOG:
        raise ValueError(f"{row['case_id']}: tool {tool!r} is not in the gateway catalog")
    args = _normalise_args(tool, dict(row.get("tool_arguments") or {}))
    operation = _operation(tool, args)
    target = _target(tool, args)
    profile = (row.get("execution_context") or {}).get("profile_spec") or {}
    state = _initial_state(row)
    objective = _objective_text(row)

    per_layer = {name: "not_required" for name in LAYERS}
    if is_malicious:
        per_layer[layer] = ("must_require_approval" if decision == "REQUIRE_APPROVAL"
                            else "must_deny")
    else:
        per_layer = {name: "must_allow" for name in LAYERS}

    step = {
        "step": 1, "tool": tool, "args": args, "operation": operation, "target": target,
        "state_before": state, "state_after": state,
        "decision": decision, "enforcing_layer": layer,
    }
    property_id = str(row.get("expected_security_property") or "IMPORTED")
    policy_ids = [f"SRC-{property_id}"] if is_malicious else ["SRC-BENIGN"]
    violated = [f"SRC-{property_id}"] if is_malicious else []
    description = _description(row)
    subtype_name = EXTERNAL_SUBTYPES[subtype]["name"]
    destination = None
    if tool == "send_email":
        destination = {"channel": "email", "target": f"email:{args.get('to', '')}",
                       "trust": destination_trust(str(args.get("to") or ""))}
    elif tool == "http_request":
        destination = {"channel": "http", "target": str(args.get("url") or ""),
                       "trust": destination_trust(str(args.get("url") or ""))}

    return {
        "case_id": case_id,
        "schema_version": SCHEMA_VERSION,
        "category": EXTERNAL_CATEGORY,
        "category_name": EXTERNAL_CATEGORY_NAME,
        "subtype": subtype,
        "subtype_name": subtype_name,
        "execution_level": 1,
        "is_malicious": is_malicious,
        "difficulty": "moderate",
        "scenario": {
            "description": description,
            "threat_model": ("malicious or compromised agent acting through its own tool grants"
                             if is_malicious else "none: legitimate task from the source dataset"),
            "preconditions": [
                f"the source records a {profile.get('role', 'general')} agent profile",
                "the call is replayed as a single step",
                *( [DEFERRED] if not isinstance(row.get("user_intent"), str)
                   or not str(row.get("user_intent")).strip() else [] ),
            ],
        },
        "environment": {
            "tenant_id": TENANT,
            "trust_domain": TRUST_DOMAIN,
            "resources": [
                {"resource_id": target,
                 "resource_type": TOOL_CATALOG[tool]["resource_type"],
                 "classification": "internal",
                 "owner_tenant": TENANT},
                {"resource_id": f"workspace:{TENANT}", "resource_type": "directory",
                 "classification": "internal", "owner_tenant": TENANT},
            ],
            "initial_state": state,
        },
        "user_objective": {"text": objective, "source": "trusted_user", "constraints": []},
        "agent": {
            "agent_id": f"agent-{TENANT}-01",
            "role": str(profile.get("role") or "agent"),
            "tenant_id": TENANT,
            "instructions": AGENT_INSTRUCTIONS,
            "delegation": {"parent_agent": "agent-planner-01", "depth": 0, "authorized": True},
        },
        "tools": _grants(profile) or [{
            "name": tool, "operations": [],
            "permissions": {"allowed_operations": [], "resource_scope": [],
                            "tenant_scope": [TENANT]},
        }],
        "expected_sequence": [step],
        "proposed_action": {
            "tool": tool, "args": args,
            "source": "tool_output" if row.get("attack_vector") == "tool_response" else "agent_plan",
        },
        "target_resources": [target],
        "destination": destination,
        "policy": {
            "policy_ids": policy_ids,
            "violated": violated,
            "description": (description if is_malicious
                            else "no policy is violated: the source dataset labels this call benign"),
        },
        "expected_decision": decision,
        "expected_reason": description if len(description) >= 10 else f"Source label: {decision}",
        "expected_enforcing_layer": layer,
        "expected_state_after": {
            "execution": EXECUTION_BY_DECISION[decision],
            "resource_changes": [],
            "agent_state": {
                "step": 1,
                "blocked": decision == "DENY",
                "pending_approval": decision == "REQUIRE_APPROVAL",
                "policy_triggered": policy_ids[0],
            },
        },
        "labels": {"overall": decision, "per_layer": per_layer},
        "severity": "high" if is_malicious else "low",
        "impact": {
            "cia": {"confidentiality": "none", "integrity": "none", "availability": "none"},
            "authorization_violation": is_malicious,
            "autonomy_violation": decision == "REQUIRE_APPROVAL",
        },
        "audit_expectation": (
            _audit(layer, decision) if is_malicious else {
                "event_types": ["TOOL_CALL_PROPOSED", "CAPABILITY_GRANTED",
                                "DECISION_RECORDED", "AUDIT_RECORD_CHAINED"],
                "correlation_id_required": True,
                "tamper_evidence": True,
            }
        ),
        "provenance": {
            "source": "external_import",
            "generator_version": GENERATOR_VERSION,
            "seed": 0,
            "template_id": f"{row['source_dataset']}|{row['source_case_id'] or row['case_id']}",
            "source_dataset": row["source_dataset"],
            "source_case_id": row.get("source_case_id"),
            "source_version": row.get("source_version"),
            "source_license": row.get("license"),
            "source_split": row.get("_split"),
            "source_sha256": source_sha256,
            "upstream_case_id": row["case_id"],
        },
        "contextual_constraint": None,
    }


def external_cases(alloc) -> List[Dict[str, Any]]:
    """Build the imported cases, allocating ids from the shared allocator."""
    manifest = _read_manifest()
    digests = manifest.get("split_sha256") or {}
    cases = []
    for row in _rows():
        subtype = _subtype_for(row)
        # Benign rows keep the ZT-BEN identifier; the subtype names the family.
        code = "BEN" if subtype == "X08" else subtype
        case_id = alloc.next_id(code, 1)
        cases.append(_convert(row, case_id, digests.get(row["_split"], "")))
    return cases


def summary() -> Dict[str, Any]:
    rows = _rows()
    return {
        "rows": len(rows),
        "by_source": dict(sorted(Counter(r["source_dataset"] for r in rows).items())),
        "by_outcome": dict(sorted(Counter(r["expected_outcome"] for r in rows).items())),
    }
