"""
gate Information-Flow Control Layer
Taint-based egress lattice: reads carry confidentiality labels into the
session, and labelled data may not leave to a destination outside the
declared trust boundary.
"""

import json
import re
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse

from ..core.interfaces import InformationFlowController
from ..core.models import ToolCall, AgentState

LABEL_ORDER = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3, "secret": 4}

READ_TOOLS = {"sql_query", "database_query", "file_read", "web_search", "memory_read"}
EGRESS_TOOLS = {"send_email", "http_request", "webhook_post"}

_SECRET = re.compile(
    r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\bbearer\s+[A-Za-z0-9._-]{16,}|"
    r"\b(?:api[_-]?key|secret|password|token)\s*[:=]\s*\S{8,}|"
    r"\.aws/credentials",
    re.I,
)
_RESTRICTED = re.compile(
    r"\b\d{3}-\d{2}-\d{4}\b|\bSSN\b|\bDOB\b|\bdate of birth\b|\bpassport\b",
    re.I,
)
_CONFIDENTIAL = re.compile(
    r"\b(customer|customers|contact|contacts|lead|leads|employee|employees|"
    r"people|profiles?|directory|name|email|phone|mobile|address|"
    r"revenue|net income|financial|salary|salaries|compensation|payroll)\b",
    re.I,
)
_CONFIDENTIAL_RESOURCE = re.compile(
    r"\b(customer|customers|contact|contacts|employee|employees|people|"
    r"profiles?|directory|users|payroll|salary|salaries|compensation|revenue|financial)\b",
    re.I,
)
_PAYLOAD_KEYS = ("body", "subject", "attachment", "query", "command", "content", "value", "dataset")


def _join(labels: List[str]) -> str:
    best = "internal"
    for label in labels:
        if LABEL_ORDER.get(label, 0) > LABEL_ORDER[best]:
            best = label
    return best


def _payload(action: ToolCall) -> str:
    parts: List[str] = []
    for key in _PAYLOAD_KEYS:
        value = action.tool_args.get(key)
        if isinstance(value, dict):
            parts.append(json.dumps(value, sort_keys=True))
        elif value is not None:
            parts.append(str(value))
    return " ".join(parts)


def _content_label(text: str, base: str) -> str:
    label = base
    if _RESTRICTED.search(text):
        label = _join([label, "restricted"])
    elif _CONFIDENTIAL.search(text):
        label = _join([label, "confidential"])
    if _SECRET.search(text):
        label = "secret"
    return label


def _destination(action: ToolCall) -> str:
    if action.tool_name == "send_email":
        return str(action.tool_args.get("to", ""))
    return str(action.tool_args.get("url", "")) or str(action.tool_args.get("endpoint", ""))


def _host_of(entry: str) -> str:
    if "://" in entry:
        return urlparse(entry).hostname or entry
    if "@" in entry:
        return entry.rsplit("@", 1)[-1]
    return entry


class DefaultInformationFlowController(InformationFlowController):
    """Deterministic confidentiality lattice over reads and egress calls.

    A read joins the most restrictive label among its resource classification
    and its payload markers into ``state.read_labels``. An egress call joins
    the session label with its own payload label; secret material never
    crosses the boundary, and confidential-or-higher content only leaves to
    a destination inside the declared trust boundary.
    """

    def __init__(self, config: Any) -> None:
        boundary: Set[str] = set(getattr(config.ifc_config, "trust_boundary", set()))
        for endpoint in config.agent_profile.data_scope.allowed_api_endpoints:
            boundary.add(_host_of(endpoint))
        self.trust_boundary = {b.lower().rstrip("/") for b in boundary if b}

    def _trusted(self, destination: str) -> bool:
        if not destination:
            return False
        target = _host_of(destination).lower().rstrip("/")
        for entry in self.trust_boundary:
            if target == entry or target.endswith("." + entry) or entry.endswith("." + target):
                return True
        return False

    def record_read(self, action: ToolCall, state: AgentState) -> None:
        if action.tool_name not in READ_TOOLS:
            return
        resource = " ".join(
            str(action.tool_args.get(k, "")) for k in ("table", "resource", "path", "query")
        )
        base = "confidential" if _CONFIDENTIAL_RESOURCE.search(resource) else "internal"
        label = _content_label(_payload(action), base)
        if label not in state.read_labels:
            state.read_labels.append(label)

    def check_flow(self, action: ToolCall, state: AgentState) -> Tuple[bool, str]:
        if action.tool_name not in EGRESS_TOOLS:
            return True, ""
        if not self._transmits(action):
            return True, ""
        payload = _payload(action)
        destination = _destination(action)
        label = _content_label(payload, _join(list(state.read_labels)))
        if LABEL_ORDER[label] >= LABEL_ORDER["secret"]:
            return False, (
                f"secret material in the payload may never cross the trust boundary "
                f"(destination {destination!r})"
            )
        if LABEL_ORDER[label] >= LABEL_ORDER["confidential"] and not self._trusted(destination):
            return False, (
                f"{label} content may not leave the trust boundary to {destination!r}; "
                "declare the destination in ifc_config.trust_boundary to permit the flow"
            )
        return True, ""

    @staticmethod
    def _transmits(action: ToolCall) -> bool:
        if action.tool_name == "send_email":
            return True
        if action.tool_name == "http_request":
            body = action.tool_args.get("body")
            if isinstance(body, str) and body.strip():
                return True
            return str(action.tool_args.get("method", "GET")).upper() in (
                "POST", "PUT", "PATCH", "DELETE", "UPLOAD"
            )
        return True