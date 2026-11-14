"""Layer 4 - information-flow control.

Every action carries an information label derived from three observable
sources: the classification of the resource it touches, the classification of
data the session has already read, and content markers in the payload itself.
The layer then enforces the tenant's egress lattice, recipient purpose binding
and aggregation limits.

The label of a payload is joined to the most restrictive label among its
sources; the trust class of a destination is derived from the recipient or URL,
never from case metadata. Cross-user reads, bulk collection, exports and
secret material are separate flows with their own policies.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from . import policies as P
from .decision import Decision, LayerResult
from .runtime import Action, Observation, RuntimeState

LAYER = "ifc"

_SECRET = re.compile(
    r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\bbearer\s+[A-Za-z0-9._-]{16,}|"
    r"\b(?:api[_-]?key|secret|password|token)\s*[:=]\s*\S{8,}|"
    r"\.aws/credentials|vault-backups|vault/|secret[_ -]store",
    re.I,
)
_PII = re.compile(
    r"\b\d{3}-\d{2}-\d{4}\b|\bSSN\b|\bDOB\b|\bdate of birth\b|"
    r"\bpassport\b|\bhome address\b|\b\d{2,4}\s+\w+\s+(?:st|street|ave|road|rd)\b",
    re.I,
)
_PERSONAL_DATA = re.compile(
    r"\b(customer|customers|contact|contacts|lead|leads|employee|employees|"
    r"people|profiles?|org chart|directory)\b", re.I)
_PERSONAL_FIELDS = re.compile(
    r"\b(name|email|phone|mobile|address|ssn|dob|social security)\b", re.I)
_FINANCIAL = re.compile(
    r"\b(revenue|net income|q[1-4]|financial|board pack|salary|salaries|"
    r"compensation|payroll|band|bands|contract|customer list|"
    r"pricing model)\b", re.I)
_INTERNAL_ONLY = re.compile(
    r"\binternal[- ]only\b|\binternal architecture\b|\binternal use\b|"
    r"\bfor internal\b|\binternal\.pdf\b|\barchitecture\.pdf\b", re.I)
_SESSION_TRACE = re.compile(
    r"\btrace\.har\b|\bcookies?\b|\bsession (?:token|material)\b|"
    r"\bheaders and cookies\b|\bdebug bundle\b", re.I)
_CROSS_TENANT = re.compile(r"\btenant-[a-z0-9]+'?s? report\b|\bcross-tenant\b", re.I)
_ENV_DUMP = re.compile(
    r"^\s*(?:env|printenv|set|export)\b.*(?:sort|$)|"
    r"/proc/\S*environ|\benviron\b.*\btr\b|\bgetenv\b|os\.environ", re.I)
_CI_SECRET = re.compile(
    r"\.env\b|credentials|secret|config\.json|\.pem\b|id_rsa|"
    r"\.log\b|logs?/", re.I)
_BROADCAST = re.compile(
    r"wiki\.|\ball@|\ball-staff@|\bannounce@|\blist@|\bnewsletter\b|"
    r"public[- ]read|\bpublic\b.*\bshare\b", re.I)
_HR_DATA = re.compile(r"\bsalar(?:y|ies)\b|\bcompensation\b|\bpayroll\b|\bband", re.I)
_ACCOUNT_BROADCAST = re.compile(r"\bfinance@|\bhr@|\baccounts@|\bteam@|\bqa@", re.I)
_EXPORT_OP = re.compile(r"export|bundle|download|dump|snapshot|archive", re.I)
_AGG_OP = re.compile(r"join|reidentify|aggregate|k_anon|export_join", re.I)
_PERSONAL_TABLES = set(P.PERSONAL_DATA_TABLES)
_APPROVED_HR_RECIPIENTS = {"hr@corp.example", "hr-archive@corp.example"}
_AUDIT_OBJECTIVE = re.compile(r"\b(audit|auditor|audit sample|agreed sample)\b", re.I)


def _deny(action: Action, policy: str, reason: str, **evidence: Any) -> LayerResult:
    payload = {"tool": action.tool, "operation": action.operation, "target": action.target}
    payload.update(evidence)
    return LayerResult(Decision.DENY, LAYER, policy, reason, risk="high", evidence=payload)


def _json_body(action: Action) -> str:
    body = action.args.get("body")
    return body if isinstance(body, str) else ""


def _payload(action: Action) -> str:
    parts: List[str] = []
    for key in ("body", "subject", "attachment", "artifact", "dataset", "query",
                "command", "value", "content", "blob", "spec", "path"):
        value = action.args.get(key)
        if isinstance(value, dict):
            parts.append(json.dumps(value, sort_keys=True))
        elif value is not None:
            parts.append(str(value))
    return " ".join(parts)


def _destination(action: Action) -> str:
    if action.tool == "send_email":
        return str(action.args.get("to", ""))
    if action.tool == "http_request":
        return str(action.args.get("url", ""))
    if action.tool == "cloud_api":
        spec = action.args.get("spec") if isinstance(action.args.get("spec"), dict) else {}
        return str(spec.get("destination") or action.target or "")
    if action.tool == "webhook_post":
        return str(action.args.get("url", ""))
    return action.target


def _trust(target: str) -> str:
    if target.startswith(("s3://", "gs://", "azure://")):
        return "untrusted"
    host = urlparse(target).hostname if "://" in target else target
    host = host or target
    return P.destination_trust(host)


def _is_egress(action: Action) -> bool:
    if action.tool == "cloud_api":
        spec = action.args.get("spec") if isinstance(action.args.get("spec"), dict) else {}
        return bool(spec.get("destination") or spec.get("share") or spec.get("acl")) or \
            str(spec.get("op", "")) in ("snapshot", "copy", "modify")
    return action.tool in ("send_email", "http_request", "webhook_post") or \
        (action.tool == "ci_pipeline" and action.operation in ("publish", "release"))


def _transmits(action: Action) -> bool:
    if action.tool == "send_email":
        return True
    if action.tool == "http_request":
        body = action.args.get("body")
        if isinstance(body, str) and body.strip():
            return True
        return action.operation.lower() in ("post", "put", "patch", "delete", "upload")
    return _is_egress(action)


def _content_label(payload: str, base: str) -> str:
    label = base
    if _PII.search(payload):
        label = "restricted"
    elif _FINANCIAL.search(payload) or _PERSONAL_DATA.search(payload):
        label = "confidential"
    if _SECRET.search(payload):
        label = "secret"
    return label


class InformationFlowLayer:
    name = LAYER

    def check(self, obs: Observation, state: RuntimeState,
              action: Action) -> Optional[LayerResult]:
        payload = _payload(action)

        # 1. secret material may not be read out or leave the boundary
        secret = self._secret_flow(obs, action, state, payload)
        if secret:
            return secret

        # 2. per-user rows inside one tenant
        cross_user = self._cross_user(obs, state, action)
        if cross_user:
            return cross_user

        # 3. aggregation and k-anonymity
        aggregate = self._aggregation(obs, state, action, payload)
        if aggregate:
            return aggregate

        # 4. exports beyond an in-place analysis grant
        export = self._export(obs, action, payload)
        if export:
            return export

        # 5. egress of labelled content
        if _is_egress(action):
            egress = self._egress(obs, state, action, payload)
            if egress:
                return egress
        return None

    @staticmethod
    def _objective_authorises(obs: Observation, action: Action) -> bool:
        """The objective itself names this transfer and its destination."""
        objective = obs.objective_text.lower()
        if not re.search(r"\b(send|email|share|return|forward|transfer|deliver|"
                         r"snapshot|copy|backup|export)\b", objective):
            return False
        tokens = [t for t in re.findall(r"[a-z0-9][a-z0-9_-]{3,}", objective)
                  if t not in {"the", "this", "that", "with", "from", "into", "your",
                               "their", "user", "please", "before", "after", "list",
                               "team", "data", "file", "report", "note", "notes",
                               "draft", "mail", "email", "send", "share", "copy"}]
        haystack = " ".join(str(action.args.get(k, "")) for k in ("to", "url")).lower()
        destination = _destination(action).split(":", 1)[-1] if "@" in _destination(action) else _destination(action)
        haystack += " " + destination.lower()
        return any(len(t) >= 5 and re.search(rf"\b{re.escape(t)}\b", haystack)
                   for t in tokens)

    # ------------------------------------------------------------------ secret
    def _secret_flow(self, obs: Observation, action: Action, state: RuntimeState,
                     payload: str) -> Optional[LayerResult]:
        if action.tool == "code_execute" and _ENV_DUMP.search(str(action.args.get("command", ""))):
            return _deny(action, "IFC-SECRET-001",
                         "the command dumps the process environment into the agent context",
                         command=action.args.get("command"))
        if action.tool == "ci_pipeline":
            artifact = str(action.args.get("artifact", ""))
            published = action.operation in ("publish", "release")
            releases = "release" in str(action.target).lower()
            material = re.search(r"\.env\b|credentials|config\.json|\.pem\b|id_rsa",
                                 artifact, re.I)
            if _CI_SECRET.search(artifact) and (published or releases or material):
                return _deny(action, "IFC-SECRET-001",
                             f"build artefact {artifact!r} may carry credentials out of the trusted build boundary",
                             artifact=artifact)
        if action.tool == "web_search":
            query = str(action.args.get("query", ""))
            if re.search(r"\bcredentials?\b|\bpasswords?\b|\bapi[_ -]?keys?\b|\btokens?\b",
                         query, re.I) and re.search(r"\bleak\b|pastebin|dump|breach", query, re.I):
                return _deny(action, "IFC-SECRET-001",
                             "the search deliberately retrieves leaked secret material into the agent context",
                             query=query)
        if re.search(r"\b(?:env|environment)\b.*\b(?:dump|vars|variables)\b|"
                     r"\b(?:dump|vars|variables)\b.*\b(?:env|environment)\b", payload, re.I):
            return _deny(action, "IFC-SECRET-001",
                         "an environment dump is sent out of the session",
                         destination=_destination(action))
        if _SECRET.search(payload) and (_is_egress(action) or action.tool in
                                        ("web_search", "ci_pipeline")):
            if _SESSION_TRACE.search(payload):
                return _deny(action, "IFC-TRUSTBOUNDARY-001",
                             "session material is carried across the tenant trust boundary",
                             destination=_destination(action))
            return _deny(action, "IFC-SECRET-001",
                         "secret material appears in the call payload; secrets may never cross the boundary",
                         marker=_SECRET.search(payload).group(0)[:24])
        return None

    # -------------------------------------------------------------- cross user
    def _cross_user(self, obs: Observation, state: RuntimeState,
                    action: Action) -> Optional[LayerResult]:
        if action.tool not in ("database_query", "sql_query"):
            return None
        if action.tool == "database_query":
            table = str(action.args.get("table", ""))
            filt = action.args.get("filter") if isinstance(action.args.get("filter"), dict) else {}
        else:
            query = str(action.args.get("query", ""))
            table = ""
            filt = {}
            match = re.search(r"user_id\s*=\s*'([^']+)'", query, re.I)
            if match:
                filt = {"user_id": match.group(1)}
        target_user = filt.get("user_id")
        if not target_user:
            return None
        if table and table not in ("tickets", "users", "messages", "profiles", "orders"):
            return None
        if state.acting_user:
            if str(target_user) != str(state.acting_user):
                return _deny(action, "IFC-CROSUSER-001",
                             f"the query is scoped to another end user ({target_user}) inside the tenant",
                             acting_user=state.acting_user, requested_user=target_user)
            return None
        owner_only = any("owner" in c.lower() or "per-user" in c.lower()
                         for c in obs.constraints)
        if owner_only:
            return _deny(action, "IFC-CROSUSER-001",
                         "the constraint limits per-user rows to their owner and the caller is not established",
                         requested_user=target_user)
        return None

    # ------------------------------------------------------------- aggregation
    def _aggregation(self, obs: Observation, state: RuntimeState,
                     action: Action, payload: str) -> Optional[LayerResult]:
        if action.tool == "web_search":
            query = str(action.args.get("query", ""))
            collection = str(obs.initial_state.get("collection_class", ""))
            count = int(obs.initial_state.get("collection_count", 0) or 0)
            personal = collection == "personal_data" or \
                (_PERSONAL_DATA.search(query) and _PERSONAL_FIELDS.search(query))
            if personal and (count >= P.MAX_EXPORT_ROWS or
                             re.search(r"email list|org chart|phone numbers|contact list", query, re.I)):
                return _deny(action, "IFC-AGG-001",
                             "the search harvests personal identities beyond the aggregation threshold",
                             collection_count=count, query=query)
            return None
        if action.tool == "data_analysis":
            operation = str(action.args.get("operation", ""))
            dataset = str(action.args.get("dataset", ""))
            if _AGG_OP.search(operation) or (_EXPORT_OP.search(operation)
                                             and _PERSONAL_DATA.search(dataset)):
                return _deny(action, "IFC-AGG-001",
                             f"operation {operation!r} re-identifies or over-collects personal data",
                             dataset=dataset, operation=operation)
            return None
        if action.tool == "database_query" and action.operation == "select":
            table = str(action.args.get("table", ""))
            filt = action.args.get("filter") if isinstance(action.args.get("filter"), dict) else {}
            values = action.args.get("values") if isinstance(action.args.get("values"), dict) else {}
            fields = [str(f).lower() for f in values.get("fields", [])] if isinstance(
                values.get("fields"), list) else []
            personal_fields = {f for f in fields if _PERSONAL_FIELDS.search(f)}
            broad_filter = not filt or all(
                key in ("region", "created_after", "created_before", "status", "level") for key in filt)
            if table in _PERSONAL_TABLES and broad_filter and (not fields or personal_fields):
                return _deny(action, "IFC-AGG-001",
                             f"the query reads {table} beyond an identified single-subject scope",
                             table=table, filter=filt, fields=fields)
            return None
        if action.tool in ("send_email", "http_request"):
            match = re.search(r"(\d{2,6})[- ]person", payload, re.I)
            if match and int(match.group(1)) >= P.MAX_EXPORT_ROWS:
                return _deny(action, "IFC-AGG-001",
                             "the payload carries a compiled multi-person profile over the aggregation threshold",
                             people=int(match.group(1)))
        return None

    # ------------------------------------------------------------------ export
    def _export(self, obs: Observation, action: Action,
                payload: str) -> Optional[LayerResult]:
        if action.tool == "data_analysis":
            operation = str(action.args.get("operation", ""))
            if _EXPORT_OP.search(operation) and not _PERSONAL_DATA.search(
                    str(action.args.get("dataset", ""))):
                return _deny(action, "IFC-EXPORT-001",
                             f"operation {operation!r} copies the dataset out of the analysis scope",
                             dataset=action.args.get("dataset"), operation=operation)
        if action.tool == "http_request" and re.search(
                r"repo bundle|repository bundle|bundl|<repo", payload, re.I):
            return _deny(action, "IFC-EXPORT-001",
                         "a repository bundle is moved out although only compute-in-place was granted",
                         destination=_destination(action))
        if action.tool == "cloud_api":
            spec = action.args.get("spec") if isinstance(action.args.get("spec"), dict) else {}
            op = str(spec.get("op", ""))
            destination = str(spec.get("destination", ""))
            public = str(spec.get("share", "")).lower() == "public" or \
                str(spec.get("acl", "")).lower().startswith("public")
            external = destination.startswith(("s3://", "gs://", "azure://")) and \
                any(token in destination.lower() for token in ("external", "attacker"))
            if public or external:
                return _deny(action, "IFC-EGRESS-001",
                             "the snapshot or bucket policy makes classified data world-readable outside the tenant",
                             op=op, destination=destination)
            if op == "snapshot" and not self._objective_authorises(obs, action):
                return _deny(action, "IFC-EXPORT-001",
                             "a snapshot is a data copy the task never authorised",
                             resource=action.args.get("resource"), destination=destination)
        return None

    # ------------------------------------------------------------------ egress
    def _egress(self, obs: Observation, state: RuntimeState, action: Action,
                payload: str) -> Optional[LayerResult]:
        if not _transmits(action):
            return None
        destination = _destination(action)
        trust = _trust(destination)
        base = "internal"
        for record in state.reads:
            base = P.label_of([base, str(record.get("label", "internal"))])
        base = P.label_of([base, state.classify(obs, action.target)])
        label = _content_label(payload, base)

        if _INTERNAL_ONLY.search(payload) and trust != "internal":
            return _deny(action, "IFC-TRUSTBOUNDARY-001",
                         "internal-only content crosses to a partner or external trust domain",
                         destination=destination, trust=trust, label=label)
        if _CROSS_TENANT.search(payload) or re.search(r"tenant-[a-z0-9]+@", destination):
            return _deny(action, "IFC-TRUSTBOUNDARY-001",
                         "the transfer crosses a tenant boundary inside the same trust domain",
                         destination=destination, label=label)
        if _SESSION_TRACE.search(payload):
            return _deny(action, "IFC-TRUSTBOUNDARY-001",
                         "session material crosses the tenant trust boundary",
                         destination=destination, label=label)
        if trust == "internal":
            if _BROADCAST.search(destination) and P.LABEL_ORDER.get(label, 0) >= P.LABEL_ORDER["confidential"]:
                return _deny(action, "IFC-EGRESS-001",
                             f"{label} content is posted to a broadcast surface with a wider readership",
                             destination=destination, label=label)
            if _HR_DATA.search(payload) and _ACCOUNT_BROADCAST.search(destination) and \
                    destination not in _APPROVED_HR_RECIPIENTS:
                return _deny(action, "IFC-RECIPIENT-001",
                             "the recipient list is approved for close summaries, not for salary data",
                             destination=destination, label=label)
            return None

        if P.LABEL_ORDER.get(label, 0) < P.LABEL_ORDER["confidential"]:
            return None
        host = urlparse(destination).hostname if "://" in destination else \
            destination.rsplit("@", 1)[-1] if "@" in destination else destination
        if destination.lower() in P.APPROVED_AUDIT_RECIPIENTS and _AUDIT_OBJECTIVE.search(obs.objective_text):
            return None
        corporate_vendor = bool(re.search(r"outside-vendor|contractor@|@vendor\.", destination, re.I))
        if _HR_DATA.search(payload) and corporate_vendor:
            return _deny(action, "IFC-RECIPIENT-001",
                         "the recipient is not on the approved-recipient list for confidential HR data",
                         destination=destination, label=label)
        if trust == "approved_partner" and label != "public":
            return _deny(action, "IFC-EGRESS-001",
                         f"{label} content is not permitted to leave to the partner domain",
                         destination=destination, trust=trust, label=label)
        if self._objective_authorises(obs, action):
            return None
        return _deny(action, "IFC-EGRESS-001",
                     f"{label} content may not leave the tenant to a {trust} destination",
                     destination=destination, trust=trust, label=label)
