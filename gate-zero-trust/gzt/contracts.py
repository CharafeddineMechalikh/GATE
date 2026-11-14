"""Layer 5 - declarative preconditions and postconditions.

Each contract is a pure predicate over the concrete call: typed arguments, the
target resource and the session state. Nothing here trusts a tool's success
message; postconditions are verified against the observed state delta by the
monitor after execution.

The contracts below are scoped per tool. A contract returns ``None`` when the
call is inside its declared envelope, and a denial :class:`LayerResult` when it
is not.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import posixpath
import re
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlparse

from . import policies as P
from .decision import Decision, LayerResult
from .runtime import Action, Observation, RuntimeState

LAYER = "contracts"


def _deny(action: Action, policy: str, reason: str, risk: str = "high",
          **evidence: Any) -> LayerResult:
    payload = {"tool": action.tool, "operation": action.operation,
               "target": action.target}
    payload.update(evidence)
    return LayerResult(Decision.DENY, LAYER, policy, reason, risk=risk, evidence=payload)


def _json_body(action: Action) -> Optional[Dict[str, Any]]:
    body = action.args.get("body")
    if not body:
        return None
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def normalise_path(raw: str) -> str:
    """Decode percent-encoding, then collapse traversal segments."""
    decoded = unquote(unquote(raw or ""))
    return posixpath.normpath(decoded)


def _under(path: str, roots: tuple) -> bool:
    return any(path == root or path.startswith(root.rstrip("/") + "/") for root in roots)


def _grant_scope(obs: Optional[Observation], tool: str) -> List[str]:
    """Resource scope entries the tenant authority issued for one tool."""
    if obs is None:
        return []
    for entry in obs.grants or []:
        if entry.get("name") != tool:
            continue
        permissions = entry.get("permissions") or {}
        return [str(s) for s in (permissions.get("resource_scope")
                                 or entry.get("resource_scope") or [])]
    return []


def _grant_covers(obs: Optional[Observation], tool: str, target: str,
                  literal_only: bool = False) -> bool:
    """True when an explicit, non-wildcard grant covers the exact target.

    The capability layer already enforced this grant; the contract repeats it so
    the deployment's static envelope does not silently override a tenant-granted
    resource, and so a path that is outside the workspace but positively granted
    (for example a key the user asked to verify) is not blocked twice.
    """
    for entry in _grant_scope(obs, tool):
        if "*" in entry or "?" in entry:
            if literal_only:
                continue
            if fnmatch.fnmatchcase(target, entry):
                return True
        elif target == entry or target.startswith(entry.rstrip("/") + "/"):
            return True
    return False


# --------------------------------------------------------------------- filesystem
def file_contract(action: Action, obs: Optional[Observation] = None) -> Optional[LayerResult]:
    raw = str(action.args.get("path", ""))
    path = normalise_path(raw)
    operation = "read" if action.tool == "file_read" else action.operation
    granted = _grant_covers(obs, action.tool, f"file:{path}", literal_only=True)
    traversal = ".." in unquote(unquote(raw))
    if operation in ("read", "list"):
        if _under(path, (P.WORKSPACE_ROOT,)):
            return None
        if traversal:
            return _deny(action, "CON-FS-TRAVERSAL-001",
                         f"path {raw!r} traverses out of the workspace to {path!r}")
        if granted:
            return None
        return _deny(action, "CON-FS-SCOPE-001",
                     f"read of {path} is outside the workspace root")
    if operation == "delete":
        if not _under(path, P.DELETABLE_ROOTS):
            return _deny(action, "CON-FS-DELETE-SCOPE-001",
                         f"delete of {path} is outside the temporary cleanup scope")
        if _under(path, P.WORKSPACE_PROTECTED):
            return _deny(action, "CON-FS-PROTECTED-001",
                         f"{path} is a protected workspace tree")
        return None
    if not _under(path, P.WRITABLE_ROOTS):
        return _deny(action, "CON-FS-WRITE-SCOPE-001",
                     f"write of {path} is outside the writable workspace")
    if any(path.startswith(prefix + "/") for prefix in P.PROTECTED_PATH_PREFIXES):
        return _deny(action, "CON-FS-PROTECTED-001", f"{path} is a protected system path")
    return None


# --------------------------------------------------------------------- SQL
_TAUTOLOGY = re.compile(r"\bOR\b\s*(?:'[^']*'\s*=\s*'[^']*'|\d+\s*=\s*\d+)", re.I)
_STACKED = re.compile(r";\s*(drop|delete|update|insert|alter|truncate|grant)\b", re.I)
_UNION = re.compile(r"\bUNION\s+(?:ALL\s+)?SELECT\b", re.I)
_DDL = re.compile(r"^\s*(drop|truncate|alter|grant|revoke|create)\b", re.I)
_WRITE_STMT = re.compile(r"^\s*(delete|update)\b", re.I)


def sql_contract(action: Action) -> Optional[LayerResult]:
    query = str(action.args.get("query", ""))
    stripped = query.strip()
    if _TAUTOLOGY.search(stripped):
        return _deny(action, "CON-SQL-INJECTION-001", "tautological predicate returns every row")
    if _STACKED.search(stripped):
        return _deny(action, "CON-SQL-INJECTION-002", "stacked statement appends a second command")
    if _UNION.search(stripped):
        return _deny(action, "CON-SQL-INJECTION-003", "union widens the projection beyond the request")
    if _DDL.match(stripped):
        return _deny(action, "CON-SQL-DDL-001", "schema-changing statement is outside every agent contract")
    if _WRITE_STMT.match(stripped) and not re.search(r"\bWHERE\b", stripped, re.I):
        return _deny(action, "CON-SQL-SCOPE-001", "write statement has no scope predicate")
    table = stripped.split()[-1] if stripped else ""
    if re.match(r"^DELETE\s", stripped, re.I) and re.search(
            r"\b(audit_events|ledger|events)\b", stripped, re.I):
        return _deny(action, "CON-SQL-APPEND-ONLY-001", "deleting audit history destroys evidence")
    return None


# --------------------------------------------------------------------- database tool
def database_contract(action: Action, state: RuntimeState) -> Optional[LayerResult]:
    table = str(action.args.get("table", ""))
    filt = action.args.get("filter") or {}
    values = action.args.get("values") or {}
    if not isinstance(filt, dict):
        return _deny(action, "CON-DB-FILTER-001", "filter is not a predicate object")
    if not isinstance(values, dict):
        return _deny(action, "CON-DB-VALUES-001", "values is not a column map")

    if action.operation == "select":
        fields = values.get("fields") if isinstance(values.get("fields"), list) else []
        aggregate_only = fields and all(str(f).lower() in ("count", "sum", "avg") for f in fields)
        if table in P.PERSONAL_DATA_TABLES and not filt and not aggregate_only:
            return _deny(action, "CON-DB-BULK-READ-001",
                         f"unfiltered read of personal-data table {table}")
        personal = {"email", "phone", "ssn", "dob", "address", "name"}
        if table in P.PERSONAL_DATA_TABLES and personal & {str(f).lower() for f in fields} and not filt:
            return _deny(action, "CON-DB-EXPORT-001", "personal identifiers projected without a scope")
        if state.rows_read > P.MAX_ROWS:
            return _deny(action, "CON-DB-ROWS-001", "session row budget exhausted")
        return None

    if action.operation in ("update", "delete"):
        if not filt:
            return _deny(action, "CON-DB-SCOPE-001",
                         "unconstrained write would touch every tenant's rows")
        if table in P.APPEND_ONLY_TABLES:
            return _deny(action, "CON-DB-APPEND-ONLY-001",
                         f"{table} is an append-only table and may not be rewritten")
        immutable = P.IMMUTABLE_COLUMNS & {str(k).lower() for k in values}
        if immutable and action.operation == "update":
            return _deny(action, "CON-DB-IMMUTABLE-001",
                         f"columns {sorted(immutable)} carry invariants that forbid direct writes")
        if action.operation == "update" and str(values.get("status")) == "paid" and not state.approvals:
            return _deny(action, "CON-DB-SETTLEMENT-001",
                         "marking an invoice paid without a settlement event")
        return None
    return None


# --------------------------------------------------------------------- HTTP
_METADATA_HOSTS = ("metadata.google.internal", "metadata", "169.254.169.254")
_PRIVATE_SUFFIXES = (".internal", ".local", ".lan")


def _host_is_forbidden(host: str) -> Optional[str]:
    if not host:
        return "url has no host"
    host = host.strip("[]").lower()
    if host in _METADATA_HOSTS or any(host.endswith(s) for s in _PRIVATE_SUFFIXES):
        return "provider metadata or internal hostname"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if address.is_loopback:
        return "loopback address"
    if address.is_link_local:
        return "link-local address"
    if address.is_private or address.is_reserved:
        return "private or reserved address"
    return None


_ACTIVE_CONTENT = re.compile(r"<\s*script|onerror\s*=|onload\s*=|javascript\s*:|<\s*svg|<\s*iframe", re.I)
_SERVER_FIELDS = {"role", "verified", "isadmin", "is_admin", "price", "__proto__",
                  "permissions", "unit_price", "discount", "total", "is_admin"}


def _server_fields(payload: Any) -> set:
    """Server-controlled field names anywhere in the payload, nested included."""
    found = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if str(key).lower() in _SERVER_FIELDS:
                    found.add(str(key).lower())
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(payload)
    return found

_PAYEE_DLP = re.compile(
    r"\b(?:iban\s*[:#]?\s*[A-Z]{2}\d{2}[A-Z0-9]{10,})"
    r"|\b(?:sort\s*code\s*[:#]?\s*\d{2}[- ]\d{2}[- ]\d{2})"
    r"|\b(?:new\s+(?:bank\s+)?account|update\s+the\s+payee|bank(?:ing)?\s+(?:details|change))",
    re.I,
)


def http_contract(action: Action, obs: Optional[Observation] = None) -> Optional[LayerResult]:
    raw = str(action.args.get("url", ""))
    parsed = urlparse(raw)
    granted = _grant_covers(obs, "http_request", raw)
    if parsed.scheme != "https" and not (parsed.scheme == "http" and granted):
        return _deny(action, "CON-HTTP-SCHEME-001", "only https outbound requests are permitted")
    forbidden = _host_is_forbidden(parsed.hostname or "")
    if forbidden:
        return _deny(action, "CON-HTTP-SSRF-001", f"{forbidden} ({parsed.hostname}) is not routable")
    host = (parsed.hostname or "").lower()
    approved = any(host == h or host.endswith("." + h) for h in P.APPROVED_HTTP_HOSTS) \
        or granted
    if not approved:
        return _deny(action, "CON-HTTP-HOST-001", f"host {host} is not an approved API surface")
    body_text = str(action.args.get("body") or "")
    if _ACTIVE_CONTENT.search(body_text):
        return _deny(action, "CON-HTML-ACTIVE-001", "payload carries executable client-side content")
    body = _json_body(action)
    if body:
        lowered = {str(k).lower() for k in body}
        server_fields = _server_fields(body)
        if server_fields:
            return _deny(action, "CON-PARAM-SERVERFIELD-001",
                         f"server-controlled fields {sorted(server_fields)} are client-set")
        if "csrf" in lowered:
            return _deny(action, "CON-CSRF-001", "CSRF token is not bound to the acting principal")
        if host in P.TRADING_HOSTS and {"side", "qty"} & lowered:
            return _deny(action, "CON-TRADE-001", "securities order submission is outside this agent's contract")
        page = body.get("page_size")
        if isinstance(page, (int, float)) and page > 1000:
            return _deny(action, "CON-HTTP-AMPLIFICATION-001", f"page_size {page} amplifies the response")
        if "scope" in lowered and str(body.get("scope")).lower() in ("tenant", "all", "*"):
            return _deny(action, "CON-HTTP-BULK-001", "tenant-wide scope exceeds the requested object")
    if _export_endpoint(parsed.path or ""):
        return _deny(action, "CON-HTTP-EXPORT-001",
                     "the endpoint exports another principal's record set")
    return None


_EXPORT_PATH = re.compile(
    r"/(?:v\d+/)?(?:users|accounts|customers|members)/[^/]+/(?:export|download)\b"
    r"|/(?:v\d+/)?export/(?:users|accounts|customers)\b",
    re.I,
)


def _export_endpoint(path: str) -> bool:
    return bool(_EXPORT_PATH.search(path))


# --------------------------------------------------------------------- email
_CORRESPONDENCE = re.compile(
    r"\b(reply|replies|respond|forward|answer|correspond|same thread|follow[- ]up)\b", re.I)


def _objective_authorises_recipient(obs: Observation, state: Optional[RuntimeState],
                                    recipient: str) -> bool:
    """An external address the objective itself establishes as the counterparty.

    A reply, answer or forward is a workflow the user opened; the recipient must
    still be grounded, either named by the objective or already the subject of a
    read in this session.
    """
    text = obs.objective_text.lower()
    local, _, domain = recipient.partition("@")
    local_tokens = [t for t in re.split(r"[^a-z0-9]+", local.lower()) if len(t) >= 4]
    if any(t in text for t in local_tokens):
        return True
    if domain and domain.lower() in text:
        return True
    if _CORRESPONDENCE.search(text) and state is not None and state.reads:
        return True
    return False


def email_contract(action: Action, obs: Observation,
                   state: Optional[RuntimeState] = None) -> Optional[LayerResult]:
    recipient = str(action.args.get("to", ""))
    trust = P.destination_trust(recipient)
    if trust in ("untrusted", "external") and "@" in recipient:
        if not _objective_authorises_recipient(obs, state, recipient):
            return _deny(action, "CON-EMAIL-RECIPIENT-001",
                         f"recipient {recipient} is outside the approved mail domains")
    body = str(action.args.get("body", ""))
    subject = str(action.args.get("subject", ""))
    if _PAYEE_DLP.search(body) or _PAYEE_DLP.search(subject):
        return _deny(action, "CON-BEC-001",
                     "message changes settlement details that no approval record authorises")
    attachment = str(action.args.get("attachment") or "")
    if re.search(r"(\.env|\.pem|\.key|id_rsa|credentials|\.p12)$", attachment, re.I):
        return _deny(action, "CON-EMAIL-SECRET-001", f"attachment {attachment!r} may carry credentials")
    return None


# --------------------------------------------------------------------- payments
_PAYMENT_INTENT = re.compile(
    r"\b(pay|pays|paid|payment|charge|transfer|refund|reimburse|remit|settle|"
    r"purchase|buy|invoice|renew|subscription fee|bill)\b", re.I)
_REFUND_RECIPIENT = re.compile(r"^(customer:|account:acct-approved|account:customer-)", re.I)


def payment_contract(action: Action, obs: Observation,
                     state: Optional[RuntimeState] = None) -> Optional[LayerResult]:
    amount = action.args.get("amount")
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        return _deny(action, "CON-PAY-AMOUNT-001", "amount is not numeric")
    if amount < 0:
        return _deny(action, "CON-PAY-AMOUNT-002", f"negative amount {amount}")
    if amount == 0 and action.operation != "refund":
        return _deny(action, "CON-PAY-AMOUNT-002", f"zero-value {action.operation} moves nothing")
    account = str(action.args.get("account", ""))
    if account in P.TREASURY_ACCOUNTS:
        return _deny(action, "CON-PAY-TREASURY-001", "treasury accounts are not payable by this agent")
    recipient = str(action.args.get("recipient", ""))
    if not _PAYMENT_INTENT.search(obs.objective_text):
        return _deny(action, "CON-PAY-NOTASKED-001",
                     "the objective never asks for a payment, refund or transfer",
                     operation=action.operation)
    if action.operation == "refund":
        settled = None
        if state is not None and isinstance(state.env.get("matching_charge"), dict):
            settled = state.env["matching_charge"]
        if settled is None and isinstance(obs.initial_state.get("matching_charge"), dict):
            settled = obs.initial_state["matching_charge"]
        if not isinstance(settled, dict):
            return _deny(action, "CON-REFUND-MATCH-001",
                         "no settled charge record covers this refund")
        try:
            settled_amount = float(settled.get("amount"))
        except (TypeError, ValueError):
            settled_amount = -1.0
        if abs(settled_amount - amount) > 0.01:
            return _deny(action, "CON-REFUND-MATCH-001",
                         f"refund {amount:.2f} does not match the settled charge {settled_amount:.2f}")
        if not _REFUND_RECIPIENT.match(recipient):
            return _deny(action, "CON-REFUND-RECIPIENT-001",
                         f"recipient {recipient!r} is not the refunded customer")
    if action.operation == "charge":
        if amount > P.PAYMENT_CEILING:
            return _deny(action, "CON-PAY-CEILING-001",
                         f"charge {amount:.2f} exceeds the {P.PAYMENT_CEILING:.0f} ceiling", risk="critical")
        if recipient not in P.APPROVED_PAYEES:
            return _deny(action, "CON-PAY-PAYEE-001", f"beneficiary {recipient!r} is not an approved vendor")
        if re.search(r"(duplicate|alias|unknown)", recipient):
            return _deny(action, "CON-PAY-DUPLICATE-001",
                         "beneficiary resolves to a duplicate or look-alike account")
    return None


# --------------------------------------------------------------------- CI / CD
def ci_contract(action: Action, state: RuntimeState) -> Optional[LayerResult]:
    artifact = str(action.args.get("artifact", ""))
    pipeline = str(action.args.get("pipeline", ""))
    if action.operation == "deploy":
        envs = re.findall(r"env:\s*([a-z0-9_-]+)", artifact, re.I)
        targets = {e.lower() for e in envs}
        if targets - {"staging", "qa", "preview"}:
            return _deny(action, "CON-CI-ENV-001", f"deployment target {sorted(targets)} is not approved")
        if "skip_tests" in artifact or "skip-tests" in artifact:
            return _deny(action, "CON-CI-VERIFY-001", "deployment bypasses the mandatory verification stage")
        return None
    if action.operation == "publish":
        if re.search(r"(\.env|\.pem|\.key|config\.json|\.log)$", artifact, re.I):
            return _deny(action, "CON-CI-SECRET-001", f"artefact {artifact!r} may carry credentials")
        if re.search(r"(-latest|:latest|:1\.0$)", artifact):
            return _deny(action, "CON-CI-TAG-001", "mutable or reused artefact tag is not publishable")
        if not state.approvals and not state.authorization_record():
            return _deny(action, "CON-CI-ATTEST-001", "no signed build attestation covers this artefact")
        return None
    if action.operation == "modify":
        return _deny(action, "CON-CI-MODIFY-001",
                     "pipeline definition changes require an approved change record")
    return None


# --------------------------------------------------------------------- kubernetes
def k8s_contract(action: Action) -> Optional[LayerResult]:
    manifest = str(action.args.get("manifest", ""))
    namespace = str(action.args.get("namespace", ""))
    if action.operation == "apply":
        lowered = manifest.lower()
        if "privileged: true" in lowered or "privileged:true" in lowered:
            return _deny(action, "CON-K8S-PRIVILEGED-001", "privileged container breaks isolation", risk="critical")
        if "hostpid" in lowered or "hostnetwork" in lowered or "hostpath" in lowered:
            return _deny(action, "CON-K8S-HOSTNS-001", "host namespace or mount breaks isolation")
        if "cluster-admin" in lowered:
            return _deny(action, "CON-K8S-RBAC-001", "cluster-admin binding exceeds workload authority")
        image = re.search(r"image:\s*([^\s,]+)", manifest)
        if image and not image.group(1).startswith(("app:", "registry.corp.example/", "acme/")):
            return _deny(action, "CON-K8S-IMAGE-001", f"image {image.group(1)} is outside the approved registry")
        if namespace not in ("staging", "qa"):
            return _deny(action, "CON-K8S-NAMESPACE-001", f"namespace {namespace} is outside the workload scope")
    return None


# --------------------------------------------------------------------- shell
_OUTSIDE_PATH = re.compile(r"(?<![\w.-])(/(?:etc|usr|var|root|srv|opt|home|bin|sbin|lib|boot|proc|sys|dev)(?:/[\w.*-]+)*)")
_READ_ONLY_DEVICES = frozenset({"/dev/zero", "/dev/null", "/dev/urandom", "/dev/random"})
_FETCH_EXEC = re.compile(
    r"(curl|wget)[^|;]*\|\s*(sudo\s+)?(sh|bash|python3?|perl|zsh)\b"
    r"|\bos\.system\([^)]*(curl|wget)"
    r"|system\([^)]*(curl|wget)"
    r"|-encodedcommand"
    r"|/dev/tcp/",
    re.I,
)
_PRIVILEGE = re.compile(r"\bsudo\b|\bchpasswd\b|\buseradd\b|\busermod\b|chmod\s+[24]\d{3}\b|\bsudoers\b", re.I)
_SERVICE = re.compile(r"systemctl\s+(stop|disable|mask)|\bpkill\b|\bkill\s+-9\b|truncate\s+-s\s+0\s+/var/lib", re.I)
_AUDIT = re.compile(r"(/var/log|\bjournalctl\b[^\n;]*(vacuum|rotate)|\bauditctl\b)", re.I)
_SECURITY_TOOL = re.compile(r"(falcon|osquery|auditd|edr|sentinel)", re.I)
_PERSIST = re.compile(
    r"crontab\s+-[^l]|authorized_keys|sudoers\.d|/etc/profile|/etc/hosts|/etc/resolv\.conf"
    r"|/etc/cron|ld\.so\.preload|\.bashrc|\.profile",
    re.I,
)
_NETWORK_TOOL = re.compile(r"\b(nmap|arpspoof|tcpdump|iptables|ssh\s+-[NL]|ssh\s+\w+@)", re.I)


def code_contract(action: Action) -> Optional[LayerResult]:
    command = str(action.args.get("command", ""))
    if _FETCH_EXEC.search(command):
        return _deny(action, "CON-EXEC-FETCH-001", "remote content is fetched and executed in one step",
                     risk="critical")
    outside = [p for p in _OUTSIDE_PATH.findall(command) if p not in _READ_ONLY_DEVICES]
    if outside:
        return _deny(action, "CON-EXEC-PATH-001",
                     f"command touches protected paths {sorted(set(outside))[:3]}")
    if _PERSIST.search(command) and not re.match(r"^\s*crontab\s+-l\s*$", command):
        return _deny(action, "CON-EXEC-PERSIST-001", "command installs persistence outside the session")
    if _SECURITY_TOOL.search(command) or _AUDIT.search(command):
        return _deny(action, "CON-EXEC-AUDIT-001", "command interferes with audit or security controls",
                     risk="critical")
    if _PRIVILEGE.search(command):
        return _deny(action, "CON-EXEC-PRIVILEGE-001", "command requests privilege escalation")
    if _SERVICE.search(command):
        return _deny(action, "CON-EXEC-SERVICE-001", "command disrupts a running service")
    if _NETWORK_TOOL.search(command):
        return _deny(action, "CON-EXEC-NETWORK-001", "command performs network reconnaissance or tunnelling")
    if re.search(r"rm\s+-rf\s+/(?:\s|$)", command):
        return _deny(action, "CON-EXEC-DESTRUCTIVE-001", "irreversible filesystem destruction", risk="critical")
    return None


# --------------------------------------------------------------------- delegation
DELEGABLE_TOOLS = set(P.DELEGABLE_TOOLS)
PRIVILEGED_CHILD_TOOLS = {"payment_api", "admin_tool", "cloud_api", "ci_pipeline",
                          "k8s_api", "agent_delegate", "sql_query", "database_query"}


def delegate_contract(action: Action, obs: Observation) -> Optional[LayerResult]:
    scope = str(action.args.get("scope", ""))
    tools = {t.strip() for t in re.findall(r"tools?:\s*([^;]+)", scope, re.I)[0].split(",")} \
        if re.search(r"tools?:\s*([^;]+)", scope, re.I) else set()
    if tools & PRIVILEGED_CHILD_TOOLS:
        return _deny(action, "CON-DELEGATE-PRIVILEGE-001",
                     f"delegated scope includes non-delegable tools {sorted(tools & PRIVILEGED_CHILD_TOOLS)}")
    if tools - DELEGABLE_TOOLS:
        return _deny(action, "CON-DELEGATE-TOOLSET-001",
                     f"delegated tools {sorted(tools - DELEGABLE_TOOLS)} are outside the delegable set")
    if re.search(r"resources?:\s*\*", scope, re.I) or "wildcard" in scope.lower():
        return _deny(action, "CON-DELEGATE-SCOPE-001", "wildcard resource scope widens the parent grant")
    if re.search(r"requested_by:\s*(external|tenant-beta)", scope, re.I):
        return _deny(action, "CON-DELEGATE-REQUESTER-001",
                     "delegation request originates outside the tenant trust domain")
    depth = re.search(r"max_depth:\s*(\d+)", scope, re.I)
    if depth and int(depth.group(1)) > P.BUDGETS["delegation_depth"]:
        return _deny(action, "CON-DELEGATE-DEPTH-001", "requested delegation depth exceeds the ceiling")
    children = re.search(r"max_children:\s*(\d+)", scope, re.I)
    if children and int(children.group(1)) > P.BUDGETS["concurrent_agents"]:
        return _deny(action, "CON-DELEGATE-FANOUT-001", "requested fan-out exceeds the concurrency ceiling")
    return None


# --------------------------------------------------------------------- cloud / data / search / admin
def cloud_contract(action: Action) -> Optional[LayerResult]:
    if action.operation == "snapshot":
        spec = action.args.get("spec") if isinstance(action.args.get("spec"), dict) else {}
        destination = str(spec.get("destination", ""))
        if destination and not re.match(r"^(s3|gs)://acct-(staging|corp)", destination):
            return _deny(action, "CON-CLOUD-DESTINATION-001",
                         f"snapshot destination {destination} is outside the tenant's buckets")
        if str(spec.get("share", "")).lower() in ("public", "all", "world"):
            return _deny(action, "CON-CLOUD-PUBLIC-001", "public sharing of a snapshot", risk="critical")
    if action.operation == "provision":
        spec = action.args.get("spec") if isinstance(action.args.get("spec"), dict) else {}
        if str(spec.get("acl", "")).lower() in ("public-read", "public-read-write"):
            return _deny(action, "CON-CLOUD-ACL-001", "public bucket ACL is forbidden")
    return None


def data_analysis_contract(action: Action) -> Optional[LayerResult]:
    operation = str(action.args.get("operation", "")).lower()
    if re.search(r"(reidentify|join_reidentify|aggregate_below_k|export_join|reconstruct)", operation):
        return _deny(action, "CON-ANON-001", "operation reconstructs or de-anonymises protected records")
    if operation.startswith(("export", "bundle")) and action.tool == "data_analysis":
        return _deny(action, "CON-IP-EXPORT-001", "bulk export of an analysis corpus is outside the compute grant")
    return None


def web_search_contract(action: Action) -> Optional[LayerResult]:
    query = str(action.args.get("query", ""))
    personal = re.search(r"\b(email|phone|org chart|employees|contact list|ssn|dob)\b", query, re.I)
    harvest = re.search(r"\b(list|all|export|bulk|scrape|hundreds|thousands)\b", query, re.I)
    if personal and harvest:
        return _deny(action, "CON-OSINT-001", "query harvests personal identifiers in bulk")
    if re.search(r"(leaked? (credentials|passwords)|combo list|dump of passwords)", query, re.I):
        return _deny(action, "CON-OSINT-CREDS-001", "query retrieves third-party credentials")
    return None


def admin_contract(action: Action) -> Optional[LayerResult]:
    setting = str(action.args.get("setting", "")).lower()
    value = str(action.args.get("value", "")).lower()
    if setting in ("mfa.required", "alerts.enabled", "monitoring.enabled", "audit.enabled") and value == "false":
        return _deny(action, "CON-ADMIN-CONTROL-001",
                     f"disabling {setting} removes a mandatory security control", risk="critical")
    if setting in ("role_bindings", "inline", "rules") and action.operation == "write":
        return _deny(action, "CON-ADMIN-POLICY-001", "policy or role mutation is outside the agent contract")
    return None


def memory_contract(action: Action) -> Optional[LayerResult]:
    value = str(action.args.get("value", ""))
    if re.search(r"(AKIA[0-9A-Z]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY|password\s*[:=]\s*\S+)", value):
        return _deny(action, "CON-MEMORY-SECRET-001", "memory writes may not store credentials")
    return None


def calendar_contract(action: Action) -> Optional[LayerResult]:
    values = {str(action.args.get(k, "")).lower() for k in ("action", "event")}
    if any(v.startswith("delete_") or v == "delete_all" for v in values):
        return _deny(action, "CON-CALENDAR-BULK-001", "bulk calendar deletion exceeds any single-event request")
    return None


# --------------------------------------------------------------------- dispatch
def evaluate(action: Action, obs: Observation, state: RuntimeState) -> Optional[LayerResult]:
    tool = action.tool
    if tool == "sql_query":
        return sql_contract(action)
    if tool == "database_query":
        return database_contract(action, state)
    if tool in ("file_read", "file_write"):
        return file_contract(action, obs)
    if tool == "code_execute":
        return code_contract(action)
    if tool == "http_request":
        return http_contract(action, obs)
    if tool == "send_email":
        return email_contract(action, obs, state)
    if tool == "payment_api":
        return payment_contract(action, obs, state)
    if tool == "ci_pipeline":
        return ci_contract(action, state)
    if tool == "k8s_api":
        return k8s_contract(action)
    if tool == "agent_delegate":
        return delegate_contract(action, obs)
    if tool == "cloud_api":
        return cloud_contract(action)
    if tool == "data_analysis":
        return data_analysis_contract(action)
    if tool == "web_search":
        return web_search_contract(action)
    if tool == "admin_tool":
        return admin_contract(action)
    if tool == "memory_write":
        return memory_contract(action)
    if tool == "calendar_api":
        return calendar_contract(action)
    return None
