"""Layer 2 - finite-state workflow supervision.

The supervisor reasons over the *session*, not over one call in isolation. It
holds the task workflow state (what has been read, staged, stored or delegated)
and rejects a proposed step when executing it would leave the authorised plan:
a replayed one-shot authorisation, a mutation that follows a privileged read, an
instruction laundered through memory or tool output, a written artefact that is
then executed, a delegation that widens the parent's authority, a persistence
install, an environment escalation, or a bulk action wider than the request.

Each rule consumes concrete call arguments and recorded session evidence. The
policy identifiers are the deployment's vocabulary for the violated property.
"""
from __future__ import annotations

import json
import os
import posixpath
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from . import policies as P
from .decision import Decision, LayerResult
from .runtime import Action, Observation, RuntimeState

LAYER = "workflow"

READ_OPS = {"read", "select", "get", "search", "list", "compute"}
MUTATION_OPS = {"write", "append", "create", "delete", "update", "modify", "config",
                "apply", "deploy", "provision", "snapshot", "rotate", "attach"}

# ------------------------------------------------------------------ helpers
_PERSIST = re.compile(
    r"crontab\s+-(?!l)\S|\|\s*crontab\s+-|/etc/cron|systemctl\s+enable|"
    r"authorized_keys|\.bashrc|\.profile\b|launchctl\s+load|schtasks\s+/create",
    re.I,
)
_DESTROY_INFRA = re.compile(
    r"\bterraform\s+destroy\b|\b(?:aws|gcloud|az)\s+[a-z0-9-]+\s+"
    r"(?:delete|terminate|destroy)\b|\bkubectl\s+delete\b[^\n]*--all\b|"
    r"\bhelm\s+uninstall\b",
    re.I,
)
_FORCE_PUSH = re.compile(r"\bgit\s+push\b[^\n]*(?:--force|-f)\b", re.I)
_FOREIGN_SYNC = re.compile(
    r"\b(?:aws\s+s3\s+(?:sync|cp|mv)|rsync|scp)\b[^\n]*?(?P<dest>(?:s3|gs)://[^\s;'\"]+|[\w.-]+@[\w.-]+:[^\s;'\"]+)",
    re.I,
)
_FETCH_EXEC = re.compile(
    r"(?:curl|wget)[^|;]*\|\s*(?:sudo\s+)?(?:sh|bash|python3?|perl|zsh)\b", re.I)
_APPROVED_STORAGE = ("s3://acct-staging", "s3://acct-corp", "gs://acct-staging",
                     "gs://acct-corp")


def _deny(action: Action, policy: str, reason: str, risk: str = "high",
          **evidence: Any) -> LayerResult:
    payload = {"tool": action.tool, "operation": action.operation,
               "target": action.target, "step": action.step}
    payload.update(evidence)
    return LayerResult(Decision.DENY, LAYER, policy, reason, risk=risk, evidence=payload)


def _allow(action: Action, reason: str = "step is inside the authorised workflow",
           **evidence: Any) -> LayerResult:
    return LayerResult.allow(LAYER, "WF-ALLOW-001", reason, evidence=evidence)


def _body(action: Action) -> Optional[Dict[str, Any]]:
    raw = action.args.get("body")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _scope_tokens(scope: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for part in re.split(r"\s*;\s*", scope or ""):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        key = key.strip().lower()
        values = [v.strip() for v in re.split(r"[,\s]+", value) if v.strip()]
        out.setdefault(key, []).extend(values)
    return out


def _family(target: str) -> str:
    return (target or "").split("/")[0]


def _egress_trust(action: Action) -> str:
    if action.tool == "send_email":
        return P.destination_trust(str(action.args.get("to", "")))
    url = str(action.args.get("url", ""))
    host = urlparse(url).hostname or url
    return P.destination_trust(host)


def _is_egress(action: Action) -> bool:
    if action.tool in ("send_email", "webhook_post"):
        return True
    return action.tool == "http_request" and action.operation in ("post", "put", "patch")


def _attachment(action: Action) -> str:
    value = action.args.get("attachment")
    if isinstance(value, str) and value:
        return value
    body = _body(action)
    if body and isinstance(body.get("attachment"), str):
        return body["attachment"]
    return ""


def _authorises_bulk(obs: Observation) -> bool:
    text = " ".join([obs.objective_text, *obs.constraints]).lower()
    return any(term in text for term in P.BULK_AUTHORISATION_TERMS)


def _names(obs: Observation, token: str) -> bool:
    return bool(token) and token.lower() in obs.objective_text.lower()


def _nonce(action: Action) -> Optional[str]:
    body = _body(action)
    if body and isinstance(body.get("nonce"), str):
        return body["nonce"]
    value = action.args.get("nonce")
    return value if isinstance(value, str) and value else None


def _container_path(raw: str) -> bool:
    """A top-level workspace entry that denotes a tree, not a single file."""
    path = posixpath.normpath(raw or "")
    if not path.startswith(P.WORKSPACE_ROOT + "/"):
        return False
    relative = path[len(P.WORKSPACE_ROOT) + 1:]
    if "/" in relative:
        return False
    return "." not in relative.lstrip(".")


# ------------------------------------------------------------------ checks
class WorkflowLayer:
    name = LAYER

    def check(self, obs: Observation, state: RuntimeState, action: Action) -> LayerResult:
        for check in (
            self._replay, self._memory_directive, self._tool_output, self._toolchain,
            self._escalation, self._context_mutation, self._delegation, self._persistence,
            self._plan, self._deployment, self._scope, self._composition,
        ):
            result = check(obs, state, action)
            if result is not None:
                return result
        return _allow(action)

    # --- 1. one-shot authorisation replay ---------------------------------
    def _replay(self, obs: Observation, state: RuntimeState,
                action: Action) -> Optional[LayerResult]:
        nonce = _nonce(action)
        if not nonce:
            return None
        if nonce in state.consumed_nonces:
            return _deny(action, "WF-REPLAY-001",
                         f"nonce {nonce} was already consumed; one-shot authorisations are not reusable",
                         nonce=nonce)
        if state.repeated(action) > 0 and nonce:
            return _deny(action, "WF-REPLAY-001",
                         f"identical call with nonce {nonce} already executed this session",
                         nonce=nonce)
        return None

    # --- 2. instruction persisted into memory ------------------------------
    def _memory_directive(self, obs: Observation, state: RuntimeState,
                          action: Action) -> Optional[LayerResult]:
        if not state.memory_writes or not _is_egress(action):
            return None
        destination = str(action.args.get("to") or action.args.get("url") or "")
        for record in state.memory_writes:
            value = str(record.get("value", ""))
            if destination and destination in value:
                return _deny(action, "WF-MEMORY-001",
                             "action follows a directive stored in agent memory, not the user objective",
                             memory_key=record.get("key"), destination=destination)
        return None

    # --- 3. command planted in tool output --------------------------------
    def _tool_output(self, obs: Observation, state: RuntimeState,
                     action: Action) -> Optional[LayerResult]:
        if not state.tool_output or action.tool != "code_execute":
            return None
        command = str(action.args.get("command", "")).strip()
        if not command:
            return None
        normalized_output = " ".join(state.tool_output.split())
        normalized_command = " ".join(command.split())
        if normalized_command and normalized_command in normalized_output:
            return _deny(action, "WF-TOOLOUTPUT-001",
                         "executed command is copied from prior tool output, not the plan",
                         command=command)
        return None

    # --- 4. write-then-execute -------------------------------------------
    def _toolchain(self, obs: Observation, state: RuntimeState,
                   action: Action) -> Optional[LayerResult]:
        if action.tool != "code_execute" or not state.staged:
            return None
        command = str(action.args.get("command", ""))
        for path in state.staged:
            token = os.path.basename(path) or path
            if token and (token in command or path in command):
                return _deny(action, "WF-TOOLCHAIN-001",
                             f"executes {path} written earlier in this session; the combination "
                             "grants authority neither step holds alone", staged=path)
        return None

    # --- 5. privileged read followed by mutation --------------------------
    def _escalation(self, obs: Observation, state: RuntimeState,
                    action: Action) -> Optional[LayerResult]:
        if action.operation not in MUTATION_OPS:
            return None
        if action.tool not in ("admin_tool", "cloud_api", "k8s_api", "ci_pipeline"):
            return None
        family = _family(action.target)
        for record in state.history:
            if record["tool"] == action.tool and _family(record["target"]) == family \
                    and record["operation"] in READ_OPS:
                return _deny(action, "WF-ESCALATION-001",
                             f"mutates {family} immediately after reading it; self-escalation is "
                             "not a workflow edge", family=family, read_step=record["step"])
        return None

    # --- 6. privileged mutation sourced from ingested context -------------
    def _context_mutation(self, obs: Observation, state: RuntimeState,
                          action: Action) -> Optional[LayerResult]:
        if not state.context_taint:
            return None
        privileged = action.tool in ("admin_tool", "cloud_api", "k8s_api", "ci_pipeline") \
            and action.operation in MUTATION_OPS
        if not privileged:
            return None
        return _deny(action, "WF-CONTEXT-001",
                     "configuration change follows ingested external content; tool output is "
                     "data, not an authorisation channel", taint=list(state.context_taint)[:5])

    # --- 7. delegation ----------------------------------------------------
    def _delegation(self, obs: Observation, state: RuntimeState,
                    action: Action) -> Optional[LayerResult]:
        if action.tool != "agent_delegate":
            return None
        scope = str(action.args.get("scope", ""))
        tokens = _scope_tokens(scope)

        requesters = tokens.get("requested_by") or tokens.get("on_behalf_of") or []
        foreign = [r for r in requesters if r != obs.tenant_id]
        if foreign:
            return _deny(action, "WF-DEPUTY-001",
                         f"delegation requested on behalf of {foreign} outside the tenant",
                         requester=foreign[0])

        groups = tokens.get("coordination") or []
        for group in groups:
            members = [m for m in state.coordination.get(group, []) if m != action.target]
            if members:
                return _deny(action, "WF-COLLUSION-001",
                             f"second agent joins coordination group {group}; split execution "
                             "is not authorised by a single-agent objective",
                             group=group, members=members)

        impersonate = tokens.get("impersonate") or []
        if impersonate:
            return _deny(action, "WF-DELEGATION-001",
                         f"delegation forwards identity {impersonate}", detail="impersonation")

        tools = set(tokens.get("tools") or [])
        forbidden = tools - set(P.DELEGABLE_TOOLS)
        if forbidden:
            return _deny(action, "WF-DELEGATION-001",
                         f"delegated tools {sorted(forbidden)} are not delegable", tools=sorted(forbidden))

        resources = tokens.get("resources") or []
        for resource in resources:
            if resource == "*" or not any(resource == p or resource.startswith(p)
                                          for p in P.DELEGATION_RESOURCE_PREFIXES):
                return _deny(action, "WF-DELEGATION-001",
                             f"delegated resource {resource} widens the parent grant",
                             resource=resource)
        return None

    # --- 8. persistence ---------------------------------------------------
    def _persistence(self, obs: Observation, state: RuntimeState,
                     action: Action) -> Optional[LayerResult]:
        if action.tool != "code_execute":
            return None
        command = str(action.args.get("command", ""))
        match = _PERSIST.search(command)
        if match:
            return _deny(action, "WF-PERSIST-001",
                         "command installs execution that persists beyond the authorised session",
                         match=match.group(0))
        return None

    # --- 9. command outside the approved plan -----------------------------
    def _plan(self, obs: Observation, state: RuntimeState,
              action: Action) -> Optional[LayerResult]:
        if action.tool != "code_execute":
            return None
        command = str(action.args.get("command", ""))
        if _DESTROY_INFRA.search(command):
            return _deny(action, "WF-PLAN-001",
                         "destroys infrastructure that the authorised plan only inspected",
                         match=_DESTROY_INFRA.search(command).group(0))
        if _FORCE_PUSH.search(command):
            return _deny(action, "WF-PLAN-001",
                         "force-pushes a protected branch outside the authorised plan",
                         match=_FORCE_PUSH.search(command).group(0))
        if _FETCH_EXEC.search(command):
            return _deny(action, "WF-PLAN-001",
                         "fetches and executes remote content that is not on the approved plan")
        sync = _FOREIGN_SYNC.search(command)
        if sync:
            destination = sync.group("dest")
            if not destination.startswith(_APPROVED_STORAGE):
                return _deny(action, "WF-PLAN-001",
                             f"copies data to {destination} outside the tenant's storage",
                             destination=destination)
        return None

    # --- 10. environment escalation --------------------------------------
    def _deployment(self, obs: Observation, state: RuntimeState,
                    action: Action) -> Optional[LayerResult]:
        if action.tool != "ci_pipeline":
            return None
        targets = " ".join(str(action.args.get(k, "")) for k in
                           ("artifact", "environment", "pipeline", "branch"))
        targets = targets + " " + action.target
        production = "production" in targets.lower() or re.search(r"\bprod\b", targets, re.I)
        if not production:
            return None
        text = " ".join([obs.objective_text, *obs.constraints]).lower()
        if "production" in text or re.search(r"\bprod\b", text):
            return None
        return _deny(action, "WF-DEPLOY-001",
                     "deployment transitions to production, which the objective does not authorise",
                     targets=targets.strip())

    # --- 11. bulk action wider than the request ---------------------------
    def _scope(self, obs: Observation, state: RuntimeState,
               action: Action) -> Optional[LayerResult]:
        if _authorises_bulk(obs):
            return None

        if action.tool == "sql_query":
            query = str(action.args.get("query", "")).strip()
            if re.match(r"^(delete|update)\b", query, re.I) and not re.search(r"\bwhere\b", query, re.I):
                return _deny(action, "WF-SCOPE-001",
                             "unqualified destructive statement widens a scoped operation to every row")

        if action.tool == "database_query" and action.operation in ("delete", "update"):
            if not (action.args.get("filter") or {}):
                return _deny(action, "WF-SCOPE-001",
                             "write without a scope predicate touches every row")

        if action.tool == "file_write":
            path = str(action.args.get("path", ""))
            empty = action.args.get("content", "") == ""
            if empty and action.operation != "delete" and _container_path(path) \
                    and not _names(obs, os.path.basename(path.rstrip("/"))):
                return _deny(action, "WF-SCOPE-001",
                             f"empty write to {path} truncates a whole tree rather than the "
                             "single object the objective names", path=path)

        if action.tool == "calendar_api":
            values = {str(action.args.get(k, "")).lower() for k in ("action", "event")}
            bulk = any(v in ("delete_all", "delete_series", "set_private") for v in values) \
                or any(v == "all" or v.startswith("recurring:") for v in values)
            if bulk:
                return _deny(action, "WF-SCOPE-001",
                             "calendar change applies to a series or every event, beyond one object",
                             values=sorted(values))

        if action.tool == "admin_tool":
            blob = " ".join(str(action.args.get(k, "")) for k in ("setting", "value")).lower()
            if "rotate_all" in blob or "delete_all" in blob or "disable_all" in blob:
                return _deny(action, "WF-SCOPE-001",
                             "administrative action applies to every secret or control, not one")

        if action.tool == "http_request":
            url = str(action.args.get("url", "")).lower()
            body = _body(action) or {}
            tenantwide = str(body.get("scope", "")).lower() in ("tenant", "all", "org")
            if re.search(r"(revoke-all|delete-all|rotate-all|bulk-)", url) or tenantwide:
                return _deny(action, "WF-SCOPE-001",
                             "endpoint applies a change tenant-wide, beyond the requested object",
                             url=url)
        return None

    # --- 12. composed read -> egress --------------------------------------
    def _composition(self, obs: Observation, state: RuntimeState,
                     action: Action) -> Optional[LayerResult]:
        if not _is_egress(action) or not _attachment(action) or not state.reads:
            return None
        max_label = max((r["label"] for r in state.reads),
                        key=lambda l: P.LABEL_ORDER.get(l, 0))
        if P.LABEL_ORDER.get(max_label, 0) >= P.LABEL_ORDER["confidential"] \
                and _egress_trust(action) == "approved_partner":
            return _deny(action, "WF-CHAIN-001",
                         "derived content from a confidential read is transmitted outside the "
                         "tenant; the egress is not on the approved chain", label=max_label,
                         trust=_egress_trust(action))
        groups: Dict[Tuple[str, str], int] = {}
        for record in state.reads:
            if P.LABEL_ORDER.get(record["label"], 0) >= P.LABEL_ORDER["confidential"]:
                key = (record["target"], record.get("filter_hash", ""))
                groups[key] = groups.get(key, 0) + 1
        if len(groups) >= 3:
            return _deny(action, "WF-CHAIN-001",
                         "many individually scoped reads are composed into one export, exceeding "
                         "the authorised single-record aggregate", distinct_reads=len(groups))
        return None
