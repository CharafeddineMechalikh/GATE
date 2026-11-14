"""Deployment security policy for the GATE zero-trust reference monitor.

These tables are the *configuration* a tenant would ship: protected paths,
approved recipients, budgets, and the label lattice. They are deliberately
independent of any benchmark label. A policy table may be conservative, but it
must not name an attack.
"""
from __future__ import annotations

from typing import Dict, FrozenSet, List, Tuple

# ----------------------------------------------------------------- label lattice
# A total order over information classifications. ``public`` may flow anywhere
# inside the tenant; anything above ``internal`` is restricted at the boundary.
LABEL_ORDER: Dict[str, int] = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
    "secret": 4,
}

# Destinations a labelled payload may reach. Trust classes are derived from the
# recipient/URL, not from the scenario metadata.
EGRESS_ALLOWED: Dict[str, FrozenSet[str]] = {
    "public": frozenset({"internal", "approved_partner", "external"}),
    "internal": frozenset({"internal", "approved_partner"}),
    "confidential": frozenset({"internal"}),
    "restricted": frozenset({"internal"}),
    "secret": frozenset(),
}

INTERNAL_DOMAINS: Tuple[str, ...] = ("corp.example", "app.example", "api.app.example")
APPROVED_PARTNER_DOMAINS: Tuple[str, ...] = (
    "partner.example",
    "client.example",
    "vendor.example",
    "approved.example",
    "external-auditor.example",
)
# Hosts that may receive outbound HTTP from the tenant's integration surface.
APPROVED_HTTP_HOSTS: Tuple[str, ...] = (
    "api.app.example",
    "api.partner.example",
    "docs.app.example",
    "app.example",
    "partner.example",
)
APPROVED_PAYEES: FrozenSet[str] = frozenset({
    "vendor:aws", "vendor:acme", "vendor:saas-x", "vendor:partner",
    "account:acct-approved",
})
REGISTERED_COUNTERPARTIES: FrozenSet[str] = frozenset()  # none by default
# Counterparties named in a signed audit clause. A confidential transfer to one of
# these is permitted only when the objective states the agreed audit disclosure.
APPROVED_AUDIT_RECIPIENTS: FrozenSet[str] = frozenset({"audit@external-auditor.example"})

# ----------------------------------------------------------------- filesystem
WORKSPACE_ROOT = "/workspace"
WRITABLE_ROOTS: Tuple[str, ...] = ("/workspace",)
# Any workspace file may be deleted except protected trees; system paths stay
# outside the deletable scope.
DELETABLE_ROOTS: Tuple[str, ...] = ("/workspace",)
WORKSPACE_PROTECTED: Tuple[str, ...] = (
    "/workspace/src", "/workspace/docs", "/workspace/config", "/workspace/contracts",
    "/workspace/audit", "/workspace/secrets", "/workspace/inbox", "/workspace/reports",
    "/workspace/.git",
)
PROTECTED_PATH_PREFIXES: Tuple[str, ...] = (
    "/etc", "/usr", "/bin", "/sbin", "/lib", "/boot", "/root", "/home",
    "/srv", "/opt", "/var", "/proc", "/sys", "/dev", "/run", "/tmp/bank",
)

# ----------------------------------------------------------------- databases
PERSONAL_DATA_TABLES: FrozenSet[str] = frozenset({"contacts", "customers", "leads", "users"})
APPEND_ONLY_TABLES: FrozenSet[str] = frozenset({"ledger", "audit_events", "events"})
IMMUTABLE_COLUMNS: FrozenSet[str] = frozenset({
    "checksum", "balance", "role", "created_at", "amount", "is_admin", "tenant_id",
})
SETTLEMENT_REQUIRED: FrozenSet[str] = frozenset({"invoices", "refunds"})
MAX_ROWS = 1000
MAX_EXPORT_ROWS = 100
K_ANONYMITY_FLOOR = 10

# ----------------------------------------------------------------- payments
PAYMENT_CEILING = 5000.0
APPROVAL_THRESHOLD = 10000.0
TREASURY_ACCOUNTS: FrozenSet[str] = frozenset({"acct-corp-treasury"})
TRADING_HOSTS: FrozenSet[str] = frozenset({"broker.example"})
MAX_POSITION = 1000

# ----------------------------------------------------------------- compute budgets
BUDGETS: Dict[str, float] = {
    "steps": 40,
    "requests_per_hour": 600,
    "messages_per_hour": 200,
    "instances": 20,
    "delegation_depth": 3,
    "concurrent_agents": 8,
    "disk_gb": 50,
    "failed_auth": 5,
    "bytes_egress_mb": 100,
}

# ----------------------------------------------------------------- workflow
MAX_WORKFLOW_DEPTH = 40
MAX_REPEATS_PER_TOOL = 12
SESSION_TTL_SECONDS = 3600

# High-impact operations that require a bound approval unless the user's own
# request already authorises the exact operation.
IRREVERSIBLE_OPS: FrozenSet[str] = frozenset({
    "delete", "ddl", "transfer", "refund", "charge", "deploy", "provision",
    "snapshot", "modify", "apply", "expire", "rotate",
})

# Operations which may never be delegated, whatever the parent grant.
NON_DELEGABLE_OPS: FrozenSet[str] = frozenset({
    "transfer", "refund", "charge", "delete", "ddl", "provision", "deploy",
    "apply", "config", "exec",
})
NON_DELEGABLE_TOOLS: FrozenSet[str] = frozenset({"payment_api"})
# Tools a delegation request may pass to a child agent at all. Database and
# infrastructure surfaces stay with the tenant authority.
DELEGABLE_TOOLS: FrozenSet[str] = frozenset({
    "file_read", "file_write", "format_template", "web_search", "data_analysis",
    "http_request", "calendar_api", "code_execute",
})
# Resource prefixes a delegated child may be scoped to.
DELEGATION_RESOURCE_PREFIXES: Tuple[str, ...] = (
    "/workspace", "db:app_db.", "dataset:analytics_", "template:workspace",
    "web:", "email:*@corp.example", "memory:project/", "agent:self",
)

# Vocabulary a user objective uses when it authorises a bulk or recurring
# operation. Anything wider than one object needs one of these.
BULK_AUTHORISATION_TERMS: Tuple[str, ...] = (
    "all", "every", "entire", "whole", "series", "recurring", "bulk",
    "tenant-wide", "company-wide", "each", "both", "multiple",
)

# Administrative surfaces excluded from every default grant.
ADMIN_PATH_MARKERS: Tuple[str, ...] = ("/admin", "/internal/", "/superuser")


def destination_trust(recipient: str) -> str:
    """Classify a channel target into a trust class."""
    value = (recipient or "").lower()
    host = value.rsplit("@", 1)[-1] if "@" in value else value
    for domain in INTERNAL_DOMAINS:
        if host == domain or host.endswith("." + domain):
            return "internal"
    if host in ("corp.example",) or host.endswith(".corp.example"):
        return "internal"
    for domain in APPROVED_PARTNER_DOMAINS:
        if host == domain or host.endswith("." + domain):
            return "approved_partner"
    if host.endswith(".example") or host.endswith(".example.com"):
        return "external"
    return "untrusted"


def label_of(payload_labels: List[str]) -> str:
    """Join several labels to the most restrictive one."""
    if not payload_labels:
        return "public"
    return max(payload_labels, key=lambda label: LABEL_ORDER.get(label, 4))
