# Privilege enforcement

The privilege stage answers three questions before any other check runs:

1. Is this agent allowed to call this tool?
2. Is it allowed to touch the data resource named by the arguments?
3. Is the estimated cost of the call within its budget?

It is the cheapest stage and the first line of defence. When it denies, `checks_failed` is `["privilege"]` and no later stage runs.

## Configuration

```python
from gate import AgentProfile, DataScope, ResourceBudget, gateConfig

profile = AgentProfile(
    agent_id="analyst",
    role="data-analyst",
    allowed_tools={"query_metrics", "search"},
    forbidden_tools={"export_raw"},
    data_scope=DataScope(
        allowed_databases={"analytics"},
        allowed_tables={"analytics": {"orders", "customers"}},
        allowed_api_endpoints={"https://api.internal.example.com"},
    ),
    resource_budget=ResourceBudget(max_cost_usd=2.50),
)

config = gateConfig(
    agent_profile=profile,
    enabled_checks={"privilege", "dfa"},
)
```

The monitor constructs `DefaultPrivilegeEnforcer` and registers `config.agent_profile` when the stage is enabled and no enforcer was injected.

## Tool permission

`check_tool_permission(agent_id, tool_name)` behaves as follows:

| Condition | Result |
|---|---|
| No profile registered for `agent_id` | Deny, reason `no_profile` |
| `tool_name` in `forbidden_tools` | Deny, reason `forbidden` |
| `tool_name` not in `allowed_tools` | Deny, reason `not_allowed` |
| Otherwise | Allow |

Forbidden wins over allowed. The check is exact and case-sensitive; `query_metrics` and `Query_Metrics` are different names. Tool names come from the guarded object's `name` attribute (or the class name if it has none), so they must match the names the framework exposes.

## Data scope

The monitor applies the data-scope check only to string arguments that look like data resource identifiers. `_looks_like_data_resource` returns true when the string contains a dot (`.`) and contains neither whitespace nor `@`. This avoids treating free-text queries, message bodies, and email addresses as resource names. The heuristic means:

- `analytics.orders` is checked.
- `SELECT * FROM orders` is not checked by this stage; the SQL contract handles query shape.
- `alice@company.com` is not checked; the email contract handles recipients.
- `users` (no dot) is not checked.

For each checked value, `DataScope.check_access(resource)` evaluates:

1. Any `forbidden_patterns` substring match denies immediately. The default set contains the cloud metadata address `169.254.169.254`.
2. Normalised endpoint matches allow. `allowed_api_endpoints` entries may be full URLs or hosts. The resource must equal the endpoint, equal its host, or end with `.<host>`.
3. A `db.table` value is allowed when the database is in `allowed_databases` and either `allowed_tables` is empty or the table is listed for that database.
4. Every other value is denied.

An empty `DataScope` therefore denies every dotted argument. That is intentional deny-by-default behavior, but it surprises users who only configure tool allow-lists: a tool called with `{"table": "analytics.orders"}` will be blocked by the data-scope check even if the tool is allowed. Use undotted identifiers, configure the scope, or disable the privilege stage if the heuristic does not fit your tool surface.

When the scope denies, the monitor raises `DataScopeViolation` with the resource name, and the result's `checks_failed` is still `["privilege"]`.

## Resource budget

`check_resource_budget(agent_id, estimated_cost)` allows the call when:

```text
estimated_cost <= profile.resource_budget.max_cost_usd
```

The estimate is read from `action.metadata["estimated_cost"]`; it defaults to `0.0`. This is a per-call estimate, not a cumulative total. The monitor computes the value it reports in the error as `state.resource_usage.cost_usd + estimated_cost`, but the comparison against the limit uses only the estimate.

The adapter path never sets `estimated_cost`, and `after_call` does not increment `resource_usage.cost_usd`. In practice, with the stock adapters, the budget check always passes. To enforce a spend limit you must supply the estimate yourself. The current extension point is a custom `ToolEnforcement` subclass or a host-side wrapper that sets `metadata["estimated_cost"]` before validation; `wrap_agent` does not expose a metadata hook.

`ResourceBudget.max_tokens` and `max_execution_time_seconds` are declared in the configuration but are not read by the monitor or the adapters. `max_steps` and `max_loops_per_phase` are used by the DFA stage. See [Configuration](../configuration.md) for the full list of wired fields.

## What this stage does not do

- It does not authenticate the tool. A compromised tool body can still do anything its process can do.
- It does not validate tool arguments against a schema. That is the framework's job.
- It does not consult capability tokens. `DefaultPrivilegeEnforcer` can issue, revoke, and expire `CapabilityToken` objects, but `check_tool_permission` reads only the agent profile. Token methods are available for host code but are not part of the monitor decision.
- It does not use `AgentProfile.trust_level` or `can_communicate_with`. Those fields are reserved and currently unused.
- It does not stop an allowed tool from reading data it was not asked to read, beyond the dotted-argument heuristic.

## Extending the stage

Pass a custom `PrivilegeEnforcer` to a manually constructed `gateMonitor`:

```python
from gate.core.monitor import gateMonitor
from gate.security.privilege_enforcer import DefaultPrivilegeEnforcer

enforcer = DefaultPrivilegeEnforcer()
enforcer.register_profile(profile)

monitor = gateMonitor(config, privilege_enforcer=enforcer)
```

The four adapters construct their own `gateMonitor(config)` and override the privilege enforcer with one built from `config.agent_profile`. They do not accept a prebuilt monitor or enforcer, so a custom enforcer requires using the monitor and `ToolEnforcement` directly, or writing a framework adapter. See [Enforcement plumbing](../enforcement.md#custom-adapters).

A custom enforcer must implement `PrivilegeEnforcer`: `check_tool_permission`, `check_data_scope`, and `check_resource_budget`.

## Related pages

- [DFA supervision](dfa.md)
- [Smart contracts](contracts.md)
- [Configuration](../configuration.md)
