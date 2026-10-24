# Configuration

`gateConfig` is a dataclass. Only `agent_profile` is required. The defaults enable all five stages, which is a demanding configuration: the semantic firewall needs prototypes to be meaningful, and the default D-CBF barriers block repeated outbound actions. Start with the deterministic stages and add the others deliberately.

```python
from gate import AgentProfile, ResourceBudget, gateConfig

config = gateConfig(
    agent_profile=AgentProfile(
        agent_id="support-agent",
        role="support",
        allowed_tools={"search", "lookup_order", "send_email"},
    ),
    enabled_checks={"privilege", "dfa", "contracts"},
)
```

## `gateConfig` fields

| Field | Default | Used by the runtime? |
|---|---|---|
| `agent_profile` | required | Yes: privilege, DFA budgets, HITL, audit tenant |
| `enabled_checks` | `{"semantic", "contracts", "dcbf", "dfa", "privilege"}` | Yes: selects stages |
| `semantic_thresholds` | `SemanticThresholds()` | Partly: only the two SSS thresholds |
| `embedding_model_name` | `"all-MiniLM-L6-v2"` | Yes, when the semantic stage is constructed |
| `vector_store_path` | `None` | Yes, when the semantic stage is constructed |
| `timeout_seconds` | `300.0` | Yes: whole-invocation timeout in the adapters |
| `tenant_id` | `"default"` | Yes: HITL requests and audit events |
| `enable_forward_invariance_verification` | `True` | Yes: passed to the D-CBF monitor |
| `neural_cbf_config` | disabled | Yes, if `dcbf` is enabled and the config is enabled |
| `audit_log_path` | `None` | No: the monitor does not read it and adapters do not attach a logger |
| `log_level` | `INFO` | No: module logging is not configured from it |
| `enable_async_batching` | `True` | No |
| `batch_window_ms` | `10` | No |
| `irreversible_actions` | empty set | No |
| `retry_config` | `RetryConfig()` | No: the embedding model creates its own retry configuration |
| `circuit_breaker_config` | `CircuitBreakerConfig()` | No: the firewall creates breakers with its own defaults |
| `trajectory_ema_alpha` | `0.3` | No: the monitor constructs the firewall with its constructor default of `0.3` |

`enabled_checks` is a set of stage names. Unknown names are ignored. The recognised names are `privilege`, `dfa`, `contracts`, `semantic`, and `dcbf`.

`gateConfig.validate()` checks that `agent_id` is non-empty, that `sss_safe_threshold > sss_block_threshold`, that `max_steps > 0`, `timeout_seconds > 0`, and `max_attempts >= 1`. It is **not** called automatically by `gateMonitor`, `wrap_agent`, or the adapters. Call it yourself after building a config from untrusted input.

## `AgentProfile`

| Field | Default | Used? |
|---|---|---|
| `agent_id` | required | Yes: enforcer lookup, HITL, audit |
| `role` | required | No runtime effect |
| `allowed_tools` | required | Yes: privilege allow-list |
| `forbidden_tools` | empty set | Yes: privilege deny-list, takes precedence |
| `data_scope` | empty `DataScope` | Yes: privilege, only for dotted arguments |
| `resource_budget` | `ResourceBudget()` | Partly: `max_steps`, `max_loops_per_phase`, `max_cost_usd` |
| `trust_level` | `1` | No |
| `can_communicate_with` | empty set | No |

An empty `allowed_tools` set denies every tool at the privilege stage. That is a valid deny-all profile, not an "allow everything" profile.

## `ResourceBudget`

| Field | Default | Used? |
|---|---|---|
| `max_steps` | `50` | Yes: DFA step budget |
| `max_loops_per_phase` | `3` | Yes: DFA ACTING loop budget |
| `max_cost_usd` | `10.0` | Partly: privilege compares it to a per-call `estimated_cost` that the adapters never set |
| `max_tokens` | `100000` | No |
| `max_execution_time_seconds` | `300` | No: use `gateConfig.timeout_seconds` instead |

The D-CBF stability barrier has a separate step budget of 50 and does not read this object.

## `DataScope`

| Field | Default | Used by `check_access` |
|---|---|---|
| `allowed_databases` | empty set | Yes |
| `allowed_tables` | empty mapping | Yes: if non-empty, the table must be listed for the database |
| `allowed_api_endpoints` | empty set | Yes: exact endpoint, host, or subdomain suffix |
| `forbidden_patterns` | `{"169.254.169.254"}` | Yes: substring match, denies immediately |

The monitor invokes `check_access` only for string arguments that contain `.` and no whitespace or `@`. See [Privilege](stages/privilege.md#data-scope).

## `SemanticThresholds`

| Field | Default | Used? |
|---|---|---|
| `sss_safe_threshold` | `0.7` | Yes: SSS `>` this value allows |
| `sss_block_threshold` | `0.5` | Yes: SSS `<` this value blocks |
| `drift_threshold` | `0.8` | No |
| `harm_threshold` | `0.2` | No |

Scores between the two thresholds escalate. Both comparisons are strict.

## `NeuralCBFConfig`

| Field | Default | Used when enabled |
|---|---|---|
| `enabled` | `False` | Builds `NeuralCBF` instead of `EnhancedDCBFMonitor` |
| `state_dim` | `10` | Model input dimension |
| `hidden_dims` | `[64, 64]` | Model architecture |
| `alpha_kappa` | `0.5` | Class-K scaling |
| `safety_margin` | `0.1` | Safety margin |
| `model_path` | `None` | Loaded weights |
| `device` | `"cpu"` | Torch device |

Neural CBF is experimental. The hand-designed barriers are the tested path.

## Recommended postures

**Deterministic, no model:**

```python
config = gateConfig(
    agent_profile=profile,
    enabled_checks={"privilege", "dfa", "contracts"},
    timeout_seconds=120,
)
```

This gives tool allow-listing, step and loop budgets, and contract checks with no embedding model and no D-CBF barrier surprises.

**Add semantic scoring:**

```python
config = gateConfig(
    agent_profile=profile,
    enabled_checks={"privilege", "dfa", "contracts", "semantic"},
    vector_store_path="gate-vectors",
    embedding_model_name="all-MiniLM-L6-v2",
)
```

Only do this after populating harm prototypes and safe centroids and measuring the score distribution on normal traffic. Without prototypes, the stage is an intent-drift heuristic. If you cannot provision an approval queue, either tune thresholds so the escalate band is empty or expect escalated calls to be refused.

**Add D-CBF:**

```python
config = gateConfig(
    agent_profile=profile,
    enabled_checks={"privilege", "dfa", "contracts", "dcbf"},
    enable_forward_invariance_verification=True,
)
```

Only do this if the default barriers fit your tool set. They do not fit agents that send email or make multiple outbound HTTP requests; the privacy barrier becomes negative after the first such call. Custom barriers require building the monitor yourself.

**Full stack with an approval queue:**

```python
config = gateConfig(
    agent_profile=profile,
    tenant_id="tenant-a",
    timeout_seconds=300,
)
secure = wrap_agent(graph, "langgraph", config, approval_queue=queue)
```

`tenant_id` labels approval requests and audit events; it does not partition monitor state. One wrapped agent belongs to one tenant in practice.

## Validation

`gateConfig.validate()` raises `ValueError` when:

- `agent_profile.agent_id` is empty;
- `semantic_thresholds.sss_safe_threshold` is not greater than `sss_block_threshold`;
- `agent_profile.resource_budget.max_steps` is not positive;
- `timeout_seconds` is not positive;
- `retry_config.max_attempts` is less than 1.

It does not check the names in `enabled_checks`, threshold ranges, data-scope contents, vector-store paths, or Neural CBF model paths. The adapters and `gateMonitor` never call it, so invoke it yourself after building the configuration:

```python
config = gateConfig(agent_profile=profile)
config.validate()
```

A misspelled stage name passes validation and is silently ignored at runtime. Assert the stages you depend on, either by membership in `config.enabled_checks` or by inspecting the monitor components after construction.

## Timeouts

`timeout_seconds` bounds the entire `SecureAgent.invoke`/`ainvoke` call. It is not a per-tool timeout. A timeout aborts the run, so later tool calls are refused. On Windows and in worker threads the underlying framework call may continue after the timeout; see [Installation](installation.md#windows-notes).

There is no configuration field for a per-tool or per-approval timeout. The approval queue has its own `default_sla_seconds`.

## Environment-specific settings

- `gateConfig.vector_store_path` must be readable when the firewall is constructed. A missing path is treated as an empty store, not an error. Saving later creates the directory.
- The embedding model cache is controlled by `sentence-transformers`/Hugging Face environment variables (`HF_HOME`, `SENTENCE_TRANSFORMERS_HOME`). The configuration does not expose a cache path.
- The audit logger's KMS backend is chosen by its own `KMSClient`, not by `gateConfig`.
- Framework API keys are read by the frameworks, not by GATE.

## Related pages

- [Installation](installation.md)
- [Privilege](stages/privilege.md)
- [DFA supervision](stages/dfa.md)
- [Semantic firewall](stages/semantic-firewall.md)
- [D-CBF monitor](stages/dcbf.md)
