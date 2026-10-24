# API reference

The public surface is small. Internal modules such as `gate.core.monitor` are documented because the adapters expose their instances, but they are not stability-guaranteed beyond the current minor version.

## Top-level exports

```python
from gate import (
    # Configuration
    gateConfig, AgentProfile, ResourceBudget, DataScope,
    SemanticThresholds, RetryConfig, CircuitBreakerConfig, NeuralCBFConfig,
    # Exceptions
    gateException, SecurityViolation, SemanticSafetyViolation,
    ContractViolation, PrivilegeViolation, ResourceBudgetExceeded,
    DCBFViolation, DFAViolation, DataScopeViolation,
    EmbeddingModelError, VectorStoreError, AdapterError, ConfigurationError,
    # Models
    ToolCall, AgentState, ValidationResult, SemanticScore,
    # Entry points
    wrap_agent, get_registry,
)
```

`ToolExecutionBlocked` is exported from `gate.adapters`, not from `gate`:

```python
from gate.adapters import ToolExecutionBlocked
```

## Entry points

### `wrap_agent`

```python
wrap_agent(agent: Any, framework: str, config: gateConfig, **kwargs) -> SecureAgent
```

Delegates to the global `FrameworkRegistry`. Framework keys: `"langchain"`, `"langgraph"`, `"openai-agents"`, `"crewai"`. Raises `ConfigurationError` for an unknown key and `AdapterError` for an unsupported object or an import failure.

### `get_registry`

```python
get_registry() -> FrameworkRegistry
```

`FrameworkRegistry` methods:

| Method | Description |
|---|---|
| `register_adapter(framework_name, adapter)` | Register or replace an adapter; names are lower-cased |
| `get_adapter(framework_name)` | Return the adapter or raise `ConfigurationError` |
| `wrap_agent(agent, framework, config, **kwargs)` | Forward to the adapter |
| `list_supported_frameworks()` | Registered keys |

## Configuration dataclasses

All are defined in `gate.core.config`. Full field semantics are in [Configuration](configuration.md).

```python
gateConfig(
    agent_profile: AgentProfile,
    semantic_thresholds: SemanticThresholds = SemanticThresholds(),
    enabled_checks: Set[str] = {"semantic", "contracts", "dcbf", "dfa", "privilege"},
    log_level: LogLevel = LogLevel.INFO,
    embedding_model_name: str = "all-MiniLM-L6-v2",
    vector_store_path: Optional[str] = None,
    audit_log_path: Optional[str] = None,
    enable_async_batching: bool = True,
    batch_window_ms: int = 10,
    irreversible_actions: Set[str] = set(),
    tenant_id: str = "default",
    timeout_seconds: float = 300.0,
    retry_config: RetryConfig = RetryConfig(),
    circuit_breaker_config: CircuitBreakerConfig = CircuitBreakerConfig(),
    neural_cbf_config: NeuralCBFConfig = NeuralCBFConfig(),
    trajectory_ema_alpha: float = 0.3,
    enable_forward_invariance_verification: bool = True,
)

AgentProfile(
    agent_id: str,
    role: str,
    allowed_tools: Set[str],
    forbidden_tools: Set[str] = set(),
    data_scope: DataScope = DataScope(),
    resource_budget: ResourceBudget = ResourceBudget(),
    trust_level: int = 1,
    can_communicate_with: Set[str] = set(),
)

ResourceBudget(
    max_steps: int = 50,
    max_tokens: int = 100000,
    max_cost_usd: float = 10.0,
    max_execution_time_seconds: int = 300,
    max_loops_per_phase: int = 3,
)

DataScope(
    allowed_databases: Set[str] = set(),
    allowed_tables: Dict[str, Set[str]] = {},
    allowed_api_endpoints: Set[str] = set(),
    forbidden_patterns: Set[str] = {"169.254.169.254"},
)

SemanticThresholds(
    sss_safe_threshold: float = 0.7,
    sss_block_threshold: float = 0.5,
    drift_threshold: float = 0.8,
    harm_threshold: float = 0.2,
)
```

`gateConfig.validate() -> None` raises `ValueError` for an empty `agent_id`, inverted SSS thresholds, non-positive `max_steps`, non-positive `timeout_seconds`, or `max_attempts < 1`. It is not called automatically.

`DataScope.check_access(resource: str) -> bool` implements the dotted-resource rules.

## Models

All are dataclasses in `gate.core.models`.

### `ToolCall`

```python
ToolCall(
    tool_name: str,
    tool_args: Dict[str, Any],
    call_id: str,
    timestamp: datetime = utcnow,
    agent_id: Optional[str] = None,
    metadata: Dict[str, Any] = {},
)
```

Methods: `to_dict()`, `to_json()`, `get_action_description()`, `from_dict(data)`.

`get_action_description()` returns `Call <tool>(k=v, ...)`, which is the text the semantic firewall embeds.

### `AgentState`

```python
AgentState(
    agent_id: str,
    context_embedding: Optional[np.ndarray] = None,
    action_embedding: Optional[np.ndarray] = None,
    resource_usage: ResourceMetrics = ResourceMetrics(),
    tool_history: List[ToolCall] = [],
    memory_state: Optional[Dict[str, Any]] = None,
    trust_level: float = 1.0,
    current_phase: str = "IDLE",
    step_count: int = 0,
    loop_count: Dict[str, int] = {},
    created_at: datetime = utcnow,
    last_updated: datetime = utcnow,
)
```

Methods: `update_timestamp()`, `add_tool_call(tool_call)`, `increment_loop(phase)`, `get_recent_tool_calls(n=5)`, `to_dict()`.

### `ResourceMetrics`

```python
ResourceMetrics(tokens_used=0, api_calls=0, compute_time_seconds=0.0, cost_usd=0.0)
```

Method: `add_usage(tokens=0, api_calls=0, compute_time=0.0, cost=0.0)`.

### `SemanticScore`

```python
SemanticScore(
    sss_value: float,
    drift_to_intent: float,
    drift_to_harm: float,
    drift_to_safe: float,
    decision: str,
    details: Dict[str, float],
)
```

Method: `is_safe() -> bool` (true only for `decision == "ALLOW"`).

### `ValidationResult`

```python
ValidationResult(
    is_allowed: bool,
    reason: Optional[str] = None,
    details: Dict[str, Any] = {},
    semantic_score: Optional[SemanticScore] = None,
    checks_passed: List[str] = [],
    checks_failed: List[str] = [],
    escalated: bool = False,
    requires_approval: bool = False,
)
```

## Exceptions

```text
gateException
├── SecurityViolation
│   ├── SemanticSafetyViolation
│   ├── SemanticEscalation
│   ├── ContractViolation
│   ├── DCBFViolation
│   ├── PrivilegeViolation
│   ├── DataScopeViolation
│   ├── ResourceBudgetExceeded
│   ├── DFAViolation
│   └── TimeoutViolation
└── gateSystemError
    ├── EmbeddingModelError
    ├── VectorStoreError
    ├── AdapterError
    ├── ConfigurationError
    └── NeuralCBFError
```

`ToolExecutionBlocked` is a `SecurityViolation` defined in `gate.adapters.enforcement`. It is raised by the guard, not by the monitor.

All exceptions accept a message and an optional `details` mapping. Security violations also expose named attributes (for example `SemanticSafetyViolation.sss_score`, `ContractViolation.contract_name`, `PrivilegeViolation.agent_id`).

## Secure agents and adapters

```python
LangChainAdapter(default_timeout_seconds=300.0)
LangGraphAdapter(default_timeout_seconds=300.0)
OpenAIAgentsAdapter(default_timeout_seconds=300.0)
CrewAIAdapter(default_timeout_seconds=600.0)
```

Each `wrap_agent`:

```python
LangChainAdapter.wrap_agent(agent, config, *, tools=None, approval_queue=None)
LangGraphAdapter.wrap_agent(agent, config, *, tools=None, approval_queue=None)
OpenAIAgentsAdapter.wrap_agent(agent, config, *, approval_queue=None)
CrewAIAdapter.wrap_agent(agent, config, *, approval_queue=None)
```

`SecureAgent` methods:

| Method | Notes |
|---|---|
| `invoke(input, **kwargs)` | Sync for LangChain, LangGraph, CrewAI; async for OpenAI Agents |
| `ainvoke(input, **kwargs)` | LangChain, LangGraph, CrewAI only |
| `get_state() -> AgentState` | Live enforcement state |
| `terminate() -> None` | Closes the monitor loop; does not unwrap tools |

Each wrapper exposes `.monitor`, `.config`, `.enforcement`, and the wrapped object (`wrapped_agent`, `wrapped_graph`, `wrapped_crew`).

## Enforcement

From `gate.adapters.enforcement`:

```python
ToolEnforcement(monitor, config, approval_queue=None)
ToolExecutionBlocked(message, tool_name, result=None, *, post_execution=False, stage=None)
marshal_tool_args(tool, args, kwargs) -> Dict[str, Any]
install_tool_guard(tool, enforcement, *, tool_name=None, native_async=None) -> Any
guard_tool_list(tools, enforcement, *, native_async=None) -> None
collect_graph_tools(graph) -> List[Any]
schema_field_names(tool) -> List[str]
```

`ToolEnforcement` methods are listed in [Enforcement plumbing](enforcement.md#toolenforcement).

## Monitor

From `gate.core.monitor`:

```python
gateMonitor(
    config,
    semantic_firewall=None,
    contract_registry=None,
    dcbf_monitor=None,
    dfa_supervisor=None,
    privilege_enforcer=None,
    audit_logger=None,
)
```

| Method | Signature |
|---|---|
| `validate_action` | `async (action: ToolCall, state: AgentState) -> ValidationResult` |
| `validate_result` | `async (action: ToolCall, result: Any, state: AgentState) -> ValidationResult` |
| `check_semantic_safety` | `async (action: str, tool_name: str, agent_id: str) -> SemanticScore` |
| `check_state_invariants` | `async (state: AgentState) -> bool` |
| `log_event` | `async (event: SecurityEvent) -> None` |

## Stages

### Privilege

```python
DefaultPrivilegeEnforcer()
```

| Method | Description |
|---|---|
| `register_profile(profile)` | Add or replace an `AgentProfile` |
| `unregister_profile(agent_id)` | Remove a profile |
| `check_tool_permission(agent_id, tool_name) -> bool` | Allow-list and deny-list |
| `check_data_scope(agent_id, resource) -> bool` | Delegates to `DataScope.check_access` |
| `check_resource_budget(agent_id, estimated_cost) -> bool` | Per-call estimate comparison |
| `issue_token(agent_id, capabilities, ttl_seconds=None) -> CapabilityToken` | Issues a token, not consulted by the checks |
| `revoke_token(agent_id)` | Revokes a token |
| `get_profile(agent_id)` | Returns the profile or `None` |
| `get_audit_trail(agent_id=None)` | In-memory decision log |

### DFA

```python
DefaultDFASupervisor(max_steps=50, max_loops_per_phase=3, valid_transitions=None)
```

| Method | Description |
|---|---|
| `propose_transition(state, next_phase) -> (bool, str)` | Single-edge check |
| `validate_action_phase(state) -> (bool, str)` | Multi-hop check to `ACTING` |
| `add_transition(from_phase, to_phase)` | Add an edge |
| `remove_transition(from_phase, to_phase)` | Remove an edge |
| `get_transition_history()` | List of `(from, to, timestamp)` |
| `reset_history()` | Clear history |

### Contracts

From `gate.security.smart_contracts`:

```python
precondition(func)
postcondition(func)
invariant(func)              # collected, not evaluated
composition_rule(func)       # collected, not evaluated

BaseSmartContract()
ContractRegistry()
```

| Method | Description |
|---|---|
| `BaseSmartContract.validate_precondition(action, state) -> bool` | Raises `ContractViolation` on failure |
| `BaseSmartContract.validate_postcondition(action, result, state) -> bool` | Raises `ContractViolation` on failure |
| `ContractRegistry.register_contract(tool_name, contract)` | Exact-name registration |
| `ContractRegistry.get_contract(tool_name)` | Returns a contract or `None` |
| `ContractRegistry.unregister_contract(tool_name)` | Remove |
| `ContractRegistry.list_contracts()` | Registered names |

Built-ins: `SQLQueryContract`, `HTTPRequestContract`, `EmailSendContract`, `CodeExecutionContract`.

### Semantic firewall

From `gate.security.semantic_firewall`:

```python
DefaultSemanticFirewall(
    config,
    embedding_circuit_breaker=None,
    vector_store_circuit_breaker=None,
    trajectory_ema_alpha=0.3,
)
TrajectoryTracker(ema_alpha=0.3, max_trajectory_length=20)
```

| Method | Description |
|---|---|
| `check_semantic_safety(action, tool_name, agent_id) -> SemanticScore` | Synchronous scoring |
| `async embed(text) -> np.ndarray` | Embedding with the firewall circuit breaker |
| `set_intent_anchor(user_prompt)` | Embed and set the initial anchor |

`TrajectoryTracker`: `set_initial_anchor(embedding)`, `update(embedding)`, `get_current_anchor()`, `get_drift_from_trajectory(embedding)`.

### D-CBF

From `gate.security.dcbf_monitor`:

```python
EnhancedDCBFMonitor(
    alpha_function=None,
    safety_margin=0.1,
    privacy_budget=0.5,
    resource_limit=10.0,
    max_drift=0.8,
    step_budget=50,
    enable_verification=True,
)
ClassKFunction(kappa=0.5, power=1.0)
BarrierFunction(name, func, weight=1.0, margin=0.0)
```

| Method | Description |
|---|---|
| `evaluate_state(state) -> float` | Weighted average of barrier values |
| `check_transition(current_state, proposed_action) -> (bool, str)` | Per-barrier safe-set and forward-invariance check |
| `get_barrier_values(state) -> Dict[str, float]` | Per-barrier values |
| `add_barrier(name, func, weight=1.0, margin=0.0)` | Add or replace |
| `remove_barrier(name)` | Remove |
| `verify_forward_invariance(test_states, test_actions) -> Dict[str, Any]` | Offline diagnostic |
| `get_state_history()` | Composite value history |

### Human-in-the-loop

From `gate.security.hitl_queue`:

```python
HumanApprovalQueue(
    notification_channels=None,
    default_sla_seconds=300,
    max_pending_requests=100,
)
SlackNotificationChannel(webhook_url, channel)
PagerDutyNotificationChannel(integration_key)
```

| Method | Description |
|---|---|
| `async request_and_await_approval(action, agent_id, risk_level, dry_run_result=None, tenant_id="default", sla_seconds=None) -> ApprovalResult` | Create, notify, and wait |
| `async approve(request_id, approver_id, justification="")` | Approve a pending request |
| `async reject(request_id, approver_id, reason="")` | Reject a pending request |
| `get_pending_requests()` | List of `ApprovalRequest` |
| `get_audit_log()` | Resolved and expired requests |

`ApprovalRequest` fields: `request_id`, `agent_id`, `tenant_id`, `action`, `risk_level`, `dry_run_result`, `status`, `created_at`, `resolved_at`, `approver_id`, `justification`, `sla_timeout_seconds`.

`ApprovalResult` fields: `approved`, `approver_id`, `justification`, `request_id`, `timestamp`.

`ApprovalStatus`: `PENDING`, `APPROVED`, `REJECTED`, `EXPIRED`.

## Audit

From `gate.audit.encrypted_logger`:

```python
EncryptedAuditLogger(
    log_path,
    kms_client=None,
    tenant_id="default",
    queue_max_size=10000,
    batch_size=100,
    flush_interval_seconds=1.0,
    retention_policy=None,
)
SecurityEvent(
    event_type,
    agent_id,
    tenant_id,
    timestamp=utcnow,
    tool_name=None,
    tool_args=None,
    result=None,
    violation_details=None,
    metadata={},
)
KMSClient(backend="local", key_id=None)
PIIMasker()
RetentionPolicy(
    retention_days=365,
    max_file_size_mb=100,
    max_total_size_mb=10000,
    rotation_frequency="daily",
    compress_rotated=True,
)
```

Logger methods: `async start()`, `async stop()`, `async log_event(event)`, `get_log_stats()`. KMS methods: `encrypt(plaintext, key_id=None)`, `decrypt(ciphertext, key_id=None)`. Masker: `mask(data)`.

See [Audit](audit.md) for the storage format and the local KMS caveat.

## Utilities

From `gate.utils.embedding`:

```python
EmbeddingModel(model_name="all-MiniLM-L6-v2", device=None, cache_folder=None, retry_config=None)
```

Method: `embed(text: Union[str, List[str]]) -> np.ndarray`. Model instances are cached per `(model_name, device, cache_folder)`.

From `gate.utils.vector_store`:

```python
VectorStore(storage_path=None, namespace="default", embedding_dim=384)
```

| Method | Description |
|---|---|
| `add_harm_prototype(embedding, metadata=None)` | Add one prototype |
| `add_harm_prototypes_batch(embeddings, metadata=None)` | Add many |
| `add_safe_centroid(tool_name, centroid, covariance_inv, sample_count)` | Add a tool centroid |
| `get_prototypes_by_category(category)` | Returns harm prototypes for `"harm"` |
| `get_safe_centroid(tool_name)` | Dict or `None` |
| `search_nearest_harm(query, k=5)` | List of `(index, similarity)` |
| `compute_mahalanobis_distance(query, tool_name)` | Float |
| `save_to_disk()`, `clear()` | Persistence and reset |

The firewall reads prototypes directly; it does not use `search_nearest_harm`.

## Version

```python
import gate
gate.__version__  # "0.3.0"
```
