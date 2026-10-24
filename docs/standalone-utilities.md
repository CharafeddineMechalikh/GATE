# Standalone utilities

The modules on this page live in `gate.security` and `gate.utils` and can be used on their own. They are **not** part of the five-stage monitor pipeline unless noted. Importing them does not change adapter behaviour.

| Utility | Module | Used by the monitor? |
|---|---|---|
| Tenant isolation | `gate.security.tenant_isolator` | No |
| Irreversibility handler | `gate.security.irreversibility` | No |
| Circuit breaker | `gate.security.circuit_breaker` | No (the firewall builds its own private breakers, see [Semantic firewall](stages/semantic-firewall.md#failure-behavior)) |
| Neural CBF | `gate.security.neural_cbf` | Yes, when `NeuralCBFConfig.enabled=True` and the `dcbf` stage is enabled |
| Legacy policy engines | `gate.policy_engine`, `gate.advanced_policy_engine` | No |
| Legacy audit logger | `gate.audit_log` | No |
| Vector store, embedding, retry | `gate.utils.*` | Vector store and embedding are used by the semantic stage |

## Tenant isolation

`TenantIsolator` keeps a registry of `TenantContext` objects and a `ContextVar` that holds the active tenant for the current task. It does not intercept tool calls. You call it at your request boundary, then use its helpers for vector stores and audit partitions.

```python
from gate.security.tenant_isolator import (
    DataResidencyPolicy,
    TenantContext,
    TenantIsolator,
)

isolator = TenantIsolator()
isolator.register_tenant(
    TenantContext(
        tenant_id="acme",
        encryption_key_id="kms/acme",
        data_residency=DataResidencyPolicy(
            allowed_regions={"eu-west-1"},
            forbidden_regions={"us-east-1"},
        ),
    )
)

with isolator.tenant_scope("acme"):
    store = isolator.get_isolated_vector_store()
    partition = isolator.get_isolated_audit_partition()
    isolator.prevent_cross_tenant_access("other-tenant")  # raises SecurityViolation
```

| Method | Behaviour |
|---|---|
| `register_tenant(context)` | Stores the context under `context.tenant_id`. Re-registering the same id replaces it. |
| `get_tenant(tenant_id=None)` | Returns the context. With no id it uses the current `ContextVar`. Raises `SecurityViolation` for an unknown tenant or missing context. |
| `set_tenant(tenant_id)` | Sets the current context. Raises for an unknown tenant. |
| `tenant_scope(tenant_id)` | Sync and async context manager. Restores the previous context on exit. |
| `get_isolated_vector_store(tenant_id=None)` | Lazily creates one `VectorStore` per tenant with the namespace `tenant-<id>`. |
| `get_isolated_audit_partition(tenant_id=None)` | Returns the string `tenants/<id>/audit`. Nothing in GATE reads this string. |
| `prevent_cross_tenant_access(resource_tenant_id)` | Raises `SecurityViolation` unless the resource tenant equals the current tenant. |

Behaviour worth knowing:

- The `ContextVar` is per asyncio task and per thread context. It is not inherited by threads you spawn yourself; call `set_tenant` or use `tenant_scope` inside the new thread.
- `TenantContext.allowed_regions` is a separate field from `data_residency.allowed_regions`, and `validate_region()` reads the latter. Populate `data_residency` if you use region checks.
- `compliance_frameworks` and `custom_policies` are metadata only. GATE never enforces them.
- The tenant vector store is isolated by namespace, but both tenants share the FAISS process unless you also set distinct storage paths. The constructor called by the isolator does not pass `storage_path`, so `save_to_disk()` is a no-op for these stores.
- `gateConfig.tenant_id` is a plain string used in HITL approval requests. It is not validated against a `TenantIsolator` and does not set the context variable.

## Irreversibility handler

`IrreversibilityHandler` adds a dry-run and human-approval workflow around a single action. It is an alternative to the five-stage pipeline, not one of its stages: the adapters never construct it.

```python
from gate.security.irreversibility import (
    ActionClassification,
    DryRunResult,
    ImpactEstimate,
    IrreversibilityHandler,
)

async def dry_run(action):
    return DryRunResult(
        success=True,
        impact=ImpactEstimate(affected_entities=1, external_communications=1),
        risks_identified=[],
        warnings=["one email will be sent"],
    )

handler = IrreversibilityHandler(
    dry_run_executor=dry_run,
    hitl_queue=approval_queue,
)
outcome = await handler.execute_with_safeguards(action, state, real_executor)
# outcome["classification"], outcome["dry_run_result"],
# outcome["approval_result"], outcome["execution_result"]
```

Classification (`classify_action`) runs in this order:

1. The lower-cased tool name is looked up exactly in the classification table.
2. Otherwise every key is checked as a substring of the tool name, in insertion order.
3. Otherwise names containing `write`, `post`, `put`, or `patch` are `IRREVERSIBLE_LOW_RISK`.
4. Everything else is `REVERSIBLE`.

| Default classification | Tools |
|---|---|
| `REVERSIBLE` | `search`, `query`, `read`, `get` |
| `IRREVERSIBLE_LOW_RISK` | `update`, `insert`, `create` |
| `IRREVERSIBLE_HIGH_RISK` | `send_email`, `send_message`, `delete` |
| `CRITICAL` | `drop`, `truncate`, `process_payment`, `transfer_funds`, `refund` |

`execute_with_safeguards` behaviour:

- A `REVERSIBLE` action is executed immediately; none of the safeguards run.
- For anything else, if `dry_run_executor` is set it is awaited. A `DryRunResult` with `success=False` raises `SecurityViolation` and the action is not executed.
- If the classification is at or above `require_approval_threshold` (default `IRREVERSIBLE_HIGH_RISK`, so `CRITICAL` is also covered), a `hitl_queue` is required. Without one, the handler raises instead of executing. With one, it calls `request_and_await_approval(action=..., agent_id=..., risk_level=..., dry_run_result=...)`; a denial raises `SecurityViolation`.
- `real_executor` is awaited with the `ToolCall` as its only argument and must be async.

Limitations:

- Substring matching can surprise you. `dropbox_upload` contains `drop` and is classified `CRITICAL`; `sql_delete` contains `delete` and is `IRREVERSIBLE_HIGH_RISK`. Override `custom_classifications` or use exact names when the default is wrong.
- No dry-run executor means low-risk irreversible actions execute without a dry run. Only the approval threshold is enforced.
- The handler does not call the monitor, does not audit, and does not update an `AgentState`. Add those around it if you need them.
- It does not validate the returned `ApprovalResult` beyond `approved`; approver authentication is the queue's responsibility (see [Human-in-the-loop](human-in-the-loop.md)).

## Circuit breaker

`CircuitBreaker` is a small async wrapper with the usual three states. It is not wired into the monitor. The semantic firewall constructs its own breakers with fixed defaults.

```python
from gate.security.circuit_breaker import CircuitBreaker, CircuitBreakerError

breaker = CircuitBreaker(
    failure_threshold=5,
    recovery_timeout=60.0,
    name="embedding-backend",
    fallback=None,
)

try:
    result = await breaker.call(fetch_embedding, text)
except CircuitBreakerError:
    ...
```

| State | Behaviour |
|---|---|
| `CLOSED` | Calls pass through. Consecutive failures are counted. |
| `OPEN` | Calls are rejected with `CircuitBreakerError`, or answered by `fallback`. After `recovery_timeout` seconds the `state` property moves it to `HALF_OPEN`. |
| `HALF_OPEN` | At most `half_open_max_calls` calls proceed. A success count reaching the same value closes the circuit; a failure reopens it. |

Notes:

- `call()` accepts sync or async callables. Sync callables run inline on the event loop, so long blocking work still blocks the loop.
- The fallback receives the same `*args` and `**kwargs` as the wrapped call. It is not told which call failed.
- The state check and the half-open ticket are taken under a lock, but the wrapped call itself runs outside the lock. That is intentional, so one slow call does not serialise every caller. When a half-open ticket is exhausted, further callers get the fallback or `CircuitBreakerError`.
- `record_failure()` increments the failure count even while half-open; `reset()` clears state and counters.
- `with_circuit_breaker(breaker)` always returns an `async def` wrapper. Do not use it to decorate a function you intend to call synchronously.
- `CircuitBreakerError` derives from `Exception`, not from `gateException`. Catch it explicitly.

## Neural CBF

`NeuralCBF` is a learned barrier monitor. When `neural_cbf_config.enabled` is true, `gateMonitor` replaces `EnhancedDCBFMonitor` with it, and the D-CBF stage calls `check_transition(state, action)` exactly as before. Training is not automatic.

```python
from gate import NeuralCBFConfig

config.neural_cbf_config = NeuralCBFConfig(
    enabled=True,
    state_dim=10,
    hidden_dims=[64, 64],
    alpha_kappa=0.5,
    safety_margin=0.1,
    model_path="models/ncbf.pt",  # omit to start from random weights
    device="cpu",
)
```

PyTorch is required (`pip install torch`); it is not an extra in `pyproject.toml`.

### State features

`_extract_state_vector` builds a fixed-length float vector:

| Index | Feature |
|---|---|
| 0 | `step_count / 50` |
| 1 | `trust_level` |
| 2 | phase index / 4 (`IDLE`=0 ... `ANSWERING`=4) |
| 3 | `tokens_used / 100000` |
| 4 | `api_calls / 100` |
| 5 | `cost_usd / 10` |
| 6-8 | first three `context_embedding` values, or zeros |
| 9-11 | first three `action_embedding` values, or zeros |

The vector is padded with zeros or truncated to `state_dim`. With the default `state_dim=10`, only the first action-embedding value survives. A model trained with a different `state_dim` must match the configured one.

`evaluate_state` returns the network output, which ends in `tanh`, so `h(x)` is in `(-1, 1)`. The network is a stack of `Linear -> ReLU -> Dropout(0.1)` blocks followed by a linear layer and `tanh`.

### Transition check

`check_transition` fails when the current value is below `-safety_margin`, or when:

```text
h(next) - h(current) < -alpha(h(current)),   alpha(h) = alpha_kappa * max(0, h)
```

The next state is a fixed simulation: `+100` tokens, `+1` API call, `+0.01` USD, `+1` step, phase `ACTING`, same trust level, and a copy of `context_embedding`. It does not copy `tool_history`, `action_embedding`, or `loop_count`, so the learned barrier sees no record of the tool that was proposed. This is the same next-state simplification used by `EnhancedDCBFMonitor`; it is documented in [D-CBF monitor](stages/dcbf.md#next-state-simulation).

### Training and evaluation

```python
history = ncbf.train(
    safe_states=normal_states,
    unsafe_states=violation_states,
    transitions=recorded_transitions,  # optional (state, action, next_state) tuples
    epochs=100,
)
ncbf.save_model("models/ncbf.pt")

metrics = ncbf.verify_barrier(test_states, expected_safe)
# accuracy, precision, recall, f1, true_positives, ...
```

- The classification loss pushes safe states above `+safety_margin` and unsafe states below `-safety_margin`; the optional CBF loss penalises forward-invariance violations.
- `verify_barrier` treats `h >= 0` as "safe", so `positive` means safe, not unsafe.
- `load_model` uses `torch.load(..., weights_only=False)`. Only load checkpoints you trust; the pickle format can execute code.
- The shipped tests cover initialization, scoring, transition checks, save/load, and barrier verification, but not training itself. With `model_path=None` the weights are random, so decisions are arbitrary until you train and save a model. Validate it against the states your agent actually produces before enabling it.

## Legacy policy engines

Two modules at the top of the `gate` package predate the monitor. The adapters and monitor do not import them. They exist for scripts that want a lightweight YAML allow-list.

### `gate.policy_engine`

```python
from gate.policy_engine import load_policy, is_allowed, check_permission
```

`load_policy(path=gate/policy.yaml)` returns the `permissions` mapping from the YAML file. A missing file returns `{}`, which denies everything. The shipped `gate/policy.yaml` allows `network:outbound` and `fs:read` for every tool and `fs:write` only for `write_demo_file`.

`is_allowed(permission, tool_name, policy)` accepts `"*"` as a wildcard. `check_permission(contract, tool_name)` duck-types `contract.permissions`, a list of permission strings, and requires every one of them to be allowed.

The policy is loaded once at import time into a module cache. Editing the YAML file afterwards has no effect on `check_permission` until you reload the module.

### `gate.advanced_policy_engine`

```python
from gate.advanced_policy_engine import (
    check_permission,
    get_step_count,
    reset_step_count,
    set_max_steps,
    run_precondition,
    run_postcondition,
    semantic_check,
)
```

`check_permission` calls the simple engine, then enforces a process-global step budget (`MAX_STEPS`, default 1000) and increments the counter on success. The counter is shared by every caller in the process; `reset_step_count()` starts a fresh run. `semantic_check(prompt)` returns `True` when the prompt is safe and delegates to `gate.semantic_firewall.is_unsafe_prompt`. Pre/post-condition helpers simply call the supplied callable and default to `True` when it is `None`.

These modules have no state store, no audit, and no per-agent isolation. Do not use the global step counter as a substitute for the DFA budget in a multi-tenant process.

## Legacy audit logger

`gate/audit_log.py` is an older single-file audit logger, separate from `gate.audit.EncryptedAuditLogger` (documented in [Audit](audit.md)).

```python
from gate.audit_log import log_execution

log_execution("search", {"query": "retention"}, "ok", allowed=True)
```

- It appends one Fernet-encrypted JSON line per call to `gate/audit.log`.
- The Fernet key is read from or generated into `gate/audit_key.key` **at import time**. Importing the module can create a key file as a side effect.
- It records `ts`, `tool`, `args`, `result`, and `allowed`. There is no masking and no rotation; the legacy format should not be used for new deployments.
- The key and log paths are ignored by the repository `.gitignore`, but they are not protected at rest. Use `EncryptedAuditLogger` with a KMS backend when audit integrity matters.

## Supporting utilities

| Module | Purpose |
|---|---|
| `gate.utils.embedding.EmbeddingModel` | Lazy `sentence-transformers` wrapper, with a process-wide model cache and retry. Forces the PyTorch backend (`USE_TF=0`, `USE_TORCH=1`). |
| `gate.utils.vector_store.VectorStore` | FAISS `IndexFlatIP` for harm prototypes, with a numpy cosine fallback, plus per-tool safe centroids and Mahalanobis distance. Persists `.npy` files under `storage_path`. |
| `gate.utils.retry` | `RetryConfig`, `create_retry_decorator`, `with_retry`, and `RetryableOperation` built on `tenacity` with exponential backoff. |

`VectorStore(storage_path=None)` keeps data in memory only; `save_to_disk()` returns without writing. With FAISS unavailable it logs a warning and uses normalized cosine similarity instead. `EmbeddingModel` shares one `SentenceTransformer` per `(model_name, device, cache_folder)` so multiple monitors do not each load a copy.

## Related pages

- [Architecture](architecture.md) for where the five-stage monitor sits.
- [D-CBF monitor](stages/dcbf.md) for the hand-designed barriers that `NeuralCBF` can replace.
- [Audit](audit.md) for the current audit logger.
- [Human-in-the-loop](human-in-the-loop.md) for the queue contract used by the irreversibility handler.
