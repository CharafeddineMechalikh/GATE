# D-CBF monitor

The D-CBF (discrete control barrier function) stage asks whether the next action keeps the agent inside a safe set defined by five barrier functions. It runs last, after every other stage has allowed the action.

## The safe set

Each barrier `i` defines a scalar value `h_i(state)`. The safe set is the intersection:

```text
C = { state : h_i(state) >= 0 for every barrier i }
```

The monitor admits a transition only when:

1. the current state is inside `C` (every `h_i >= 0`), and
2. every barrier satisfies the discrete forward-invariance condition

```text
h_i(next) - h_i(current) >= -alpha(h_i(current))
```

where `alpha(h) = kappa * h` with `kappa = 0.5` and `power = 1`. The condition allows a barrier to decrease, but not faster than the class-K function permits. A single breached barrier denies the action regardless of the other barriers.

`enable_forward_invariance_verification=False` skips step 2 and checks only that the current state is inside the safe set. `gateConfig.enable_forward_invariance_verification` defaults to `True`.

## Default barriers

The monitor is constructed with these five barriers unless you build your own:

| Barrier | Weight | Margin | Raw value | Effective `h` |
|---|---|---|---|---|
| `safety` | 1.0 | 0.1 | `1.0 - risk`, where risk counts dangerous tool combinations in the last five calls | `raw - 0.1` |
| `privacy` | 1.5 | 0.5 | `0.5 - 0.2 * count(send_email, http_request)` over the whole history | `raw - 0.5` |
| `resource` | 1.0 | 0.0 | `10.0 - cost_usd` | `raw` |
| `scope` | 1.2 | 0.0 | `0.8 - L2(action_embedding, context_embedding)`, or `0.8` if either embedding is unset | `raw` |
| `stability` | 1.0 | 0.0 | `50 - step_count` | `raw` |

Dangerous combinations for the safety barrier:

```text
{sql_query, http_request}
{file_read, send_email}
{database_query, webhook_post}
```

A barrier that raises during evaluation returns `-1.0`, which is treated as unsafe.

The barrier values are **not** configurable through `gateConfig` in the adapter path. The monitor constructs `EnhancedDCBFMonitor(enable_verification=...)` and accepts its defaults of `safety_margin=0.1`, `privacy_budget=0.5`, `resource_limit=10.0`, `max_drift=0.8`, and `step_budget=50`. `resource_budget.max_cost_usd` and `resource_budget.max_steps` do not feed these bars.

## What the defaults do in practice

Two consequences are easy to miss:

**The privacy barrier is terminal after one email or HTTP call.** Its effective value is `-0.2 * count`. The first `send_email` or `http_request` in the history takes it to `-0.2` on the next check, which violates the current-state condition. Every later tool call in that run is denied. Because the history never loses entries, a successful email blocks the rest of the run; a denied call does not add history, so the run cannot recover. If your agent sends mail or makes outbound requests, replace this barrier or use a custom monitor before enabling D-CBF.

**The stability barrier stops the run before the DFA step budget does.** With `step_budget=50` and `alpha(h) = 0.5h`, the call after 48 executed calls sees `h = 2`, a next value of `1`, and a drop of `1`, which is exactly the allowed `alpha(2) = 1`. The next call sees `h = 1`, a next value of `0`, and a drop of `1`, which exceeds `alpha(1) = 0.5`, so it is denied. The default D-CBF therefore admits 49 executed calls, one fewer than a `max_steps=50` DFA budget would allow. The limits are independent; whichever is stricter wins.

The resource barrier is inert in the adapter path because `after_call` never increments `state.resource_usage.cost_usd`. The simulated next state does increment cost by `0.01`, so the forward-invariance check sees a small decrease, but the actual state stays at zero.

The scope barrier is inert unless something populates `state.context_embedding` and `state.action_embedding`. The adapters do not.

The safety barrier can also be terminal: once a run has both tools of a dangerous pair in its last five calls, the barrier is negative and no further call can succeed to push the pair out of the window.

## Next-state simulation

For the forward-invariance test, `_simulate_next_state` builds a fresh `AgentState` with:

- `tokens_used + 100`
- `api_calls + 1`
- `cost_usd + 0.01`
- `step_count + 1`
- phase `ACTING`
- the same `trust_level`
- a copy of `context_embedding` if present

It does not copy `tool_history`, `action_embedding`, or `loop_count`. The simulated safety barrier therefore sees no recent tools, the simulated privacy barrier sees an empty history, and the simulated scope barrier sees no action embedding. Only resource and stability change meaningfully in the lookahead.

## Composite value

`evaluate_state(state)` returns the weighted **average** of the barrier values, despite its docstring saying "weighted minimum". That composite is used by `check_state_invariants` and by `verify_forward_invariance`; it does not drive `check_transition`, which evaluates each barrier separately. A positive composite therefore does not imply a safe state. Use `get_barrier_values(state)` when you need the per-barrier picture.

`check_state_invariants` calls `evaluate_state` and tests `>= 0`. Because this is an average, a negative privacy or safety barrier can be masked by healthy resource and stability barriers.

## Custom barriers

```python
from gate.core.monitor import gateMonitor
from gate.security.dcbf_monitor import EnhancedDCBFMonitor

dcbf = EnhancedDCBFMonitor(enable_verification=True, step_budget=25)
dcbf.remove_barrier("privacy")
dcbf.add_barrier(
    "privacy",
    lambda state: 1.0 - 0.05 * sum(
        1 for call in state.tool_history if call.tool_name in {"send_email", "http_request"}
    ),
    weight=1.5,
    margin=0.0,
)

monitor = gateMonitor(config, dcbf_monitor=dcbf)
```

`add_barrier(name, func, weight=1.0, margin=0.0)` replaces a barrier with the same name. `remove_barrier(name)` deletes it. The callable receives the `AgentState` and returns the raw value; the monitor subtracts the margin.

The four adapters construct their own monitor and do not accept a D-CBF instance. Use the monitor plus `ToolEnforcement` directly or write a custom adapter to use custom barriers.

## Offline verification

`verify_forward_invariance(test_states, test_actions)` reports how often the condition fails over a dataset:

```python
report = dcbf.verify_forward_invariance(states, actions)
# {"total_checks": ..., "violations": ..., "violation_rate": ..., "forward_invariant": bool}
```

It skips states whose composite value is already negative, then simulates the next state and compares the composite values. This is a diagnostic for barrier design, not a runtime check. Because it uses the composite average, it can miss a single-barrier violation that `check_transition` would catch.

## Neural CBF

`NeuralCBFConfig` can replace the hand-designed monitor with `NeuralCBF`:

```python
from gate import NeuralCBFConfig

config.neural_cbf_config = NeuralCBFConfig(
    enabled=True,
    model_path="models/ncbf.pt",
    device="cpu",
)
```

With `enabled=True` and the `dcbf` stage enabled, the monitor builds `NeuralCBF` instead of `EnhancedDCBFMonitor`. The module is experimental and is not exercised by the integration tests in the same way as the hand-designed barriers. Read [Standalone utilities](../standalone-utilities.md) before relying on it.

## Failure modes

- A barrier exception becomes `-1.0` and denies the transition.
- A D-CBF denial raises `DCBFViolation`; the monitor records `checks_failed=["dcbf"]` and the guard raises `ToolExecutionBlocked`.
- An unexpected exception outside a barrier's own try block propagates out of `validate_action` and prevents dispatch without producing a `ValidationResult`.
- A semantic escalation returns before D-CBF, so the barrier check is skipped for escalated calls.

## Related pages

- [Semantic firewall](semantic-firewall.md) for the preceding stage.
- [Architecture](../architecture.md) for the full validation order.
- [Standalone utilities](../standalone-utilities.md) for Neural CBF and the circuit breaker.
