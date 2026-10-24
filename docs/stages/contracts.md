# Smart contracts

The contract stage attaches application-specific rules to tools. Preconditions run before dispatch; postconditions run after the tool body and can withhold its output from the agent.

Contracts are looked up by **exact tool name**. There is no pattern matching, no wildcard, and no fallback contract. A tool with no registered contract passes this stage.

## Defining a contract

```python
from gate.security.smart_contracts import (
    BaseSmartContract,
    postcondition,
    precondition,
)


class RefundContract(BaseSmartContract):
    @precondition
    def amount_is_sane(self, action, state):
        amount = action.tool_args.get("amount", 0)
        return isinstance(amount, (int, float)) and 0 < amount <= 500

    @precondition
    def order_was_checked(self, action, state):
        return "lookup_order" in {call.tool_name for call in state.tool_history}

    @postcondition
    def receipt_has_id(self, action, result, state):
        return isinstance(result, dict) and bool(result.get("receipt_id"))
```

Signature rules:

| Decorator | Signature | Return |
|---|---|---|
| `@precondition` | `(self, action: ToolCall, state: AgentState)` | `True` to pass; `False` or a raised exception to fail |
| `@postcondition` | `(self, action: ToolCall, result: Any, state: AgentState)` | `True` to pass; `False` or a raised exception to fail |

Register it by exact tool name:

```python
secure.monitor.contract_registry.register_contract("issue_refund", RefundContract())
```

A contract instance can serve several tool names, but the registry stores one contract per name. Registering the same name again replaces the previous contract.

## Evaluation semantics

`BaseSmartContract` collects decorated methods at construction. Preconditions and postconditions are evaluated in attribute-name order (the order produced by `dir(self)`), not definition order. Do not rely on one precondition running before another; make each one independent.

A check fails when it:

- returns exactly `False`,
- raises `ContractViolation`, or
- raises any other exception.

The comparison is identity-based (`is False`). A check that forgets to return a value and yields `None` passes. Return an explicit boolean from every check; a missing `return` silently disables that rule.

An exception in a precondition becomes `ContractViolation` with violation type `PRECONDITION_ERROR`; an exception in a postcondition becomes `POSTCONDITION_ERROR`. Both fail closed.

The monitor reports a failed precondition as `checks_failed=["contracts"]` and includes the contract class name and violation type in the result details.

`@invariant` and `@composition_rule` decorators exist and their methods are collected, but the runtime never evaluates those collections. Only preconditions and postconditions affect decisions.

## Built-in contracts

The default `ContractRegistry` registers four contracts:

| Tool name | Contract | Enforcement |
|---|---|---|
| `sql_query` | `SQLQueryContract` | Query shape, injection patterns, file access |
| `http_request` | `HTTPRequestContract` | Destination, internal addresses, method |
| `send_email` | `EmailSendContract` | Recipient domain, PII patterns, subject length |
| `code_execute` | `CodeExecutionContract` | Dangerous substrings, code length |

These names are literal. A tool called `run_sql` or `postgres_query` is not covered.

### `SQLQueryContract`

Reads `action.tool_args["query"]`.

| Check | Rejects |
|---|---|
| `no_destructive_operations` | The keywords `DROP`, `DELETE`, `TRUNCATE`, `ALTER`, `CREATE` as whole words, case-insensitive |
| `no_injection_patterns` | Tautologies (`OR 1=1`, `OR 'a'='a'`, `OR TRUE`), stacked statements (`;` followed by content), `UNION SELECT`, and inline `--` or `#` comments (unless the query starts with `--`) |
| `no_ssrf_patterns` | `INTO OUTFILE`, `LOAD_FILE`, `INTO DUMPFILE` |
| `row_limit_enforcement` | Nothing. If the query has no `LIMIT`, it logs a warning and appends `LIMIT 1000` to the monitored `ToolCall` args |
| `check_table_access` | Nothing. It logs the first table after `FROM` and returns true |

The appended `LIMIT` is recorded in the monitor's copy of the call, but the tool is dispatched with the original framework arguments. The row limit is **not** applied to the query the database receives. Treat the built-in contract as a query-shape filter, not a query rewriter.

### `HTTPRequestContract`

Reads `url` and optionally `method`.

- Rejects URLs containing `evil.com`, `attacker.com`, or `169.254.169.254` as substrings.
- Rejects the internal IPv4 patterns `127.0.0.x`, `10.x.x.x`, `172.16.x.x` through `172.31.x.x`, and `192.168.x.x`.
- Allows only `GET`, `POST`, `PUT`, `DELETE`, and `PATCH`; a missing method is treated as `GET`.

This is a denylist, not a destination allow-list. It does not resolve DNS, follow redirects, or inspect the response.

### `EmailSendContract`

Reads `to`, `body`, and `subject`.

- The recipient must end with `@company.com` or `@trusted-partner.com`.
- The body must not match an SSN pattern (`123-45-6789`) or a 16-digit card-like pattern.
- The subject must be at most 200 characters.

The domain list is hard-coded. Replace the contract to use your own domains.

### `CodeExecutionContract`

Reads `code`.

- Rejects the substrings `os.system`, `subprocess`, `shutil.rmtree`, `eval(`, `exec(`, and `__import__`.
- Rejects code longer than 10,000 characters.

Substring matching is easy to bypass with aliasing, encoding, or indirect calls. It is a guardrail against obvious mistakes, not a sandbox. Run untrusted code in an isolated process or container.

## Postconditions

`gateMonitor.validate_result(action, output, state)` runs after the tool body:

1. If the contracts stage is disabled or no contract is registered for the tool, the result is allowed.
2. If a postcondition returns `False`, the result is denied with reason `postcondition false`.
3. If a postcondition returns true but an earlier one fails, the earlier failure wins because checks run in order.
4. If evaluation raises, the result is denied with `POSTCONDITION_ERROR`.

When the postcondition fails, the guard raises:

```python
ToolExecutionBlocked(
    "Postcondition failed for tool <name>: ...",
    tool_name,
    result,
    post_execution=True,
)
```

`execution.is_allowed` is false, `checks_failed` is `["postcondition"]`, and the output never reaches the agent. The tool has already run. A refund may have been issued, an email sent, a row written. The postcondition withholds evidence of success; it cannot undo the action.

If the framework's tool body returns a value the postcondition cannot evaluate without raising, you get a closed failure, not an open one. Design postconditions to return booleans for every expected result shape.

## Contracts in the adapter path

To install a contract through an adapter, reach the monitor on the secure wrapper:

```python
secure = wrap_agent(graph, "langgraph", config)
secure.monitor.contract_registry.register_contract("search", SearchOutputContract())
```

This works because `secure.monitor` is the same monitor instance used by the guards. Register contracts before the first tool call. The contract registry is per wrapped agent, not global.

The default registry includes the four built-ins. Removing one is possible:

```python
secure.monitor.contract_registry.unregister_contract("send_email")
```

Do that only if another layer covers the same risk; otherwise you have removed a control.

## Limitations

- Contracts match exact tool names, so framework-prefixed names (`functions.issue_refund`) will not match.
- Preconditions see marshalled arguments, not the framework's raw call signature. See [Argument marshalling](../enforcement.md#argument-marshalling).
- The built-in SQL row limit and table-access check do not enforce anything.
- There is no contract for generic filesystem, shell, or browser tools in the default registry.
- Contract evaluation is synchronous and runs inside the tool-call path. A slow contract delays the call and occupies the monitor loop for synchronous frameworks.
- Postconditions are not transactional. Use an idempotent tool or a compensating action if the side effect matters.

## Related pages

- [Architecture](../architecture.md) for where the contract stage sits.
- [Enforcement plumbing](../enforcement.md) for argument marshalling.
- [Security model](../security-model.md) for the threat model.
