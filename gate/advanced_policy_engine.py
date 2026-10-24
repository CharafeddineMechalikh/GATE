# gate/advanced_policy_engine.py
"""
Advanced policy engine for gate.

Extends the simple policy engine with step-budget tracking, pre/post-condition
hooks, and semantic firewall integration.  This is the module that
``adapter_base.AdapterBase`` and the benchmark scripts import from.
"""

from typing import Any, Callable, Optional

from .policy_engine import check_permission as _base_check_permission
from .semantic_check import semantic_check as _semantic_check

# ---------------------------------------------------------------------------
# Step budget
# ---------------------------------------------------------------------------

#: Maximum number of tool executions before the policy engine denies further
#: calls.  Can be overridden by assigning to this name or by calling
#: :func:`set_max_steps`.
MAX_STEPS: int = 1000

_step_count: int = 0


def reset_step_count() -> None:
    """Reset the global step counter to zero."""
    global _step_count
    _step_count = 0


def get_step_count() -> int:
    """Return the current value of the global step counter."""
    return _step_count


def set_max_steps(value: int) -> None:
    """Set the maximum number of allowed steps."""
    global MAX_STEPS
    MAX_STEPS = value


# ---------------------------------------------------------------------------
# Permission check (with step budget)
# ---------------------------------------------------------------------------

def check_permission(contract, tool_name: str) -> bool:
    """Check the contract's permission list against the loaded policy, and
    enforce the step budget.

    Returns ``True`` only if:

    1. Every permission in ``contract.permissions`` is allowed for ``tool_name``
       according to the YAML policy, and
    2. The global step counter has not yet reached ``MAX_STEPS``.

    On success the step counter is incremented by one.
    """
    global _step_count

    # 1. Permission check (delegates to the simple engine)
    if not _base_check_permission(contract, tool_name):
        return False

    # 2. Step-budget check
    if _step_count >= MAX_STEPS:
        return False

    _step_count += 1
    return True


# ---------------------------------------------------------------------------
# Pre- / post-condition hooks
# ---------------------------------------------------------------------------

def run_precondition(
    pre: Optional[Callable[[dict[str, Any]], bool]],
    args: dict[str, Any],
) -> bool:
    """Run a precondition callable if one is provided.

    Returns ``True`` when no precondition is set, or when the callable
    returns a truthy value.
    """
    return pre(args) if pre else True


def run_postcondition(
    post: Optional[Callable[[Any], bool]],
    result: Any,
) -> bool:
    """Run a postcondition callable if one is provided.

    Returns ``True`` when no postcondition is set, or when the callable
    returns a truthy value.
    """
    return post(result) if post else True


# ---------------------------------------------------------------------------
# Semantic firewall
# ---------------------------------------------------------------------------

# Re-export so that ``from gate.advanced_policy_engine import semantic_check``
# works exactly as ``adapter_base.py`` expects.
semantic_check = _semantic_check

__all__ = [
    "MAX_STEPS",
    "check_permission",
    "semantic_check",
    "run_precondition",
    "run_postcondition",
    "reset_step_count",
    "get_step_count",
    "set_max_steps",
]
