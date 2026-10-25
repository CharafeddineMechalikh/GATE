"""Unit tests for the tenacity-based retry utilities.

Waits are configured to zero so the suite stays fast; the retry *behavior*
(attempt counting, reraise, exception filtering, the async path) is what is
under test.
"""

import pytest

from gate.utils.retry import (
    RetryConfig,
    RetryableOperation,
    create_retry_decorator,
    with_retry,
)


def _config(**overrides):
    base = dict(max_attempts=3, min_wait_seconds=0, max_wait_seconds=0, multiplier=1)
    base.update(overrides)
    return RetryConfig(**base)


def test_retryconfig_defaults():
    c = RetryConfig()
    assert c.max_attempts == 3
    assert c.retryable_exceptions == (Exception,)
    assert c.non_retryable_exceptions == ()


def test_decorator_retries_then_succeeds():
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise RuntimeError("transient")
        return "ok"

    decorated = create_retry_decorator(_config(), "flaky")(flaky)
    assert decorated() == "ok"
    assert calls["n"] == 3


def test_decorator_reraises_after_exhausting():
    calls = {"n": 0}

    def always_fails():
        calls["n"] += 1
        raise ValueError("boom")

    decorated = create_retry_decorator(_config(max_attempts=2), "x")(always_fails)
    with pytest.raises(ValueError):
        decorated()
    assert calls["n"] == 2


def test_decorator_only_retries_matching_types():
    calls = {"n": 0}

    def raiser():
        calls["n"] += 1
        raise TypeError("not retryable")

    decorated = create_retry_decorator(
        _config(retryable_exceptions=(ValueError,)), "x"
    )(raiser)
    with pytest.raises(TypeError):
        decorated()
    assert calls["n"] == 1  # TypeError is outside retryable set


def test_with_retry_decorator_wraps_success():
    calls = {"n": 0}

    @with_retry(max_attempts=3, min_wait_seconds=0, max_wait_seconds=0, multiplier=1)
    def work(x):
        calls["n"] += 1
        if calls["n"] < 2:
            raise RuntimeError("again")
        return x * 2

    assert work(21) == 42


def test_retryable_operation_execute():
    calls = {"n": 0}

    def op(a, b):
        calls["n"] += 1
        if calls["n"] < 2:
            raise RuntimeError("retry")
        return a + b

    operation = RetryableOperation(op, config=_config(), operation_name="add")
    assert operation.execute(2, 3) == 5
    assert operation.operation_name == "add"


def test_retryable_operation_uses_func_name_default():
    def named_op():
        return 7

    operation = RetryableOperation(named_op, config=_config())
    assert operation.operation_name == "named_op"
    assert operation.execute() == 7


@pytest.mark.asyncio
async def test_retryable_operation_aexecute_success():
    async def op(x):
        return x + 1

    operation = RetryableOperation(op, config=_config())
    assert await operation.aexecute(4) == 5


@pytest.mark.asyncio
async def test_retryable_operation_aexecute_retries():
    calls = {"n": 0}

    async def flaky():
        calls["n"] += 1
        if calls["n"] < 2:
            raise RuntimeError("retry")
        return "done"

    operation = RetryableOperation(flaky, config=_config())
    assert await operation.aexecute() == "done"
    assert calls["n"] == 2
