"""Tests for circuit breaker."""

import asyncio
import pytest
from gate.security.circuit_breaker import (
    CircuitBreaker, CircuitState, CircuitBreakerError, with_circuit_breaker,
)


class TestCircuitBreaker:
    """Tests for circuit breaker."""
    
    @pytest.mark.asyncio
    async def test_starts_closed(self):
        breaker = CircuitBreaker(name="test")
        assert breaker.state == CircuitState.CLOSED
    
    @pytest.mark.asyncio
    async def test_successful_call_stays_closed(self):
        breaker = CircuitBreaker(name="test")
        
        async def success():
            return "ok"
        
        result = await breaker.call(success)
        assert result == "ok"
        assert breaker.state == CircuitState.CLOSED
    
    @pytest.mark.asyncio
    async def test_opens_after_threshold_failures(self):
        breaker = CircuitBreaker(name="test", failure_threshold=3)
        
        async def failure():
            raise ValueError("fail")
        
        for _ in range(3):
            with pytest.raises(ValueError):
                await breaker.call(failure)
        
        assert breaker.state == CircuitState.OPEN
    
    @pytest.mark.asyncio
    async def test_open_circuit_rejects_calls(self):
        breaker = CircuitBreaker(name="test", failure_threshold=1)
        
        async def failure():
            raise ValueError("fail")
        
        with pytest.raises(ValueError):
            await breaker.call(failure)
        
        assert breaker.state == CircuitState.OPEN
        
        with pytest.raises(CircuitBreakerError):
            await breaker.call(failure)
    
    @pytest.mark.asyncio
    async def test_transitions_to_half_open_after_timeout(self):
        breaker = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=0.1)
        
        async def failure():
            raise ValueError("fail")
        
        with pytest.raises(ValueError):
            await breaker.call(failure)
        
        assert breaker.state == CircuitState.OPEN
        
        await asyncio.sleep(0.15)
        
        assert breaker.state == CircuitState.HALF_OPEN
    
    @pytest.mark.asyncio
    async def test_half_open_recovers_on_success(self):
        breaker = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=0.1)
        
        async def failure():
            raise ValueError("fail")
        
        with pytest.raises(ValueError):
            await breaker.call(failure)
        
        await asyncio.sleep(0.15)
        
        async def success():
            return "ok"
        
        result = await breaker.call(success)
        assert result == "ok"
        assert breaker.state == CircuitState.CLOSED
    
    @pytest.mark.asyncio
    async def test_half_open_opens_on_failure(self):
        breaker = CircuitBreaker(
            name="test",
            failure_threshold=1,
            recovery_timeout=0.1,
            half_open_max_calls=1,
        )
        
        async def failure():
            raise ValueError("fail")
        
        with pytest.raises(ValueError):
            await breaker.call(failure)
        
        await asyncio.sleep(0.15)
        
        with pytest.raises(ValueError):
            await breaker.call(failure)
        
        assert breaker.state == CircuitState.OPEN
    
    @pytest.mark.asyncio
    async def test_reset_manually(self):
        breaker = CircuitBreaker(name="test", failure_threshold=1)
        
        async def failure():
            raise ValueError("fail")
        
        with pytest.raises(ValueError):
            await breaker.call(failure)
        
        assert breaker.state == CircuitState.OPEN
        
        breaker.reset()
        assert breaker.state == CircuitState.CLOSED


class TestSyncAndFallback:
    @pytest.mark.asyncio
    async def test_sync_function_call(self):
        breaker = CircuitBreaker(name="sync")
        result = await breaker.call(lambda: 42)
        assert result == 42

    @pytest.mark.asyncio
    async def test_sync_function_failure_records(self):
        breaker = CircuitBreaker(name="sync", failure_threshold=1)

        def boom():
            raise ValueError("nope")

        with pytest.raises(ValueError):
            await breaker.call(boom)
        assert breaker.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_open_state_uses_sync_fallback(self):
        breaker = CircuitBreaker(
            name="fb", failure_threshold=1, fallback=lambda *a, **k: "fell-back")

        async def failure():
            raise ValueError("fail")

        with pytest.raises(ValueError):
            await breaker.call(failure)

        assert breaker.state == CircuitState.OPEN
        result = await breaker.call(failure)
        assert result == "fell-back"

    @pytest.mark.asyncio
    async def test_call_fallback_no_fallback_raises(self):
        breaker = CircuitBreaker(name="none")
        with pytest.raises(CircuitBreakerError):
            await breaker._call_fallback()

    @pytest.mark.asyncio
    async def test_half_open_max_calls_saturated_no_fallback(self):
        breaker = CircuitBreaker(
            name="ho", failure_threshold=1, recovery_timeout=0.05,
            half_open_max_calls=1)

        async def failure():
            raise ValueError("fail")

        async def success():
            return "ok"

        with pytest.raises(ValueError):
            await breaker.call(failure)
        # Let the recovery window elapse so state auto-moves to HALF_OPEN.
        await asyncio.sleep(0.08)
        assert breaker.state == CircuitState.HALF_OPEN
        breaker._half_open_calls = 1  # saturate the test-call budget
        with pytest.raises(CircuitBreakerError):
            await breaker.call(success)

    @pytest.mark.asyncio
    async def test_half_open_max_calls_saturated_with_async_fallback(self):
        async def afallback(*a, **k):
            return "async-fell-back"

        breaker = CircuitBreaker(
            name="ho-fb", failure_threshold=1, recovery_timeout=0.05,
            half_open_max_calls=1, fallback=afallback)

        async def failure():
            raise ValueError("fail")

        async def success():
            return "ok"

        with pytest.raises(ValueError):
            await breaker.call(failure)
        await asyncio.sleep(0.08)
        assert breaker.state == CircuitState.HALF_OPEN
        breaker._half_open_calls = 1
        result = await breaker.call(success)
        assert result == "async-fell-back"


class TestDecorator:
    @pytest.mark.asyncio
    async def test_with_circuit_breaker_wraps_call(self):
        breaker = CircuitBreaker(name="dec")

        @with_circuit_breaker(breaker)
        async def add(a, b):
            return a + b

        assert await add(2, 3) == 5

    @pytest.mark.asyncio
    async def test_with_circuit_breaker_propagates_failure(self):
        breaker = CircuitBreaker(name="dec-fail", failure_threshold=1)

        @with_circuit_breaker(breaker)
        async def boom():
            raise ValueError("x")

        with pytest.raises(ValueError):
            await boom()
        assert breaker.state == CircuitState.OPEN
