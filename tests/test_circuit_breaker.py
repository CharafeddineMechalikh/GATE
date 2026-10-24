"""Tests for circuit breaker."""

import asyncio
import pytest
from gate.security.circuit_breaker import CircuitBreaker, CircuitState, CircuitBreakerError


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
