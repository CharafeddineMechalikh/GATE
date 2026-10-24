"""
Circuit Breaker
Prevents cascading failures when security components fail.
"""

import asyncio
import logging
import time
from enum import Enum
from typing import Any, Callable, Optional
from functools import wraps

logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreakerError(Exception):
    """Raised when circuit is open and call is rejected."""
    pass


class CircuitBreaker:
    """
    Circuit breaker for security components.
    
    States:
    - CLOSED: Calls pass through. Failures counted.
    - OPEN: Calls rejected immediately. After timeout, transition to HALF_OPEN.
    - HALF_OPEN: One test call allowed. Success -> CLOSED. Failure -> OPEN.
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        half_open_max_calls: int = 1,
        name: str = "unnamed",
        fallback: Optional[Callable] = None,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        self.name = name
        self.fallback = fallback
        
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._half_open_calls = 0
        self._lock = asyncio.Lock()
    
    @property
    def state(self) -> CircuitState:
        """Get current state, auto-transitioning from OPEN to HALF_OPEN if timeout elapsed."""
        if self._state == CircuitState.OPEN and self._last_failure_time:
            if time.time() - self._last_failure_time >= self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
                logger.info(f"Circuit breaker '{self.name}' transitioning to HALF_OPEN")
        return self._state
    
    async def call(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """Call a function through the circuit breaker."""
        async with self._lock:
            current_state = self.state
            
            if current_state == CircuitState.OPEN:
                if self.fallback:
                    logger.warning(f"Circuit '{self.name}' OPEN, using fallback")
                    return await self._call_fallback(*args, **kwargs)
                raise CircuitBreakerError(
                    f"Circuit breaker '{self.name}' is OPEN. "
                    f"Recovery in {self.recovery_timeout - (time.time() - self._last_failure_time):.1f}s"
                )
            
            if current_state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.half_open_max_calls:
                    if self.fallback:
                        return await self._call_fallback(*args, **kwargs)
                    raise CircuitBreakerError(
                        f"Circuit breaker '{self.name}' HALF_OPEN, max test calls reached"
                    )
                self._half_open_calls += 1
        
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            await self.record_success()
            return result
        except Exception as e:
            await self.record_failure()
            raise
    
    async def record_success(self) -> None:
        """Record a successful call."""
        async with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.half_open_max_calls:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._success_count = 0
                    logger.info(f"Circuit breaker '{self.name}' recovered -> CLOSED")
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0
    
    async def record_failure(self) -> None:
        """Record a failed call."""
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                logger.warning(f"Circuit breaker '{self.name}' HALF_OPEN test failed -> OPEN")
            elif self._state == CircuitState.CLOSED:
                if self._failure_count >= self.failure_threshold:
                    self._state = CircuitState.OPEN
                    logger.warning(
                        f"Circuit breaker '{self.name}' tripped -> OPEN "
                        f"after {self._failure_count} failures"
                    )
    
    async def _call_fallback(self, *args: Any, **kwargs: Any) -> Any:
        """Call the fallback function."""
        if self.fallback:
            if asyncio.iscoroutinefunction(self.fallback):
                return await self.fallback(*args, **kwargs)
            return self.fallback(*args, **kwargs)
        raise CircuitBreakerError(f"No fallback configured for '{self.name}'")
    
    def reset(self) -> None:
        """Manually reset the circuit breaker."""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = None
        logger.info(f"Circuit breaker '{self.name}' manually reset")


def with_circuit_breaker(breaker: CircuitBreaker) -> Callable:
    """Decorator to wrap a function with a circuit breaker."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            return await breaker.call(func, *args, **kwargs)
        return wrapper
    return decorator
