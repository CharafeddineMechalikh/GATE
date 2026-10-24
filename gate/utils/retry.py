"""
Retry Utilities
Provides retry logic with exponential backoff using tenacity.
"""

import logging
from typing import Any, Callable, Optional, Tuple, Type, Union
from functools import wraps

from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    retry_if_result,
    RetryError,
)

logger = logging.getLogger(__name__)


class RetryConfig:
    """Configuration for retry behavior."""
    
    def __init__(
        self,
        max_attempts: int = 3,
        min_wait_seconds: float = 0.5,
        max_wait_seconds: float = 10.0,
        multiplier: float = 2.0,
        retryable_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
        non_retryable_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
    ) -> None:
        self.max_attempts = max_attempts
        self.min_wait_seconds = min_wait_seconds
        self.max_wait_seconds = max_wait_seconds
        self.multiplier = multiplier
        self.retryable_exceptions = retryable_exceptions or (Exception,)
        self.non_retryable_exceptions = non_retryable_exceptions or ()


def create_retry_decorator(
    config: Optional[RetryConfig] = None,
    operation_name: str = "operation",
) -> Callable:
    """
    Create a retry decorator with the given configuration.
    
    Args:
        config: Retry configuration. Uses defaults if not provided.
        operation_name: Name of the operation for logging.
    
    Returns:
        Decorator function.
    """
    if config is None:
        config = RetryConfig()
    
    def is_retryable_exception(exception: BaseException) -> bool:
        """Check if exception should be retried."""
        if isinstance(exception, config.non_retryable_exceptions):
            logger.debug(
                f"{operation_name}: Non-retryable exception: {type(exception).__name__}"
            )
            return False
        if isinstance(exception, config.retryable_exceptions):
            logger.warning(
                f"{operation_name}: Retryable exception: {type(exception).__name__}"
            )
            return True
        return False
    
    def before_sleep(retry_state: Any) -> None:
        """Log before sleeping."""
        logger.info(
            f"{operation_name}: Retrying in {retry_state.next_action.sleep} seconds "
            f"(attempt {retry_state.attempt_number}/{config.max_attempts})"
        )
    
    def after_attempt(retry_state: Any) -> None:
        """Log after each attempt."""
        if retry_state.outcome and retry_state.outcome.failed:
            logger.warning(
                f"{operation_name}: Attempt {retry_state.attempt_number} failed: "
                f"{retry_state.outcome.exception()}"
            )
    
    return retry(
        stop=stop_after_attempt(config.max_attempts),
        wait=wait_exponential(
            min=config.min_wait_seconds,
            max=config.max_wait_seconds,
            multiplier=config.multiplier,
        ),
        retry=retry_if_exception_type(config.retryable_exceptions),
        before_sleep=before_sleep,
        after=after_attempt,
        reraise=True,
    )


def with_retry(
    max_attempts: int = 3,
    min_wait_seconds: float = 0.5,
    max_wait_seconds: float = 10.0,
    multiplier: float = 2.0,
    retryable_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
    operation_name: Optional[str] = None,
) -> Callable:
    """
    Decorator to add retry logic to a function.
    
    Args:
        max_attempts: Maximum number of retry attempts.
        min_wait_seconds: Minimum wait time between retries.
        max_wait_seconds: Maximum wait time between retries.
        multiplier: Multiplier for exponential backoff.
        retryable_exceptions: Tuple of exception types to retry on.
        operation_name: Name of the operation for logging.
    
    Returns:
        Decorator function.
    """
    config = RetryConfig(
        max_attempts=max_attempts,
        min_wait_seconds=min_wait_seconds,
        max_wait_seconds=max_wait_seconds,
        multiplier=multiplier,
        retryable_exceptions=retryable_exceptions,
    )
    
    def decorator(func: Callable) -> Callable:
        op_name = operation_name or func.__name__
        retry_decorator = create_retry_decorator(config, op_name)
        
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return retry_decorator(func)(*args, **kwargs)
        
        return wrapper
    
    return decorator


class RetryableOperation:
    """
    Wrapper for operations that should be retried on failure.
    
    Usage:
        operation = RetryableOperation(my_func, config=RetryConfig())
        result = operation.execute(arg1, arg2)
    """
    
    def __init__(
        self,
        func: Callable,
        config: Optional[RetryConfig] = None,
        operation_name: Optional[str] = None,
    ) -> None:
        self.func = func
        self.config = config or RetryConfig()
        self.operation_name = operation_name or func.__name__
        self._retry_decorator = create_retry_decorator(self.config, self.operation_name)
        self._wrapped_func = self._retry_decorator(func)
    
    def execute(self, *args: Any, **kwargs: Any) -> Any:
        """Execute the operation with retry logic."""
        return self._wrapped_func(*args, **kwargs)
    
    async def aexecute(self, *args: Any, **kwargs: Any) -> Any:
        """Execute the async operation with retry logic."""
        import asyncio
        
        async def async_wrapper() -> Any:
            return await self.func(*args, **kwargs)
        
        wrapped = self._retry_decorator(async_wrapper)
        return await wrapped()
