"""
Base Framework Adapter
Enhanced with timeout handling and retry logic.
"""

import asyncio
import logging
import signal
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Any, List, Optional
from contextlib import contextmanager

from ..core.interfaces import AgentFrameworkAdapter, SecurityMonitor, SecureAgent
from ..core.config import gateConfig
from ..core.models import ToolCall, AgentState
from ..core.exceptions import AdapterError

logger = logging.getLogger(__name__)


class TimeoutError(Exception):
    """Raised when an operation times out."""
    pass


class BaseFrameworkAdapter(AgentFrameworkAdapter):
    """
    Base class for framework-specific adapters with timeout and retry support.
    """
    
    def __init__(
        self,
        framework_name: str,
        default_timeout_seconds: float = 300.0,
    ) -> None:
        self.framework_name = framework_name
        self.default_timeout_seconds = default_timeout_seconds
        logger.info(f"Initialized {framework_name} adapter")
    
    def wrap_agent(self, agent: Any, config: gateConfig) -> SecureAgent:
        """Wrap a framework-specific agent with gate security."""
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement wrap_agent()"
        )
    
    def extract_state(self, agent: Any) -> AgentState:
        """Extract agent state from framework-specific agent."""
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement extract_state()"
        )
    
    def inject_monitoring(self, agent: Any, monitor: SecurityMonitor) -> None:
        """Inject security monitoring into framework-specific agent."""
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement inject_monitoring()"
        )
    
    def get_tool_calls(self, agent: Any) -> List[ToolCall]:
        """Extract tool calls from framework-specific agent."""
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement get_tool_calls()"
        )
    
    def get_agent_id(self, agent: Any) -> str:
        """Get agent ID from framework-specific agent."""
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement get_agent_id()"
        )
    
    def _validate_agent_type(self, agent: Any, expected_type: type) -> None:
        """Validate that agent is of expected type."""
        if not isinstance(agent, expected_type):
            raise AdapterError(
                f"Expected {expected_type.__name__}, got {type(agent).__name__}"
            )
    
    @contextmanager
    def timeout_context(self, seconds: Optional[float] = None):
        """
        Context manager for timeout handling on platforms with SIGALRM.

        On Windows, and in threads other than the main thread, the signal-based
        interrupt is unavailable; use run_with_timeout for those calls.
        """
        timeout = seconds or self.default_timeout_seconds

        if not hasattr(signal, "SIGALRM") or threading.current_thread() is not threading.main_thread():
            yield
            return

        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        if running_loop is not None:
            yield
            return

        def timeout_handler(signum, frame):
            raise TimeoutError(f"Operation timed out after {timeout} seconds")

        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(int(timeout))

        try:
            yield
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

    def run_with_timeout(
        self,
        func: Any,
        *args: Any,
        seconds: Optional[float] = None,
        operation_name: str = "operation",
        **kwargs: Any,
    ) -> Any:
        """Run a blocking call with a wall-clock timeout.

        POSIX main-thread calls use SIGALRM so the interrupt is immediate. On
        Windows the call runs in a worker thread and the caller stops waiting at
        the deadline; Python cannot kill the worker, so secured agents call
        ToolEnforcement.abort() on timeout to deny any further tool calls from
        that run.
        """
        timeout = seconds or self.default_timeout_seconds

        can_alarm = (
            hasattr(signal, "SIGALRM")
            and threading.current_thread() is threading.main_thread()
        )
        if can_alarm:
            with self.timeout_context(timeout):
                return func(*args, **kwargs)

        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(func, *args, **kwargs)
        try:
            return future.result(timeout=timeout)
        except FutureTimeoutError:
            future.cancel()
            logger.error(f"{operation_name} timed out after {timeout} seconds")
            raise TimeoutError(
                f"{operation_name} timed out after {timeout} seconds"
            ) from None
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
    
    async def async_timeout_context(
        self,
        coro: Any,
        seconds: Optional[float] = None,
        operation_name: str = "operation",
    ) -> Any:
        """
        Async timeout wrapper.
        
        Args:
            coro: Coroutine to execute with timeout.
            seconds: Timeout in seconds.
            operation_name: Name for logging.
        
        Returns:
            Result of the coroutine.
        
        Raises:
            TimeoutError: If operation exceeds timeout.
        """
        timeout = seconds or self.default_timeout_seconds
        
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            logger.error(f"{operation_name} timed out after {timeout} seconds")
            raise TimeoutError(
                f"{operation_name} timed out after {timeout} seconds"
            )
    
    def get_timeout_config(self, config: gateConfig) -> float:
        """Get timeout from config or use default."""
        return getattr(
            config,
            "timeout_seconds",
            self.default_timeout_seconds,
        )
