"""Three-state asynchronous Circuit Breaker implementation for Sentinel."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Any, TypeVar

logger = logging.getLogger("sentinel.resilience.circuit_breaker")

T = TypeVar("T")


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerOpenError(RuntimeError):
    """Raised when an operation is attempted while the circuit breaker is OPEN."""

    def __init__(self, service_name: str, retry_after: float):
        super().__init__(
            f"Circuit breaker for service '{service_name}' is OPEN. Retry after {retry_after:.1f}s."
        )
        self.service_name = service_name
        self.retry_after = retry_after


class CircuitBreaker:
    """Thread-safe and async-safe Circuit Breaker.

    Transitions:
    - CLOSED -> OPEN: when consecutive failure_count reaches failure_threshold.
    - OPEN -> HALF_OPEN: when recovery_timeout seconds have elapsed since last failure.
    - HALF_OPEN -> CLOSED: when half_open_success_threshold consecutive successes occur.
    - HALF_OPEN -> OPEN: on any failure in half_open state.
    """

    def __init__(
        self,
        name: str = "default",
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_success_threshold: int = 2,
        expected_exceptions: tuple[type[Exception], ...] = (Exception,),
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_success_threshold = half_open_success_threshold
        self.expected_exceptions = expected_exceptions

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._half_open_successes = 0
        self._last_failure_time: float = 0.0
        self._total_calls = 0
        self._rejected_calls = 0
        self._lock = threading.RLock()

    def get_state(self) -> CircuitState:
        """Return current state, evaluating automatic OPEN -> HALF_OPEN transition."""
        with self._lock:
            if self._state == CircuitState.OPEN:
                elapsed = time.time() - self._last_failure_time
                if elapsed >= self.recovery_timeout:
                    logger.info(
                        f"Circuit breaker '{self.name}' transitioning from OPEN to HALF_OPEN after {elapsed:.1f}s."
                    )
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_successes = 0
            return self._state

    def get_metrics(self) -> dict[str, Any]:
        """Return operational metrics for telemetry reporting."""
        with self._lock:
            current_state = self.get_state()
            return {
                "name": self.name,
                "state": current_state.value,
                "failure_count": self._failure_count,
                "failure_threshold": self.failure_threshold,
                "recovery_timeout": self.recovery_timeout,
                "total_calls": self._total_calls,
                "rejected_calls": self._rejected_calls,
                "last_failure_time": self._last_failure_time,
            }

    async def call(self, func: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any) -> T:
        """Execute an asynchronous callable guarded by the circuit breaker."""
        with self._lock:
            self._total_calls += 1
            state = self.get_state()
            if state == CircuitState.OPEN:
                self._rejected_calls += 1
                retry_after = max(0.0, self.recovery_timeout - (time.time() - self._last_failure_time))
                raise CircuitBreakerOpenError(self.name, retry_after)

        try:
            result = await func(*args, **kwargs)
            self._on_success()
            return result
        except self.expected_exceptions as exc:
            self._on_failure(exc)
            raise

    def call_sync(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Execute a synchronous callable guarded by the circuit breaker."""
        with self._lock:
            self._total_calls += 1
            state = self.get_state()
            if state == CircuitState.OPEN:
                self._rejected_calls += 1
                retry_after = max(0.0, self.recovery_timeout - (time.time() - self._last_failure_time))
                raise CircuitBreakerOpenError(self.name, retry_after)

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except self.expected_exceptions as exc:
            self._on_failure(exc)
            raise

    def _on_success(self) -> None:
        with self._lock:
            self._success_count += 1
            if self._state == CircuitState.HALF_OPEN:
                self._half_open_successes += 1
                if self._half_open_successes >= self.half_open_success_threshold:
                    logger.info(
                        f"Circuit breaker '{self.name}' transitioning from HALF_OPEN to CLOSED after {self._half_open_successes} successes."
                    )
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0

    def _on_failure(self, exc: Exception) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            logger.warning(
                f"Circuit breaker '{self.name}' recorded failure #{self._failure_count}: {type(exc).__name__}: {exc}"
            )
            if self._state == CircuitState.HALF_OPEN or self._failure_count >= self.failure_threshold:
                logger.error(
                    f"Circuit breaker '{self.name}' tripped to OPEN (consecutive failures: {self._failure_count})."
                )
                self._state = CircuitState.OPEN

    def reset(self) -> None:
        """Manually reset circuit breaker to closed state."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            self._half_open_successes = 0
            self._last_failure_time = 0.0
