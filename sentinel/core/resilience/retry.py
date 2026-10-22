"""Exponential backoff retry utilities with full jitter for Sentinel."""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

logger = logging.getLogger("sentinel.resilience.retry")

T = TypeVar("T")


def calculate_backoff(
    attempt: int,
    base_delay: float = 0.5,
    max_delay: float = 10.0,
    jitter: bool = True,
) -> float:
    """Calculate exponential backoff duration with full jitter."""
    calculated = float(min(max_delay, base_delay * (2 ** attempt)))
    if jitter:
        return float(random.uniform(0.0, calculated))
    return calculated


async def retry_async(
    func: Callable[..., Awaitable[T]],
    *args: Any,
    max_retries: int = 3,
    base_delay: float = 0.5,
    max_delay: float = 10.0,
    jitter: bool = True,
    retry_exceptions: tuple[type[Exception], ...] = (Exception,),
    **kwargs: Any,
) -> T:
    """Execute an asynchronous function with exponential backoff and jitter."""
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except retry_exceptions as exc:
            last_exc = exc
            if attempt >= max_retries:
                logger.error(f"Function {func.__name__} exhausted all {max_retries} retries: {exc}")
                raise
            delay = calculate_backoff(attempt, base_delay=base_delay, max_delay=max_delay, jitter=jitter)
            logger.warning(
                f"Attempt {attempt + 1}/{max_retries + 1} for {func.__name__} failed ({type(exc).__name__}). Retrying in {delay:.2f}s..."
            )
            await asyncio.sleep(delay)

    if last_exc is not None:
        raise last_exc
    raise RuntimeError(f"Retry loop for {func.__name__} exited unexpectedly")


def retry_sync(
    func: Callable[..., T],
    *args: Any,
    max_retries: int = 3,
    base_delay: float = 0.5,
    max_delay: float = 10.0,
    jitter: bool = True,
    retry_exceptions: tuple[type[Exception], ...] = (Exception,),
    **kwargs: Any,
) -> T:
    """Execute a synchronous function with exponential backoff and jitter."""
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return func(*args, **kwargs)
        except retry_exceptions as exc:
            last_exc = exc
            if attempt >= max_retries:
                logger.error(f"Function {func.__name__} exhausted all {max_retries} retries: {exc}")
                raise
            delay = calculate_backoff(attempt, base_delay=base_delay, max_delay=max_delay, jitter=jitter)
            logger.warning(
                f"Attempt {attempt + 1}/{max_retries + 1} for {func.__name__} failed ({type(exc).__name__}). Retrying in {delay:.2f}s..."
            )
            time.sleep(delay)

    if last_exc is not None:
        raise last_exc
    raise RuntimeError(f"Retry loop for {func.__name__} exited unexpectedly")
