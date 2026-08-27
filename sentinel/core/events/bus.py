"""Internal Asynchronous Event Bus for Sentinel.

Provides typed publish/subscribe mechanics with an in-process memory bus,
designed to be easily swapped with Redis/NATS without altering publisher interfaces.
"""

import asyncio
import contextlib
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime
from typing import Any

from sentinel.core.models import Event, EventType

# Type alias for event listener callbacks
EventListener = Callable[[Event], Coroutine[Any, Any, None]]


class EventBus(ABC):
    """Abstract Event Bus interface."""

    @abstractmethod
    async def publish(self, event: Event) -> None:
        """Publish an event to all interested topic subscribers."""
        pass

    @abstractmethod
    async def subscribe(self, topic_pattern: str, listener: EventListener) -> None:
        """Subscribe an async listener to a topic or topic pattern."""
        pass

    @abstractmethod
    async def unsubscribe(self, topic_pattern: str, listener: EventListener) -> None:
        """Unsubscribe a listener."""
        pass

    @abstractmethod
    async def get_history(self, correlation_id: str | None = None) -> list[Event]:
        """Retrieve stored in-memory event history."""
        pass


class InMemoryEventBus(EventBus):
    """Production-grade In-Memory Async Event Bus."""

    def __init__(self, max_history: int = 10000):
        self._subscribers: dict[str, list[EventListener]] = defaultdict(list)
        self._global_subscribers: list[EventListener] = []
        self._history: list[Event] = []
        self._max_history = max_history
        self._lock = asyncio.Lock()
        self._queues: dict[str, list[asyncio.Queue[Event]]] = defaultdict(list)

    async def publish(self, event: Event) -> None:
        """Publish event to pattern-matched subscribers and record history."""
        async with self._lock:
            self._history.append(event)
            if len(self._history) > self._max_history:
                self._history.pop(0)

        # Notify direct topic subscribers
        listeners_to_notify: list[EventListener] = []
        for topic_pattern, listeners in self._subscribers.items():
            if self._matches(topic_pattern, event.topic):
                listeners_to_notify.extend(listeners)

        listeners_to_notify.extend(self._global_subscribers)

        # Deliver concurrently without blocking the publisher
        for listener in listeners_to_notify:
            asyncio.create_task(self._safe_dispatch(listener, event))

        # Push to any active SSE / task queues
        if event.correlation_id in self._queues:
            for q in self._queues[event.correlation_id]:
                await q.put(event)

    async def _safe_dispatch(self, listener: EventListener, event: Event) -> None:
        with contextlib.suppress(Exception):
            await listener(event)

    def _matches(self, pattern: str, topic: str) -> bool:
        """Match wildcard patterns, e.g. 'task.*' matches 'task.created'."""
        if pattern in ("*", topic):
            return True
        if pattern.endswith(".*"):
            prefix = pattern[:-2]
            return topic.startswith(prefix)
        return False

    async def subscribe(self, topic_pattern: str, listener: EventListener) -> None:
        async with self._lock:
            if topic_pattern == "*":
                if listener not in self._global_subscribers:
                    self._global_subscribers.append(listener)
            elif listener not in self._subscribers[topic_pattern]:
                self._subscribers[topic_pattern].append(listener)

    async def unsubscribe(self, topic_pattern: str, listener: EventListener) -> None:
        async with self._lock:
            if topic_pattern == "*":
                if listener in self._global_subscribers:
                    self._global_subscribers.remove(listener)
            elif topic_pattern in self._subscribers and listener in self._subscribers[topic_pattern]:
                self._subscribers[topic_pattern].remove(listener)

    async def get_history(self, correlation_id: str | None = None) -> list[Event]:
        async with self._lock:
            if not correlation_id:
                return list(self._history)
            return [e for e in self._history if e.correlation_id == correlation_id]

    def register_queue(self, correlation_id: str) -> asyncio.Queue[Event]:
        """Create a dedicated event queue for SSE / stream consumers."""
        q: asyncio.Queue[Event] = asyncio.Queue()
        self._queues[correlation_id].append(q)
        return q

    def unregister_queue(self, correlation_id: str, q: asyncio.Queue[Event]) -> None:
        """Remove a consumer queue."""
        if correlation_id in self._queues and q in self._queues[correlation_id]:
            self._queues[correlation_id].remove(q)
            if not self._queues[correlation_id]:
                del self._queues[correlation_id]


# Global Event Bus Singleton
event_bus = InMemoryEventBus()


async def emit_event(
    event_type: EventType,
    topic: str,
    source: str,
    payload: dict[str, Any],
    correlation_id: str,
) -> Event:
    """Helper to construct and broadcast a typed event."""
    event = Event(
        event_id=f"evt-{uuid.uuid4().hex[:12]}",
        event_type=event_type,
        topic=topic,
        source=source,
        payload=payload,
        correlation_id=correlation_id,
        timestamp=datetime.now(UTC),
    )
    await event_bus.publish(event)
    return event
