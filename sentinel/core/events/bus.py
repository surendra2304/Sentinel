"""Internal Asynchronous Event Bus for Sentinel.

Provides typed publish/subscribe mechanics with an in-process memory bus,
designed to be easily swapped with Redis/NATS without altering publisher interfaces.
"""

import asyncio
import logging
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime
from typing import Any

from sentinel.core.models import Event, EventType

logger = logging.getLogger(__name__)


DEFAULT_EVENT_QUEUE_SIZE = 256
_TERMINAL_TASK_STATES = frozenset(
    {
        "complete",
        "completed",
        "failed",
        "cancelled",
        "canceled",
        "blocked",
        "partially_completed",
        "halted",
        "terminated",
    }
)


def _is_terminal_task_event(event: Event) -> bool:
    """Return whether an event represents a terminal task state.

    A queue may discard stale progress updates under pressure, but it must not
    discard a task's final state just because a stream consumer is slow.
    """
    topic = event.topic.strip().lower().replace("-", "_")
    if topic.startswith("task.") and topic.rsplit(".", 1)[-1] in _TERMINAL_TASK_STATES:
        return True

    if event.event_type != EventType.TASK:
        return False
    for key in ("status", "task_status", "final_status"):
        value = event.payload.get(key)
        normalized = str(getattr(value, "value", value) or "").strip().lower().replace("-", "_")
        if normalized in _TERMINAL_TASK_STATES:
            return True
    return False


class EventStreamQueue:
    """A bounded non-blocking queue used by live SSE consumers.

    When full, the queue drops the oldest non-terminal event and reports the
    number dropped as a synthetic stream.overflow notice. Terminal task
    events are retained; if the ordinary buffer contains only terminal events,
    one latest terminal event is kept in a dedicated bounded slot.
    """

    def __init__(self, correlation_id: str, maxsize: int = DEFAULT_EVENT_QUEUE_SIZE) -> None:
        if isinstance(maxsize, bool) or not isinstance(maxsize, int) or maxsize < 1:
            raise ValueError("Event stream queue maxsize must be a positive integer.")
        self.correlation_id = correlation_id
        self.maxsize = maxsize
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=maxsize)
        self._dropped_events = 0
        self._pending_terminal: Event | None = None

    def offer(self, event: Event) -> bool:
        """Offer an event without awaiting; return False when it was dropped."""
        if not self._queue.full():
            self._queue.put_nowait(event)
            return True

        buffered: list[Event] = []
        while not self._queue.empty():
            buffered.append(self._queue.get_nowait())
            self._queue.task_done()

        # Discard the oldest non-terminal update to preserve newer state.
        drop_index = next(
            (
                index
                for index, queued_event in enumerate(buffered)
                if not _is_terminal_task_event(queued_event)
            ),
            None,
        )
        if drop_index is not None:
            buffered.pop(drop_index)
            self._dropped_events += 1
            for queued_event in buffered:
                self._queue.put_nowait(queued_event)
            self._queue.put_nowait(event)
            return True

        # The queue is entirely made of terminal events. Never replace those
        # with routine telemetry; retain the newest terminal event separately.
        for queued_event in buffered:
            self._queue.put_nowait(queued_event)
        if _is_terminal_task_event(event):
            if self._pending_terminal is not None:
                self._dropped_events += 1
            self._pending_terminal = event
            return True

        self._dropped_events += 1
        return False

    def qsize(self) -> int:
        """Return the number of events in the bounded primary buffer."""
        return self._queue.qsize()

    def full(self) -> bool:
        return self._queue.full()

    def empty(self) -> bool:
        return self._dropped_events == 0 and self._pending_terminal is None and self._queue.empty()

    def get_nowait(self) -> Event:
        """Return the next event, prioritizing an explicit overflow notice."""
        if self._dropped_events:
            dropped = self._dropped_events
            self._dropped_events = 0
            logger.warning(
                "Task event stream overflow; events were dropped",
                extra={"correlation_id": self.correlation_id, "dropped_events": dropped},
            )
            return Event(
                event_id=f"evt-{uuid.uuid4().hex[:12]}",
                event_type=EventType.STATUS,
                topic="stream.overflow",
                source="sentinel.event_bus",
                payload={
                    "kind": "overflow",
                    "dropped_events": dropped,
                    "recovery_hint": "Refresh task status, findings, and report to obtain a current snapshot.",
                },
                correlation_id=self.correlation_id,
                timestamp=datetime.now(UTC),
            )

        try:
            event = self._queue.get_nowait()
        except asyncio.QueueEmpty:
            if self._pending_terminal is not None:
                event = self._pending_terminal
                self._pending_terminal = None
                return event
            raise
        self._queue.task_done()
        return event

    async def get(self) -> Event:
        """Await the next event, using the same semantics as asyncio.Queue."""
        try:
            return self.get_nowait()
        except asyncio.QueueEmpty:
            event = await self._queue.get()
            self._queue.task_done()
            return event


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

    def __init__(
        self,
        max_history: int = 10000,
        max_queue_size: int = DEFAULT_EVENT_QUEUE_SIZE,
    ):
        if isinstance(max_queue_size, bool) or not isinstance(max_queue_size, int) or max_queue_size < 1:
            raise ValueError("max_queue_size must be a positive integer.")
        self._max_queue_size = max_queue_size
        self._subscribers: dict[str, list[EventListener]] = defaultdict(list)
        self._global_subscribers: list[EventListener] = []
        self._history: list[Event] = []
        self._max_history = max_history
        self._lock = asyncio.Lock()
        self._queues: dict[str, list[EventStreamQueue]] = defaultdict(list)

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

        # Offer to active stream queues without back-pressuring producers.
        # Queues are bounded and expose any loss to their consumers explicitly.
        for queue in tuple(self._queues.get(event.correlation_id, ())):
            queue.offer(event)

        # Asynchronously record in durable EventRepository
        asyncio.create_task(self._safe_persist(event))

    async def _safe_persist(self, event: Event) -> None:
        try:
            from sentinel.storage.repositories.factory import get_event_repository

            repo = get_event_repository()
            await repo.save_event(event)
        except Exception as exc:
            logger.debug("Event persistence omitted or failed: %s", exc)

    async def _safe_dispatch(self, listener: EventListener, event: Event) -> None:
        try:
            await listener(event)
        except Exception as exc:
            # Keep one broken consumer from blocking other listeners, but make
            # the lost delivery visible without logging event payloads.
            logger.error(
                "Event listener failed; delivery was not confirmed",
                extra={
                    "event_id": event.event_id,
                    "event_topic": event.topic,
                    "listener": getattr(listener, "__qualname__", type(listener).__name__),
                    "error_type": type(exc).__name__,
                },
            )

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

    def register_queue(
        self,
        correlation_id: str,
        maxsize: int | None = None,
    ) -> EventStreamQueue:
        """Create a bounded dedicated event queue for SSE / stream consumers."""
        q = EventStreamQueue(correlation_id, self._max_queue_size if maxsize is None else maxsize)
        self._queues[correlation_id].append(q)
        return q

    def unregister_queue(self, correlation_id: str, q: EventStreamQueue) -> None:
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
