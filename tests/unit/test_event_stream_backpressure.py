"""Regression tests for bounded event-stream queues and overflow signaling."""

import asyncio

import pytest

from sentinel.core.events.bus import InMemoryEventBus
from sentinel.core.models import Event, EventType


def make_event(
    topic: str,
    *,
    correlation_id: str = "correlation-1",
    payload: dict | None = None,
    event_type: EventType = EventType.STATUS,
) -> Event:
    return Event(
        event_id=f"test-{topic}-{id(payload)}",
        event_type=event_type,
        topic=topic,
        source="tests",
        payload=payload or {},
        correlation_id=correlation_id,
    )


@pytest.mark.asyncio
async def test_event_queue_is_bounded_and_overflow_is_reported_without_backpressure():
    bus = InMemoryEventBus(max_queue_size=2)
    queue = bus.register_queue("correlation-1")

    for index in range(10):
        await asyncio.wait_for(
            bus.publish(make_event("task.progress", payload={"index": index})),
            timeout=0.1,
        )

    assert queue.qsize() == 2
    notice = await queue.get()
    assert notice.topic == "stream.overflow"
    assert notice.payload["dropped_events"] == 8
    assert "recovery_hint" in notice.payload

    remaining = [await queue.get(), await queue.get()]
    assert [event.payload["index"] for event in remaining] == [8, 9]


@pytest.mark.asyncio
async def test_terminal_task_event_survives_a_full_queue():
    bus = InMemoryEventBus(max_queue_size=2)
    queue = bus.register_queue("correlation-1")
    first = make_event("task.progress", payload={"index": 1})
    latest = make_event("task.progress", payload={"index": 2})
    terminal = make_event(
        "task.completed",
        event_type=EventType.TASK,
        payload={"status": "completed"},
    )

    for event in (first, latest, terminal):
        await bus.publish(event)

    assert queue.qsize() == 2
    notice = await queue.get()
    assert notice.topic == "stream.overflow"
    received = [await queue.get(), await queue.get()]
    assert received[0].event_id == latest.event_id
    assert received[1].event_id == terminal.event_id


@pytest.mark.asyncio
async def test_routine_event_cannot_evict_buffered_terminal_events():
    bus = InMemoryEventBus(max_queue_size=2)
    queue = bus.register_queue("correlation-1")
    terminal_events = [
        make_event("task.completed", event_type=EventType.TASK, payload={"status": "completed"}),
        make_event("task.failed", event_type=EventType.TASK, payload={"status": "failed"}),
    ]
    for event in terminal_events:
        await bus.publish(event)

    accepted = queue.offer(make_event("task.progress", payload={"index": 1}))
    assert accepted is False
    assert queue.qsize() == 2

    assert (await queue.get()).payload["dropped_events"] == 1
    received = [await queue.get(), await queue.get()]
    assert [event.event_id for event in received] == [e.event_id for e in terminal_events]


@pytest.mark.asyncio
async def test_new_terminal_event_has_reserved_slot_when_queue_contains_only_terminals():
    bus = InMemoryEventBus(max_queue_size=1)
    queue = bus.register_queue("correlation-1")
    earlier = make_event("task.completed", event_type=EventType.TASK, payload={"status": "completed"})
    latest = make_event("task.failed", event_type=EventType.TASK, payload={"status": "failed"})

    await bus.publish(earlier)
    await bus.publish(latest)

    assert queue.qsize() == 1
    assert (await queue.get()).event_id == earlier.event_id
    assert (await queue.get()).event_id == latest.event_id


def test_queue_registration_and_validation():
    with pytest.raises(ValueError, match="positive integer"):
        InMemoryEventBus(max_queue_size=0)

    bus = InMemoryEventBus(max_queue_size=4)
    with pytest.raises(ValueError, match="positive integer"):
        bus.register_queue("correlation-1", maxsize=0)

    queue = bus.register_queue("correlation-1")
    bus.unregister_queue("correlation-1", queue)
    assert "correlation-1" not in bus._queues


@pytest.mark.asyncio
async def test_stream_overflow_isolated_to_slow_consumer():
    bus = InMemoryEventBus(max_queue_size=2)
    slow = bus.register_queue("correlation-1")
    fast = bus.register_queue("correlation-1")

    observed = []
    for index in range(5):
        event = make_event("task.progress", payload={"index": index})
        await bus.publish(event)
        observed.append(await fast.get())

    assert [event.payload["index"] for event in observed] == list(range(5))
    assert slow.qsize() == 2
    assert (await slow.get()).payload["dropped_events"] == 3


def test_friday_stream_overflow_mapping_is_explicit_and_recoverable():
    from sentinel.apps.api.main import _map_friday_stream_event

    event = make_event(
        "stream.overflow",
        payload={"kind": "overflow", "dropped_events": 3},
    )
    mapped = _map_friday_stream_event(event, task_id="task-123")

    assert mapped.event_type == "stream_overflow"
    assert mapped.task_id == "task-123"
    assert "3 event(s)" in mapped.reason
    assert "Refresh task status" in mapped.reason
    assert "unchanged" in mapped.summary
