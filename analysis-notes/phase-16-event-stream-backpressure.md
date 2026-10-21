# Phase 16 — Bounded event-stream backpressure

**Date:** 2026-10-21  
**Scope:** Per-task in-process SSE event queues and the FRIDAY task-stream adapter.

## Finding

The event bus previously created an unbounded asyncio.Queue for every stream consumer and awaited queue writes from publish. A slow consumer could grow memory without limit and make event production wait on a consumer. The bounded event history did not constrain the per-consumer queues.

## Change

- Each stream queue now has a positive, configurable per-instance capacity (default 256 events).
- Event publication uses non-blocking offers. When full, it drops the oldest routine event and emits a synthetic stream.overflow notice describing the number dropped.
- A routine update cannot evict buffered terminal task events. A separate single terminal slot preserves the latest terminal event if the ordinary buffer contains only terminal events.
- The generic task SSE stream naturally surfaces stream.overflow; the FRIDAY stream maps it to stream_overflow and tells consumers to refresh task status, findings, and reports.
- Tests cover bounded capacity, non-blocking publish, drop accounting, terminal-event retention, consumer isolation, queue cleanup, invalid sizes, and FRIDAY overflow mapping.

## Verification boundary

The feature branch includes regression tests for CI. Source changes are not considered locally verified until CI reports success. This is still an in-process event bus; bounded queues do not provide durable replay or distributed fan-out. Consumers should resynchronize from task/status/report APIs after an overflow notice.
