# Phase 18 — Bounded rate-limit identity state

**Date:** 2026-10-21

## Finding

Rate limiting used a dictionary keyed by API identity or client IP with cleanup only for the identity on the current request. Old identity buckets therefore remained allocated indefinitely, and unauthenticated client churn could grow the map.

## Change

- Added a configurable per-instance identity cap (default 10,000 buckets) and positive finite validation for limits and windows.
- Switched sliding-window timestamps to a monotonic clock.
- Added periodic expiry sweeps and rate-limited capacity sweeps; active identities are not evicted to allocate a new slot.
- When all identity slots are active, new identities are denied without inserting a bucket. Capacity-triggered full sweeps are throttled so random-identity floods do not cause an O(capacity) scan for every denied request.
- Serialized rate-limit admission and cleanup for concurrent calls.
- Added regression tests for identity churn, expiry, periodic cleanup, validation, per-identity independence, and preserved thresholds.

## Limits

The limiter remains process-local. This change bounds local state and prevents bucket churn from resetting active users' quotas, but it does not make quotas consistent across multiple API workers or replicas. The API maps capacity exhaustion to the existing rate-limit rejection response because the middleware currently exposes a boolean limiter contract.
