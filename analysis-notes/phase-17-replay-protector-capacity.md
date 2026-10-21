# Phase 17 — Bounded replay-protection nonce state

**Date:** 2026-10-21

## Finding

The ingress replay protector retained nonces without a maximum capacity and rebuilt its full dictionary on each request. Since nonce validation runs before ingress rate limiting, a caller could force significant allocation and repeated full-cache scans even when later requests are rate-limited.

## Change

- Replaced wall-clock nonce retention with monotonic-time retention in insertion order; expiration prunes only entries that have expired, amortized O(1) per nonce rather than scanning the full cache on every request.
- Capped the default cache at 100,000 active nonce entries and rejects new nonces when full rather than evicting an active nonce that could then be replayed.
- Serialized the check-and-record path so concurrent duplicate requests cannot both claim a nonce.
- Bounded individual nonce length and rejected whitespace/control characters.
- Mapped a full replay cache to HTTP 503 with Retry-After: 1; normal replay conflicts and invalid timestamps retain their existing response categories.
- Added regression tests for full capacity, active nonce retention, monotonic expiry after wall-clock adjustment, malformed values, concurrency, and the ingress response.

## Limits

The nonce cache remains process-local. Multiple API workers still need shared replay state to enforce nonce uniqueness across workers. Capacity exhaustion intentionally fails closed until entries expire, so operators should size the bound for the deployment's burst rate and TTL. This change does not replace trusted identity or authorization validation.
