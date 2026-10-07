"""Synthetic API pressure test restricted to the local loopback service.

Start Sentinel locally with API authentication enabled, then set
SENTINEL_PRESSURE_TEST_API_KEY to a disposable test key. This script never
accepts a target URL and never sends traffic to a non-loopback host.
"""

import argparse
import asyncio
import os
import statistics
import sys
import time
from collections import Counter
from dataclasses import dataclass

import httpx

BASE_URL = "http://127.0.0.1:8000"
MAX_REQUESTS = 10_000
MAX_CONCURRENCY = 1_000


@dataclass(frozen=True)
class PressureResult:
    label: str
    requested: int
    concurrency: int
    status_counts: dict[int, int]
    transport_errors: int
    p50_ms: float | None
    p95_ms: float | None
    elapsed_seconds: float


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


async def run_pressure(
    client: httpx.AsyncClient,
    *,
    label: str,
    path: str,
    request_count: int,
    concurrency: int,
    headers: dict[str, str] | None = None,
) -> PressureResult:
    semaphore = asyncio.Semaphore(concurrency)
    statuses: Counter[int] = Counter()
    timings: list[float] = []
    errors = 0

    async def make_request() -> None:
        nonlocal errors
        async with semaphore:
            started_at = time.perf_counter()
            try:
                response = await client.get(path, headers=headers)
            except httpx.HTTPError:
                errors += 1
                return
            timings.append((time.perf_counter() - started_at) * 1000)
            statuses[response.status_code] += 1

    started_at = time.perf_counter()
    await asyncio.gather(*(make_request() for _ in range(request_count)))
    elapsed = time.perf_counter() - started_at
    ordered = sorted(timings)
    p50 = statistics.median(ordered) if ordered else None
    p95 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))] if ordered else None
    return PressureResult(
        label=label,
        requested=request_count,
        concurrency=concurrency,
        status_counts=dict(sorted(statuses.items())),
        transport_errors=errors,
        p50_ms=p50,
        p95_ms=p95,
        elapsed_seconds=elapsed,
    )


def print_result(result: PressureResult) -> None:
    print(
        f"{result.label}: requested={result.requested} concurrency={result.concurrency} "
        f"statuses={result.status_counts} transport_errors={result.transport_errors} "
        f"p50_ms={result.p50_ms if result.p50_ms is not None else 'n/a'} "
        f"p95_ms={result.p95_ms if result.p95_ms is not None else 'n/a'} "
        f"elapsed_s={result.elapsed_seconds:.2f}"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--health-count", type=positive_int, default=2_000)
    parser.add_argument("--api-count", type=positive_int, default=1_000)
    parser.add_argument("--concurrency", type=positive_int, default=250)
    args = parser.parse_args()
    if args.health_count > MAX_REQUESTS or args.api_count > MAX_REQUESTS:
        parser.error(f"request counts must not exceed {MAX_REQUESTS}")
    if args.concurrency > MAX_CONCURRENCY:
        parser.error(f"concurrency must not exceed {MAX_CONCURRENCY}")
    return args


async def run(args: argparse.Namespace, api_key: str) -> int:
    limits = httpx.Limits(
        max_connections=args.concurrency,
        max_keepalive_connections=args.concurrency,
    )
    timeout = httpx.Timeout(45.0)
    async with httpx.AsyncClient(base_url=BASE_URL, limits=limits, timeout=timeout) as client:
        missing_key = await client.get("/api/v1/findings")
        invalid_key = await client.get(
            "/api/v1/findings",
            headers={"X-API-Key": "invalid-pressure-test-key"},
        )
        print(f"missing_key_status={missing_key.status_code}")
        print(f"invalid_key_status={invalid_key.status_code}")
        results = [
            await run_pressure(
                client,
                label="health",
                path="/health",
                request_count=args.health_count,
                concurrency=args.concurrency,
            ),
            await run_pressure(
                client,
                label="authenticated_findings",
                path="/api/v1/findings",
                request_count=args.api_count,
                concurrency=args.concurrency,
                headers={"X-API-Key": api_key},
            ),
        ]

    for result in results:
        print_result(result)

    unexpected = 0
    for result in results:
        expected = {200, 503} if result.label == "health" else {200, 429, 503}
        unexpected += sum(count for status, count in result.status_counts.items() if status not in expected)
        unexpected += result.transport_errors
    auth_preflight_failed = missing_key.status_code != 401 or invalid_key.status_code != 403
    return int(unexpected > 0 or auth_preflight_failed)


def main() -> int:
    args = parse_args()
    api_key = os.environ.get("SENTINEL_PRESSURE_TEST_API_KEY", "").strip()
    if not api_key:
        print("SENTINEL_PRESSURE_TEST_API_KEY must be set to a disposable local test key.", file=sys.stderr)
        return 2
    return asyncio.run(run(args, api_key))


if __name__ == "__main__":
    raise SystemExit(main())
