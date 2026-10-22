"""Regression tests for explicit ASGI load shedding under concurrent requests."""

import asyncio

import httpx
import pytest
from fastapi import FastAPI

from sentinel.apps.api.middleware import RequestCapacityMiddleware


@pytest.mark.asyncio
async def test_request_capacity_sheds_excess_work_but_reserves_health_capacity():
    app = FastAPI()
    work_started = asyncio.Event()
    release_work = asyncio.Event()

    @app.get("/work")
    async def work():
        work_started.set()
        await release_work.wait()
        return {"status": "complete"}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    limited_app = RequestCapacityMiddleware(
        app,
        max_concurrent_requests=1,
        max_health_requests=1,
    )
    transport = httpx.ASGITransport(app=limited_app)

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        active_work = asyncio.create_task(client.get("/work"))
        try:
            await asyncio.wait_for(work_started.wait(), timeout=2)

            excess_work = await client.get("/work")
            assert excess_work.status_code == 503
            assert excess_work.headers["retry-after"] == "1"
            assert excess_work.json()["error"] == "service_overloaded"

            health_response = await client.get("/health")
            assert health_response.status_code == 200
            assert health_response.json() == {"status": "ok"}
        finally:
            release_work.set()
            assert (await active_work).status_code == 200


@pytest.mark.asyncio
async def test_health_capacity_is_bounded_without_leaking_slots():
    app = FastAPI()
    health_started = asyncio.Event()
    release_health = asyncio.Event()

    @app.get("/health")
    async def health():
        health_started.set()
        await release_health.wait()
        return {"status": "ok"}

    limited_app = RequestCapacityMiddleware(
        app,
        max_concurrent_requests=1,
        max_health_requests=1,
    )
    transport = httpx.ASGITransport(app=limited_app)

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        active_health = asyncio.create_task(client.get("/health"))
        try:
            await asyncio.wait_for(health_started.wait(), timeout=2)

            excess_health = await client.get("/health")
            assert excess_health.status_code == 503
            assert excess_health.json()["error"] == "service_overloaded"
        finally:
            release_health.set()
            assert (await active_health).status_code == 200

        # The capacity token was released even after concurrent work completed.
        assert (await client.get("/health")).status_code == 200


def test_request_capacity_requires_positive_limits():
    with pytest.raises(ValueError, match="must be positive"):
        RequestCapacityMiddleware(FastAPI(), max_concurrent_requests=0)
    with pytest.raises(ValueError, match="must be positive"):
        RequestCapacityMiddleware(FastAPI(), max_health_requests=0)
