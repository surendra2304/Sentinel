"""Regression tests for object-storage metadata adaptation."""

import hashlib
import io
from typing import Any

import pytest

from sentinel.storage.artifacts.storage import MinIOObjectStorage


class FakeMinioClient:
    def __init__(self) -> None:
        self.put_arguments: dict[str, Any] = {}

    def put_object(self, **kwargs: Any) -> None:
        self.put_arguments = kwargs


@pytest.mark.asyncio
async def test_minio_artifact_store_preserves_string_metadata():
    storage = MinIOObjectStorage.__new__(MinIOObjectStorage)
    storage._io = io
    storage.bucket = "sentinel-test-bucket"
    client = FakeMinioClient()
    storage.client = client
    data = b"signed evidence payload"
    metadata = {"source": "security-test", "task-id": "task-local-test"}

    storage_uri, sha256 = await storage.store_artifact(
        "artifacts/example.bin",
        data,
        content_type="application/octet-stream",
        metadata=metadata,
    )

    assert storage_uri == "s3://sentinel-test-bucket/artifacts/example.bin"
    assert sha256 == hashlib.sha256(data).hexdigest()
    assert client.put_arguments["data"].read() == data
    assert client.put_arguments["metadata"] == metadata
