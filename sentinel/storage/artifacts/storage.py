"""Storage abstraction for Sentinel evidence and raw artifacts."""

import hashlib
import os
from abc import ABC, abstractmethod
from typing import Any

import aiofiles
import aiofiles.os

from sentinel.config.settings import get_settings


class ArtifactStorage(ABC):
    """Abstract interface for artifact and evidence blob storage."""

    @abstractmethod
    async def store_artifact(
        self,
        key: str,
        data: bytes | bytearray,
        content_type: str = "application/octet-stream",
        metadata: dict[str, str] | None = None,
    ) -> tuple[str, str]:
        """Store artifact data. Returns (storage_uri, sha256_hash)."""
        pass

    @abstractmethod
    async def get_artifact(self, key: str) -> bytes:
        """Retrieve raw artifact bytes by key."""
        pass

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if an artifact exists."""
        pass

    @abstractmethod
    async def delete_artifact(self, key: str) -> bool:
        """Delete an artifact by key."""
        pass


class LocalFileSystemStorage(ArtifactStorage):
    """Local filesystem storage implementation with SHA-256 integrity verification."""

    def __init__(self, base_dir: str = "data/artifacts"):
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)

    def _resolve_path(self, key: str) -> str:
        clean_key = key.lstrip("/\\")
        return os.path.join(self.base_dir, clean_key)

    async def store_artifact(
        self,
        key: str,
        data: bytes | bytearray,
        content_type: str = "application/octet-stream",
        metadata: dict[str, str] | None = None,
    ) -> tuple[str, str]:
        sha256 = hashlib.sha256(data).hexdigest()
        file_path = self._resolve_path(key)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        async with aiofiles.open(file_path, "wb") as f:
            await f.write(data)

        storage_uri = f"file://{os.path.abspath(file_path).replace(os.sep, '/')}"
        return storage_uri, sha256

    async def get_artifact(self, key: str) -> bytes:
        file_path = self._resolve_path(key)
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Artifact not found at key: {key}")
        async with aiofiles.open(file_path, "rb") as f:
            content = await f.read()
            return bytes(content)

    async def exists(self, key: str) -> bool:
        return os.path.exists(self._resolve_path(key))

    async def delete_artifact(self, key: str) -> bool:
        file_path = self._resolve_path(key)
        if os.path.exists(file_path):
            await aiofiles.os.remove(file_path)
            return True
        return False


class MinIOObjectStorage(ArtifactStorage):
    """S3-compatible MinIO object storage provider."""

    def __init__(self):
        import io

        from minio import Minio

        self._io = io
        settings = get_settings()
        self.bucket = settings.storage.bucket_name
        self.client = Minio(
            endpoint=settings.storage.endpoint,
            access_key=settings.storage.access_key,
            secret_key=settings.storage.secret_key,
            secure=settings.storage.secure,
        )
        self._ensure_bucket()

    def _ensure_bucket(self) -> None:
        try:
            if not self.client.bucket_exists(self.bucket):
                self.client.make_bucket(self.bucket)
        except Exception:
            raise

    async def store_artifact(
        self,
        key: str,
        data: bytes | bytearray,
        content_type: str = "application/octet-stream",
        metadata: dict[str, str] | None = None,
    ) -> tuple[str, str]:
        sha256 = hashlib.sha256(data).hexdigest()
        stream = self._io.BytesIO(data)
        self.client.put_object(
            bucket_name=self.bucket,
            object_name=key,
            data=stream,
            length=len(data),
            content_type=content_type,
            metadata=metadata or {},
        )
        storage_uri = f"s3://{self.bucket}/{key}"
        return storage_uri, sha256

    async def get_artifact(self, key: str) -> bytes:
        response: Any = self.client.get_object(self.bucket, key)
        try:
            content = response.read()
            return bytes(content)
        finally:
            response.close()
            response.release_conn()

    async def exists(self, key: str) -> bool:
        try:
            self.client.stat_object(self.bucket, key)
            return True
        except Exception:
            return False

    async def delete_artifact(self, key: str) -> bool:
        try:
            self.client.remove_object(self.bucket, key)
            return True
        except Exception:
            return False


def get_artifact_storage() -> ArtifactStorage:
    """Factory creating appropriate storage provider based on environment."""
    try:
        storage = MinIOObjectStorage()
        return storage
    except Exception:
        return LocalFileSystemStorage()
