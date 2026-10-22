"""Artifact storage must never let a key escape its configured directory."""

import os

import pytest

from sentinel.storage.artifacts.storage import LocalFileSystemStorage


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "key",
    [
        "../escape.bin",
        "nested/../../escape.bin",
        r"..\escape.bin",
        r"nested\..\..\escape.bin",
        "/absolute/path.bin",
        r"C:\outside\path.bin",
    ],
)
async def test_local_artifact_storage_rejects_traversal_and_absolute_keys(tmp_path, key):
    storage = LocalFileSystemStorage(str(tmp_path / "artifacts"))

    with pytest.raises(ValueError, match="relative path contained"):
        await storage.store_artifact(key, b"must stay inside the store")
    with pytest.raises(ValueError, match="relative path contained"):
        await storage.get_artifact(key)
    with pytest.raises(ValueError, match="relative path contained"):
        await storage.exists(key)
    with pytest.raises(ValueError, match="relative path contained"):
        await storage.delete_artifact(key)

    # The classic POSIX traversal key would otherwise escape one directory up.
    assert not (tmp_path / "escape.bin").exists()


@pytest.mark.asyncio
@pytest.mark.skipif(
    os.name == "nt",
    reason="Creating directory symlinks on Windows requires developer mode or elevation",
)
async def test_local_artifact_storage_rejects_symlink_escape(tmp_path):
    root = tmp_path / "artifacts"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "linked").symlink_to(outside, target_is_directory=True)
    storage = LocalFileSystemStorage(str(root))

    with pytest.raises(ValueError, match="relative path contained"):
        await storage.store_artifact("linked/escaped.bin", b"must not cross symlink")
    with pytest.raises(ValueError, match="relative path contained"):
        await storage.get_artifact("linked/escaped.bin")
    with pytest.raises(ValueError, match="relative path contained"):
        await storage.exists("linked/escaped.bin")
    with pytest.raises(ValueError, match="relative path contained"):
        await storage.delete_artifact("linked/escaped.bin")

    assert not (outside / "escaped.bin").exists()
