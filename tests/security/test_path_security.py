
import pytest

from sentinel.core.security.path_guard import PathViolation, SafePath


def test_path_within_root(tmp_path):
    guard = SafePath(tmp_path)
    safe = guard.resolve("subdir/file.txt")
    assert str(safe).startswith(str(tmp_path))

def test_path_traversal_dot_dot_blocked(tmp_path):
    guard = SafePath(tmp_path)
    with pytest.raises(PathViolation):
        guard.resolve("../../etc/passwd")

def test_path_sibling_prefix_blocked(tmp_path):
    root = tmp_path / "sandbox"
    root.mkdir()
    sibling = tmp_path / "sandbox_escape"
    sibling.mkdir()
    guard = SafePath(root)
    with pytest.raises(PathViolation):
        guard.resolve(sibling / "secret.txt")

def test_absolute_path_escape_blocked(tmp_path):
    guard = SafePath(tmp_path)
    with pytest.raises(PathViolation):
        guard.resolve("/etc/shadow")
