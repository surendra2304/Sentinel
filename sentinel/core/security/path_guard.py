"""Sentinel Path Guard.

Enforces strict canonical path security resistant to ../ traversal, sibling-prefix escapes,
absolute escapes, and symlink sandbox escapes using os.path.commonpath.
"""

from __future__ import annotations

import os
from pathlib import Path


class PathViolation(ValueError):
    """Raised when a path escapes the trusted sandbox root."""


class SafePath:
    """Canonical path enforcement resistant to sibling-prefix and symlink escapes."""

    def __init__(self, root: str | Path, *, allow_missing: bool = True):
        self.root = Path(root).expanduser().resolve(strict=False)
        self.allow_missing = allow_missing

    def resolve(self, candidate: str | Path) -> Path:
        """Resolve candidate path and verify it remains strictly within root."""
        cand_path = Path(candidate)
        if not cand_path.is_absolute():
            cand_path = self.root / cand_path
        resolved = cand_path.expanduser().resolve(strict=not self.allow_missing)
        try:
            common = Path(os.path.commonpath([str(self.root), str(resolved)]))
        except ValueError as exc:
            raise PathViolation("Cross-device or incompatible path") from exc
        if common != self.root:
            raise PathViolation(f"Path escapes sandbox root: {candidate}")
        return resolved

    def relative(self, candidate: str | Path) -> str:
        """Return canonical path relative to sandbox root."""
        return str(self.resolve(candidate).relative_to(self.root))

    def ensure_directory(self, candidate: str | Path) -> Path:
        """Create directory safely within sandbox root."""
        path = self.resolve(candidate)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def safe_open_target(self, candidate: str | Path) -> Path:
        """Verify that candidate (and its target if symlink) does not escape root."""
        path = self.resolve(candidate)
        if path.exists() and path.is_symlink():
            target = path.resolve(strict=True)
            if Path(os.path.commonpath([str(self.root), str(target)])) != self.root:
                raise PathViolation("Symlink target escapes sandbox")
        return path
