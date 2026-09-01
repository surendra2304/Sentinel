"""Test Git and Workspace Cleanliness Invariants.

Verifies:
1. No .pyc or __pycache__ directories are tracked by git.
2. Logs directory does not contain tracked .jsonl files.
"""

import subprocess


def test_git_tree_cleanliness_and_ignore_rules():
    result = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True)
    tracked_files = result.stdout.splitlines()

    tracked_pyc = [f for f in tracked_files if f.endswith(".pyc") or "__pycache__" in f]
    assert len(tracked_pyc) == 0, f"Tracked pyc files found in git: {tracked_pyc[:5]}"

    tracked_logs = [f for f in tracked_files if f.startswith("logs/") and f.endswith(".jsonl")]
    assert len(tracked_logs) == 0, f"Tracked log files found in git: {tracked_logs}"
