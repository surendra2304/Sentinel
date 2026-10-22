"""Sentinel Command Policy.

Enforces argv-based execution allowlists and shell-metacharacter rejection.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CommandRule:
    executable: str
    subcommands: tuple[str, ...] = ()
    allow: bool = True
    network: bool = False
    destructive: bool = False


@dataclass(frozen=True, slots=True)
class CommandDecision:
    allowed: bool
    reason: str
    argv: tuple[str, ...] = ()
    risk: str = "low"
    network: bool = False


class CommandPolicy:
    """Argument-based allowlist; shell metacharacters are denied by default."""

    SHELL_META = frozenset([";", "&&", "||", "|", ">", ">>", "<", "$(", "`"])

    def __init__(self, rules: list[CommandRule] | None = None, *, allow_shell: bool = False):
        self.rules = rules or [
            CommandRule("python", ("-m",), True),
            CommandRule("python.exe", ("-m",), True),
            CommandRule("pytest", (), True),
            CommandRule("ruff", (), True),
            CommandRule("git", ("status", "diff", "show", "log"), True),
            CommandRule("rg", (), True),
            CommandRule("nmap", (), True, network=True),
        ]
        self.allow_shell = allow_shell

    def validate(self, argv: list[str], *, network_requested: bool = False) -> CommandDecision:
        if not argv or not all(isinstance(x, str) and x != "" for x in argv):
            return CommandDecision(False, "Command must be a non-empty argv list")
        if not self.allow_shell and any(
            meta in token or "\n" in token or "\r" in token
            for token in argv
            for meta in self.SHELL_META
        ):
            return CommandDecision(False, "Shell metacharacters are forbidden")
        exe = argv[0].split("/")[-1].split("\\")[-1]
        for rule in self.rules:
            if rule.executable != exe:
                continue
            if not rule.allow:
                return CommandDecision(False, f"Executable denied by policy: {exe}", risk="high")
            if rule.subcommands and not any(arg in rule.subcommands for arg in argv[1:2]):
                return CommandDecision(False, f"Subcommand denied for {exe}")
            if network_requested and not rule.network:
                return CommandDecision(False, f"Network access denied for {exe}", risk="high")
            return CommandDecision(
                True,
                "Command allowed",
                tuple(argv),
                "high" if rule.destructive else "low",
                rule.network,
            )
        return CommandDecision(False, f"Executable not allowlisted: {exe}", risk="high")

    def parse_shell_text(self, command: str) -> list[str]:
        if not self.allow_shell:
            raise ValueError("Shell parsing is disabled; provide argv explicitly")
        return shlex.split(command, posix=True)
