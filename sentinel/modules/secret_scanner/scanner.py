"""High-entropy, pattern-based secret and credential scanner."""

from __future__ import annotations

import re
from collections.abc import Sequence

from pydantic import BaseModel

from sentinel.core.models import SeverityLevel
from sentinel.modules.secret_scanner.entropy import calculate_shannon_entropy
from sentinel.modules.secret_scanner.patterns import SECRET_PATTERNS, SecretPattern


class SecretFinding(BaseModel):
    """Structured finding representing an exposed secret or credential."""

    rule_id: str
    name: str
    severity: SeverityLevel
    matched_text: str
    redacted_value: str
    line_number: int | None = None
    file_path: str | None = None
    entropy: float = 0.0
    description: str = ""


class SecretScanner:
    """Detects and redacts credentials, API keys, and private keys in code and diffs."""

    def __init__(self, patterns: Sequence[SecretPattern] | None = None):
        self.patterns = list(patterns or SECRET_PATTERNS)

    def _redact_token(self, token: str) -> str:
        """Create a safe redacted representation preserving prefix/suffix hint."""
        if len(token) <= 8:
            return "[REDACTED_SECRET]"
        prefix = token[:4]
        suffix = token[-4:]
        return f"{prefix}...[REDACTED]...{suffix}"

    def scan_text(
        self,
        text: str,
        filename: str | None = None,
    ) -> list[SecretFinding]:
        """Scan a raw string or file content for exposed secrets."""
        findings: list[SecretFinding] = []
        if not text:
            return findings

        lines = text.splitlines()
        for pattern in self.patterns:
            for line_idx, line in enumerate(lines, start=1):
                # Ignore comment lines that explicitly label as dummy/mock/example in test files
                lower_line = line.lower()
                if any(x in lower_line for x in ("example", "dummy", "placeholder", "your_api_key_here")) and "test" in (filename or "").lower():
                    continue

                for match in pattern.pattern.finditer(line):
                    matched_str = match.group(1) if match.groups() else match.group(0)
                    entropy = calculate_shannon_entropy(matched_str)

                    # Validate minimum entropy threshold if pattern requires it
                    if pattern.min_entropy > 0 and entropy < pattern.min_entropy:
                        continue

                    findings.append(
                        SecretFinding(
                            rule_id=pattern.rule_id,
                            name=pattern.name,
                            severity=pattern.severity,
                            matched_text=matched_str,
                            redacted_value=self._redact_token(matched_str),
                            line_number=line_idx,
                            file_path=filename,
                            entropy=entropy,
                            description=pattern.description,
                        )
                    )
        return findings

    def scan_files(self, files: dict[str, str]) -> list[SecretFinding]:
        """Scan a mapping of relative file paths to file contents."""
        all_findings: list[SecretFinding] = []
        for file_path, content in files.items():
            all_findings.extend(self.scan_text(content, filename=file_path))
        return all_findings

    def scan_diff(self, diff_content: str) -> list[SecretFinding]:
        """Parse a unified git diff and inspect newly added lines ('+') for secrets.

        Tracks exact target file paths and line numbers in the new file.
        """
        findings: list[SecretFinding] = []
        if not diff_content:
            return findings

        current_file: str | None = None
        current_new_line = 0

        # Regex for diff header: +++ b/path/to/file or +++ /dev/null
        new_file_re = re.compile(r"^\+\+\+\s+(?:b/)?(.+)$")
        # Regex for hunk header: @@ -10,5 +15,10 @@
        hunk_re = re.compile(r"^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@")

        for line in diff_content.splitlines():
            # Check for file header
            file_match = new_file_re.match(line)
            if file_match:
                candidate = file_match.group(1).strip()
                current_file = candidate if candidate != "/dev/null" else None
                continue

            # Check for hunk header
            hunk_match = hunk_re.match(line)
            if hunk_match:
                current_new_line = int(hunk_match.group(1)) - 1
                continue

            # Check if this line is an addition (starts with '+', but not '+++')
            if line.startswith("+") and not line.startswith("+++"):
                current_new_line += 1
                added_code = line[1:]  # strip the '+' prefix

                for pattern in self.patterns:
                    for match in pattern.pattern.finditer(added_code):
                        matched_str = match.group(1) if match.groups() else match.group(0)
                        entropy = calculate_shannon_entropy(matched_str)

                        if pattern.min_entropy > 0 and entropy < pattern.min_entropy:
                            continue

                        findings.append(
                            SecretFinding(
                                rule_id=pattern.rule_id,
                                name=pattern.name,
                                severity=pattern.severity,
                                matched_text=matched_str,
                                redacted_value=self._redact_token(matched_str),
                                line_number=current_new_line,
                                file_path=current_file,
                                entropy=entropy,
                                description=pattern.description,
                            )
                        )
            elif not line.startswith("-"):
                # Context line (unchanged)
                current_new_line += 1

        return findings

    def redact(self, text: str) -> str:
        """Replace all detected secret tokens in text with redacted strings."""
        if not text:
            return text

        result = text
        for pattern in self.patterns:
            matches = list(pattern.pattern.finditer(result))
            # Reverse iterate matches so indices remain valid
            for match in reversed(matches):
                matched_str = match.group(1) if match.groups() else match.group(0)
                entropy = calculate_shannon_entropy(matched_str)
                if pattern.min_entropy > 0 and entropy < pattern.min_entropy:
                    continue
                redacted = self._redact_token(matched_str)
                start, end = match.span(1 if match.groups() else 0)
                result = result[:start] + redacted + result[end:]

        return result
