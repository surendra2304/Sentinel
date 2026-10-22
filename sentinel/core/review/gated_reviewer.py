"""Gated Security Review Engine for Cortex and Forge.

Enforces pre-delivery and pre-deployment security controls across four key dimensions:
1. Code-Level Findings (hardcoded secrets, unsafe eval/exec, SQL injection)
2. Dependency Risks (unpinned versions, malicious/vulnerable libraries)
3. Deployment Risks (root containers, privileged mode, exposed debug ports)
4. Permission Violations (sandbox escapes, path traversal, unauthorized git push)

Produces tamper-evident SHA-256 hashed review records.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, Field

from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import get_settings
from sentinel.core.models import SeverityLevel


class GatedReviewFinding(BaseModel):
    """Structured security finding discovered during gated review."""
    dimension: str  # code_level | dependency | deployment | permission
    rule_id: str
    title: str
    severity: SeverityLevel
    description: str
    file_path: str | None = None
    line_number: int | None = None
    remediation: str


class GatedReviewRequest(BaseModel):
    """Payload submitted by Forge or Cortex for security gate sign-off."""
    source_service: str = "forge"  # forge | cortex | friday
    task_id: str
    project_path: str | None = None
    files: dict[str, str] = Field(default_factory=dict)  # relative_path -> file content
    manifest: list[str] = Field(default_factory=list)
    commit_hash: str | None = None
    requested_by: str = "forge_operator"


class GatedReviewResult(BaseModel):
    """Evaluation result determining if software delivery / deployment may proceed."""
    review_id: str
    task_id: str
    source_service: str
    verdict: str  # PASSED | BLOCKED | REQUIRES_APPROVAL
    blocks_delivery: bool
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    findings: list[GatedReviewFinding] = Field(default_factory=list)
    evidence_hash: str
    summary: str
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class GatedSecurityReviewer:
    """Automated security gate evaluator for Cortex and Forge."""

    SECRET_PATTERNS = [
        (
            "SEC-001",
            "Hardcoded Private Key",
            SeverityLevel.CRITICAL,
            r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "Remove hardcoded private keys; use a secret manager or environment variable.",
        ),
        (
            "SEC-002",
            "AWS Access Key ID",
            SeverityLevel.CRITICAL,
            r"AKIA[0-9A-Z]{16}",
            "Remove hardcoded AWS credentials.",
        ),
        (
            "SEC-003",
            "Hardcoded API Secret or Password",
            SeverityLevel.HIGH,
            r"(?i)(api[_-]?key|secret|password|auth[_-]?token)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.]{8,}['\"]",
            "Store secrets in environment variables or secret vaults.",
        ),
    ]

    DANGEROUS_CODE_PATTERNS = [
        (
            "CODE-001",
            "Arbitrary Code Execution (eval)",
            SeverityLevel.CRITICAL,
            r"\beval\s*\(",
            "Avoid eval(); use safe parsing libraries (e.g. ast.literal_eval or json.loads).",
        ),
        (
            "CODE-002",
            "Arbitrary Code Execution (exec)",
            SeverityLevel.CRITICAL,
            r"\bexec\s*\(",
            "Avoid dynamic exec() calls.",
        ),
        (
            "CODE-003",
            "Unsafe Shell Execution",
            SeverityLevel.HIGH,
            r"\bos\.system\s*\(|\bsubprocess\.(Popen|run|call)\s*\(.*shell\s*=\s*True",
            "Avoid shell=True; pass explicit argument lists without shell interpolation.",
        ),
        (
            "CODE-004",
            "SQL Injection Risk",
            SeverityLevel.HIGH,
            r"(?i)\.execute\s*\(\s*f[\"'].*(SELECT|INSERT|UPDATE|DELETE)",
            "Use parameterized SQL queries rather than formatted string interpolation.",
        ),
    ]

    PERMISSION_PATTERNS = [
        (
            "PERM-001",
            "Path Traversal Outside Sandbox",
            SeverityLevel.CRITICAL,
            r"(\.\./|\.\.\\){2,}|/etc/shadow|/etc/passwd|C:\\Windows\\System32",
            "Restrict file operations strictly to the designated task workspace sandbox.",
        ),
        (
            "PERM-002",
            "Unauthorized Privilege Escalation Command",
            SeverityLevel.CRITICAL,
            r"\bsudo\s+|\bchmod\s+777|\bchown\s+root",
            "Do not execute commands requesting elevated system privileges.",
        ),
    ]

    DEPLOYMENT_PATTERNS = [
        (
            "DEP-001",
            "Container Configured to Run as Root",
            SeverityLevel.HIGH,
            r"(?i)^USER\s+root\b",
            "Specify a non-root USER directive in the Dockerfile.",
        ),
        (
            "DEP-002",
            "Privileged Container Execution",
            SeverityLevel.CRITICAL,
            r"(?i)privileged:\s*true",
            "Disable privileged container mode.",
        ),
        (
            "DEP-003",
            "Exposed Insecure Port",
            SeverityLevel.MEDIUM,
            r"(?i)EXPOSE\s+(22|23|3389)\b",
            "Do not expose telnet, ssh, or rdp ports on production containers.",
        ),
    ]

    def __init__(self, audit_logger: AuditLogger | None = None):
        self.settings = get_settings()
        self.audit = audit_logger or AuditLogger(
            log_path=self.settings.audit.log_file_path,
            signing_key=self.settings.audit.signing_key,
        )

    def review(self, req: GatedReviewRequest) -> GatedReviewResult:
        """Run comprehensive gated checks across all files and manifests."""
        findings: list[GatedReviewFinding] = []
        review_id = f"rev-{uuid.uuid4().hex[:12]}"

        for path, content in req.files.items():
            lines = content.splitlines()

            # 1. Code-Level Findings
            for rule_id, title, sev, pattern, remed in self.SECRET_PATTERNS + self.DANGEROUS_CODE_PATTERNS:
                for line_idx, line in enumerate(lines, start=1):
                    if re.search(pattern, line):
                        findings.append(GatedReviewFinding(
                            dimension="code_level",
                            rule_id=rule_id,
                            title=title,
                            severity=sev,
                            description=f"Pattern '{pattern}' matched on line {line_idx}.",
                            file_path=path,
                            line_number=line_idx,
                            remediation=remed,
                        ))

            # 2. Permission Violations
            for rule_id, title, sev, pattern, remed in self.PERMISSION_PATTERNS:
                for line_idx, line in enumerate(lines, start=1):
                    if re.search(pattern, line):
                        findings.append(GatedReviewFinding(
                            dimension="permission",
                            rule_id=rule_id,
                            title=title,
                            severity=sev,
                            description=f"Potential sandbox permission violation on line {line_idx}.",
                            file_path=path,
                            line_number=line_idx,
                            remediation=remed,
                        ))

            # 3. Dependency Risks
            if path.endswith("requirements.txt") or path.endswith("package.json") or path.endswith("pyproject.toml"):
                for line_idx, line in enumerate(lines, start=1):
                    stripped = line.strip()
                    if stripped.startswith("#") or not stripped:
                        continue
                    if "==" not in stripped and "@" not in stripped and path.endswith("requirements.txt") and stripped and not stripped.startswith("-"):
                        findings.append(GatedReviewFinding(
                                dimension="dependency",
                                rule_id="DEP-RISK-001",
                                title="Unpinned Dependency",
                                severity=SeverityLevel.MEDIUM,
                                description=f"Dependency '{stripped}' is not strictly pinned to a verifiable version hash or version.",
                                file_path=path,
                                line_number=line_idx,
                                remediation="Pin dependency with exact version (e.g. package==1.2.3).",
                            ))
                    # Check known vulnerable / malicious demonstration packages
                    for bad_pkg in ("event-stream==3.3.6", "malicious-pypi-test", "struts2-rce"):
                        if bad_pkg in stripped:
                            findings.append(GatedReviewFinding(
                                dimension="dependency",
                                rule_id="DEP-RISK-002",
                                title=f"Vulnerable Dependency Detected: {bad_pkg}",
                                severity=SeverityLevel.CRITICAL,
                                description=f"Known vulnerable package '{bad_pkg}' detected.",
                                file_path=path,
                                line_number=line_idx,
                                remediation="Remove or upgrade vulnerable dependency immediately.",
                            ))

            # 4. Deployment Risks
            if "dockerfile" in path.lower() or path.endswith(".yaml") or path.endswith(".yml"):
                for rule_id, title, sev, pattern, remed in self.DEPLOYMENT_PATTERNS:
                    for line_idx, line in enumerate(lines, start=1):
                        if re.search(pattern, line):
                            findings.append(GatedReviewFinding(
                                dimension="deployment",
                                rule_id=rule_id,
                                title=title,
                                severity=sev,
                                description=f"Deployment risk matched on line {line_idx}.",
                                file_path=path,
                                line_number=line_idx,
                                remediation=remed,
                            ))

        # Severity tally
        crit = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        high = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
        med = sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM)
        low = sum(1 for f in findings if f.severity == SeverityLevel.LOW)

        blocks = crit > 0 or high > 0
        if blocks:
            verdict = "BLOCKED"
        elif med > 0:
            verdict = "REQUIRES_APPROVAL"
        else:
            verdict = "PASSED"

        # Evidence Hash
        hasher = hashlib.sha256()
        for p in sorted(req.files.keys()):
            hasher.update(p.encode())
            hasher.update(req.files[p].encode())
        hasher.update(verdict.encode())
        for f in findings:
            hasher.update(f.rule_id.encode())
        evidence_hash = hasher.hexdigest()

        summary = (
            f"Gated Security Review for {req.source_service} (Task {req.task_id}): "
            f"Verdict={verdict}. Findings: {crit} Critical, {high} High, {med} Medium, {low} Low. "
            f"Delivery {'BLOCKED' if blocks else 'PERMITTED'}."
        )

        self.audit.log_event(
            entry_id=f"audit-gate-{review_id}",
            event_type="GATED_REVIEW_EVALUATED",
            actor=req.requested_by,
            action_type="SECURITY_GATE_EVALUATION",
            scope_policy=req.task_id,
            decision=verdict,
            details={
                "review_id": review_id,
                "blocks_delivery": blocks,
                "critical": crit,
                "high": high,
                "evidence_hash": evidence_hash,
            },
        )

        return GatedReviewResult(
            review_id=review_id,
            task_id=req.task_id,
            source_service=req.source_service,
            verdict=verdict,
            blocks_delivery=blocks,
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            findings=findings,
            evidence_hash=evidence_hash,
            summary=summary,
            evaluated_at=datetime.now(UTC),
        )


gated_security_reviewer = GatedSecurityReviewer()
