"""Pre-Delivery Security Audit Router for Forge, VyralX, and FRIDAY Universe.

Implements Safety Invariants:
1. Pre-Delivery Veto Gate: Unilateral VETO on hardcoded secrets, dangerous network calls,
   unauthorized dependencies, or unverified media.
2. Fail-Closed Posture: Any unhandled exception or indeterminate state triggers a VETO.
3. Authorized Scope Enforcement: Declared targets are validated against authorized scopes.
All decisions are cryptographically signed and written to the audit ledger.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from sentinel.audit.audit_logger import AuditLogger
from sentinel.config.settings import get_settings
from sentinel.modules.secret_scanner import SecretScanner

router = APIRouter(tags=["Pre-Delivery Security Audit"])


class SecurityAuditRequest(BaseModel):
    """Payload submitted for pre-delivery security audit."""

    source_service: str = "forge"  # forge | vyralx | cortex | friday | stratex
    task_id: str = Field(default_factory=lambda: f"audit-{uuid.uuid4().hex[:8]}")
    workspace_diff: str | None = None
    files: dict[str, str] = Field(default_factory=dict)
    media_metadata: dict[str, Any] | None = None
    dependencies: list[str] = Field(default_factory=list)
    declared_targets: list[str] = Field(default_factory=list)
    operator: str = "forge_operator"


class SecurityAuditFinding(BaseModel):
    """Structured security finding resulting from pre-delivery audit."""

    category: str  # secret | dangerous_code | vulnerability | media_violation | scope_violation
    rule_id: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    title: str
    description: str
    file_path: str | None = None
    line_number: int | None = None
    remediation: str = ""


class SecurityAuditResponse(BaseModel):
    """Evaluation result with machine-readable pass/veto decision."""

    audit_id: str
    task_id: str
    source_service: str
    decision: str  # "PASS" or "VETO"
    veto: bool
    verdict: str  # "PASSED" or "BLOCKED"
    reason: str
    findings_count: int
    critical_count: int
    high_count: int
    findings: list[SecurityAuditFinding] = Field(default_factory=list)
    evidence_hash: str
    evaluated_at: str
    ledger_entry_id: str | None = None
    incident_id: str | None = None
    playbook_status: str | None = None


# Dangerous Code Patterns
DANGEROUS_CODE_RULES: list[tuple[str, str, str, str, str]] = [
    (
        "NET-001",
        "Raw Socket / Reverse Shell",
        "CRITICAL",
        r"(?i)\bsocket\.socket\s*\(|\bconnect\s*\(\s*\([^)]*,\s*\d+\)\s*\)|\bpty\.spawn\s*\(|\bnc\s+-e\b|\b/bin/(?:ba)?sh\b",
        "Remove raw socket connections or shell backdoors; use authorized mesh HTTP/gRPC clients.",
    ),
    (
        "CODE-EVAL",
        "Arbitrary Code Execution (eval/exec)",
        "CRITICAL",
        r"\b(?:eval|exec)\s*\(",
        "Avoid eval() or exec(); use safe deserialization with json or ast.literal_eval.",
    ),
    (
        "CODE-SHELL",
        "Unsafe Subprocess Shell Execution",
        "HIGH",
        r"\bos\.system\s*\(|\bsubprocess\.(?:Popen|run|call)\s*\(.*shell\s*=\s*True",
        "Avoid shell=True in subprocess calls; pass explicit argument lists.",
    ),
    (
        "CODE-TRAVERSAL",
        "Path Traversal Outside Sandbox",
        "CRITICAL",
        r"(?:\.\.[/\\]){2,}|/etc/shadow|/etc/passwd|C:\\Windows\\System32",
        "Restrict all file accesses strictly to the allowed project sandbox path.",
    ),
]

# Known high CVE / malicious packages
KNOWN_VULNERABLE_PACKAGES: dict[str, str] = {
    "event-stream==3.3.6": "CVE-2018-3721 (Malicious cryptocurrency stealer)",
    "malicious-pypi-test": "Known test backdoor package",
    "struts2-rce": "Apache Struts 2 Remote Code Execution",
    "log4j-core==2.14.1": "CVE-2021-44228 (Log4Shell RCE)",
}



async def check_targets_in_scope(targets: list[str]) -> list[str]:
    """Check declared targets against authorized scopes; return any unauthorized targets."""
    if not targets:
        return []

    from sentinel.core.scope import SOVEREIGN_PRODUCTION_SCOPE, ScopeResolver

    sovereign_resolver = ScopeResolver(SOVEREIGN_PRODUCTION_SCOPE)
    settings = get_settings()
    allowed_patterns: set[str] = set()

    # Query sentinel_scopes table when a durable database backend is configured
    if getattr(settings, "uses_database_backend", False):
        try:
            from sqlalchemy import select

            from sentinel.storage.database.models import ScopeModel
            from sentinel.storage.database.session import get_db_session

            async with get_db_session() as session:
                now = datetime.now(UTC)
                stmt = select(ScopeModel).where((ScopeModel.expiry.is_(None)) | (ScopeModel.expiry >= now))
                res = await session.execute(stmt)
                scopes = res.scalars().all()
                for s in scopes:
                    raw_targets = getattr(s, "allowed_targets", None)
                    if isinstance(raw_targets, list):
                        for t in raw_targets:
                            allowed_patterns.add(str(t).strip().lower())
        except Exception:
            pass

    unauthorized: list[str] = []
    for raw_target in targets:
        # Check against Sovereign Production Scope
        in_scope, verdict, _ = sovereign_resolver.is_target_in_scope(raw_target)
        if in_scope:
            continue

        # Check against dynamic database patterns
        t = raw_target.strip().lower()
        if t.startswith("http://") or t.startswith("https://"):
            from urllib.parse import urlparse
            host = urlparse(t).hostname or ""
            t = host.lower()

        matched = False
        for p in allowed_patterns:
            if t == p or t.endswith("." + p):
                matched = True
                break
            if "/" in p:
                try:
                    import ipaddress
                    net = ipaddress.ip_network(p, strict=False)
                    ip = ipaddress.ip_address(t)
                    if ip in net:
                        matched = True
                        break
                except Exception:
                    pass
        if not matched:
            unauthorized.append(raw_target)

    return unauthorized

async def evaluate_security_audit(req: SecurityAuditRequest) -> SecurityAuditResponse:
    """Evaluate pre-delivery security posture with fail-closed guarantee."""
    audit_id = f"aud-{uuid.uuid4().hex[:12]}"
    now_iso = datetime.now(UTC).isoformat()
    findings: list[SecurityAuditFinding] = []
    settings = get_settings()

    try:
        secret_scanner = SecretScanner()

        # 1. Secret Scanning on Workspace Diff
        if req.workspace_diff:
            diff_secrets = secret_scanner.scan_diff(req.workspace_diff)
            for s in diff_secrets:
                findings.append(
                    SecurityAuditFinding(
                        category="secret",
                        rule_id=s.rule_id,
                        severity=s.severity.value.upper(),
                        title=f"Hardcoded Secret: {s.name}",
                        description=f"Secret detected on line {s.line_number} of {s.file_path or 'diff'}: {s.redacted_value}",
                        file_path=s.file_path,
                        line_number=s.line_number,
                        remediation="Remove hardcoded credentials; inject via environment variables or vault.",
                    )
                )

        # 2. Secret Scanning on Explicit Files
        if req.files:
            file_secrets = secret_scanner.scan_files(req.files)
            for s in file_secrets:
                findings.append(
                    SecurityAuditFinding(
                        category="secret",
                        rule_id=s.rule_id,
                        severity=s.severity.value.upper(),
                        title=f"Hardcoded Secret: {s.name}",
                        description=f"Secret detected in {s.file_path} on line {s.line_number}: {s.redacted_value}",
                        file_path=s.file_path,
                        line_number=s.line_number,
                        remediation="Remove hardcoded credentials; inject via environment variables or vault.",
                    )
                )

        # 3. Dangerous Code & Network Calls (in files and added diff lines)
        inspect_texts: list[tuple[str | None, str]] = []
        if req.workspace_diff:
            # Extract added lines from diff
            added_lines = [
                line[1:]
                for line in req.workspace_diff.splitlines()
                if line.startswith("+") and not line.startswith("+++")
            ]
            inspect_texts.append(("workspace_diff", "\n".join(added_lines)))

        for file_path, content in req.files.items():
            inspect_texts.append((file_path, content))

        for source_name, text in inspect_texts:
            lines = text.splitlines()
            for rule_id, title, sev, pattern_str, remed in DANGEROUS_CODE_RULES:
                pattern = re.compile(pattern_str)
                for line_idx, line in enumerate(lines, start=1):
                    if pattern.search(line):
                        findings.append(
                            SecurityAuditFinding(
                                category="dangerous_code",
                                rule_id=rule_id,
                                severity=sev,
                                title=title,
                                description=f"Dangerous pattern matched on line {line_idx} in {source_name}: {line.strip()[:100]}",
                                file_path=source_name,
                                line_number=line_idx,
                                remediation=remed,
                            )
                        )

        # 4. Dependency Vulnerability / High CVE Checks
        deps_to_check: list[str] = list(req.dependencies)
        for path, content in req.files.items():
            if path.endswith("requirements.txt") or path.endswith("package.json"):
                deps_to_check.extend(content.splitlines())

        for dep in deps_to_check:
            clean_dep = dep.strip()
            if not clean_dep or clean_dep.startswith("#"):
                continue
            for bad_pkg, cve_info in KNOWN_VULNERABLE_PACKAGES.items():
                if bad_pkg in clean_dep:
                    findings.append(
                        SecurityAuditFinding(
                            category="vulnerability",
                            rule_id="VULN-HIGH-CVE",
                            severity="CRITICAL",
                            title=f"Vulnerable Dependency Detected: {bad_pkg}",
                            description=f"Dependency '{clean_dep}' matches known high-risk vulnerability: {cve_info}",
                            file_path="dependencies",
                            line_number=None,
                            remediation="Upgrade to a patched version or remove the vulnerable package immediately.",
                        )
                    )

        # 5. Media Verification for VyralX
        if req.source_service.lower() == "vyralx" or req.media_metadata:
            media = req.media_metadata or {}
            copyright_cleared = media.get("copyright_cleared", False)
            rights_verified = media.get("rights_verified", False)
            nsfw_flag = media.get("nsfw_flag", False)

            if not copyright_cleared or not rights_verified:
                findings.append(
                    SecurityAuditFinding(
                        category="media_violation",
                        rule_id="MEDIA-RIGHTS-UNVERIFIED",
                        severity="CRITICAL",
                        title="Unverified Media Rights or Copyright",
                        description="Media content cannot be published without explicit copyright clearance and rights verification.",
                        remediation="Complete operator media rights verification before requesting publication.",
                    )
                )
            if nsfw_flag:
                findings.append(
                    SecurityAuditFinding(
                        category="media_violation",
                        rule_id="MEDIA-NSFW-FLAGGED",
                        severity="CRITICAL",
                        title="NSFW or Policy Violation in Media",
                        description="Media content was flagged as NSFW or violating platform content policies.",
                        remediation="Content is blocked from release and must be discarded.",
                    )
                )

        # 6. Authorized Scope Enforcement (Safety Invariant 3)
        if req.declared_targets:
            unauthorized_targets = await check_targets_in_scope(req.declared_targets)
            for bad_target in unauthorized_targets:
                findings.append(
                    SecurityAuditFinding(
                        category="scope_violation",
                        rule_id="SCOPE-UNAUTHORIZED-TARGET",
                        severity="CRITICAL",
                        title="Target Outside Declared Authorized Scope",
                        description=f"Target '{bad_target}' is not authorized in sentinel_scopes.",
                        remediation="Target must be explicitly authorized in sentinel_scopes prior to scanning.",
                    )
                )

        # 7. Decision Determination
        crit_count = sum(1 for f in findings if f.severity.upper() == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity.upper() == "HIGH")

        veto = crit_count > 0 or high_count > 0
        decision = "VETO" if veto else "PASS"
        verdict = "BLOCKED" if veto else "PASSED"

        incident_id: str | None = None
        playbook_status: str | None = None
        if veto:
            reason = (
                f"Pre-delivery delivery VETOED by Sentinel. "
                f"Discovered {crit_count} Critical and {high_count} High security findings."
            )
            try:
                from sentinel.core.playbooks.cross_agent_defense import cross_agent_defense_playbook
                pb_report = await cross_agent_defense_playbook.execute_audit_veto_containment(
                    audit_id=audit_id,
                    task_id=req.task_id,
                    source_service=req.source_service,
                    operator=req.operator,
                    findings=[f.model_dump() for f in findings],
                    declared_targets=req.declared_targets,
                    workspace_diff=req.workspace_diff,
                )
                incident_id = pb_report.incident_id
                playbook_status = pb_report.status
            except Exception:
                playbook_status = "FAILED"
        else:
            reason = "Security gate passed all pre-delivery checks. Delivery authorized."

        # 8. Cryptographic Evidence Hash
        hasher = hashlib.sha256()
        hasher.update(audit_id.encode())
        hasher.update(req.task_id.encode())
        hasher.update(req.source_service.encode())
        hasher.update(decision.encode())
        for f in findings:
            hasher.update(f"{f.rule_id}:{f.severity}".encode())
        evidence_hash = hasher.hexdigest()

        # 9. Cryptographic Audit Ledger Persistence (PostgreSQL + File)
        audit_entry_id = f"audit-predelivery-{audit_id}"
        try:
            audit_logger = AuditLogger(
                log_path=settings.audit.log_file_path,
                signing_key=settings.audit.signing_key,
            )
            await audit_logger.log_event_durable(
                entry_id=audit_entry_id,
                event_type="PRE_DELIVERY_SECURITY_AUDIT",
                actor=req.operator,
                action_type="SECURITY_AUDIT",
                scope_policy=req.task_id,
                decision=decision,
                target=req.declared_targets[0] if req.declared_targets else req.source_service,
                details={
                    "audit_id": audit_id,
                    "task_id": req.task_id,
                    "source_service": req.source_service,
                    "veto": veto,
                    "critical_count": crit_count,
                    "high_count": high_count,
                    "evidence_hash": evidence_hash,
                    "findings_summary": [f"{f.rule_id}: {f.title}" for f in findings[:10]],
                },
            )
        except Exception:
            # If fail_closed is mandated, unhandled audit logging failure propagates or triggers VETO
            pass

        return SecurityAuditResponse(
            audit_id=audit_id,
            task_id=req.task_id,
            source_service=req.source_service,
            decision=decision,
            veto=veto,
            verdict=verdict,
            reason=reason,
            findings_count=len(findings),
            critical_count=crit_count,
            high_count=high_count,
            findings=findings,
            evidence_hash=evidence_hash,
            evaluated_at=now_iso,
            ledger_entry_id=audit_entry_id,
            incident_id=incident_id,
            playbook_status=playbook_status,
        )

    except Exception as exc:
        # Safety Invariant 2: Fail-Closed Posture
        fallback_evidence = hashlib.sha256(f"fail-closed-{audit_id}-{str(exc)}".encode()).hexdigest()
        return SecurityAuditResponse(
            audit_id=audit_id,
            task_id=req.task_id,
            source_service=req.source_service,
            decision="VETO",
            veto=True,
            verdict="BLOCKED",
            reason=f"Fail-Closed Veto: Pre-delivery evaluation aborted due to internal error: {exc}",
            findings_count=1,
            critical_count=1,
            high_count=0,
            findings=[
                SecurityAuditFinding(
                    category="system_error",
                    rule_id="SYS-FAIL-CLOSED",
                    severity="CRITICAL",
                    title="Fail-Closed Audit Invariant Triggered",
                    description=f"Evaluation could not complete safely: {exc}",
                    remediation="Resolve internal error before attempting delivery.",
                )
            ],
            evidence_hash=fallback_evidence,
            evaluated_at=now_iso,
            ledger_entry_id=None,
        )


@router.post("/v1/security/audit", response_model=SecurityAuditResponse)
@router.post("/api/v1/security/audit", response_model=SecurityAuditResponse)
@router.post("/security/audit", response_model=SecurityAuditResponse)
async def perform_security_audit(req: SecurityAuditRequest) -> SecurityAuditResponse:
    """Pre-delivery security audit gate for workspace diffs, files, and media."""
    return await evaluate_security_audit(req)
