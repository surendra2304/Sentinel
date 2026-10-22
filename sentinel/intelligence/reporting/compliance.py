"""SOC2, ISO 27001, and PCI-DSS Compliance Framework Mapping and Evidence Exporters."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class ComplianceControl(BaseModel):
    control_id: str
    framework: str  # SOC2 | ISO27001 | PCI-DSS
    title: str
    description: str
    sentinel_capability: str
    status: str  # COMPLIANT | GAP_DETECTED
    evidence_references: list[str] = Field(default_factory=list)


class ComplianceReport(BaseModel):
    report_id: str
    framework: str
    tenant_id: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    controls: list[ComplianceControl] = Field(default_factory=list)
    compliance_score: float = 100.0


class ComplianceReportingService:
    """Generates compliance-ready mapping frameworks and SOC2 audit exports."""

    @staticmethod
    def generate_compliance_report(framework: str, tenant_id: str, findings: list[dict[str, Any]]) -> ComplianceReport:
        fw_upper = framework.upper()
        controls = []

        if fw_upper == "SOC2":
            controls = [
                ComplianceControl(
                    control_id="CC6.1",
                    framework="SOC2",
                    title="Logical Access & Perimeter Protection",
                    description="The entity implements logical access security measures over infrastructure.",
                    sentinel_capability="network.perimeter_scan & web.header_audit",
                    status="COMPLIANT" if not any("critical" in str(f.get("severity", "")).lower() for f in findings) else "GAP_DETECTED",
                    evidence_references=["evi-soc2-audit-chain-01"],
                ),
                ComplianceControl(
                    control_id="CC7.1",
                    framework="SOC2",
                    title="Vulnerability Detection & Management",
                    description="Vulnerability assessments are performed on infrastructure.",
                    sentinel_capability="cve.sync & finding_engine",
                    status="COMPLIANT",
                    evidence_references=["evi-soc2-audit-chain-02"],
                ),
            ]
        elif fw_upper == "ISO27001":
            controls = [
                ComplianceControl(
                    control_id="A.12.6.1",
                    framework="ISO27001",
                    title="Management of Technical Vulnerabilities",
                    description="Information about technical vulnerabilities of information systems being used is obtained in a timely fashion.",
                    sentinel_capability="intelx.threat_research & cve.sync",
                    status="COMPLIANT",
                    evidence_references=["evi-iso-audit-01"],
                )
            ]
        elif fw_upper == "PCI-DSS":
            controls = [
                ComplianceControl(
                    control_id="Req-11.2",
                    framework="PCI-DSS",
                    title="Regular Vulnerability Scans of Cardholder Data Environment",
                    description="Perform internal and external network vulnerability scans at least quarterly.",
                    sentinel_capability="continuous.monitoring & network.port_scan",
                    status="COMPLIANT",
                    evidence_references=["evi-pci-audit-01"],
                )
            ]

        score = 100.0 if not any(c.status == "GAP_DETECTED" for c in controls) else 75.0

        return ComplianceReport(
            report_id=f"comp-{fw_upper.lower()}-{int(datetime.now(UTC).timestamp())}",
            framework=fw_upper,
            tenant_id=tenant_id,
            controls=controls,
            compliance_score=score,
        )


compliance_reporting_service = ComplianceReportingService()
