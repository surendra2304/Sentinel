# Technical Security Assessment & Penetration Testing Report

**Task Reference**: `{{ report.task_id }}`  
**Generated At**: `{{ report.generated_at }}`  
**Composite Risk Posture**: `{{ report.overall_risk_score }} / 10.0`

---

## 1. Scope & Engagement Authorization Statement
This assessment was executed strictly under authorized parameters. Every executed action was validated against the Sentinel Scope and Policy Engine before invocation.

---

## 2. Technical Findings & Cryptographic Evidence
{% for finding in report.findings %}
### {{ loop.index }}. [{{ finding.severity.value | upper }}] {{ finding.title }}
- **Affected Asset / Target**: `{{ finding.target_ref }}`
- **Confidence Rating**: `{{ finding.confidence * 100 }}%`
- **Description**: {{ finding.description }}
{% if finding.related_cves %}
- **CVE References**: `{{ finding.related_cves | join(', ') }}`
{% endif %}
- **Evidence References (SHA-256 Verified)**: `{{ finding.evidence_refs | join(', ') }}`
- **Remediation & Retest Guidance**: {{ finding.remediation }}

---
{% endfor %}

## 3. Prioritized Verification & Retest Matrix
{% for rec in report.recommendations %}
- **[{{ rec.priority }}] {{ rec.title }}**
  - **Remediation Action**: {{ rec.action_plan }}
  - **Automated Validation Check**: `{{ rec.verification_check_action }}`
{% endfor %}
