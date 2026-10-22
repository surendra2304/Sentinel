# Technical Security Assessment & Penetration Testing Report

**Task Reference**: `{{ report.task_id }}`  
**Generated At**: `{{ report.generated_at }}`  
**Composite Risk Posture**: `{{ report.overall_risk_score }} / 10.0`

---

## Table of Contents
1. [Scope & Engagement Authorization Statement](#1-scope--engagement-authorization-statement)
2. [Technical Findings & Cryptographic Evidence](#2-technical-findings--cryptographic-evidence)
3. [Prioritized Verification & Retest Matrix](#3-prioritized-verification--retest-matrix)
4. [Appendix: Cryptographic Evidence Index](#4-appendix-cryptographic-evidence-index)

---

## 1. Scope & Engagement Authorization Statement
This assessment was executed strictly under authorized parameters. Every executed action was validated against the Sentinel Scope and Policy Engine before invocation.

---

## 2. Technical Findings & Cryptographic Evidence
{% for finding in report.findings %}
### {{ loop.index }}. [{{ (finding.severity.value if finding.severity.value is defined else finding.severity) | upper }} (Confidence: {{ (finding.confidence * 100) | round | int }}%)] {{ finding.title }}
- **Affected Asset / Target**: `{{ finding.target_ref }}`
- **Severity Rating**: `{{ (finding.severity.value if finding.severity.value is defined else finding.severity) | upper }} ({{ (finding.confidence * 100) | round | int }}% Confidence)`
- **Description**: {{ finding.description }}
{% if finding.related_cves %}
- **CVE References**: `{{ finding.related_cves | join(', ') }}`
{% endif %}
- **Evidence References (SHA-256 Verified)**: `{{ finding.evidence_refs | join(', ') }}`
- **Remediation & Retest Guidance**: {{ finding.remediation or "Follow vendor hardening guidance and re-evaluate with Sentinel automated validation." }}

---
{% endfor %}

## 3. Prioritized Verification & Retest Matrix
{% for rec in report.recommendations %}
- **[{{ rec.priority }}] {{ rec.title }}**
  - **Remediation Action**: {{ rec.action_plan }}
  - **Automated Validation Check**: `{{ rec.verification_check_action }}`
{% endfor %}

---

## 4. Appendix: Cryptographic Evidence Index
The following evidence artifacts were collected and cryptographically signed during task execution:

| Evidence Reference ID | Associated Target |
|:----------------------|:------------------|
{% for finding in report.findings %}
{% for eref in finding.evidence_refs %}
| `{{ eref }}` | `{{ finding.target_ref }}` |
{% endfor %}
{% endfor %}
