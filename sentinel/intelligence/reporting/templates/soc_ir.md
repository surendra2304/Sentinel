# SOC Incident Response & Forensic Investigation Report

**Incident Investigation Case**: `{{ report.task_id }}`  
**Report Date**: `{{ report.generated_at }}`  
**Triage Severity**: `{{ report.overall_risk_score }} / 10.0`

---

## 1. Executive Incident Summary
{{ report.summary_narrative }}

---

## 2. Correlated Forensic Findings & IOCs
{% for finding in report.findings %}
### Incident Observation: {{ finding.title }}
- **Source Asset / Indicator**: `{{ finding.target_ref }}`
- **Confidence Rating**: `{{ finding.confidence * 100 }}%`
- **Forensic Detail**: {{ finding.description }}
- **Evidence Anchor Ref**: `{{ finding.evidence_refs | join(', ') }}`
{% endfor %}

---

## 3. Recommended Containment Proposals (Human Approval Gated)
{% for rec in report.recommendations %}
- **Containment Step [{{ rec.priority }}]**: {{ rec.title }}
  - **Proposed Action**: {{ rec.action_plan }}
  - **Verification Action**: `{{ rec.verification_check_action }}`
{% endfor %}
