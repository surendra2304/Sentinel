# Executive Cybersecurity Risk Assessment Report

**Engagement / Task ID**: `{{ report.task_id }}`  
**Generated At**: `{{ report.generated_at }}`  
**Platform Risk Score**: `{{ report.overall_risk_score }} / 10.0`

---

## 1. Business Impact & Executive Summary
{{ report.summary_narrative }}

### Risk Profile Breakdown
- **Critical Severity**: {{ report.findings_summary.critical }}
- **High Severity**: {{ report.findings_summary.high }}
- **Medium Severity**: {{ report.findings_summary.medium }}
- **Low Severity**: {{ report.findings_summary.low }}

---

## 2. Critical Attack Paths & Threat Narratives
{% for path in report.attack_paths %}
### Attack Path Hypothesis: {{ path.path_id }}
- **Ingress Surface**: `{{ path.entry_point }}`
- **Crown Jewel at Risk**: `{{ path.target_crown_jewel }}`
- **Path Confidence Rating**: `{{ path.path_confidence * 100 }}%`
{% for step in path.steps %}
  {{ loop.index }}. {{ step.action_or_technique }} (Target: `{{ step.target_asset }}`)
{% endfor %}
{% endfor %}

---

## 3. Strategic Remediation Roadmap
{% for rec in report.recommendations %}
- **[{{ rec.priority }}] {{ rec.title }}** (Effort: {{ rec.estimated_effort }})
  - **Action Plan**: {{ rec.action_plan }}
  - **Compensating Control**: {{ rec.compensating_control }}
  - **Verification Method**: `{{ rec.verification_check_action }}`
{% endfor %}
