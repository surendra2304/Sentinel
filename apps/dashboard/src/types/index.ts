export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingStatus = 'open' | 'triaged' | 'confirmed' | 'in_remediation' | 'remediated' | 'false_positive' | 'accepted_risk';
export type TaskStatus = 'submitted' | 'planning' | 'executing' | 'awaiting_approval' | 'reporting' | 'complete' | 'failed' | 'cancelled';

export interface Target {
  id: string;
  type: string;
  value: string;
}

export interface Task {
  id: string;
  objective: string;
  mode: string;
  status: TaskStatus;
  progress_percentage: number;
  correlation_id: string;
  created_at: string;
  updated_at?: string;
  target_count: number;
}

export interface Finding {
  id: string;
  task_id: string;
  title: string;
  description: string;
  target_ref: string;
  severity: SeverityLevel;
  confidence: number;
  evidence_refs: string[];
  related_cves?: string[];
  remediation?: string;
  status: FindingStatus;
  first_seen: string;
}

export interface Evidence {
  id: string;
  task_id: string;
  target_ref: string;
  source_tool: string;
  timestamp: string;
  content_type: string;
  sha256_hash: string;
}

export interface ApprovalRecord {
  approval_id: string;
  task_id: string;
  action_type: string;
  target: string;
  requested_by: string;
  reason: string;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  expires_at: string;
  approved_by?: string;
  authorization_reference?: string;
  decided_at?: string;
}

export interface Alert {
  alert_id: string;
  target_ref: string;
  severity: SeverityLevel;
  change_type: string;
  title: string;
  message: string;
  status: 'open' | 'acknowledged' | 'resolved';
  created_at: string;
  occurrence_count: number;
}

export interface AuditEntry {
  entry_id: string;
  timestamp: string;
  event_type: string;
  actor: string;
  action_type: string;
  scope_policy: string;
  decision: string;
  details: Record<string, any>;
  sha256_hash: string;
  previous_entry_hash: string;
}

export interface PolicyRule {
  id: string;
  name: string;
  allowed_action_classes: string[];
  blocked_action_classes: string[];
  max_requests_per_second: number;
  burst_budget: number;
  require_approval_for_offensive: boolean;
  active: boolean;
}

export interface Schedule {
  id: string;
  name: string;
  cron_expression: string;
  task_template_id: string;
  target_ref: string;
  status: 'active' | 'paused';
  last_run_at?: string;
  next_run_at: string;
}

export interface BaselineDiff {
  id: string;
  target_ref: string;
  detected_at: string;
  diff_type: 'new_port' | 'certificate_change' | 'header_anomaly' | 'dns_change';
  severity: SeverityLevel;
  description: string;
  previous_state: string;
  current_state: string;
}

export interface AttackPathStep {
  step_number: number;
  node_id: string;
  node_label: string;
  target_ref: string;
  finding_id?: string;
  confidence: number;
  impact_level: string;
}

export interface AttackPath {
  id: string;
  name: string;
  target_ref: string;
  criticality: SeverityLevel;
  steps: AttackPathStep[];
}
