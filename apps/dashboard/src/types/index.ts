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
