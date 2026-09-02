import { Task, Finding, ApprovalRecord, Alert, AuditEntry, PolicyRule, Schedule, BaselineDiff, AttackPath } from '../types';

const API_BASE = '/api/v1';

export async function fetchTasks(): Promise<Task[]> {
  try {
    const res = await fetch(`${API_BASE}/tasks`);
    if (!res.ok) return [];
    const data = await res.json();
    return data.map((t: any) => ({
      ...t,
      id: t.task_id || t.id,
    }));
  } catch {
    return [];
  }
}

export async function submitTask(payload: {
  objective: string;
  targets: Array<{ type: string; value: string }>;
  mode: string;
  requested_output?: string;
}): Promise<any> {
  try {
    const res = await fetch(`${API_BASE}/tasks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

export async function fetchTaskDetail(taskId: string): Promise<Task | null> {
  try {
    const res = await fetch(`${API_BASE}/tasks/${taskId}`);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

export async function fetchFindings(taskId?: string): Promise<Finding[]> {
  try {
    const url = taskId ? `${API_BASE}/findings?task_id=${taskId}` : `${API_BASE}/findings`;
    const res = await fetch(url);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function fetchApprovals(): Promise<ApprovalRecord[]> {
  try {
    const res = await fetch(`${API_BASE}/approvals`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function decideApproval(
  approvalId: string,
  approve: boolean,
  justification: string,
  authorizationReference?: string
): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/approvals/${approvalId}/decide`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        approve,
        justification,
        operator: 'soc_dashboard_operator@corp.local',
        authorization_reference: authorizationReference || 'CHG-DASHBOARD-AUTO',
      }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function cancelTask(taskId: string): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/tasks/${taskId}/cancel`, { method: 'POST' });
    return res.ok;
  } catch {
    return false;
  }
}

export async function fetchAuditLogs(): Promise<AuditEntry[]> {
  try {
    const res = await fetch(`${API_BASE}/audit/logs`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function fetchPolicies(): Promise<PolicyRule[]> {
  try {
    const res = await fetch(`${API_BASE}/policies`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function fetchAlerts(): Promise<Alert[]> {
  try {
    const res = await fetch(`${API_BASE}/operations/alerts`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function updateAlertStatus(alertId: string, status: 'acknowledged' | 'resolved'): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/operations/alerts/${alertId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function fetchSchedules(): Promise<Schedule[]> {
  try {
    const res = await fetch(`${API_BASE}/operations/schedules`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function fetchBaselineDiffs(): Promise<BaselineDiff[]> {
  try {
    const res = await fetch(`${API_BASE}/operations/baselines/diffs`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function fetchAttackPaths(): Promise<AttackPath[]> {
  try {
    const res = await fetch(`${API_BASE}/intelligence/attack-paths`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export function getReportDownloadUrl(taskId: string, reportType: string, format: 'markdown' | 'html' | 'pdf'): string {
  return `${API_BASE}/tasks/${taskId}/reports/${reportType}?format=${format}`;
}

export function getEvidenceBundleDownloadUrl(taskId: string): string {
  return `${API_BASE}/tasks/${taskId}/evidence/bundle`;
}
