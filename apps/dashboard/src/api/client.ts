import { Task, Finding, ApprovalRecord } from '../types';

const API_BASE = '/api/v1';

export async function fetchTasks(): Promise<Task[]> {
  try {
    const res = await fetch(`${API_BASE}/tasks`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function fetchTaskDetail(taskId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/tasks/${taskId}`);
  if (!res.ok) throw new Error('Task not found');
  return await res.json();
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

export async function decideApproval(approvalId: string, approve: boolean, justification: string): Promise<boolean> {
  const res = await fetch(`${API_BASE}/approvals/${approvalId}/decide`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ approve, justification, operator: 'dashboard_operator' }),
  });
  return res.ok;
}

export async function cancelTask(taskId: string): Promise<boolean> {
  const res = await fetch(`${API_BASE}/tasks/${taskId}/cancel`, { method: 'POST' });
  return res.ok;
}
