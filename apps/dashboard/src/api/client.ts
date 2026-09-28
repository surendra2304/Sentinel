import { Task, Finding, ApprovalRecord, Alert, AuditEntry, PolicyRule, Schedule, BaselineDiff, AttackPath } from '../types';

const API_ORIGIN = import.meta.env.VITE_API_URL ? import.meta.env.VITE_API_URL.replace(/\/+$/, '') : '';
const API_BASE_PREFIX = `${API_ORIGIN}/api/v1`;
const API_BASE = API_BASE_PREFIX;

const API_KEY_STORAGE = 'sentinel-dashboard-api-key';

export function getDashboardApiKey(): string {
  return window.sessionStorage.getItem(API_KEY_STORAGE) || '';
}

export function setDashboardApiKey(value: string): void {
  const key = value.trim();
  if (key) window.sessionStorage.setItem(API_KEY_STORAGE, key);
  else window.sessionStorage.removeItem(API_KEY_STORAGE);
}

async function apiFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  const key = getDashboardApiKey();
  if (key) headers.set('X-API-Key', key);
  return fetch(input, { ...init, headers });
}

async function fetchJson<T>(url: string): Promise<T> {
  const response = await apiFetch(url);
  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    throw new Error(`Sentinel API returned ${response.status}${detail ? `: ${detail.slice(0, 180)}` : ''}`);
  }
  return response.json() as Promise<T>;
}

export interface ConsoleHealth {
  status: string;
  service: string;
  version: string;
  environment: string;
  kill_switch_active: boolean;
  audit_chain_valid: boolean;
}

export interface ConsoleRiskSummary {
  task_id: string;
  total_findings: number;
  overall_risk_score: number;
  highest_risk_tier: string;
  tier_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  top_risks: Array<{
    id: string;
    finding_id: string;
    task_id: string;
    severity: string;
    asset_criticality: string;
    computed_risk_score: number;
    risk_tier: string;
    rationale: string;
  }>;
}

export interface ConsoleAttackSurface {
  task_id: string;
  total_nodes: number;
  total_edges: number;
  domains_count: number;
  ips_count: number;
  services_count: number;
  technologies: string[];
  nodes: Array<{ id: string; node_type: string; label: string; is_internet_facing: boolean; criticality: string; properties: Record<string, unknown> }>;
  edges: Array<{ id: string; source_node_id: string; target_node_id: string; edge_type: string }>;
  internet_facing_ratio: number;
  generated_at: string;
}

export async function fetchConsoleHealth(): Promise<ConsoleHealth> {
  return fetchJson<ConsoleHealth>(`${API_ORIGIN}/health`);
}

export async function fetchConsoleTasks(): Promise<Task[]> {
  const tasks = await fetchJson<Array<Task & { task_id?: string }>>(`${API_BASE}/tasks`);
  return tasks.map((task) => ({ ...task, id: task.task_id || task.id }));
}

export async function fetchConsoleFindings(): Promise<Finding[]> {
  return fetchJson<Finding[]>(`${API_BASE}/findings`);
}

export async function fetchConsoleApprovals(): Promise<ApprovalRecord[]> {
  return fetchJson<ApprovalRecord[]>(`${API_BASE}/approvals`);
}

export async function fetchConsoleRiskSummary(taskId: string): Promise<ConsoleRiskSummary> {
  return fetchJson<ConsoleRiskSummary>(`${API_BASE}/tasks/${encodeURIComponent(taskId)}/risk-summary`);
}

export async function fetchConsoleAttackSurface(taskId: string): Promise<ConsoleAttackSurface> {
  return fetchJson<ConsoleAttackSurface>(`${API_BASE}/tasks/${encodeURIComponent(taskId)}/attack-surface`);
}

export async function downloadProtectedResource(url: string, filename: string): Promise<void> {
  const response = await apiFetch(url);
  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    throw new Error(`Sentinel API returned ${response.status}${detail ? `: ${detail.slice(0, 180)}` : ''}`);
  }
  const blob = await response.blob();
  const objectUrl = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = objectUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(objectUrl);
}

export function createTaskEventStream(taskId: string, onEvent: (event: { name: string; data: unknown }) => void,
  onStatus: (status: 'connecting' | 'connected' | 'error') => void): () => void {
  const controller = new AbortController();
  const url = `${API_BASE}/tasks/${encodeURIComponent(taskId)}/events`;
  onStatus('connecting');

  void (async () => {
    try {
      const response = await apiFetch(url, { signal: controller.signal, headers: { Accept: 'text/event-stream' } });
      if (!response.ok || !response.body) {
        throw new Error(`Sentinel event stream returned ${response.status}`);
      }
      onStatus('connected');
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let eventName = 'message';
      let dataLines: string[] = [];
      while (!controller.signal.aborted) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split(/\r?\n/);
        buffer = lines.pop() || '';
        for (const line of lines) {
          if (!line) {
            if (dataLines.length) {
              const raw = dataLines.join('\n');
              let parsed: unknown = raw;
              try { parsed = JSON.parse(raw); } catch { /* keep the SSE data as text */ }
              onEvent({ name: eventName, data: parsed });
            }
            eventName = 'message';
            dataLines = [];
          } else if (line.startsWith('event:')) eventName = line.slice(6).trim();
          else if (line.startsWith('data:')) dataLines.push(line.slice(5).trimStart());
        }
      }
    } catch {
      if (!controller.signal.aborted) onStatus('error');
    }
  })();

  return () => controller.abort();
}

export async function fetchTasks(): Promise<Task[]> {
  try {
    const res = await apiFetch(`${API_BASE}/tasks`);
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
    const res = await apiFetch(`${API_BASE}/tasks`, {
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
    const res = await apiFetch(`${API_BASE}/tasks/${taskId}`);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

export async function fetchFindings(taskId?: string): Promise<Finding[]> {
  try {
    const url = taskId ? `${API_BASE}/findings?task_id=${taskId}` : `${API_BASE}/findings`;
    const res = await apiFetch(url);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function fetchApprovals(): Promise<ApprovalRecord[]> {
  try {
    const res = await apiFetch(`${API_BASE}/approvals`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function decideApproval(
  approvalId: string,
  approve: boolean,
  operator: string,
  justification: string,
  authorizationReference?: string
): Promise<boolean> {
  try {
    const res = await apiFetch(`${API_BASE}/approvals/${approvalId}/decide`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        approve,
        justification,
        operator,
        authorization_reference: authorizationReference || null,
      }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function cancelTask(taskId: string): Promise<boolean> {
  try {
    const res = await apiFetch(`${API_BASE}/tasks/${taskId}/cancel`, { method: 'POST' });
    return res.ok;
  } catch {
    return false;
  }
}

export async function fetchAuditLogs(): Promise<AuditEntry[]> {
  try {
    const res = await apiFetch(`${API_BASE}/audit/logs`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function fetchPolicies(): Promise<PolicyRule[]> {
  try {
    const res = await apiFetch(`${API_BASE}/policies`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function fetchAlerts(): Promise<Alert[]> {
  try {
    const res = await apiFetch(`${API_BASE}/operations/alerts`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function updateAlertStatus(alertId: string, status: 'acknowledged' | 'resolved'): Promise<boolean> {
  try {
    const res = await apiFetch(`${API_BASE}/operations/alerts/${alertId}`, {
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
    const res = await apiFetch(`${API_BASE}/operations/schedules`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function fetchBaselineDiffs(): Promise<BaselineDiff[]> {
  try {
    const res = await apiFetch(`${API_BASE}/operations/baselines/diffs`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function fetchAttackPaths(): Promise<AttackPath[]> {
  try {
    const res = await apiFetch(`${API_BASE}/intelligence/attack-paths`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export function getReportDownloadUrl(taskId: string, reportType: string, format: 'markdown' | 'html' | 'pdf' | 'json'): string {
  return `${API_BASE}/tasks/${encodeURIComponent(taskId)}/report?type=${encodeURIComponent(reportType)}&format=${encodeURIComponent(format)}`;
}

export function getEvidenceBundleDownloadUrl(taskId: string): string {
  return `${API_BASE}/tasks/${encodeURIComponent(taskId)}/evidence/bundle`;
}
