import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import { OverviewPage } from '../pages/OverviewPage';
import { createTaskEventStream, fetchConsoleApprovals, fetchConsoleFindings, fetchConsoleHealth, fetchConsoleRiskSummary, fetchConsoleTasks } from '../api/client';

vi.mock('../api/client', () => ({
  createTaskEventStream: vi.fn(),
  fetchConsoleApprovals: vi.fn(),
  fetchConsoleFindings: vi.fn(),
  fetchConsoleHealth: vi.fn(),
  fetchConsoleRiskSummary: vi.fn(),
  fetchConsoleTasks: vi.fn(),
  getDashboardApiKey: vi.fn(() => ''),
  setDashboardApiKey: vi.fn(),
}));

describe('Sentinel control room', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(createTaskEventStream).mockReturnValue(() => undefined);
    vi.mocked(fetchConsoleHealth).mockResolvedValue({
      status: 'HEALTHY', service: 'SENTINEL', version: '2.0.0', environment: 'production',
      kill_switch_active: false, audit_chain_valid: true,
    });
    vi.mocked(fetchConsoleTasks).mockResolvedValue([{
      id: 'task-42', objective: 'Review approved perimeter', mode: 'passive_recon',
      status: 'executing', progress_percentage: 45, correlation_id: 'c-42',
      created_at: '2026-09-28T10:00:00Z', target_count: 1,
    }]);
    vi.mocked(fetchConsoleFindings).mockResolvedValue([{
      id: 'finding-7', task_id: 'task-42', title: 'Exposed admin endpoint',
      description: 'Observed endpoint is accessible without the expected control.',
      target_ref: 'app.example.test', severity: 'critical', confidence: 0.9,
      evidence_refs: ['evidence-1'], status: 'open', first_seen: '2026-09-28T09:00:00Z',
    }]);
    vi.mocked(fetchConsoleApprovals).mockResolvedValue([{
      approval_id: 'approval-3', task_id: 'task-42', action_id: 'action-3',
      action_type: 'web.assessment', target_refs: ['app.example.test'], requested_by: 'operator',
      justification_needed: 'Review', status: 'PENDING',
      requested_at: '2026-09-28T10:00:00Z', expires_at: '2026-09-29T00:00:00Z',
    }]);
    vi.mocked(fetchConsoleRiskSummary).mockResolvedValue({
      task_id: 'task-42', total_findings: 1, overall_risk_score: 88,
      highest_risk_tier: 'high', tier_counts: { high: 1 }, severity_counts: { critical: 1 },
      top_risks: [{ id: 'risk-1', finding_id: 'finding-7', task_id: 'task-42', severity: 'critical', asset_criticality: 'high', computed_risk_score: 88, risk_tier: 'high', rationale: 'Observed risk' }],
    });
  });

  it('renders API-backed risk, approvals, findings, and task stream without fabricated metrics', async () => {
    vi.mocked(createTaskEventStream).mockImplementation((_taskId, onEvent, onStatus) => {
      onStatus('connected');
      onEvent({ name: 'risk.updated', data: { topic: 'risk.updated', payload: { tier: 'high', score: 88, finding_id: 'finding-7' } } });
      return () => undefined;
    });

    render(<BrowserRouter><OverviewPage /></BrowserRouter>);

    expect(await screen.findByText('Exposed admin endpoint')).toBeInTheDocument();
    expect(screen.getByText('Risk update: high tier · score 88 · finding finding-7')).toBeInTheDocument();
    expect(await screen.findByText('88')).toBeInTheDocument();
    expect(screen.getByText('Streaming')).toBeInTheDocument();
    expect(fetchConsoleRiskSummary).toHaveBeenCalledWith('task-42');
    expect(createTaskEventStream).toHaveBeenCalledWith('task-42', expect.any(Function), expect.any(Function));
  });

  it('shows API failures as unavailable instead of presenting them as zero', async () => {
    vi.mocked(fetchConsoleHealth).mockResolvedValue({
      status: 'HEALTHY', service: 'SENTINEL', version: '2.0.0', environment: 'production',
      kill_switch_active: false, audit_chain_valid: true,
    });
    vi.mocked(fetchConsoleTasks).mockRejectedValue(new Error('Sentinel API returned 401'));
    vi.mocked(fetchConsoleFindings).mockRejectedValue(new Error('Sentinel API returned 401'));
    vi.mocked(fetchConsoleApprovals).mockRejectedValue(new Error('Sentinel API returned 401'));

    render(<BrowserRouter><OverviewPage /></BrowserRouter>);

    expect(await screen.findByText('API key required or rejected')).toBeInTheDocument();
    await waitFor(() => expect(screen.getAllByText('Unavailable').length).toBeGreaterThanOrEqual(3));
    expect(screen.queryByText('No findings returned')).not.toBeInTheDocument();
  });
});
