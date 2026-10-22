import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import { TasksPage } from '../pages/TasksPage';
import { FindingsPage } from '../pages/FindingsPage';
import { ApprovalsPage } from '../pages/ApprovalsPage';
import { RiskPage } from '../pages/RiskPage';
import * as api from '../api/client';

vi.mock('../api/client');

describe('Dashboard Component Test Suite', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders Tasks page with task list and kill-switch control', async () => {
    vi.spyOn(api, 'fetchConsoleTasks').mockResolvedValue([
      {
        id: 'task-e2e-01',
        objective: 'Assess vulnerable web service',
        mode: 'authorized_assessment',
        status: 'executing',
        progress_percentage: 65,
        correlation_id: 'corr-01',
        created_at: '2026-08-28T12:00:00Z',
        target_count: 1,
      },
    ]);

    render(
      <BrowserRouter>
        <TasksPage />
      </BrowserRouter>
    );

    expect(screen.getByText(/Security Tasks/i)).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText('task-e2e-01')).toBeInTheDocument();
      expect(screen.getByText('Assess vulnerable web service')).toBeInTheDocument();
      expect(screen.getByText(/Kill/i)).toBeInTheDocument();
    });
  });

  it('renders Findings page with filter and evidence drawer detail', async () => {
    vi.spyOn(api, 'fetchConsoleFindings').mockResolvedValue([
      {
        id: 'find-01',
        task_id: 'task-e2e-01',
        title: 'Exposed SQL Database Backup',
        description: 'Plaintext credentials exposed at /backup/database.sql.bak',
        target_ref: 'http://lab.local',
        severity: 'critical',
        confidence: 0.95,
        evidence_refs: ['evi-sha256-001'],
        remediation: 'Restrict access to sensitive backup archives.',
        status: 'open',
        first_seen: '2026-08-28T12:00:00Z',
      },
    ]);

    render(
      <BrowserRouter>
        <FindingsPage />
      </BrowserRouter>
    );

    expect(screen.getByText(/Security Findings & Weaknesses/i)).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText('Exposed SQL Database Backup')).toBeInTheDocument();
      expect(screen.getByText('1 artifact(s)')).toBeInTheDocument();
    });

    // Click finding row to inspect evidence drawer
    fireEvent.click(screen.getByText('Exposed SQL Database Backup'));
    expect(screen.getByText(/SHA256 Anchor: evi-sha256-001/i)).toBeInTheDocument();
    expect(screen.getByText(/Restrict access to sensitive backup archives/i)).toBeInTheDocument();
  });

  it('renders Approvals page with Approve and Deny actions', async () => {
    vi.spyOn(api, 'fetchConsoleApprovals').mockResolvedValue([
      {
        approval_id: 'appr-999',
        task_id: 'task-e2e-01',
        action_id: 'action-approval-999',
        action_type: 'web.admin_database_flush',
        target_refs: ['http://lab.local/api/admin'],
        requested_by: 'exploit_agent',
        justification_needed: 'Authorized destructive database verification test',
        status: 'PENDING',
        requested_at: '2026-08-28T12:00:00Z',
        expires_at: '2026-08-28T18:00:00Z',
      },
    ]);

    const decideSpy = vi.spyOn(api, 'decideApproval').mockResolvedValue(true);
    render(
      <BrowserRouter>
        <ApprovalsPage />
      </BrowserRouter>
    );

    expect(screen.getByText(/Pending approvals/i)).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText('appr-999')).toBeInTheDocument();
      expect(screen.getByText('web.admin_database_flush')).toBeInTheDocument();
    });

    // Click Approve button
    const approveBtn = screen.getByRole('button', { name: /Approve/i });
    fireEvent.click(approveBtn);
    fireEvent.change(screen.getByLabelText(/Operator identity/i), { target: { value: 'Analyst One' } });
    fireEvent.change(screen.getByLabelText(/Decision rationale/i), { target: { value: 'Reviewed the requested scope.' } });
    fireEvent.click(screen.getByRole('button', { name: /Confirm approval/i }));
    await waitFor(() => expect(decideSpy).toHaveBeenCalledWith('appr-999', true, 'Analyst One', 'Reviewed the requested scope.', undefined));
  });

  it('renders risk values from the selected task risk-summary API', async () => {
    vi.spyOn(api, 'fetchConsoleTasks').mockResolvedValue([{
      id: 'task-e2e-01', objective: 'Review target', mode: 'passive_recon', status: 'complete',
      progress_percentage: 100, correlation_id: 'corr-1', created_at: '2026-08-28T12:00:00Z', target_count: 1,
    }]);
    vi.spyOn(api, 'fetchConsoleRiskSummary').mockResolvedValue({
      task_id: 'task-e2e-01', total_findings: 2, overall_risk_score: 88.4,
      highest_risk_tier: 'high', tier_counts: { high: 1 }, severity_counts: { critical: 1 },
      top_risks: [{
        id: 'risk-1', finding_id: 'find-01', task_id: 'task-e2e-01', severity: 'critical',
        asset_criticality: 'high', computed_risk_score: 88.4, risk_tier: 'high',
        rationale: 'Evaluated severity (critical) on high-critical asset.',
      }],
    });

    render(
      <BrowserRouter>
        <RiskPage />
      </BrowserRouter>
    );

    expect(screen.getByTestId('risk-view')).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText('Computed task risk')).toBeInTheDocument();
      expect(screen.getByText('Finding find-01')).toBeInTheDocument();
      expect(screen.getAllByText('88.4')).toHaveLength(2);
    });
  });

  it('supports findings table severity filtering and empty results state', async () => {
    vi.spyOn(api, 'fetchConsoleFindings').mockResolvedValue([
      {
        id: 'find-01',
        task_id: 'task-e2e-01',
        title: 'Critical RCE Vector',
        description: 'Command injection vulnerability',
        target_ref: 'http://lab.local',
        severity: 'critical',
        confidence: 0.99,
        evidence_refs: ['evi-01'],
        remediation: 'Sanitize inputs',
        status: 'open',
        first_seen: '2026-08-28T12:00:00Z',
      },
      {
        id: 'find-02',
        task_id: 'task-e2e-01',
        title: 'Low Info Leak',
        description: 'Server version disclosed',
        target_ref: 'http://lab.local',
        severity: 'low',
        confidence: 0.8,
        evidence_refs: ['evi-02'],
        remediation: 'Hide headers',
        status: 'open',
        first_seen: '2026-08-28T12:00:00Z',
      },
    ]);

    render(
      <BrowserRouter>
        <FindingsPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Critical RCE Vector')).toBeInTheDocument();
      expect(screen.getByText('Low Info Leak')).toBeInTheDocument();
    });

    // Filter to CRITICAL only
    const select = screen.getByRole('combobox');
    fireEvent.change(select, { target: { value: 'critical' } });

    expect(screen.getByText('Critical RCE Vector')).toBeInTheDocument();
    expect(screen.queryByText('Low Info Leak')).not.toBeInTheDocument();

    // Filter to MEDIUM (expect empty state)
    fireEvent.change(select, { target: { value: 'medium' } });
    expect(screen.getByText(/No findings match the selected criteria/i)).toBeInTheDocument();
  });

  it('updates task progress in real time upon task list polling / refresh', async () => {
    const fetchSpy = vi.spyOn(api, 'fetchConsoleTasks');
    fetchSpy.mockResolvedValueOnce([
      {
        id: 'task-live-01',
        objective: 'Continuous scan',
        mode: 'authorized_assessment',
        status: 'executing',
        progress_percentage: 25,
        correlation_id: 'c1',
        created_at: '2026-08-28T12:00:00Z',
        target_count: 1,
      },
    ]);

    render(
      <BrowserRouter>
        <TasksPage />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('25%')).toBeInTheDocument();
    });

    // Mock subsequent refresh with 85% progress
    fetchSpy.mockResolvedValueOnce([
      {
        id: 'task-live-01',
        objective: 'Continuous scan',
        mode: 'authorized_assessment',
        status: 'executing',
        progress_percentage: 85,
        correlation_id: 'c1',
        created_at: '2026-08-28T12:00:00Z',
        target_count: 1,
      },
    ]);

    const refreshBtn = screen.getByRole('button', { name: /Refresh/i });
    fireEvent.click(refreshBtn);

    await waitFor(() => {
      expect(screen.getByText('85%')).toBeInTheDocument();
    });
  });
});
