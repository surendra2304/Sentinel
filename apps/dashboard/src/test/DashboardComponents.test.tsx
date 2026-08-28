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
    vi.spyOn(api, 'fetchTasks').mockResolvedValue([
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
    vi.spyOn(api, 'fetchFindings').mockResolvedValue([
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
    vi.spyOn(api, 'fetchApprovals').mockResolvedValue([
      {
        approval_id: 'appr-999',
        task_id: 'task-e2e-01',
        action_type: 'web.admin_database_flush',
        target: 'http://lab.local/api/admin',
        requested_by: 'exploit_agent',
        reason: 'Authorized destructive database verification test',
        status: 'pending',
        expires_at: '2026-08-28T18:00:00Z',
      },
    ]);

    const decideSpy = vi.spyOn(api, 'decideApproval').mockResolvedValue(true);
    window.prompt = vi.fn().mockReturnValue('Approved by security test');

    render(
      <BrowserRouter>
        <ApprovalsPage />
      </BrowserRouter>
    );

    expect(screen.getByText(/Policy Governance & Approvals/i)).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText('appr-999')).toBeInTheDocument();
      expect(screen.getByText('web.admin_database_flush')).toBeInTheDocument();
    });

    // Click Approve button
    const approveBtn = screen.getByRole('button', { name: /Approve/i });
    fireEvent.click(approveBtn);
    expect(decideSpy).toHaveBeenCalledWith('appr-999', true, 'Approved by security test');
  });

  it('renders Risk view with matrix breakdown and exploitability scores', async () => {
    vi.spyOn(api, 'fetchFindings').mockResolvedValue([
      {
        id: 'find-01',
        task_id: 'task-e2e-01',
        title: 'Critical RCE Vector',
        description: 'Remote code execution possible.',
        target_ref: 'api.corp.local',
        severity: 'critical',
        confidence: 0.95,
        evidence_refs: ['evi-1'],
        status: 'open',
        first_seen: '2026-08-28T12:00:00Z',
      },
      {
        id: 'find-02',
        task_id: 'task-e2e-01',
        title: 'Missing CSP Header',
        description: 'Content security policy header is absent.',
        target_ref: 'api.corp.local',
        severity: 'medium',
        confidence: 0.8,
        evidence_refs: ['evi-2'],
        status: 'open',
        first_seen: '2026-08-28T12:00:00Z',
      },
    ]);

    render(
      <BrowserRouter>
        <RiskPage />
      </BrowserRouter>
    );

    expect(screen.getByTestId('risk-view')).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText('Critical RCE Vector')).toBeInTheDocument();
      expect(screen.getByText('Missing CSP Header')).toBeInTheDocument();
      expect(screen.getByText(/Vulnerability Criticality Matrix/i)).toBeInTheDocument();
    });
  });
});