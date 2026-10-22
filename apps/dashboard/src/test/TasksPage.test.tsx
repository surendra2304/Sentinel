import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { cancelTask, fetchConsoleTasks, submitTask } from '../api/client';
import { inferTargetType, TasksPage } from '../pages/TasksPage';

vi.mock('../api/client', () => ({
  cancelTask: vi.fn(),
  fetchConsoleTasks: vi.fn(),
  submitTask: vi.fn(),
}));

describe('TasksPage authorization submission', () => {
  it('classifies IPv6 CIDRs before individual IP addresses', () => {
    expect(inferTargetType('2001:db8::/32')).toBe('cidr');
    expect(inferTargetType('2001:db8::1')).toBe('ip');
    expect(inferTargetType('192.0.2.0/24')).toBe('cidr');
    expect(inferTargetType('https://example.test/path')).toBe('url');
    expect(inferTargetType('example.test')).toBe('domain');
  });

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(fetchConsoleTasks).mockResolvedValue([]);
    vi.mocked(cancelTask).mockResolvedValue(true);
    vi.mocked(submitTask).mockResolvedValue({
      task_id: 'task-local', objective: 'Local assessment', mode: 'assessment',
      status: 'submitted', progress_percentage: 0, correlation_id: 'corr-local',
      created_at: '2026-10-07T00:00:00Z', target_count: 1,
    });
  });

  it('sends a user-entered authorization contract rather than omitting scope', async () => {
    render(<BrowserRouter><TasksPage /></BrowserRouter>);
    fireEvent.click(await screen.findByRole('button', { name: /launch new task/i }));

    fireEvent.change(screen.getByLabelText('Objective'), { target: { value: 'Local assessment' } });
    fireEvent.change(screen.getByLabelText(/Target/), { target: { value: '127.0.0.1' } });
    fireEvent.change(screen.getByLabelText('Authorizing owner'), { target: { value: 'local-operator' } });
    fireEvent.change(screen.getByLabelText('Written authorization reference'), { target: { value: 'LOCAL-ONLY-1' } });
    fireEvent.change(screen.getByLabelText('Authorization starts'), { target: { value: '2026-10-07T00:00' } });
    fireEvent.change(screen.getByLabelText('Authorization ends'), { target: { value: '2026-10-08T00:00' } });
    fireEvent.change(screen.getByLabelText('Maximum impact'), { target: { value: 'low' } });
    fireEvent.click(screen.getByLabelText('Discovery and service observation'));

    fireEvent.click(screen.getByRole('button', { name: 'Dispatch Task' }));

    await waitFor(() => expect(submitTask).toHaveBeenCalledTimes(1));
    expect(submitTask).toHaveBeenCalledWith(expect.objectContaining({
      targets: [{ type: 'ip', value: '127.0.0.1' }],
      scope: expect.objectContaining({
        owner: 'local-operator',
        written_authorization_reference: 'LOCAL-ONLY-1',
        allowed_targets: ['127.0.0.1'],
        allowed_methods: ['discovery'],
        maximum_impact: 'low',
        rate_limit: 25,
        authorization: { allow_third_party_enrichment: false },
      }),
    }));
    expect(await screen.findByText(/No tasks registered/)).toBeInTheDocument();
  });

  it('shows server validation detail and leaves the form available to correct it', async () => {
    vi.mocked(submitTask).mockRejectedValue(new Error('Sentinel API returned 422: Scope expired'));
    render(<BrowserRouter><TasksPage /></BrowserRouter>);
    fireEvent.click(await screen.findByRole('button', { name: /launch new task/i }));

    fireEvent.change(screen.getByLabelText('Objective'), { target: { value: 'Local assessment' } });
    fireEvent.change(screen.getByLabelText(/Target/), { target: { value: '127.0.0.1' } });
    fireEvent.change(screen.getByLabelText('Authorizing owner'), { target: { value: 'local-operator' } });
    fireEvent.change(screen.getByLabelText('Written authorization reference'), { target: { value: 'LOCAL-ONLY-2' } });
    fireEvent.change(screen.getByLabelText('Authorization starts'), { target: { value: '2026-10-07T00:00' } });
    fireEvent.change(screen.getByLabelText('Authorization ends'), { target: { value: '2026-10-08T00:00' } });
    fireEvent.change(screen.getByLabelText('Maximum impact'), { target: { value: 'low' } });
    fireEvent.click(screen.getByLabelText('Discovery and service observation'));
    fireEvent.click(screen.getByRole('button', { name: 'Dispatch Task' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Scope expired');
    expect(screen.getByText('Launch Autonomous Security Task')).toBeInTheDocument();
  });
});
