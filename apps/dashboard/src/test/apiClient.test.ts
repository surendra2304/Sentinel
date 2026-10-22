import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchConsoleTasks, getDashboardApiKey, setDashboardApiKey, submitTask } from '../api/client';

describe('Sentinel dashboard API client', () => {
  afterEach(() => {
    setDashboardApiKey('');
    vi.unstubAllGlobals();
  });

  it('keeps the API key in tab session storage and sends the required header', async () => {
    const request = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [{ task_id: 'task-17', objective: 'Approved scan', mode: 'passive_recon', status: 'submitted' }],
    });
    vi.stubGlobal('fetch', request);
    setDashboardApiKey('sentinel-test-token');

    const tasks = await fetchConsoleTasks();

    expect(getDashboardApiKey()).toBe('sentinel-test-token');
    expect(request).toHaveBeenCalledWith('/api/v1/tasks', expect.objectContaining({
      headers: expect.any(Headers),
    }));
    const init = request.mock.calls[0][1] as RequestInit;
    expect(new Headers(init.headers).get('X-API-Key')).toBe('sentinel-test-token');
    expect(tasks[0].id).toBe('task-17');
  });

  it('submits the complete authorization scope and surfaces API validation errors', async () => {
    const payload = {
      objective: 'Local authorized assessment',
      targets: [{ type: 'ip', value: '127.0.0.1' }],
      mode: 'passive_recon',
      scope: {
        owner: 'local-operator',
        written_authorization_reference: 'LOCAL-ONLY',
        allowed_targets: ['127.0.0.1'],
        allowed_methods: ['passive_recon'],
        time_window: { start_time: '2026-10-07T00:00:00Z', end_time: '2026-10-08T00:00:00Z' },
        maximum_impact: 'low',
        rate_limit: 5,
        authorization: { allow_third_party_enrichment: false },
      },
    };
    const successfulResponse = {
      ok: true,
      json: async () => ({ task_id: 'task-local', status: 'submitted' }),
    };
    const request = vi.fn().mockResolvedValue(successfulResponse);
    vi.stubGlobal('fetch', request);

    await submitTask(payload);

    const init = request.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(String(init.body))).toEqual(payload);

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 422,
      text: async () => JSON.stringify({ detail: 'Scope must include an authorizing owner.' }),
    }));
    await expect(submitTask(payload)).rejects.toThrow('Scope must include an authorizing owner');
  });
});
