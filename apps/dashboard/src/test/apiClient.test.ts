import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchConsoleTasks, getDashboardApiKey, setDashboardApiKey } from '../api/client';

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
});
