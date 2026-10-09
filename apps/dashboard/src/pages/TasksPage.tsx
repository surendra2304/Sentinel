import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { fetchConsoleTasks, cancelTask, submitTask } from '../api/client';
import { Task } from '../types';
import { StopCircle, RefreshCw, Plus, Play, ShieldAlert, FileText } from 'lucide-react';

export function inferTargetType(value: string): string {
  const normalized = value.trim();
  if (/^https?:\/\//i.test(normalized)) return 'url';
  if (/^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(normalized)) return 'cidr';
  if (/^[0-9a-f:]+\/\d{1,3}$/i.test(normalized) && normalized.includes(':')) return 'cidr';
  if (/^\[[0-9a-f:]+\](?:\/\d{1,3})?$/i.test(normalized)) {
    return normalized.includes('/') ? 'cidr' : 'ip';
  }
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(normalized)) return 'ip';
  if (/^[0-9a-f:]+$/i.test(normalized) && normalized.includes(':')) return 'ip';
  return 'domain';
}

export const TasksPage: React.FC = () => {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [objective, setObjective] = useState('');
  const [target, setTarget] = useState('');
  const [mode, setMode] = useState('passive_recon');
  const [scopeOwner, setScopeOwner] = useState('');
  const [authorizationReference, setAuthorizationReference] = useState('');
  const [scopeStart, setScopeStart] = useState('');
  const [scopeEnd, setScopeEnd] = useState('');
  const [allowedMethods, setAllowedMethods] = useState<string[]>([]);
  const [maximumImpact, setMaximumImpact] = useState('');
  const [rateLimit, setRateLimit] = useState('25');
  const [allowThirdPartyEnrichment, setAllowThirdPartyEnrichment] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      setTasks(await fetchConsoleTasks());
      setError(null);
    } catch (reason) {
      setTasks([]);
      setError(reason instanceof Error ? reason.message : 'Unable to load Sentinel tasks.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const interval = setInterval(() => void load(), 15000);
    return () => clearInterval(interval);
  }, []);

  const handleCancel = async (id: string) => {
    if (confirm(`Halt execution of Task ${id}?`)) {
      const cancelled = await cancelTask(id);
      if (!cancelled) setError('Sentinel did not confirm task cancellation.');
      await load();
    }
  };

  const handleCreateTask = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const startMs = new Date(scopeStart).getTime();
    const endMs = new Date(scopeEnd).getTime();
    if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || startMs >= endMs) {
      setError('Enter a valid authorization window with an end time after its start time.');
      return;
    }
    if (allowedMethods.length === 0) {
      setError('Select at least one explicitly authorized assessment method.');
      return;
    }
    const parsedRateLimit = Number(rateLimit);
    if (!Number.isInteger(parsedRateLimit) || parsedRateLimit < 1 || parsedRateLimit > 1000) {
      setError('Rate limit must be an integer between 1 and 1000 requests per minute.');
      return;
    }

    setSubmitting(true);
    try {
      await submitTask({
        objective: objective.trim(),
        targets: [{ type: inferTargetType(target), value: target.trim() }],
        mode,
        requested_output: 'comprehensive_report',
        scope: {
          owner: scopeOwner.trim(),
          written_authorization_reference: authorizationReference.trim(),
          allowed_targets: [target.trim()],
          allowed_methods: allowedMethods,
          time_window: {
            start_time: new Date(startMs).toISOString(),
            end_time: new Date(endMs).toISOString(),
          },
          maximum_impact: maximumImpact,
          rate_limit: parsedRateLimit,
          authorization: { allow_third_party_enrichment: allowThirdPartyEnrichment },
        },
      });
      setShowModal(false);
      await load();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Sentinel could not submit the task.');
    } finally {
      setSubmitting(false);
    }
  };

  const toggleAllowedMethod = (method: string) => {
    setAllowedMethods((current) => current.includes(method)
      ? current.filter((value) => value !== method)
      : [...current, method]);
  };

  return (
    <div className="p-8 space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Tasks</h1>
          <p className="text-slate-400 text-sm mt-1">Autonomous orchestration state machines and task lifecycle status.</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-sm rounded-lg font-semibold shadow-lg shadow-cyan-950/50 transition"
          >
            <Plus className="w-4 h-4" />
            Launch New Task
          </button>
          <button
            onClick={load}
            className="flex items-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm rounded-lg font-medium border border-slate-700 transition"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>

      {error && <div role="alert" className="rounded-xl border border-red-500/20 bg-red-500/[0.05] p-4 text-sm text-red-200">Task operation failed. {error}</div>}

      {showModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-2xl max-h-[90vh] overflow-y-auto w-full shadow-2xl space-y-4">
            <div className="flex justify-between items-center">
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Play className="w-5 h-5 text-cyan-400" />
                Launch Autonomous Security Task
              </h2>
              <button onClick={() => setShowModal(false)} className="text-slate-400 hover:text-slate-200">
                ✕
              </button>
            </div>
            <form onSubmit={handleCreateTask} className="space-y-4">
              <div>
                <label htmlFor="task-objective" className="block text-xs font-semibold text-slate-300 uppercase mb-1">Objective</label>
                <input
                  id="task-objective"
                  type="text"
                  value={objective}
                  onChange={(e) => setObjective(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>
              <div>
                <label htmlFor="task-target" className="block text-xs font-semibold text-slate-300 uppercase mb-1">Target (Domain / IP / URL / CIDR)</label>
                <input
                  id="task-target"
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>
              <div>
                <label htmlFor="task-mode" className="block text-xs font-semibold text-slate-300 uppercase mb-1">Task Mode</label>
                <select
                  id="task-mode"
                  value={mode}
                  onChange={(e) => setMode(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="passive_recon">Passive Reconnaissance (Non-intrusive)</option>
                  <option value="assessment">Security Assessment (Discovery and observation)</option>
                  <option value="authorized_assessment">Authorized Assessment</option>
                </select>
              </div>

              <fieldset className="rounded-lg border border-amber-500/30 bg-amber-500/[0.04] p-4 space-y-3">
                <legend className="px-2 text-xs font-semibold uppercase text-amber-200">Authorization scope — required</legend>
                <p className="text-xs text-slate-300">
                  Only submit targets you are authorized to assess. Sentinel checks the declared scope but does not verify that an external authorization ticket exists.
                </p>
                <div>
                  <label htmlFor="scope-owner" className="block text-xs font-semibold text-slate-300 uppercase mb-1">Authorizing owner</label>
                  <input
                    id="scope-owner"
                    type="text"
                    value={scopeOwner}
                    onChange={(e) => setScopeOwner(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                    required
                  />
                </div>
                <div>
                  <label htmlFor="authorization-reference" className="block text-xs font-semibold text-slate-300 uppercase mb-1">Written authorization reference</label>
                  <input
                    id="authorization-reference"
                    type="text"
                    value={authorizationReference}
                    onChange={(e) => setAuthorizationReference(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                    required
                  />
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <label htmlFor="scope-start" className="block text-xs font-semibold text-slate-300 uppercase mb-1">Authorization starts</label>
                    <input
                      id="scope-start"
                      type="datetime-local"
                      value={scopeStart}
                      onChange={(e) => setScopeStart(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                      required
                    />
                  </div>
                  <div>
                    <label htmlFor="scope-end" className="block text-xs font-semibold text-slate-300 uppercase mb-1">Authorization ends</label>
                    <input
                      id="scope-end"
                      type="datetime-local"
                      value={scopeEnd}
                      onChange={(e) => setScopeEnd(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                      required
                    />
                  </div>
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <label htmlFor="maximum-impact" className="block text-xs font-semibold text-slate-300 uppercase mb-1">Maximum impact</label>
                    <select
                      id="maximum-impact"
                      value={maximumImpact}
                      onChange={(e) => setMaximumImpact(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                      required
                    >
                      <option value="" disabled>Select an impact ceiling</option>
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>
                  <div>
                    <label htmlFor="scope-rate-limit" className="block text-xs font-semibold text-slate-300 uppercase mb-1">Rate limit (requests/minute)</label>
                    <input
                      id="scope-rate-limit"
                      type="number"
                      min="1"
                      max="1000"
                      step="1"
                      value={rateLimit}
                      onChange={(e) => setRateLimit(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                      required
                    />
                  </div>
                </div>
                <fieldset className="space-y-2">
                  <legend className="block text-xs font-semibold text-slate-300 uppercase">Allowed methods (select explicitly)</legend>
                  {[
                    ['passive_recon', 'Passive reconnaissance'],
                    ['discovery', 'Discovery and service observation'],
                    ['validation', 'Vulnerability validation'],
                  ].map(([value, label]) => (
                    <label key={value} className="flex items-center gap-2 text-sm text-slate-200">
                      <input
                        type="checkbox"
                        checked={allowedMethods.includes(value)}
                        onChange={() => toggleAllowedMethod(value)}
                      />
                      {label}
                    </label>
                  ))}
                </fieldset>
                <label className="flex items-start gap-2 text-sm text-slate-200">
                  <input
                    type="checkbox"
                    checked={allowThirdPartyEnrichment}
                    onChange={(e) => setAllowThirdPartyEnrichment(e.target.checked)}
                  />
                  <span>Allow third-party enrichment. Leave unchecked unless the authorization explicitly permits sharing target data with external providers.</span>
                </label>
              </fieldset>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm rounded-lg font-medium transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-sm rounded-lg font-semibold transition"
                >
                  {submitting ? 'Submitting...' : 'Dispatch Task'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-950/40 text-xs font-mono text-slate-400 uppercase">
              <th className="py-3.5 px-6">Task ID</th>
              <th className="py-3.5 px-6">Objective</th>
              <th className="py-3.5 px-6">Mode</th>
              <th className="py-3.5 px-6">Progress</th>
              <th className="py-3.5 px-6">Status</th>
              <th className="py-3.5 px-6 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-sm">
                  {loading && tasks.length === 0 && <tr><td colSpan={6} className="py-8 text-center text-slate-500">Loading tasks from Sentinel…</td></tr>}
                  {tasks.map((t) => (
              <tr key={t.id} className="hover:bg-slate-800/30 transition">
                <td className="py-4 px-6 font-mono text-cyan-400 font-semibold">{t.id}</td>
                <td className="py-4 px-6 font-medium text-slate-200">{t.objective}</td>
                <td className="py-4 px-6 font-mono text-xs text-slate-400">{t.mode}</td>
                <td className="py-4 px-6">
                  <div className="w-32 bg-slate-800 rounded-full h-2 overflow-hidden">
                    <div
                      className={`h-2 rounded-full transition-all duration-300 ${
                        t.status === 'complete' ? 'bg-emerald-500' : 'bg-cyan-500'
                      }`}
                      style={{ width: `${t.progress_percentage}%` }}
                    ></div>
                  </div>
                  <span className="text-[11px] font-mono text-slate-500 mt-1 block">{t.progress_percentage}%</span>
                </td>
                <td className="py-4 px-6">
                  <span
                    className={`px-2.5 py-1 text-xs font-mono rounded-full font-bold uppercase ${
                      t.status === 'complete'
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        : t.status === 'executing'
                        ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 animate-pulse'
                        : t.status === 'awaiting_approval'
                        ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {t.status}
                  </span>
                </td>
                <td className="py-4 px-6 text-right">
                  {t.status === 'executing' ? (
                    <button
                      onClick={() => handleCancel(t.id)}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/30 rounded transition"
                      title="Trigger Kill Switch"
                    >
                      <StopCircle className="w-3.5 h-3.5" />
                      Kill
                    </button>
                  ) : (
                    <div className="flex items-center justify-end gap-2">
                      <Link
                        to="/findings"
                        className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium bg-cyan-950/50 hover:bg-cyan-900 text-cyan-300 border border-cyan-800/60 rounded transition"
                        title="View Findings"
                      >
                        <ShieldAlert className="w-3.5 h-3.5" />
                        Findings
                      </Link>
                      <Link
                        to="/reports"
                        className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded transition"
                        title="View Reports"
                      >
                        <FileText className="w-3.5 h-3.5" />
                        Reports
                      </Link>
                    </div>
                  )}
                </td>
              </tr>
            ))}
            {tasks.length === 0 && !loading && !error && (
              <tr>
                <td colSpan={6} className="py-8 text-center text-slate-500">
                  No tasks registered. Click &quot;Launch New Task&quot; above to dispatch an autonomous security assessment!
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
