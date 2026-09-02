import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { fetchTasks, cancelTask, submitTask } from '../api/client';
import { Task } from '../types';
import { StopCircle, RefreshCw, Plus, Play, CheckCircle2, ShieldAlert, FileText } from 'lucide-react';

export const TasksPage: React.FC = () => {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [objective, setObjective] = useState('Perimeter attack surface discovery and port audit');
  const [target, setTarget] = useState('example.com');
  const [mode, setMode] = useState('passive_recon');

  const load = () => {
    fetchTasks().then((t) => {
      setTasks(t);
      setLoading(false);
    });
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 2500);
    return () => clearInterval(interval);
  }, []);

  const handleCancel = async (id: string) => {
    if (confirm(`Halt execution of Task ${id}?`)) {
      await cancelTask(id);
      load();
    }
  };

  const handleCreateTask = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    const targetType = target.match(/^\d+\.\d+\.\d+\.\d+$/) ? 'ip' : 'domain';
    await submitTask({
      objective,
      targets: [{ type: targetType, value: target }],
      mode,
      requested_output: 'comprehensive_report',
    });
    setSubmitting(false);
    setShowModal(false);
    load();
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

      {showModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-lg w-full shadow-2xl space-y-4">
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
                <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">Objective</label>
                <input
                  type="text"
                  value={objective}
                  onChange={(e) => setObjective(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">Target (Domain / IP)</label>
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">Task Mode</label>
                <select
                  value={mode}
                  onChange={(e) => setMode(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="passive_recon">Passive Reconnaissance (Non-intrusive)</option>
                  <option value="assessment">Security Assessment (Scanning & Discovery)</option>
                  <option value="authorized_assessment">Full Authorized Assessment (Active Evaluation)</option>
                </select>
              </div>
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
            {tasks.length === 0 && !loading && (
              <tr>
                <td colSpan={6} className="py-8 text-center text-slate-500">
                  No tasks registered. Click "Launch New Task" above to dispatch an autonomous security assessment!
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
