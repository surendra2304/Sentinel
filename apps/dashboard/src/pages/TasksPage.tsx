import React, { useEffect, useState } from 'react';
import { fetchTasks, cancelTask } from '../api/client';
import { Task } from '../types';
import { StopCircle, RefreshCw } from 'lucide-react';

export const TasksPage: React.FC = () => {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    fetchTasks().then((t) => {
      setTasks(t);
      setLoading(false);
    });
  };

  useEffect(() => {
    load();
  }, []);

  const handleCancel = async (id: string) => {
    if (confirm(`Halt execution of Task ${id}?`)) {
      await cancelTask(id);
      load();
    }
  };

  return (
    <div className="p-8 space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Tasks</h1>
          <p className="text-slate-400 text-sm mt-1">Autonomous orchestration state machines and task lifecycle status.</p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm rounded-lg font-medium border border-slate-700 transition"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

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
                      className="bg-cyan-500 h-2 rounded-full transition-all duration-300"
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
                  {t.status === 'executing' && (
                    <button
                      onClick={() => handleCancel(t.id)}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/30 rounded transition"
                      title="Trigger Kill Switch"
                    >
                      <StopCircle className="w-3.5 h-3.5" />
                      Kill
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {tasks.length === 0 && !loading && (
              <tr>
                <td colSpan={6} className="py-8 text-center text-slate-500">
                  No tasks registered in the platform.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
