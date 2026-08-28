import React, { useEffect, useState } from 'react';
import { fetchTasks, fetchFindings, fetchApprovals } from '../api/client';
import { Task, Finding, ApprovalRecord } from '../types';
import { ShieldCheck, AlertTriangle, Activity, CheckSquare } from 'lucide-react';

export const OverviewPage: React.FC = () => {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [approvals, setApprovals] = useState<ApprovalRecord[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([fetchTasks(), fetchFindings(), fetchApprovals()]).then(([t, f, a]) => {
      setTasks(t);
      setFindings(f);
      setApprovals(a);
      setLoading(false);
    });
  }, []);

  const critCount = findings.filter((f) => f.severity === 'critical').length;
  const highCount = findings.filter((f) => f.severity === 'high').length;
  const activeTasks = tasks.filter((t) => t.status === 'executing' || t.status === 'planning').length;

  return (
    <div className="p-8 space-y-8">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Posture Overview</h1>
          <p className="text-slate-400 text-sm mt-1">Autonomous enterprise attack surface surveillance and threat visibility.</p>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-5">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex justify-between items-center">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Active Tasks</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-3xl font-bold text-white mt-3 font-mono">{loading ? '...' : activeTasks}</div>
          <div className="text-xs text-slate-500 mt-1">Total registered: {tasks.length}</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex justify-between items-center">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Critical Weaknesses</span>
            <AlertTriangle className="w-4 h-4 text-red-500" />
          </div>
          <div className="text-3xl font-bold text-red-500 mt-3 font-mono">{loading ? '...' : critCount}</div>
          <div className="text-xs text-slate-500 mt-1">Requires immediate remediation</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex justify-between items-center">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">High Severity</span>
            <AlertTriangle className="w-4 h-4 text-amber-500" />
          </div>
          <div className="text-3xl font-bold text-amber-500 mt-3 font-mono">{loading ? '...' : highCount}</div>
          <div className="text-xs text-slate-500 mt-1">Total findings: {findings.length}</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex justify-between items-center">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Pending Approvals</span>
            <CheckSquare className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-3xl font-bold text-purple-400 mt-3 font-mono">{loading ? '...' : approvals.length}</div>
          <div className="text-xs text-slate-500 mt-1">Policy governance queue</div>
        </div>
      </div>

      {/* Task & Findings Tables */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            Recent Security Tasks
          </h2>
          <div className="space-y-3">
            {tasks.slice(0, 5).map((t) => (
              <div key={t.id} className="flex justify-between items-center p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <div className="flex flex-col">
                  <span className="text-sm font-medium text-slate-200">{t.objective}</span>
                  <span className="text-xs font-mono text-slate-500 mt-0.5">{t.id} • {t.mode}</span>
                </div>
                <span className={`px-2.5 py-1 text-xs font-mono rounded-full font-semibold ${
                  t.status === 'complete' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                  t.status === 'executing' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 animate-pulse' :
                  'bg-slate-800 text-slate-400'
                }`}>
                  {t.status.toUpperCase()}
                </span>
              </div>
            ))}
            {tasks.length === 0 && !loading && (
              <div className="text-center py-6 text-slate-500 text-sm">No tasks submitted yet.</div>
            )}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            Vulnerability Highlights
          </h2>
          <div className="space-y-3">
            {findings.slice(0, 5).map((f) => (
              <div key={f.id} className="flex justify-between items-center p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <div className="flex flex-col">
                  <span className="text-sm font-medium text-slate-200">{f.title}</span>
                  <span className="text-xs font-mono text-slate-500 mt-0.5">{f.target_ref}</span>
                </div>
                <span className={`px-2 py-0.5 text-xs font-mono rounded uppercase font-bold ${
                  f.severity === 'critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                  f.severity === 'high' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                  'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                }`}>
                  {f.severity}
                </span>
              </div>
            ))}
            {findings.length === 0 && !loading && (
              <div className="text-center py-6 text-slate-500 text-sm">No security findings recorded.</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
