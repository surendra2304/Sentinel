import React, { useEffect, useState } from 'react';
import { fetchAlerts, updateAlertStatus, fetchSchedules, fetchBaselineDiffs } from '../api/client';
import { Alert, Schedule, BaselineDiff } from '../types';
import { Clock, Bell, GitCompare, CheckCircle2 } from 'lucide-react';

export const OperationsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [diffs, setDiffs] = useState<BaselineDiff[]>([]);
  const [loading, setLoading] = useState(true);

  const loadData = () => {
    setLoading(true);
    Promise.all([fetchAlerts(), fetchSchedules(), fetchBaselineDiffs()]).then(([a, s, d]) => {
      setAlerts(a);
      setSchedules(s);
      setDiffs(d);
      setLoading(false);
    });
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleAlertAction = async (id: string, status: 'acknowledged' | 'resolved') => {
    await updateAlertStatus(id, status);
    loadData();
  };

  return (
    <div className="p-8 space-y-8" data-testid="operations-view">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Operations & Surveillance</h1>
          <p className="text-slate-400 text-sm mt-1">Continuous monitoring schedules, alert feeds with acknowledge/resolve triage, and baseline diffs.</p>
        </div>
      </div>

      {/* Alert Feed */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-5 border-b border-slate-800 flex justify-between items-center">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Bell className="w-4 h-4 text-cyan-400" />
            Live Alert Feed
          </h2>
          <span className="text-xs font-mono text-slate-400">{alerts.length} Active Alert(s)</span>
        </div>
        <div className="divide-y divide-slate-800/60">
          {alerts.map((a) => (
            <div key={a.alert_id} className="p-4 flex items-center justify-between hover:bg-slate-800/30 transition">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 text-[10px] font-mono rounded font-bold uppercase ${
                    a.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                    a.severity === 'high' ? 'bg-amber-500/20 text-amber-400' :
                    'bg-blue-500/20 text-blue-400'
                  }`}>
                    {a.severity}
                  </span>
                  <span className="text-sm font-semibold text-slate-200">{a.title}</span>
                  <span className="text-xs font-mono text-slate-500">• {a.target_ref}</span>
                </div>
                <p className="text-xs text-slate-400">{a.message}</p>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-500 mr-2 uppercase">{a.status}</span>
                {a.status === 'open' && (
                  <button
                    onClick={() => handleAlertAction(a.alert_id, 'acknowledged')}
                    className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono rounded border border-slate-700"
                  >
                    Acknowledge
                  </button>
                )}
                {a.status !== 'resolved' && (
                  <button
                    onClick={() => handleAlertAction(a.alert_id, 'resolved')}
                    className="px-2.5 py-1 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 text-xs font-mono rounded border border-emerald-500/30 flex items-center gap-1"
                  >
                    <CheckCircle2 className="w-3 h-3" />
                    Resolve
                  </button>
                )}
              </div>
            </div>
          ))}
          {alerts.length === 0 && !loading && (
            <div className="p-8 text-center text-slate-500 text-sm">No active alerts pending triage.</div>
          )}
        </div>
      </div>

      {/* Grid for Schedules & Baseline Diffs */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Continuous Monitoring Schedules */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            Scheduled Continuous Audits
          </h2>
          <div className="space-y-3">
            {schedules.map((s) => (
              <div key={s.id} className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex justify-between items-center">
                <div>
                  <span className="text-sm font-semibold text-slate-200">{s.name}</span>
                  <div className="text-xs font-mono text-slate-500 mt-0.5">{s.target_ref} • Cron: {s.cron_expression}</div>
                </div>
                <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20 uppercase font-bold">
                  {s.status}
                </span>
              </div>
            ))}
            {schedules.length === 0 && !loading && (
              <div className="p-6 text-center text-slate-500 text-sm">No cron schedules active.</div>
            )}
          </div>
        </div>

        {/* Baseline Diffs */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
            <GitCompare className="w-4 h-4 text-amber-400" />
            Attack Surface Baseline Drift
          </h2>
          <div className="space-y-3">
            {diffs.map((d) => (
              <div key={d.id} className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                <div className="flex justify-between items-start">
                  <span className="text-xs font-mono font-bold text-amber-400 uppercase">{d.diff_type.replace('_', ' ')}</span>
                  <span className="text-[10px] font-mono text-slate-500">{d.target_ref}</span>
                </div>
                <p className="text-xs text-slate-300 mt-1">{d.description}</p>
              </div>
            ))}
            {diffs.length === 0 && !loading && (
              <div className="p-6 text-center text-slate-500 text-sm">Zero baseline drift detected across targets.</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};