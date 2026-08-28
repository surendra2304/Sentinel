import React, { useEffect, useState } from 'react';
import { fetchAuditLogs } from '../api/client';
import { AuditEntry } from '../types';
import { FileCheck, Filter, Lock } from 'lucide-react';

export const AuditPolicyPage: React.FC = () => {
  const [auditLogs, setAuditLogs] = useState<AuditEntry[]>([]);
  const [filterActor, setFilterActor] = useState<string>('all');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAuditLogs().then((logs) => {
      setAuditLogs(logs);
      setLoading(false);
    });
  }, []);

  const filteredLogs = auditLogs.filter((l) => {
    if (filterActor !== 'all' && l.actor !== filterActor) return false;
    return true;
  });

  return (
    <div className="p-8 space-y-8" data-testid="audit-policy-view">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Audit Logging & Zero-Tolerance Policy</h1>
          <p className="text-slate-400 text-sm mt-1">Cryptographically chained audit trail (SHA-256) and active execution guardrails.</p>
        </div>
      </div>

      {/* Active Policy Rules Viewer */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <h2 className="text-base font-semibold text-white flex items-center gap-2">
          <Lock className="w-4 h-4 text-cyan-400" />
          Active Policy Guardrails & Enforcement Rules
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-xs font-mono text-cyan-400 font-bold uppercase">Approval Invariant Gate</span>
              <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded uppercase font-bold">STRICT</span>
            </div>
            <p className="text-xs text-slate-300">
              Level-3 / CRITICAL impact actions unconditionally require human-in-the-loop operator approval with immutable attribution.
            </p>
          </div>

          <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-xs font-mono text-cyan-400 font-bold uppercase">Scope Smuggling Defense</span>
              <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded uppercase font-bold">ACTIVE</span>
            </div>
            <p className="text-xs text-slate-300">
              Zero-tolerance boundary checks blocking embedded IP smuggling, punycode spoofing, and unapproved wildcards.
            </p>
          </div>
        </div>
      </div>

      {/* Read-Only Filterable Audit Log Viewer */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-5 border-b border-slate-800 flex justify-between items-center">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <FileCheck className="w-4 h-4 text-purple-400" />
            Immutable Audit Trail (Append-Only Hash Chain)
          </h2>
          <div className="flex items-center gap-3">
            <Filter className="w-4 h-4 text-slate-400" />
            <select
              value={filterActor}
              onChange={(e) => setFilterActor(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono rounded-lg px-3 py-1.5 focus:outline-none"
            >
              <option value="all">ALL ACTORS</option>
              <option value="sentinel_executor">sentinel_executor</option>
              <option value="policy_engine">policy_engine</option>
              <option value="kill_switch">kill_switch</option>
            </select>
          </div>
        </div>

        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-950/40 text-xs font-mono text-slate-400 uppercase">
              <th className="py-3.5 px-6">Timestamp</th>
              <th className="py-3.5 px-6">Event Type</th>
              <th className="py-3.5 px-6">Actor</th>
              <th className="py-3.5 px-6">Decision</th>
              <th className="py-3.5 px-6 font-mono text-right">SHA-256 Hash</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-sm">
            {filteredLogs.map((log) => (
              <tr key={log.entry_id} className="hover:bg-slate-800/30 transition">
                <td className="py-4 px-6 font-mono text-xs text-slate-400">{log.timestamp}</td>
                <td className="py-4 px-6 font-mono text-xs text-cyan-400">{log.event_type}</td>
                <td className="py-4 px-6 font-medium text-slate-200">{log.actor}</td>
                <td className="py-4 px-6 font-mono text-xs">
                  <span className={`px-2 py-0.5 rounded font-bold uppercase ${
                    log.decision === 'ALLOWED' ? 'bg-emerald-500/10 text-emerald-400' :
                    log.decision === 'BLOCKED' ? 'bg-red-500/10 text-red-400' :
                    'bg-slate-800 text-slate-400'
                  }`}>
                    {log.decision}
                  </span>
                </td>
                <td className="py-4 px-6 font-mono text-[11px] text-slate-500 text-right truncate max-w-xs">{log.sha256_hash}</td>
              </tr>
            ))}
            {filteredLogs.length === 0 && !loading && (
              <tr>
                <td colSpan={5} className="py-8 text-center text-slate-500 text-sm">
                  No audit log entries found matching filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};