import React, { useEffect, useState } from 'react';
import { fetchFindings } from '../api/client';
import { Finding } from '../types';
import { Filter } from 'lucide-react';

export const FindingsPage: React.FC = () => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchFindings().then((f) => {
      setFindings(f);
      setLoading(false);
    });
  }, []);

  const filtered = findings.filter((f) => {
    if (filterSeverity !== 'all' && f.severity !== filterSeverity) return false;
    return true;
  });

  return (
    <div className="p-8 space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Findings & Weaknesses</h1>
          <p className="text-slate-400 text-sm mt-1">Evidence-backed findings with cryptographic chain-of-custody verification.</p>
        </div>
        <div className="flex items-center gap-3">
          <Filter className="w-4 h-4 text-slate-400" />
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-slate-900 border border-slate-800 text-slate-200 text-sm rounded-lg px-3 py-2 font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="all">ALL SEVERITIES</option>
            <option value="critical">CRITICAL</option>
            <option value="high">HIGH</option>
            <option value="medium">MEDIUM</option>
            <option value="low">LOW</option>
            <option value="info">INFO</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/40 text-xs font-mono text-slate-400 uppercase">
                <th className="py-3.5 px-6">Severity</th>
                <th className="py-3.5 px-6">Finding Title</th>
                <th className="py-3.5 px-6">Target Asset</th>
                <th className="py-3.5 px-6">Evidence Refs</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-sm">
              {filtered.map((f) => (
                <tr
                  key={f.id}
                  onClick={() => setSelectedFinding(f)}
                  className={`cursor-pointer transition hover:bg-slate-800/40 ${
                    selectedFinding?.id === f.id ? 'bg-cyan-500/10 border-l-2 border-cyan-500' : ''
                  }`}
                >
                  <td className="py-4 px-6">
                    <span
                      className={`px-2.5 py-0.5 text-xs font-mono rounded uppercase font-bold ${
                        f.severity === 'critical'
                          ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                          : f.severity === 'high'
                          ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                          : f.severity === 'medium'
                          ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {f.severity}
                    </span>
                  </td>
                  <td className="py-4 px-6 font-medium text-slate-200">{f.title}</td>
                  <td className="py-4 px-6 font-mono text-xs text-slate-400">{f.target_ref}</td>
                  <td className="py-4 px-6 font-mono text-xs text-cyan-400">{f.evidence_refs.length} artifact(s)</td>
                </tr>
              ))}
              {filtered.length === 0 && !loading && (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-slate-500">
                    No findings match the selected criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Finding Detail Panel */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 h-fit sticky top-6">
          {selectedFinding ? (
            <div className="space-y-4">
              <div className="flex justify-between items-start">
                <span
                  className={`px-2.5 py-0.5 text-xs font-mono rounded uppercase font-bold ${
                    selectedFinding.severity === 'critical'
                      ? 'bg-red-500/20 text-red-400'
                      : 'bg-amber-500/20 text-amber-400'
                  }`}
                >
                  {selectedFinding.severity}
                </span>
                <span className="text-xs font-mono text-slate-500">{selectedFinding.id}</span>
              </div>
              <h2 className="text-lg font-bold text-white">{selectedFinding.title}</h2>
              <div>
                <span className="text-xs font-mono text-slate-400 uppercase">Target Reference</span>
                <p className="text-sm font-mono text-cyan-400 mt-0.5">{selectedFinding.target_ref}</p>
              </div>
              <div>
                <span className="text-xs font-mono text-slate-400 uppercase">Description</span>
                <p className="text-sm text-slate-300 mt-1 leading-relaxed">{selectedFinding.description}</p>
              </div>
              {selectedFinding.remediation && (
                <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800">
                  <span className="text-xs font-mono text-emerald-400 uppercase font-semibold">Remediation Guidance</span>
                  <p className="text-xs text-slate-300 mt-1 leading-relaxed">{selectedFinding.remediation}</p>
                </div>
              )}
              <div>
                <span className="text-xs font-mono text-slate-400 uppercase">Evidence Anchors</span>
                <div className="space-y-1 mt-1">
                  {selectedFinding.evidence_refs.map((ref) => (
                    <div key={ref} className="text-xs font-mono text-cyan-400 bg-slate-950/80 px-2 py-1 rounded border border-slate-800/60">
                      SHA256 Anchor: {ref}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="py-12 text-center text-slate-500 text-sm">
              Select a finding from the table to view its cryptographic evidence and remediation guidance.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
