import React, { useEffect, useState } from 'react';
import { fetchApprovals, decideApproval } from '../api/client';
import { ApprovalRecord } from '../types';
import { CheckSquare, Check, X } from 'lucide-react';

export const ApprovalsPage: React.FC = () => {
  const [approvals, setApprovals] = useState<ApprovalRecord[]>([]);
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    fetchApprovals().then((a) => {
      setApprovals(a);
      setLoading(false);
    });
  };

  useEffect(() => {
    load();
  }, []);

  const handleDecision = async (id: string, approve: boolean) => {
    const reason = prompt(approve ? 'Enter approval rationale:' : 'Enter rejection rationale:') || 'Operator action';
    await decideApproval(id, approve, reason);
    load();
  };

  return (
    <div className="p-8 space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Policy Governance & Approvals</h1>
          <p className="text-slate-400 text-sm mt-1">Human-in-the-loop authorization gates for elevated and offensive security actions.</p>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-950/40 text-xs font-mono text-slate-400 uppercase">
              <th className="py-3.5 px-6">Approval ID</th>
              <th className="py-3.5 px-6">Task ID</th>
              <th className="py-3.5 px-6">Action Type</th>
              <th className="py-3.5 px-6">Requested By</th>
              <th className="py-3.5 px-6">Target</th>
              <th className="py-3.5 px-6 text-right">Operator Decision</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-sm">
            {approvals.map((a) => (
              <tr key={a.approval_id} className="hover:bg-slate-800/30 transition">
                <td className="py-4 px-6 font-mono text-purple-400 font-semibold">{a.approval_id}</td>
                <td className="py-4 px-6 font-mono text-slate-400">{a.task_id}</td>
                <td className="py-4 px-6 font-mono text-cyan-400">{a.action_type}</td>
                <td className="py-4 px-6 text-slate-300">{a.requested_by}</td>
                <td className="py-4 px-6 font-mono text-xs text-amber-400">{a.target}</td>
                <td className="py-4 px-6 text-right space-x-2">
                  <button
                    onClick={() => handleDecision(a.approval_id, true)}
                    className="inline-flex items-center gap-1 px-3 py-1.5 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/30 rounded-lg text-xs font-semibold transition"
                  >
                    <Check className="w-3.5 h-3.5" />
                    Approve
                  </button>
                  <button
                    onClick={() => handleDecision(a.approval_id, false)}
                    className="inline-flex items-center gap-1 px-3 py-1.5 bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/30 rounded-lg text-xs font-semibold transition"
                  >
                    <X className="w-3.5 h-3.5" />
                    Deny
                  </button>
                </td>
              </tr>
            ))}
            {approvals.length === 0 && !loading && (
              <tr>
                <td colSpan={6} className="py-12 text-center text-slate-500">
                  <CheckSquare className="w-8 h-8 mx-auto text-slate-600 mb-2" />
                  No pending policy approval requests. All actions compliant.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
