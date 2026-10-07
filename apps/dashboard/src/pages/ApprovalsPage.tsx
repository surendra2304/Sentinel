import React, { FormEvent, useCallback, useEffect, useState } from 'react';
import { Check, CheckCircle2, LoaderCircle, ShieldCheck, X } from 'lucide-react';
import { decideApproval, fetchConsoleApprovals } from '../api/client';
import { ApprovalRecord } from '../types';

type Decision = { approval: ApprovalRecord; approve: boolean };

export const ApprovalsPage: React.FC = () => {
  const [approvals, setApprovals] = useState<ApprovalRecord[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [decision, setDecision] = useState<Decision | null>(null);
  const [operator, setOperator] = useState('');
  const [justification, setJustification] = useState('');
  const [authorizationReference, setAuthorizationReference] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try { setApprovals(await fetchConsoleApprovals()); setError(null); }
    catch (reason) { setApprovals(null); setError(reason instanceof Error ? reason.message : 'Unable to load pending approvals.'); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const openDecision = (approval: ApprovalRecord, approve: boolean) => {
    setDecision({ approval, approve });
    setOperator('');
    setJustification('');
    setAuthorizationReference('');
  };

  const submitDecision = async (event: FormEvent) => {
    event.preventDefault();
    if (!decision || !operator.trim() || !justification.trim()) return;
    setSubmitting(true);
    const ok = await decideApproval(decision.approval.approval_id, decision.approve, operator.trim(), justification.trim(), authorizationReference.trim() || undefined);
    setSubmitting(false);
    if (!ok) { setError('Sentinel did not accept the decision. Verify API access and that the approval is still pending.'); return; }
    setDecision(null);
    await load();
  };

  return (
    <div className="min-h-full px-4 pb-10 pt-5 sm:px-6 lg:px-9 lg:pt-8">
      <div className="mx-auto max-w-[1250px] space-y-6">
        <header className="border-b border-white/[0.07] pb-6"><div className="mb-3 text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-200/70">Governance / Human review</div><h1 className="text-3xl font-semibold tracking-[-0.04em] text-white">Pending approvals</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">Review the authorization request from Sentinel and submit a decision with your operator identity and rationale.</p></header>
        {error && <div role="alert" className="rounded-xl border border-rose-200/15 bg-rose-200/[0.04] p-4 text-xs leading-5 text-rose-100/80">Approval data or decision unavailable. {error}</div>}
        <section className="panel overflow-hidden">
          <div className="flex items-center justify-between border-b border-white/[0.07] px-5 py-4 sm:px-6"><div><div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Operator queue</div><h2 className="mt-1 text-base font-semibold text-white">Approval requests</h2></div>{approvals && <span className="rounded-full border border-white/[0.08] px-2.5 py-1 text-[10px] text-slate-400">{approvals.length} pending</span>}</div>
          {loading ? <div className="flex items-center gap-2 p-6 text-xs text-slate-400"><LoaderCircle className="h-4 w-4 animate-spin" />Loading approvals…</div> : !error && approvals?.length === 0 ? <div className="p-8"><div className="flex items-center gap-2 text-sm font-medium text-slate-300"><CheckCircle2 className="h-4 w-4 text-emerald-200" />No pending approvals returned</div><p className="mt-1.5 text-xs text-slate-500">This is the current response from Sentinel’s approvals endpoint.</p></div> : approvals && <div className="divide-y divide-white/[0.055]">{approvals.map((approval) => <article key={approval.approval_id} className="grid gap-4 px-5 py-5 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-center lg:px-6"><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><span className="text-sm font-semibold text-slate-100">{approval.action_type}</span><span className="rounded border border-orange-200/15 bg-orange-200/[0.04] px-2 py-0.5 text-[9px] uppercase tracking-wide text-orange-100">{approval.status}</span></div><div className="mt-2 grid gap-x-5 gap-y-1 text-[11px] text-slate-500 sm:grid-cols-2"><span>Request <span className="font-mono text-slate-400">{approval.approval_id}</span></span><span>Task <span className="font-mono text-slate-400">{approval.task_id}</span></span><span>Requested by <span className="text-slate-300">{approval.requested_by}</span></span><span>Expires <span className="text-slate-300">{formatTime(approval.expires_at)}</span></span></div><div className="mt-3 rounded-lg border border-white/[0.06] bg-white/[0.015] p-3"><div className="text-[9px] font-semibold uppercase tracking-wide text-slate-500">Target</div><div className="mt-1 break-all font-mono text-xs text-slate-300">{approval.target_refs.join(', ')}</div><p className="mt-2 text-xs leading-5 text-slate-400">{approval.justification_needed}</p></div></div><div className="flex gap-2 lg:flex-col"><button onClick={() => openDecision(approval, true)} className="inline-flex h-9 flex-1 items-center justify-center gap-1.5 rounded-lg border border-emerald-200/15 bg-emerald-200/[0.05] px-3 text-xs font-medium text-emerald-100 hover:bg-emerald-200/10 lg:flex-none"><Check className="h-3.5 w-3.5" />Approve</button><button onClick={() => openDecision(approval, false)} className="inline-flex h-9 flex-1 items-center justify-center gap-1.5 rounded-lg border border-rose-200/15 bg-rose-200/[0.04] px-3 text-xs font-medium text-rose-100 hover:bg-rose-200/10 lg:flex-none"><X className="h-3.5 w-3.5" />Reject</button></div></article>)}</div>}
        </section>
      </div>

      {decision && <div className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-sm" onMouseDown={(event) => { if (event.target === event.currentTarget && !submitting) setDecision(null); }}>
        <form onSubmit={submitDecision} className="w-full max-w-lg space-y-4 rounded-2xl border border-white/10 bg-[#111923] p-5 shadow-2xl shadow-black/50 sm:p-6">
          <div className="flex items-start justify-between"><div className="flex gap-3"><div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-200/15 bg-cyan-200/[0.06]"><ShieldCheck className="h-4 w-4 text-cyan-200" /></div><div><h2 className="text-base font-semibold text-white">{decision.approve ? 'Approve request' : 'Reject request'}</h2><p className="mt-1 text-xs text-slate-400">{decision.approval.action_type} · {decision.approval.approval_id}</p></div></div><button type="button" aria-label="Close" disabled={submitting} onClick={() => setDecision(null)} className="rounded-md p-1.5 text-slate-500 hover:bg-white/5 hover:text-white"><X className="h-4 w-4" /></button></div>
          <label className="block text-xs font-medium text-slate-300">Operator identity<input required value={operator} onChange={(event) => setOperator(event.target.value)} placeholder="Your name or operator ID" className="mt-1.5 h-10 w-full rounded-lg border border-white/10 bg-slate-950/70 px-3 text-sm text-slate-100 outline-none focus:border-cyan-200/40" /></label>
          <label className="block text-xs font-medium text-slate-300">Decision rationale<textarea required value={justification} onChange={(event) => setJustification(event.target.value)} rows={3} placeholder="Explain why you approve or reject this action" className="mt-1.5 w-full resize-y rounded-lg border border-white/10 bg-slate-950/70 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-200/40" /></label>
          <label className="block text-xs font-medium text-slate-300">Authorization reference <span className="font-normal text-slate-500">(optional)</span><input value={authorizationReference} onChange={(event) => setAuthorizationReference(event.target.value)} placeholder="Change or ticket reference, if available" className="mt-1.5 h-10 w-full rounded-lg border border-white/10 bg-slate-950/70 px-3 text-sm text-slate-100 outline-none focus:border-cyan-200/40" /></label>
          <div className="flex justify-end gap-2 border-t border-white/[0.06] pt-4"><button type="button" disabled={submitting} onClick={() => setDecision(null)} className="rounded-lg border border-white/10 px-3 py-2 text-xs text-slate-300 hover:bg-white/[0.04]">Cancel</button><button type="submit" disabled={submitting || !operator.trim() || !justification.trim()} className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-semibold disabled:opacity-50 ${decision.approve ? 'bg-emerald-200 text-slate-950 hover:bg-emerald-100' : 'bg-rose-200 text-slate-950 hover:bg-rose-100'}`}>{submitting ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : decision.approve ? <Check className="h-3.5 w-3.5" /> : <X className="h-3.5 w-3.5" />}{submitting ? 'Submitting…' : decision.approve ? 'Confirm approval' : 'Confirm rejection'}</button></div>
        </form>
      </div>}
    </div>
  );
};

function formatTime(value: string) { const date = new Date(value); return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date); }
