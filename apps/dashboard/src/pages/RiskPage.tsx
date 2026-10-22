import React, { useEffect, useState } from 'react';
import { ArrowUpRight, LoaderCircle, Shield, ShieldAlert } from 'lucide-react';
import { ConsoleRiskSummary, fetchConsoleRiskSummary, fetchConsoleTasks } from '../api/client';
import { Task } from '../types';

export const RiskPage: React.FC = () => {
  const [tasks, setTasks] = useState<Task[] | null>(null);
  const [taskError, setTaskError] = useState<string | null>(null);
  const [selectedTaskId, setSelectedTaskId] = useState('');
  const [risk, setRisk] = useState<ConsoleRiskSummary | null>(null);
  const [riskError, setRiskError] = useState<string | null>(null);
  const [riskLoading, setRiskLoading] = useState(false);

  useEffect(() => {
    let active = true;
    fetchConsoleTasks().then((data) => {
      if (!active) return;
      setTasks(data);
      const initial = data.find((task) => ['planning', 'executing', 'reporting'].includes(task.status)) || data[0];
      if (initial) setSelectedTaskId(initial.id);
    }).catch((error: unknown) => {
      if (active) setTaskError(error instanceof Error ? error.message : 'Unable to load assessments.');
    });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (!selectedTaskId) {
      setRisk(null);
      setRiskError(null);
      return;
    }
    let active = true;
    setRiskLoading(true);
    setRiskError(null);
    fetchConsoleRiskSummary(selectedTaskId).then((data) => {
      if (active) setRisk(data);
    }).catch((error: unknown) => {
      if (active) {
        setRisk(null);
        setRiskError(error instanceof Error ? error.message : 'Unable to load the task risk summary.');
      }
    }).finally(() => { if (active) setRiskLoading(false); });
    return () => { active = false; };
  }, [selectedTaskId]);

  const selectedTask = tasks?.find((task) => task.id === selectedTaskId);
  const hasScoredFindings = Boolean(risk?.top_risks.length);

  return (
    <div data-testid="risk-view" className="min-h-full px-4 pb-10 pt-5 sm:px-6 lg:px-9 lg:pt-8">
      <div className="mx-auto max-w-[1250px] space-y-6">
        <header className="flex flex-col justify-between gap-4 border-b border-white/[0.07] pb-6 sm:flex-row sm:items-end">
          <div><div className="mb-3 text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-200/70">Monitor / Risk intelligence</div><h1 className="text-3xl font-semibold tracking-[-0.04em] text-white">Computed task risk</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">Risk scores and tiers returned by Sentinel’s risk engine for a selected assessment.</p></div>
          <label className="block min-w-0 sm:w-[330px]"><span className="mb-1.5 block text-[10px] font-medium uppercase tracking-wider text-slate-500">Assessment</span><select value={selectedTaskId} onChange={(event) => setSelectedTaskId(event.target.value)} disabled={!tasks?.length} className="h-10 w-full rounded-lg border border-white/10 bg-[#111923] px-3 text-xs text-slate-200 outline-none focus:border-cyan-200/30 disabled:opacity-50"><option value="">{taskError ? 'Tasks unavailable' : tasks === null ? 'Loading assessments…' : 'No assessments returned'}</option>{tasks?.map((task) => <option key={task.id} value={task.id}>{task.id} · {task.objective}</option>)}</select></label>
        </header>

        {taskError && <ErrorPanel message={taskError} />}
        {!taskError && tasks?.length === 0 && <EmptyPanel title="No assessments returned" text="Risk summaries are scoped to a Sentinel task. Create or select an assessment to view its computed risk." />}
        {selectedTask && <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500"><span className="rounded-md border border-white/[0.08] px-2 py-1 font-mono text-slate-300">{selectedTask.id}</span><span>{selectedTask.objective}</span><span className="capitalize">· {selectedTask.status.replace(/_/g, ' ')}</span></div>}

        {selectedTaskId && <>
          {riskLoading && <div className="panel flex items-center gap-2 p-5 text-xs text-slate-400"><LoaderCircle className="h-4 w-4 animate-spin" />Loading risk summary from Sentinel…</div>}
          {riskError && <ErrorPanel message={riskError} />}
          {risk && !riskLoading && <>
            <section className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div className="panel p-5"><div className="flex items-center justify-between text-xs text-slate-400"><span>Computed average risk</span><Shield className="h-4 w-4 text-cyan-200" /></div><div className="mt-4 text-3xl font-semibold text-white">{hasScoredFindings ? risk.overall_risk_score : 'Not scored'}{hasScoredFindings && <span className="ml-1 text-sm font-normal text-slate-500">/ 100</span>}</div><p className="mt-2 text-[11px] text-slate-500">{hasScoredFindings ? 'Value returned by Sentinel risk summary.' : 'No calculated risk records were returned.'}</p></div>
              <div className="panel p-5"><div className="flex items-center justify-between text-xs text-slate-400"><span>Highest returned tier</span><ShieldAlert className="h-4 w-4 text-orange-200" /></div><div className="mt-4 text-3xl font-semibold capitalize text-white">{hasScoredFindings ? risk.highest_risk_tier : 'Unavailable'}</div><p className="mt-2 text-[11px] text-slate-500">Based on calculated risk records only.</p></div>
              <div className="panel p-5"><div className="flex items-center justify-between text-xs text-slate-400"><span>Risk records shown</span><ArrowUpRight className="h-4 w-4 text-violet-200" /></div><div className="mt-4 text-3xl font-semibold text-white">{risk.top_risks.length}</div><p className="mt-2 text-[11px] text-slate-500">Task findings returned: {risk.total_findings}. List is limited to the top five records.</p></div>
            </section>

            <section className="panel overflow-hidden">
              <div className="border-b border-white/[0.07] px-5 py-4 sm:px-6"><div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Sentinel risk records</div><h2 className="mt-1 text-base font-semibold text-white">Evidence-linked scoring rationale</h2></div>
              {risk.top_risks.length ? <div className="divide-y divide-white/[0.055]">{risk.top_risks.map((item) => <article key={item.id} className="grid gap-3 px-5 py-4 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center sm:px-6"><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><span className="text-sm font-medium text-slate-100">Finding {item.finding_id}</span><span className="rounded border border-white/[0.08] px-2 py-0.5 text-[9px] uppercase tracking-wide text-slate-400">{item.severity}</span></div><p className="mt-2 text-xs leading-5 text-slate-400">{item.rationale || 'No rationale was provided by the risk engine.'}</p><p className="mt-1 text-[10px] text-slate-600">Asset criticality: {item.asset_criticality}</p></div><div className="flex items-center gap-2 sm:flex-col sm:items-end"><span className="font-mono text-lg font-semibold text-white">{item.computed_risk_score}<span className="ml-1 text-[10px] font-normal text-slate-500">/100</span></span><span className="rounded-md border border-cyan-200/10 bg-cyan-200/[0.04] px-2 py-1 text-[9px] uppercase text-cyan-100">{item.risk_tier}</span></div></article>)}</div> : <EmptyPanel title="No risk records were calculated" text={`Sentinel returned ${risk.total_findings} task finding(s), but no calculated risk records. This view does not substitute a severity-based estimate.`} />}
              {risk.top_risks.length > 0 && <div className="flex flex-wrap gap-x-5 gap-y-2 border-t border-white/[0.06] px-5 py-3 text-[10px] text-slate-500 sm:px-6">{Object.entries(risk.tier_counts).map(([tier, count]) => <span key={tier} className="capitalize">{tier}: <span className="font-mono text-slate-300">{count}</span></span>)}</div>}
            </section>
          </>}
        </>}
      </div>
    </div>
  );
};

function ErrorPanel({ message }: { message: string }) { return <div className="rounded-xl border border-rose-200/15 bg-rose-200/[0.04] p-4 text-xs leading-5 text-rose-100/80">Risk data unavailable. {message}</div>; }
function EmptyPanel({ title, text }: { title: string; text: string }) { return <div className="panel px-5 py-8"><div className="text-sm font-medium text-slate-200">{title}</div><p className="mt-1.5 text-xs leading-5 text-slate-500">{text}</p></div>; }
