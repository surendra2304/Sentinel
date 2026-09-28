import React, { useEffect, useState } from 'react';
import { ArrowRight, LoaderCircle, Network } from 'lucide-react';
import { ConsoleAttackSurface, fetchConsoleAttackSurface, fetchConsoleTasks } from '../api/client';
import { Task } from '../types';

export const AttackSurfacePage: React.FC = () => {
  const [tasks, setTasks] = useState<Task[] | null>(null);
  const [selectedTaskId, setSelectedTaskId] = useState('');
  const [report, setReport] = useState<ConsoleAttackSurface | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let active = true;
    fetchConsoleTasks().then((data) => {
      if (!active) return;
      setTasks(data);
      const initial = data.find((task) => ['planning', 'executing', 'reporting'].includes(task.status)) || data[0];
      if (initial) setSelectedTaskId(initial.id);
    }).catch((reason: unknown) => {
      if (active) setError(reason instanceof Error ? reason.message : 'Unable to load assessment list.');
    });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (!selectedTaskId) { setReport(null); return; }
    let active = true;
    setLoading(true);
    setError(null);
    fetchConsoleAttackSurface(selectedTaskId).then((data) => { if (active) setReport(data); })
      .catch((reason: unknown) => { if (active) { setReport(null); setError(reason instanceof Error ? reason.message : 'Unable to load the attack-surface inventory.'); } })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [selectedTaskId]);

  return (
    <div className="min-h-full px-4 pb-10 pt-5 sm:px-6 lg:px-9 lg:pt-8">
      <div className="mx-auto max-w-[1300px] space-y-6">
        <header className="flex flex-col justify-between gap-4 border-b border-white/[0.07] pb-6 sm:flex-row sm:items-end"><div><div className="mb-3 text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-200/70">Monitor / Asset graph</div><h1 className="text-3xl font-semibold tracking-[-0.04em] text-white">Attack surface inventory</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">Nodes and relationships captured in Sentinel’s task graph. This view does not infer exploit paths.</p></div><label className="block min-w-0 sm:w-[330px]"><span className="mb-1.5 block text-[10px] font-medium uppercase tracking-wider text-slate-500">Assessment</span><select value={selectedTaskId} onChange={(event) => setSelectedTaskId(event.target.value)} disabled={!tasks?.length} className="h-10 w-full rounded-lg border border-white/10 bg-[#111923] px-3 text-xs text-slate-200 outline-none focus:border-cyan-200/30 disabled:opacity-50"><option value="">{tasks === null ? 'Loading assessments…' : 'No assessments returned'}</option>{tasks?.map((task) => <option key={task.id} value={task.id}>{task.id} · {task.objective}</option>)}</select></label></header>

        {error && <div role="alert" className="rounded-xl border border-rose-200/15 bg-rose-200/[0.04] p-4 text-xs leading-5 text-rose-100/80">Unable to load attack-surface data. {error}</div>}
        {!error && tasks?.length === 0 && <EmptyState title="No assessments returned" detail="Select a task after one has been registered in Sentinel." />}
        {loading && <div className="panel flex items-center gap-2 p-5 text-xs text-slate-400"><LoaderCircle className="h-4 w-4 animate-spin" />Loading Sentinel’s task graph…</div>}
        {report && !loading && <>
          <section className="grid grid-cols-2 gap-3 lg:grid-cols-5">
            <CountCard label="Graph nodes" value={report.total_nodes} />
            <CountCard label="Relationships" value={report.total_edges} />
            <CountCard label="Domains" value={report.domains_count} />
            <CountCard label="IP addresses" value={report.ips_count} />
            <CountCard label="Services" value={report.services_count} />
          </section>
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.05fr)_minmax(340px,0.95fr)]">
            <section className="panel overflow-hidden"><div className="border-b border-white/[0.07] px-5 py-4 sm:px-6"><div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Task graph · {report.task_id}</div><h2 className="mt-1 text-base font-semibold text-white">Discovered nodes</h2></div>
              {report.nodes.length ? <div className="max-h-[520px] divide-y divide-white/[0.055] overflow-y-auto">{report.nodes.map((node) => <div key={node.id} className="flex items-start gap-3 px-5 py-3.5 sm:px-6"><div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-cyan-200/10 bg-cyan-200/[0.04]"><Network className="h-3.5 w-3.5 text-cyan-200" /></div><div className="min-w-0 flex-1"><div className="truncate text-sm font-medium text-slate-100">{node.label}</div><div className="mt-1 flex flex-wrap gap-x-2 text-[10px] text-slate-500"><span className="uppercase">{node.node_type}</span><span>·</span><span>{node.is_internet_facing ? 'Internet facing' : 'Not marked internet facing'}</span><span>·</span><span className="capitalize">{node.criticality} criticality</span></div></div></div>)}</div> : <EmptyState title="No graph nodes returned" detail="Sentinel has no node records for this task graph." />}
            </section>
            <section className="panel overflow-hidden"><div className="border-b border-white/[0.07] px-5 py-4 sm:px-6"><div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Relationships</div><h2 className="mt-1 text-base font-semibold text-white">Observed connections</h2></div>
              {report.edges.length ? <div className="max-h-[420px] divide-y divide-white/[0.055] overflow-y-auto">{report.edges.map((edge) => <div key={edge.id} className="flex items-center gap-2 px-5 py-4 sm:px-6"><span className="min-w-0 truncate rounded-md border border-white/[0.07] bg-white/[0.02] px-2 py-1 text-[10px] font-mono text-slate-300">{edge.source_node_id}</span><div className="flex shrink-0 flex-col items-center text-cyan-200/70"><ArrowRight className="h-3.5 w-3.5" /><span className="max-w-24 text-center text-[8px] text-slate-500">{edge.edge_type.replace(/_/g, ' ')}</span></div><span className="min-w-0 truncate rounded-md border border-white/[0.07] bg-white/[0.02] px-2 py-1 text-[10px] font-mono text-slate-300">{edge.target_node_id}</span></div>)}</div> : <EmptyState title="No relationships returned" detail="Sentinel has no graph edges for this task." />}
              <div className="border-t border-white/[0.06] px-5 py-3 text-[10px] text-slate-500 sm:px-6">Technologies: {report.technologies.length ? report.technologies.join(', ') : 'No technology entries returned'}<div className="mt-1">Generated {formatDate(report.generated_at)} · Reported internet-facing ratio {Number.isFinite(report.internet_facing_ratio) ? `${Math.round(report.internet_facing_ratio * 100)}%` : 'unavailable'}</div></div>
            </section>
          </div>
        </>}
        {!error && !loading && !report && tasks?.length && !selectedTaskId && <EmptyState title="Select an assessment" detail="The attack-surface graph is scoped to a Sentinel task." />}
      </div>
    </div>
  );
};

function CountCard({ label, value }: { label: string; value: number }) { return <div className="panel p-4"><div className="text-[10px] font-medium text-slate-500">{label}</div><div className="mt-2 text-2xl font-semibold text-white">{value}</div></div>; }
function EmptyState({ title, detail }: { title: string; detail: string }) { return <div className="px-5 py-8 sm:px-6"><div className="text-sm font-medium text-slate-300">{title}</div><p className="mt-1 text-xs leading-5 text-slate-500">{detail}</p></div>; }
function formatDate(value: string) { const date = new Date(value); return Number.isNaN(date.getTime()) ? 'time unavailable' : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date); }
