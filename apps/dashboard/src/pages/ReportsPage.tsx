import React, { useEffect, useState } from 'react';
import { Archive, Download, FileText, LoaderCircle } from 'lucide-react';
import { downloadProtectedResource, fetchConsoleTasks, getEvidenceBundleDownloadUrl, getReportDownloadUrl } from '../api/client';
import { Task } from '../types';

const reportTypes = [
  { type: 'executive', name: 'Executive summary', description: 'Summary report generated from the selected task and its recorded findings.' },
  { type: 'technical', name: 'Technical report', description: 'Assessment details, findings, evidence references, and remediation recommendations.' },
  { type: 'soc_ir', name: 'SOC / incident response', description: 'SOC and incident-response report for the selected assessment.' },
  { type: 'json', name: 'Machine-readable report', description: 'Structured JSON report for downstream processing.' },
];
const formats = [
  { value: 'markdown', extension: 'md' },
  { value: 'html', extension: 'html' },
  { value: 'pdf', extension: 'pdf' },
  { value: 'json', extension: 'json' },
] as const;

export const ReportsPage: React.FC = () => {
  const [tasks, setTasks] = useState<Task[] | null>(null);
  const [taskError, setTaskError] = useState<string | null>(null);
  const [selectedTask, setSelectedTask] = useState('');
  const [downloadState, setDownloadState] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    fetchConsoleTasks().then((data) => {
      if (!active) return;
      setTasks(data);
      if (data.length) setSelectedTask(data[0].id);
    }).catch((error: unknown) => {
      if (active) setTaskError(error instanceof Error ? error.message : 'Unable to load tasks.');
    });
    return () => { active = false; };
  }, []);

  const download = async (key: string, url: string, filename: string) => {
    setDownloadState(key);
    setDownloadError(null);
    try { await downloadProtectedResource(url, filename); }
    catch (error) { setDownloadError(error instanceof Error ? error.message : 'The download failed.'); }
    finally { setDownloadState(null); }
  };

  return (
    <div className="min-h-full px-4 pb-10 pt-5 sm:px-6 lg:px-9 lg:pt-8">
      <div className="mx-auto max-w-[1250px] space-y-6">
        <header className="flex flex-col justify-between gap-4 border-b border-white/[0.07] pb-6 sm:flex-row sm:items-end"><div><div className="mb-3 text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-200/70">Governance / Outputs</div><h1 className="text-3xl font-semibold tracking-[-0.04em] text-white">Reports & evidence</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">Generate reports and evidence bundles from a task returned by Sentinel.</p></div><label className="block min-w-0 sm:w-[360px]"><span className="mb-1.5 block text-[10px] font-medium uppercase tracking-wider text-slate-500">Assessment</span><select value={selectedTask} onChange={(event) => setSelectedTask(event.target.value)} disabled={!tasks?.length} className="h-10 w-full rounded-lg border border-white/10 bg-[#111923] px-3 text-xs text-slate-200 outline-none focus:border-cyan-200/30 disabled:opacity-50"><option value="">{taskError ? 'Tasks unavailable' : tasks === null ? 'Loading assessments…' : 'No assessments returned'}</option>{tasks?.map((task) => <option key={task.id} value={task.id}>{task.id} · {task.objective}</option>)}</select></label></header>

        {taskError && <div role="alert" className="rounded-xl border border-rose-200/15 bg-rose-200/[0.04] p-4 text-xs leading-5 text-rose-100/80">Sentinel task list unavailable. {taskError}</div>}
        {!taskError && tasks?.length === 0 && <EmptyState title="No tasks returned" detail="Report generation requires a task ID from Sentinel." />}
        {downloadError && <div role="alert" className="rounded-xl border border-rose-200/15 bg-rose-200/[0.04] p-4 text-xs leading-5 text-rose-100/80">Download failed. {downloadError}</div>}
        {selectedTask && <div className="grid grid-cols-1 gap-3 md:grid-cols-2">{reportTypes.map((report) => <section key={report.type} className="panel flex flex-col justify-between gap-5 p-5 sm:p-6"><div><div className="flex items-center gap-2 text-sm font-semibold text-white"><FileText className="h-4 w-4 text-cyan-200" />{report.name}</div><p className="mt-2 text-xs leading-5 text-slate-400">{report.description}</p></div><div className="flex flex-wrap items-center justify-between gap-3 border-t border-white/[0.06] pt-4"><span className="text-[10px] uppercase tracking-wider text-slate-600">Format</span><div className="flex flex-wrap gap-2">{formats.map((format) => {
              const key = `${report.type}-${format.value}`;
              return <button key={key} disabled={downloadState !== null} onClick={() => void download(key, getReportDownloadUrl(selectedTask, report.type, format.value), `sentinel-${selectedTask}-${report.type}.${format.extension}`)} className="inline-flex h-8 items-center gap-1.5 rounded-md border border-white/[0.09] bg-white/[0.025] px-2.5 text-[10px] font-medium uppercase text-slate-300 transition hover:border-cyan-200/20 hover:text-white disabled:opacity-50">{downloadState === key ? <LoaderCircle className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3 text-cyan-200" />}{format.value === 'markdown' ? 'MD' : format.value}</button>;
            })}</div></div></section>)}</div>}
        {selectedTask && <section className="panel flex flex-col justify-between gap-5 p-5 sm:flex-row sm:items-center sm:p-6"><div><div className="flex items-center gap-2 text-sm font-semibold text-white"><Archive className="h-4 w-4 text-violet-200" />Evidence bundle</div><p className="mt-2 text-xs leading-5 text-slate-400">Download the recorded evidence bundle for this task.</p></div><button disabled={downloadState !== null} onClick={() => void download('evidence', getEvidenceBundleDownloadUrl(selectedTask), `sentinel-${selectedTask}-evidence.zip`)} className="inline-flex h-9 shrink-0 items-center justify-center gap-2 rounded-lg border border-violet-200/15 bg-violet-200/[0.05] px-3.5 text-xs font-medium text-violet-100 transition hover:bg-violet-200/10 disabled:opacity-50">{downloadState === 'evidence' ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}Export ZIP</button></section>}
      </div>
    </div>
  );
};

function EmptyState({ title, detail }: { title: string; detail: string }) { return <div className="panel px-5 py-8"><div className="text-sm font-medium text-slate-300">{title}</div><p className="mt-1 text-xs leading-5 text-slate-500">{detail}</p></div>; }
