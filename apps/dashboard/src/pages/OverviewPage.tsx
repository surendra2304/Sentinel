import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity, AlertTriangle, ArrowRight, ArrowUpRight, Check, CircleHelp,
  Clock3, KeyRound, LoaderCircle, RefreshCw, Shield, ShieldAlert, ShieldCheck, Wifi,
  WifiOff, X,
} from 'lucide-react';
import {
  ConsoleHealth, ConsoleRiskSummary, createTaskEventStream, fetchConsoleApprovals, fetchConsoleFindings,
  fetchConsoleHealth, fetchConsoleRiskSummary, fetchConsoleTasks, getDashboardApiKey, setDashboardApiKey,
} from '../api/client';
import { ApprovalRecord, Finding, Task } from '../types';

type LoadState<T> = { data: T | null; error: string | null; loading: boolean };
type ConsoleEvent = { id: string; name: string; detail: string; timestamp: string };

const emptyState = <T,>(): LoadState<T> => ({ data: null, error: null, loading: true });

function getEventText(value: unknown): string {
  if (!value || typeof value !== 'object') return typeof value === 'string' ? value : 'Event received';
  const payload = value as Record<string, unknown>;
  const nested = payload.payload && typeof payload.payload === 'object'
    ? payload.payload as Record<string, unknown>
    : payload;
  if (payload.topic === 'risk.updated') {
    const risk = `${nested.tier || 'unknown'} tier`;
    const score = typeof nested.score === 'number' ? ` · score ${nested.score}` : '';
    const finding = nested.finding_id ? ` · finding ${nested.finding_id}` : '';
    return `Risk update: ${risk}${score}${finding}`;
  }
  if (payload.topic === 'finding.created' || payload.topic === 'finding.updated') {
    const title = nested.title ? String(nested.title) : 'Finding record updated';
    const target = nested.target_ref ? ` · ${nested.target_ref}` : '';
    return `${title}${target}`;
  }
  return String(nested.summary || nested.title || nested.status || nested.message || payload.topic || 'Sentinel event received');
}

function formatTime(value?: string): string {
  if (!value) return 'Time unavailable';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(parsed);
}

export const OverviewPage: React.FC = () => {
  const [health, setHealth] = useState<LoadState<ConsoleHealth>>(emptyState);
  const [tasksState, setTasksState] = useState<LoadState<Task[]>>(emptyState);
  const [findingsState, setFindingsState] = useState<LoadState<Finding[]>>(emptyState);
  const [approvalsState, setApprovalsState] = useState<LoadState<ApprovalRecord[]>>(emptyState);
  const [riskState, setRiskState] = useState<LoadState<ConsoleRiskSummary>>(emptyState);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [keyDialogOpen, setKeyDialogOpen] = useState(false);
  const [apiKey, setApiKey] = useState(getDashboardApiKey);
  const [keyDraft, setKeyDraft] = useState(getDashboardApiKey);
  const [selectedTaskId, setSelectedTaskId] = useState('');
  const [streamStatus, setStreamStatus] = useState<'idle' | 'connecting' | 'connected' | 'error'>('idle');
  const [events, setEvents] = useState<ConsoleEvent[]>([]);

  const loadData = useCallback(async (manual = false) => {
    if (manual) setRefreshing(true);
    const results = await Promise.allSettled([
      fetchConsoleHealth(), fetchConsoleTasks(), fetchConsoleFindings(), fetchConsoleApprovals(),
    ]);
    const apply = <T,>(result: PromiseSettledResult<T>, setter: React.Dispatch<React.SetStateAction<LoadState<T>>>) => {
      if (result.status === 'fulfilled') setter({ data: result.value, error: null, loading: false });
      else setter({ data: null, error: result.reason instanceof Error ? result.reason.message : 'Sentinel could not load this data.', loading: false });
    };
    apply(results[0], setHealth);
    apply(results[1], setTasksState);
    apply(results[2], setFindingsState);
    apply(results[3], setApprovalsState);
    setLastUpdated(new Date().toISOString());
    setRefreshing(false);
  }, []);

  useEffect(() => {
    void loadData();
    const interval = window.setInterval(() => void loadData(), 15000);
    return () => window.clearInterval(interval);
  }, [loadData, apiKey]);

  const tasks = tasksState.data || [];
  const findings = useMemo(() => findingsState.data || [], [findingsState.data]);
  const approvals = approvalsState.data || [];
  const protectedStates = [tasksState, findingsState, approvalsState];
  const apiAuthorizationError = protectedStates.some((state) => /returned (401|403)/.test(state.error || ''));
  const protectedError = protectedStates.some((state) => Boolean(state.error));
  const protectedDataLoaded = protectedStates.some((state) => state.data !== null);
  const connectionLabel = health.error
    ? 'API unavailable'
    : apiAuthorizationError
      ? 'API key required or rejected'
      : protectedDataLoaded && protectedError
        ? 'Partial API data'
        : protectedDataLoaded
          ? 'API connected'
          : health.data
            ? 'Health check only'
            : 'Connecting';
  const activeTasks = tasks.filter((task) => ['planning', 'executing', 'reporting'].includes(task.status));
  const criticalFindings = findings.filter((finding) => finding.severity === 'critical');
  const highFindings = findings.filter((finding) => finding.severity === 'high');
  const selectedTask = tasks.find((task) => task.id === selectedTaskId) || activeTasks[0] || tasks[0];
  const currentTaskId = selectedTask?.id;
  const riskScoreValue = riskState.data && riskState.data.top_risks.length === 0 && riskState.data.total_findings > 0
    ? 'Not scored'
    : riskState.data?.overall_risk_score ?? '—';

  useEffect(() => {
    if (!currentTaskId) {
      setRiskState({ data: null, error: null, loading: false });
      return;
    }
    let current = true;
    setRiskState((previous) => ({ ...previous, loading: true, error: null }));
    fetchConsoleRiskSummary(currentTaskId).then(
      (data) => { if (current) setRiskState({ data, error: null, loading: false }); },
      (error: unknown) => { if (current) setRiskState({ data: null, error: error instanceof Error ? error.message : 'Risk summary is unavailable.', loading: false }); },
    );
    return () => { current = false; };
  }, [currentTaskId, apiKey]);
  const severityCounts = useMemo(() => [
    { name: 'Critical', color: 'bg-rose-400', count: criticalFindings.length },
    { name: 'High', color: 'bg-orange-300', count: highFindings.length },
    { name: 'Medium', color: 'bg-amber-300', count: findings.filter((finding) => finding.severity === 'medium').length },
    { name: 'Low / Info', color: 'bg-sky-300', count: findings.filter((finding) => ['low', 'info'].includes(finding.severity)).length },
  ], [criticalFindings.length, findings, highFindings.length]);
  const maxSeverity = Math.max(1, ...severityCounts.map((item) => item.count));

  useEffect(() => {
    if (!currentTaskId) {
      setStreamStatus('idle');
      setEvents([]);
      return;
    }
    setEvents([]);
    const close = createTaskEventStream(currentTaskId, (event) => {
      setEvents((previous) => [
        { id: `${Date.now()}-${Math.random()}`, name: event.name, detail: getEventText(event.data), timestamp: new Date().toISOString() },
        ...previous,
      ].slice(0, 8));
    }, setStreamStatus);
    return close;
  }, [currentTaskId, apiKey]);

  const saveApiKey = (event: React.FormEvent) => {
    event.preventDefault();
    setDashboardApiKey(keyDraft);
    setApiKey(keyDraft.trim());
    setKeyDialogOpen(false);
  };

  const recentFindings = [...findings].sort((a, b) => {
    const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return rank[a.severity] - rank[b.severity] || new Date(b.first_seen).getTime() - new Date(a.first_seen).getTime();
  }).slice(0, 5);

  return (
    <div className="min-h-full px-4 pb-10 pt-5 sm:px-6 lg:px-9 lg:pt-8">
      <div className="mx-auto max-w-[1500px] space-y-7">
        <header className="flex flex-col justify-between gap-5 border-b border-white/[0.07] pb-6 md:flex-row md:items-end">
          <div>
            <div className="mb-3 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.19em] text-cyan-300/75">
              <span className="h-1.5 w-1.5 rounded-full bg-cyan-300" /> Sentinel / Operations
            </div>
            <h1 className="text-3xl font-semibold tracking-[-0.04em] text-white sm:text-[2.15rem]">Security control room</h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">Evidence-backed findings, active assessments, and operator approvals from Sentinel’s API.</p>
          </div>
          <div className="flex flex-wrap items-center gap-2.5">
            <div className="inline-flex h-10 items-center gap-2 rounded-lg border border-white/[0.08] bg-white/[0.025] px-3 text-xs text-slate-300">
              {connectionLabel === 'API connected' ? <Wifi className="h-3.5 w-3.5 text-emerald-300" /> : connectionLabel === 'API unavailable' || connectionLabel === 'API key required or rejected' ? <WifiOff className="h-3.5 w-3.5 text-rose-300" /> : protectedStates.some((state) => state.loading) ? <LoaderCircle className="h-3.5 w-3.5 animate-spin text-amber-300" /> : <CircleHelp className="h-3.5 w-3.5 text-amber-300" />}
              <span>{connectionLabel}</span>
            </div>
            <button onClick={() => { setKeyDraft(apiKey); setKeyDialogOpen(true); }} className="inline-flex h-10 items-center gap-2 rounded-lg border border-white/[0.08] bg-white/[0.025] px-3 text-xs font-medium text-slate-300 transition hover:border-cyan-300/30 hover:text-white">
              <KeyRound className="h-3.5 w-3.5 text-slate-400" /> {apiKey ? 'API key set' : 'Connect API'}
            </button>
            <button onClick={() => void loadData(true)} disabled={refreshing} className="inline-flex h-10 items-center gap-2 rounded-lg bg-cyan-300 px-3.5 text-xs font-semibold text-slate-950 transition hover:bg-cyan-200 disabled:opacity-60">
              <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} /> Refresh
            </button>
          </div>
        </header>

        {health.error && (
          <div className="flex flex-col gap-3 rounded-xl border border-rose-300/20 bg-rose-400/[0.06] p-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-start gap-3">
              <WifiOff className="mt-0.5 h-4 w-4 shrink-0 text-rose-300" />
              <div><p className="text-sm font-medium text-rose-100">Sentinel API is not available</p><p className="mt-1 text-xs text-rose-100/60">{health.error}</p></div>
            </div>
            <button onClick={() => { setKeyDraft(apiKey); setKeyDialogOpen(true); }} className="shrink-0 rounded-md border border-rose-100/15 px-3 py-2 text-xs text-rose-50 hover:bg-rose-200/10">Check connection</button>
          </div>
        )}

        <section className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
          <MetricCard label="Critical findings" value={criticalFindings.length} state={findingsState} icon={<ShieldAlert className="h-4 w-4" />} accent="rose" detail="Returned by findings endpoint" />
          <MetricCard label="High findings" value={highFindings.length} state={findingsState} icon={<AlertTriangle className="h-4 w-4" />} accent="orange" detail="Returned by findings endpoint" />
          <MetricCard label="Active assessments" value={activeTasks.length} state={tasksState} icon={<Activity className="h-4 w-4" />} accent="cyan" detail={`${tasksState.data?.length ?? '—'} tasks returned`} />
          <MetricCard label="Pending approvals" value={approvals.length} state={approvalsState} icon={<ShieldCheck className="h-4 w-4" />} accent="violet" detail="Awaiting an operator decision" />
          <MetricCard label="Selected task risk" value={riskScoreValue} state={riskState} icon={<Shield className="h-4 w-4" />} accent="cyan" detail={riskState.data ? riskState.data.top_risks.length === 0 ? 'No calculated risk records returned' : `${riskState.data.highest_risk_tier} tier · ${riskState.data.total_findings} findings · /100` : selectedTask ? `Computed for ${selectedTask.id}` : 'Select a task to load risk'} />
        </section>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.12fr)_minmax(360px,0.88fr)]">
          <section className="panel overflow-hidden">
            <div className="flex items-start justify-between gap-4 border-b border-white/[0.07] px-5 py-4 sm:px-6">
              <div><PanelEyebrow>Current workload</PanelEyebrow><h2 className="mt-1 text-base font-semibold text-white">Assessment queue</h2></div>
              <Link to="/tasks" className="inline-flex items-center gap-1.5 text-xs font-medium text-cyan-200/80 transition hover:text-cyan-100">All tasks <ArrowRight className="h-3.5 w-3.5" /></Link>
            </div>
            <div className="divide-y divide-white/[0.055]">
              {tasksState.loading ? <PanelLoading /> : tasksState.error ? <PanelError message={tasksState.error} /> : tasks.length === 0 ? <PanelEmpty title="No assessments returned" text="Sentinel has not returned any registered tasks." /> : tasks.slice(0, 6).map((task) => (
                <button key={task.id} onClick={() => setSelectedTaskId(task.id)} className={`grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-4 px-5 py-4 text-left transition hover:bg-white/[0.025] sm:px-6 ${selectedTask?.id === task.id ? 'bg-cyan-300/[0.035]' : ''}`}>
                  <div className="min-w-0"><div className="truncate text-sm font-medium text-slate-100">{task.objective}</div><div className="mt-1.5 flex flex-wrap items-center gap-x-2.5 gap-y-1 text-[11px] text-slate-500"><span className="font-mono text-slate-400">{task.id}</span><span>{task.mode}</span><span>{task.target_count} target{task.target_count === 1 ? '' : 's'}</span></div>
                    <div className="mt-3 flex items-center gap-2"><div className="h-1 w-24 overflow-hidden rounded-full bg-white/[0.07]"><div className="h-full rounded-full bg-cyan-300" style={{ width: `${Math.min(100, Math.max(0, task.progress_percentage || 0))}%` }} /></div><span className="text-[10px] text-slate-500">{task.progress_percentage || 0}%</span></div>
                  </div>
                  <TaskStatus status={task.status} />
                </button>
              ))}
            </div>
          </section>

          <section className="panel p-5 sm:p-6">
            <div className="flex items-start justify-between gap-3">
              <div><PanelEyebrow>Observed severity</PanelEyebrow><h2 className="mt-1 text-base font-semibold text-white">Finding distribution</h2></div>
              <Link to="/findings" aria-label="Open all findings" className="rounded-md p-1.5 text-slate-500 transition hover:bg-white/[0.05] hover:text-cyan-200"><ArrowUpRight className="h-4 w-4" /></Link>
            </div>
            <div className="mt-7 space-y-5">
              {severityCounts.map((item) => <div key={item.name}>
                <div className="mb-2 flex items-center justify-between text-xs"><span className="text-slate-300">{item.name}</span><span className="font-mono text-slate-400">{findingsState.error ? '—' : item.count}</span></div>
                <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]"><div className={`h-full rounded-full ${item.color} transition-all duration-500`} style={{ width: `${findingsState.data ? (item.count / maxSeverity) * 100 : 0}%` }} /></div>
              </div>)}
            </div>
            <div className="mt-7 flex items-center justify-between border-t border-white/[0.07] pt-4 text-xs">
              <span className="text-slate-500">Total findings returned</span><span className="font-mono font-semibold text-slate-100">{findingsState.data?.length ?? (findingsState.error ? 'Unavailable' : '…')}</span>
            </div>
            <p className="mt-3 text-[11px] leading-5 text-slate-500">Counts are based on Sentinel’s findings response. No blended or inferred risk score is shown.</p>
          </section>
        </div>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.12fr)_minmax(360px,0.88fr)]">
          <section className="panel overflow-hidden">
            <div className="flex items-start justify-between border-b border-white/[0.07] px-5 py-4 sm:px-6">
              <div><PanelEyebrow>Evidence-linked records</PanelEyebrow><h2 className="mt-1 text-base font-semibold text-white">Priority findings</h2></div>
              <Link to="/findings" className="inline-flex items-center gap-1.5 text-xs font-medium text-cyan-200/80 transition hover:text-cyan-100">Review findings <ArrowRight className="h-3.5 w-3.5" /></Link>
            </div>
            <div className="divide-y divide-white/[0.055]">
              {findingsState.loading ? <PanelLoading /> : findingsState.error ? <PanelError message={findingsState.error} /> : recentFindings.length === 0 ? <PanelEmpty title="No findings returned" text="There are no finding records in the current API response." /> : recentFindings.map((finding) => <FindingRow key={finding.id} finding={finding} />)}
            </div>
          </section>

          <section className="panel overflow-hidden">
            <div className="border-b border-white/[0.07] px-5 py-4 sm:px-6">
              <div className="flex items-start justify-between gap-3">
                <div><PanelEyebrow>Task event stream</PanelEyebrow><h2 className="mt-1 text-base font-semibold text-white">Live activity</h2></div>
                <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-medium ${streamStatus === 'connected' ? 'border-emerald-300/20 bg-emerald-300/[0.06] text-emerald-200' : streamStatus === 'error' ? 'border-rose-300/20 bg-rose-300/[0.06] text-rose-200' : 'border-white/[0.09] bg-white/[0.025] text-slate-400'}`}><span className={`h-1.5 w-1.5 rounded-full ${streamStatus === 'connected' ? 'bg-emerald-300' : streamStatus === 'error' ? 'bg-rose-300' : 'bg-slate-500'}`} />{streamStatus === 'connected' ? 'Streaming' : streamStatus === 'connecting' ? 'Connecting' : streamStatus === 'error' ? 'Unavailable' : 'Waiting'}</span>
              </div>
              {selectedTask && <div className="mt-3 flex items-center gap-2 text-[11px] text-slate-500"><span className="truncate">{selectedTask.id} · {selectedTask.objective}</span></div>}
            </div>
            <div className="min-h-[208px] divide-y divide-white/[0.055]">
              {!selectedTask ? <PanelEmpty title="Select an assessment" text="Task events are streamed for an individual task. They are not a global event feed." /> : streamStatus === 'error' && events.length === 0 ? <PanelError message="The task event stream could not be opened. Check API access and retry." /> : events.length === 0 ? <PanelEmpty title={streamStatus === 'connected' ? 'Waiting for task activity' : 'Opening stream'} text={streamStatus === 'connected' ? 'New task events will appear here as Sentinel emits them.' : 'Connecting to this task’s event endpoint.'} /> : events.map((event) => <div key={event.id} className="flex gap-3 px-5 py-3.5 sm:px-6"><div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-cyan-200/10 bg-cyan-200/[0.05]"><Activity className="h-3.5 w-3.5 text-cyan-200" /></div><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-x-2 gap-y-1"><span className="text-xs font-medium text-slate-200">{event.name.replace(/\./g, ' ')}</span><span className="text-[10px] text-slate-600">{formatTime(event.timestamp)}</span></div><p className="mt-1 break-words text-xs leading-5 text-slate-400">{event.detail}</p></div></div>)}
            </div>
          </section>
        </div>

        <footer className="flex flex-col gap-2 border-t border-white/[0.06] pt-4 text-[11px] text-slate-600 sm:flex-row sm:items-center sm:justify-between">
          <span className="inline-flex items-center gap-1.5"><Clock3 className="h-3 w-3" /> {lastUpdated ? `Updated ${formatTime(lastUpdated)}` : 'Waiting for API data'}</span>
          <span>{health.data ? `${health.data.service} · ${health.data.environment} · ${health.data.version}` : 'Service details unavailable'}</span>
        </footer>
      </div>

      {keyDialogOpen && <div className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-sm" onMouseDown={(event) => { if (event.target === event.currentTarget) setKeyDialogOpen(false); }}>
        <form onSubmit={saveApiKey} className="w-full max-w-md rounded-2xl border border-white/10 bg-[#111923] p-5 shadow-2xl shadow-black/50 sm:p-6">
          <div className="flex items-start justify-between"><div className="flex gap-3"><div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-200/15 bg-cyan-200/[0.06]"><KeyRound className="h-4 w-4 text-cyan-200" /></div><div><h2 className="text-base font-semibold text-white">Connect to Sentinel</h2><p className="mt-1 text-xs text-slate-400">Enter the API key configured for the Sentinel service.</p></div></div><button type="button" aria-label="Close" onClick={() => setKeyDialogOpen(false)} className="rounded-md p-1.5 text-slate-500 hover:bg-white/5 hover:text-white"><X className="h-4 w-4" /></button></div>
          <label className="mt-5 block text-xs font-medium text-slate-300">Sentinel API key<input autoFocus type="password" value={keyDraft} onChange={(event) => setKeyDraft(event.target.value)} placeholder="Paste API key" autoComplete="off" className="mt-2 h-11 w-full rounded-lg border border-white/10 bg-slate-950/70 px-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-200/40" /></label>
          <p className="mt-2 flex items-start gap-2 text-[11px] leading-5 text-slate-500"><CircleHelp className="mt-0.5 h-3.5 w-3.5 shrink-0" />Stored in this browser tab’s session storage and sent only to the configured Sentinel API.</p>
          {apiKey && <button type="button" onClick={() => { setDashboardApiKey(''); setApiKey(''); setKeyDraft(''); setKeyDialogOpen(false); }} className="mt-4 text-xs text-rose-200/80 hover:text-rose-100">Remove saved key</button>}
          <div className="mt-5 flex justify-end gap-2"><button type="button" onClick={() => setKeyDialogOpen(false)} className="rounded-lg border border-white/10 px-3 py-2 text-xs text-slate-300 hover:bg-white/[0.04]">Cancel</button><button type="submit" className="inline-flex items-center gap-2 rounded-lg bg-cyan-300 px-3.5 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-200"><Check className="h-3.5 w-3.5" />Save and connect</button></div>
        </form>
      </div>}
    </div>
  );
};

function MetricCard({ label, value, state, icon, accent, detail }: { label: string; value: number | string; state: LoadState<unknown>; icon: React.ReactNode; accent: string; detail: string }) {
  const accents: Record<string, string> = { rose: 'text-rose-200 bg-rose-300/[0.07] border-rose-200/10', orange: 'text-orange-200 bg-orange-300/[0.07] border-orange-200/10', cyan: 'text-cyan-200 bg-cyan-300/[0.07] border-cyan-200/10', violet: 'text-violet-200 bg-violet-300/[0.07] border-violet-200/10' };
  const hasData = state.data !== null;
  return <div className="panel p-4 sm:p-5"><div className="flex items-center justify-between"><span className="text-xs font-medium text-slate-400">{label}</span><span className={`flex h-8 w-8 items-center justify-center rounded-lg border ${accents[accent]}`}>{icon}</span></div><div className="mt-4 text-3xl font-semibold tracking-tight text-white">{state.loading ? <LoaderCircle className="h-7 w-7 animate-spin text-slate-500" /> : state.error ? <span className="text-xl text-slate-600">Unavailable</span> : hasData ? value : '—'}</div><p className="mt-2 text-[11px] text-slate-500">{state.error ? 'API request failed' : detail}</p></div>;
}

function PanelEyebrow({ children }: { children: React.ReactNode }) { return <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">{children}</div>; }

function PanelLoading() { return <div className="flex items-center gap-2 px-6 py-8 text-xs text-slate-500"><LoaderCircle className="h-4 w-4 animate-spin" />Loading Sentinel data…</div>; }

function PanelError({ message }: { message: string }) { return <div className="px-6 py-8 text-xs leading-5 text-rose-200/80">Unable to load this section. {message}</div>; }

function PanelEmpty({ title, text }: { title: string; text: string }) { return <div className="px-6 py-9"><p className="text-sm font-medium text-slate-300">{title}</p><p className="mt-1.5 text-xs leading-5 text-slate-500">{text}</p></div>; }

function TaskStatus({ status }: { status: string }) {
  const active = ['planning', 'executing', 'reporting'].includes(status);
  return <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-medium capitalize ${active ? 'border-cyan-200/15 bg-cyan-200/[0.06] text-cyan-100' : status === 'failed' ? 'border-rose-200/15 bg-rose-200/[0.06] text-rose-200' : 'border-white/[0.08] bg-white/[0.025] text-slate-400'}`}><span className={`h-1.5 w-1.5 rounded-full ${active ? 'animate-pulse bg-cyan-200' : status === 'failed' ? 'bg-rose-300' : 'bg-slate-500'}`} />{status.replace(/_/g, ' ')}</span>;
}

function FindingRow({ finding }: { finding: Finding }) {
  const marker = finding.severity === 'critical' ? 'bg-rose-300' : finding.severity === 'high' ? 'bg-orange-300' : finding.severity === 'medium' ? 'bg-amber-200' : 'bg-sky-300';
  return <div className="flex items-start gap-3 px-5 py-4 sm:px-6"><span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${marker}`} /><div className="min-w-0 flex-1"><div className="truncate text-sm font-medium text-slate-100">{finding.title}</div><div className="mt-1.5 flex flex-wrap items-center gap-x-2.5 gap-y-1 text-[11px] text-slate-500"><span className="truncate font-mono">{finding.target_ref}</span><span>{finding.evidence_refs?.length ?? 0} evidence reference{finding.evidence_refs?.length === 1 ? '' : 's'}</span><span>{formatTime(finding.first_seen)}</span></div></div><span className="rounded-md border border-white/[0.08] px-2 py-1 text-[9px] font-semibold uppercase tracking-wide text-slate-300">{finding.severity}</span></div>;
}
