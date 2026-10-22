import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Activity, Bell, CheckSquare, ChevronRight, FileText, Flame, LayoutDashboard,
  Network, Shield, TrendingUp, X,
} from 'lucide-react';

interface SidebarProps {
  open?: boolean;
  onClose?: () => void;
  pendingApprovalsCount?: number | null;
}

const navItems = [
  { to: '/', label: 'Control room', icon: LayoutDashboard, group: 'Monitor' },
  { to: '/tasks', label: 'Assessments', icon: Activity, group: 'Monitor' },
  { to: '/findings', label: 'Findings', icon: Flame, group: 'Monitor' },
  { to: '/risk', label: 'Risk intelligence', icon: TrendingUp, group: 'Monitor' },
  { to: '/attack-surface', label: 'Attack surface', icon: Network, group: 'Monitor' },
  { to: '/approvals', label: 'Approvals', icon: CheckSquare, group: 'Governance' },
  { to: '/reports', label: 'Reports & evidence', icon: FileText, group: 'Governance' },
];

export const Sidebar: React.FC<SidebarProps> = ({ open = false, onClose, pendingApprovalsCount }) => (
  <aside className={`fixed inset-y-0 left-0 z-50 flex w-[264px] -translate-x-full flex-col border-r border-white/[0.07] bg-[#0c121a] transition-transform duration-200 md:sticky md:top-0 md:z-20 md:h-screen md:translate-x-0 ${open ? 'translate-x-0' : ''}`}>
    <div className="flex h-[72px] shrink-0 items-center justify-between border-b border-white/[0.07] px-5">
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-cyan-200/15 bg-cyan-200/[0.06]"><Shield className="h-[18px] w-[18px] text-cyan-200" /></div>
        <div><div className="text-[13px] font-semibold tracking-[0.16em] text-white">SENTINEL</div><div className="mt-0.5 text-[9px] font-medium uppercase tracking-[0.16em] text-slate-500">Security operations</div></div>
      </div>
      <button aria-label="Close navigation" onClick={onClose} className="rounded-md p-1.5 text-slate-500 hover:bg-white/[0.06] hover:text-white md:hidden"><X className="h-4 w-4" /></button>
    </div>

    <nav aria-label="Main navigation" className="flex-1 overflow-y-auto px-3 py-5">
      {['Monitor', 'Governance'].map((group) => <div key={group} className="mb-6">
        <div className="mb-2 px-3 text-[9px] font-semibold uppercase tracking-[0.19em] text-slate-600">{group}</div>
        <div className="space-y-1">{navItems.filter((item) => item.group === group).map((item) => {
          const Icon = item.icon;
          return <NavLink key={item.to} to={item.to} end={item.to === '/'} className={({ isActive }) => `group flex h-10 items-center gap-3 rounded-lg border px-3 text-[12px] font-medium transition ${isActive ? 'border-cyan-200/10 bg-cyan-200/[0.065] text-cyan-100' : 'border-transparent text-slate-400 hover:bg-white/[0.035] hover:text-slate-200'}`}>
            {({ isActive }) => <><Icon className={`h-4 w-4 ${isActive ? 'text-cyan-200' : 'text-slate-500 group-hover:text-slate-300'}`} /><span className="flex-1">{item.label}</span>{item.to === '/approvals' && pendingApprovalsCount != null && pendingApprovalsCount > 0 && <span className="rounded-full bg-orange-300/10 px-2 py-0.5 text-[10px] text-orange-200">{pendingApprovalsCount}</span>}{isActive && <ChevronRight className="h-3.5 w-3.5 text-cyan-200/50" />}</>}
          </NavLink>;
        })}</div>
      </div>)}
    </nav>

    <div className="border-t border-white/[0.07] p-4">
      <div className="flex items-center gap-2.5 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2.5"><span className="flex h-7 w-7 items-center justify-center rounded-md bg-slate-700/50"><Bell className="h-3.5 w-3.5 text-slate-300" /></span><div><div className="text-[10px] font-medium text-slate-300">Sentinel console</div><div className="mt-0.5 text-[9px] text-slate-600">Live data requires API access</div></div></div>
    </div>
  </aside>
);
