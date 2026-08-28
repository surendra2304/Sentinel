import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  Activity, 
  Network, 
  Flame, 
  TrendingUp, 
  FileText, 
  Clock, 
  CheckSquare,
  Lock
} from 'lucide-react';

interface SidebarProps {
  pendingApprovalsCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({ pendingApprovalsCount = 0 }) => {
  const navItems = [
    { to: '/', label: 'Overview', icon: LayoutDashboard },
    { to: '/tasks', label: 'Tasks', icon: Activity },
    { to: '/attack-surface', label: 'Attack Surface', icon: Network },
    { to: '/findings', label: 'Findings', icon: Flame },
    { to: '/risk', label: 'Risk Intelligence', icon: TrendingUp },
    { to: '/reports', label: 'Reports', icon: FileText },
    { to: '/operations', label: 'Operations', icon: Clock },
    { to: '/audit-policy', label: 'Audit & Policy', icon: Lock },
    { to: '/approvals', label: 'Approvals', icon: CheckSquare, badge: pendingApprovalsCount },
  ];

  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col h-screen select-none">
      <div className="h-16 flex items-center px-6 gap-3 border-b border-slate-800">
        <ShieldAlert className="w-7 h-7 text-cyan-400" />
        <div className="flex flex-col">
          <span className="font-bold tracking-wider text-white text-lg leading-none">SENTINEL</span>
          <span className="text-[10px] text-slate-400 font-mono tracking-widest mt-1">SECURITY PLATFORM</span>
        </div>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`
              }
            >
              <Icon className="w-4 h-4" />
              <span className="flex-1">{item.label}</span>
              {Boolean(item.badge && item.badge > 0) && (
                <span className="px-2 py-0.5 text-xs font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30 rounded-full">
                  {item.badge}
                </span>
              )}
            </NavLink>
          );
        })}
      </nav>

      <div className="p-4 border-t border-slate-800 text-xs text-slate-500 flex justify-between items-center font-mono">
        <span>v1.0.0-PROD</span>
        <span className="flex items-center gap-1.5 text-emerald-400">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          ACTIVE
        </span>
      </div>
    </aside>
  );
};