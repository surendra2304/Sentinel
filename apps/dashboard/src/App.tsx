import React, { useEffect, useState } from 'react';
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { Menu, Shield } from 'lucide-react';
import { Sidebar } from './components/Sidebar';
import { OverviewPage } from './pages/OverviewPage';
import { TasksPage } from './pages/TasksPage';
import { FindingsPage } from './pages/FindingsPage';
import { ApprovalsPage } from './pages/ApprovalsPage';
import { RiskPage } from './pages/RiskPage';
import { ReportsPage } from './pages/ReportsPage';
import { AttackSurfacePage } from './pages/AttackSurfacePage';

const ConsoleLayout: React.FC = () => {
  const [navigationOpen, setNavigationOpen] = useState(false);
  const location = useLocation();

  useEffect(() => setNavigationOpen(false), [location.pathname]);
  useEffect(() => {
    document.body.style.overflow = navigationOpen ? 'hidden' : '';
    return () => { document.body.style.overflow = ''; };
  }, [navigationOpen]);

  return (
    <div className="min-h-screen bg-[#080d14] text-slate-100 md:flex">
      {navigationOpen && <button aria-label="Close navigation" className="fixed inset-0 z-40 bg-black/65 md:hidden" onClick={() => setNavigationOpen(false)} />}
      <Sidebar open={navigationOpen} onClose={() => setNavigationOpen(false)} />
      <main className="min-w-0 flex-1">
        <div className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-white/[0.07] bg-[#080d14]/90 px-4 backdrop-blur-xl md:hidden">
          <button aria-label="Open navigation" onClick={() => setNavigationOpen(true)} className="rounded-md p-2 text-slate-300 hover:bg-white/[0.06]"><Menu className="h-5 w-5" /></button>
          <div className="flex items-center gap-2 text-xs font-semibold tracking-[0.12em] text-white"><Shield className="h-4 w-4 text-cyan-200" /> SENTINEL</div>
          <span className="w-9" />
        </div>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/tasks" element={<TasksPage />} />
          <Route path="/attack-surface" element={<AttackSurfacePage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/risk" element={<RiskPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/approvals" element={<ApprovalsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
};

export const App: React.FC = () => <BrowserRouter><ConsoleLayout /></BrowserRouter>;
