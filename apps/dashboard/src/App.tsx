import React, { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Sidebar } from './components/Sidebar';
import { OverviewPage } from './pages/OverviewPage';
import { TasksPage } from './pages/TasksPage';
import { FindingsPage } from './pages/FindingsPage';
import { ApprovalsPage } from './pages/ApprovalsPage';
import { fetchApprovals } from './api/client';

export const App: React.FC = () => {
  const [approvalsCount, setApprovalsCount] = useState(0);

  useEffect(() => {
    fetchApprovals().then((a) => setApprovalsCount(a.length));
  }, []);

  return (
    <BrowserRouter>
      <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden font-sans">
        <Sidebar pendingApprovalsCount={approvalsCount} />
        <main className="flex-1 overflow-y-auto">
          <Routes>
            <Route path="/" element={<OverviewPage />} />
            <Route path="/tasks" element={<TasksPage />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/approvals" element={<ApprovalsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
};
