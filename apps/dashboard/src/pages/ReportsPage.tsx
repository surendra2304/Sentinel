import React, { useEffect, useState } from 'react';
import { fetchTasks, getReportDownloadUrl, getEvidenceBundleDownloadUrl } from '../api/client';
import { Task } from '../types';
import { FileText, Download, FileCode, Archive } from 'lucide-react';

export const ReportsPage: React.FC = () => {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [selectedTask, setSelectedTask] = useState<string>('');

  useEffect(() => {
    fetchTasks().then((t) => {
      setTasks(t);
      if (t.length > 0) setSelectedTask(t[0].id);
    });
  }, []);

  const reportTypes = [
    { type: 'executive', name: 'Executive Summary', desc: 'High-level business risk overview, CVSS score distribution, and posture trends.' },
    { type: 'technical', name: 'Technical Findings Report', desc: 'Detailed vulnerability proofs, evidence indexes, and developer remediation steps.' },
    { type: 'compliance', name: 'Compliance & Audit Matrix', desc: 'SOC 2, ISO 27001, and NIST framework requirement alignments.' },
    { type: 'incident_response', name: 'Incident & Threat Intelligence', desc: 'Timeline event reconstruction, IOC correlations, and threat actor notes.' },
  ];

  return (
    <div className="p-8 space-y-8" data-testid="reports-view">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Reports & Evidence Bundles</h1>
          <p className="text-slate-400 text-sm mt-1">Export high-fidelity Markdown, HTML, and WeasyPrint PDFs with cryptographic evidence bundles.</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs font-mono text-slate-400">SELECT TASK:</span>
          <select
            value={selectedTask}
            onChange={(e) => setSelectedTask(e.target.value)}
            className="bg-slate-900 border border-slate-800 text-slate-200 text-sm rounded-lg px-3 py-2 font-mono focus:outline-none focus:border-cyan-500"
          >
            {tasks.map((t) => (
              <option key={t.id} value={t.id}>
                {t.id} - {t.objective.slice(0, 30)}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Report Cards Matrix */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {reportTypes.map((rep) => (
          <div key={rep.type} className="bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col justify-between space-y-4">
            <div>
              <div className="flex items-center gap-2 text-cyan-400 font-semibold text-base mb-1">
                <FileText className="w-5 h-5" />
                {rep.name}
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">{rep.desc}</p>
            </div>

            <div className="pt-4 border-t border-slate-800/80 flex items-center justify-between">
              <span className="text-xs font-mono text-slate-500">FORMATS</span>
              <div className="flex gap-2">
                <a
                  href={getReportDownloadUrl(selectedTask, rep.type, 'markdown')}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded flex items-center gap-1.5 transition"
                >
                  <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                  MD
                </a>
                <a
                  href={getReportDownloadUrl(selectedTask, rep.type, 'html')}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono rounded flex items-center gap-1.5 transition"
                >
                  <Download className="w-3.5 h-3.5 text-amber-400" />
                  HTML
                </a>
                <a
                  href={getReportDownloadUrl(selectedTask, rep.type, 'pdf')}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-1.5 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-xs font-mono rounded flex items-center gap-1.5 transition font-semibold"
                >
                  <Download className="w-3.5 h-3.5" />
                  PDF
                </a>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Standalone Evidence Bundle Export */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 flex justify-between items-center">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-white font-semibold text-base">
            <Archive className="w-5 h-5 text-purple-400" />
            Cryptographic Evidence Bundle (ZIP)
          </div>
          <p className="text-xs text-slate-400">
            Download self-contained ZIP archive containing <span className="font-mono text-cyan-400">manifest.json</span>, all collected raw artifacts, SHA256 hashes, and finding-to-evidence links.
          </p>
        </div>
        <a
          href={getEvidenceBundleDownloadUrl(selectedTask)}
          download
          className="px-4 py-2 bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 rounded-lg text-sm font-semibold flex items-center gap-2 transition"
        >
          <Download className="w-4 h-4" />
          Export Evidence Bundle
        </a>
      </div>
    </div>
  );
};