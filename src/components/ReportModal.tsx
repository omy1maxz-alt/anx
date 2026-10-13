import React, { useState } from 'react';
import { X, FileText, Download, Copy, Check } from 'lucide-react';
import { InvestigationSession } from '../types/forensics';
import { generateMarkdownReport } from '../services/reportGenerator';
import { downloadText } from '../services/fileDownloader';

interface ReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  session: InvestigationSession;
}

export const ReportModal: React.FC<ReportModalProps> = ({ isOpen, onClose, session }) => {
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const markdownReport = generateMarkdownReport(session);

  const handleCopy = () => {
    navigator.clipboard.writeText(markdownReport);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadMd = async () => {
    await downloadText(
      markdownReport,
      `DroidForensics_Report_${session.id}.md`,
      'text/markdown;charset=utf-8'
    );
  };

  const handleDownloadJson = async () => {
    const jsonStr = JSON.stringify(session, null, 2);
    await downloadText(
      jsonStr,
      `DroidForensics_Session_${session.id}.json`,
      'application/json;charset=utf-8'
    );
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex flex-col justify-end sm:justify-center p-0 sm:p-4">
      <div className="w-full max-w-lg bg-slate-900 border-t sm:border border-slate-700 rounded-t-3xl sm:rounded-2xl max-h-[90dvh] flex flex-col overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="p-3.5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center">
              <FileText className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-xs font-bold text-white">Forensic Investigation Report</h3>
              <p className="text-[11px] text-slate-400">Formal export & verification log</p>
            </div>
          </div>

          <div className="flex items-center space-x-1">
            <button
              onClick={handleCopy}
              className="h-8 px-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center space-x-1"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-400 text-[10px]">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span className="text-[10px]">Copy MD</span>
                </>
              )}
            </button>

            <button
              onClick={onClose}
              className="w-8 h-8 rounded-lg bg-slate-800 text-slate-400 hover:text-white flex items-center justify-center"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Content Preview */}
        <div className="flex-1 overflow-y-auto p-3.5 bg-slate-950 font-mono text-[11px] leading-relaxed text-slate-300 whitespace-pre-wrap">
          {markdownReport}
        </div>

        {/* Footer Actions */}
        <div className="p-3 border-t border-slate-800 bg-slate-900 grid grid-cols-2 gap-2">
          <button
            onClick={handleDownloadMd}
            className="min-h-[44px] px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 active:scale-98 text-slate-200 text-xs font-semibold flex items-center justify-center space-x-1.5 transition-all"
          >
            <Download className="w-4 h-4 text-cyan-400" />
            <span>Export Markdown</span>
          </button>

          <button
            onClick={handleDownloadJson}
            className="min-h-[44px] px-3 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 active:scale-98 text-white text-xs font-bold flex items-center justify-center space-x-1.5 transition-all shadow-md shadow-cyan-950/40"
          >
            <Download className="w-4 h-4" />
            <span>Export Raw JSON</span>
          </button>
        </div>
      </div>
    </div>
  );
};
