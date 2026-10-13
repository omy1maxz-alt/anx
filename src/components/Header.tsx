import React from 'react';
import { ShieldAlert, Sparkles, Beaker, FileText, FolderPlus, Download, Cpu, Smartphone, Bot } from 'lucide-react';

interface HeaderProps {
  onOpenNewProject: () => void;
  onOpenFixtures: () => void;
  onOpenReport: () => void;
  onOpenDownloadCenter: () => void;
  onOpenSmaliToDex: () => void;
  onOpenMtGuide?: () => void;
  onOpenChat?: () => void;
  isAiConnected: boolean;
  activeScenarioName?: string;
  appliedPatchesCount?: number;
}

export const Header: React.FC<HeaderProps> = ({
  onOpenNewProject,
  onOpenFixtures,
  onOpenReport,
  onOpenDownloadCenter,
  onOpenSmaliToDex,
  onOpenMtGuide,
  onOpenChat,
  isAiConnected,
  activeScenarioName,
  appliedPatchesCount = 0,
}) => {
  return (
    <header className="sticky top-0 z-40 bg-slate-900/95 backdrop-blur-md border-b border-slate-800 px-2.5 py-2 flex items-center justify-between text-white select-none">
      <div className="flex items-center space-x-2 min-w-0">
        <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-emerald-600 to-cyan-500 flex items-center justify-center shadow-lg shadow-emerald-950/40 shrink-0">
          <ShieldAlert className="w-4 h-4 text-white" />
        </div>
        <div className="min-w-0">
          <div className="flex items-center space-x-1">
            <h1 className="text-xs font-bold tracking-tight truncate">DroidForensics</h1>
            <span className="text-[9px] px-1 py-0.2 rounded font-mono font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
              v1.1
            </span>
          </div>
          <div className="flex items-center space-x-1 text-[10px] text-slate-400">
            <span className="flex items-center space-x-1 truncate">
              <span className={`w-1.5 h-1.5 rounded-full ${isAiConnected ? 'bg-emerald-400 shadow-sm shadow-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
              <span className="truncate">{isAiConnected ? 'Gemini 3.8 Flash' : 'Local Engine'}</span>
            </span>
            {activeScenarioName && (
              <>
                <span className="text-slate-600">•</span>
                <span className="truncate text-cyan-400 font-medium">{activeScenarioName}</span>
              </>
            )}
          </div>
        </div>
      </div>

      <div className="flex items-center space-x-1 shrink-0">
        {onOpenChat && (
          <button
            onClick={onOpenChat}
            className="h-9 px-2 rounded-lg bg-indigo-950/70 hover:bg-indigo-900/80 active:scale-95 text-indigo-300 border border-indigo-700/60 text-xs font-semibold flex items-center space-x-1 transition-all shadow-sm shadow-indigo-950/40"
            title="Chat directly with AI Copilot"
            aria-label="Chat AI"
          >
            <Bot className="w-3.5 h-3.5 text-indigo-400" />
            <span className="hidden xs:inline">Chat</span>
          </button>
        )}

        {onOpenMtGuide && (
          <button
            onClick={onOpenMtGuide}
            className="h-9 px-2 rounded-lg bg-emerald-950/60 hover:bg-emerald-900/60 active:scale-95 text-emerald-300 border border-emerald-700/60 text-xs font-semibold flex items-center space-x-1 transition-all shadow-sm"
            title="MT Manager Android Mobile Guide"
            aria-label="MT Manager Guide"
          >
            <Smartphone className="w-3.5 h-3.5 text-emerald-400" />
            <span className="hidden xs:inline">MT Guide</span>
          </button>
        )}

        <button
          onClick={onOpenSmaliToDex}
          className="h-9 px-2 rounded-lg bg-cyan-950/60 hover:bg-cyan-900/60 active:scale-95 text-cyan-300 border border-cyan-700/60 text-xs font-semibold flex items-center space-x-1 transition-all shadow-sm"
          title="Smali ZIP to DEX Assembler"
          aria-label="Smali to DEX"
        >
          <Cpu className="w-3.5 h-3.5 text-cyan-400" />
          <span className="hidden xs:inline">DEX</span>
        </button>

        <button
          onClick={onOpenNewProject}
          className="h-9 px-2 rounded-lg bg-emerald-950/60 hover:bg-emerald-900/60 active:scale-95 text-emerald-300 border border-emerald-700/60 text-xs font-semibold flex items-center space-x-1 transition-all shadow-sm"
          title="Start New Project"
          aria-label="Start New Project"
        >
          <FolderPlus className="w-3.5 h-3.5 text-emerald-400" />
          <span className="hidden sm:inline">New</span>
        </button>

        <button
          onClick={onOpenDownloadCenter}
          className="h-9 px-2 rounded-lg bg-slate-800 hover:bg-slate-700 active:scale-95 text-slate-200 border border-slate-700 text-xs font-semibold flex items-center space-x-1 transition-all relative"
          title="Download Center (Clean APK, Smali ZIP, DEX)"
          aria-label="Download Center"
        >
          <Download className="w-3.5 h-3.5 text-cyan-400" />
          <span className="hidden sm:inline">Outputs</span>
          {appliedPatchesCount > 0 && (
            <span className="w-3.5 h-3.5 rounded-full bg-emerald-500 text-slate-950 text-[9px] font-black flex items-center justify-center">
              {appliedPatchesCount}
            </span>
          )}
        </button>

        <button
          onClick={onOpenFixtures}
          className="h-9 px-2 rounded-lg bg-slate-800 hover:bg-slate-700 active:scale-95 text-slate-200 border border-slate-700 text-xs font-semibold flex items-center space-x-1 transition-all"
          title="Load Test Fixtures (A-F)"
          aria-label="Load Test Fixtures"
        >
          <Beaker className="w-3.5 h-3.5 text-cyan-400" />
          <span className="hidden sm:inline">Tests</span>
        </button>

        <button
          onClick={onOpenReport}
          className="w-9 h-9 rounded-lg bg-slate-800 hover:bg-slate-700 active:scale-95 text-slate-200 border border-slate-700 flex items-center justify-center transition-all"
          title="View Forensic Report"
          aria-label="View Forensic Report"
        >
          <FileText className="w-3.5 h-3.5 text-slate-300" />
        </button>
      </div>
    </header>
  );
};
