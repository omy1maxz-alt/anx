import React, { useState } from 'react';
import {
  ShieldAlert,
  Beaker,
  FolderTree,
  SearchCode,
  ShieldCheck,
  CheckCircle2,
  AlertOctagon,
  ArrowRight,
  Sparkles,
  Link2,
  FolderPlus,
  BookOpen,
  ChevronDown,
  ChevronUp,
  Smartphone,
  Cpu,
  Zap,
  Bot,
  MessageSquareText,
} from 'lucide-react';
import { InvestigationSession } from '../types/forensics';
import { TEST_SCENARIOS } from '../services/testFixtures';

interface DashboardViewProps {
  session: InvestigationSession;
  onNavigateTab: (tab: any) => void;
  onSelectScenario: (scenarioId: string) => void;
  onStartAnalysis: () => void;
  onOpenNewProject: () => void;
  onOpenMtGuide?: () => void;
  onOpenChat?: () => void;
  isAnalyzing: boolean;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  session,
  onNavigateTab,
  onSelectScenario,
  onStartAnalysis,
  onOpenNewProject,
  onOpenMtGuide,
  onOpenChat,
  isAnalyzing,
}) => {
  const [showGuide, setShowGuide] = useState(false);
  const criticalFindings = session.findings.filter((f) => f.severity === 'Critical');
  const highFindings = session.findings.filter((f) => f.severity === 'High');

  return (
    <div className="space-y-4 pb-20">
      {/* Top Banner Card */}
      <div className="p-4 rounded-2xl bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 border border-slate-700/80 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 -mt-4 -mr-4 w-32 h-32 bg-cyan-500/10 rounded-full blur-2xl pointer-events-none" />
        <div className="flex items-start justify-between">
          <div>
            <div className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-[11px] font-medium mb-1.5">
              <Sparkles className="w-3 h-3" />
              <span>Evidence-Driven Forensics</span>
            </div>
            <h2 className="text-lg font-bold text-white tracking-tight">
              Android APK & Mod Reverse Engineering Lab
            </h2>
            <p className="text-xs text-slate-300 mt-1 leading-relaxed">
              Trace execution paths, unmask forced update blockers, analyze dynamic redirects, and formulate safe Smali patches with Gemini AI.
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="grid grid-cols-3 gap-1.5 mt-4 pt-3 border-t border-slate-700/60">
          <button
            onClick={onOpenNewProject}
            className="min-h-[44px] px-2 py-2 rounded-xl bg-emerald-950/60 hover:bg-emerald-900/60 active:scale-98 text-emerald-300 border border-emerald-700/60 text-xs font-semibold flex items-center justify-center space-x-1 transition-all shadow-sm"
          >
            <FolderPlus className="w-4 h-4 text-emerald-400 shrink-0" />
            <span className="truncate">New Project</span>
          </button>

          <button
            onClick={() => onNavigateTab('files')}
            className="min-h-[44px] px-2 py-2 rounded-xl bg-slate-850 hover:bg-slate-750 active:scale-98 text-slate-200 border border-slate-700 text-xs font-semibold flex items-center justify-center space-x-1 transition-all"
          >
            <FolderTree className="w-4 h-4 text-cyan-400 shrink-0" />
            <span className="truncate">Upload Files</span>
          </button>

          <button
            onClick={onStartAnalysis}
            disabled={isAnalyzing}
            className="min-h-[44px] px-2 py-2 rounded-xl bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 active:scale-98 text-white shadow-lg shadow-emerald-950/40 text-xs font-bold flex items-center justify-center space-x-1 transition-all disabled:opacity-60"
          >
            <SearchCode className="w-4 h-4 shrink-0" />
            <span className="truncate">{isAnalyzing ? 'Auditing...' : 'Run Forensics'}</span>
          </button>
        </div>
      </div>

      {/* AI Copilot Direct Chat Banner Card */}
      {onOpenChat && (
        <div className="p-3.5 rounded-2xl bg-gradient-to-r from-indigo-950/60 via-slate-900 to-cyan-950/60 border border-indigo-600/40 shadow-lg flex items-center justify-between gap-3">
          <div className="flex items-center space-x-3 min-w-0">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-indigo-600 to-cyan-500 flex items-center justify-center text-white shadow-md shadow-indigo-950/50 shrink-0">
              <Bot className="w-5 h-5" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center space-x-1.5">
                <span className="text-xs font-bold text-white">Direct AI Chat Copilot</span>
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              </div>
              <p className="text-[11px] text-slate-300 mt-0.5 truncate">
                Chat directly about your APK, Chrome adware, MT Manager, or Smali code
              </p>
            </div>
          </div>
          <button
            onClick={onOpenChat}
            className="min-h-[44px] px-3.5 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 active:scale-95 text-white font-bold text-xs shadow-md shadow-indigo-950/40 flex items-center space-x-1.5 shrink-0 transition-all"
            aria-label="Open AI Copilot Chat"
          >
            <MessageSquareText className="w-4 h-4" />
            <span>Chat</span>
          </button>
        </div>
      )}

      {/* Daily Chrome Adware & MT Manager Remediation Card */}
      <div className="p-4 rounded-2xl bg-gradient-to-r from-amber-950/40 via-slate-900 to-cyan-950/40 border border-amber-600/30 shadow-lg space-y-3">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center space-x-2.5">
            <div className="w-10 h-10 rounded-xl bg-amber-500/15 border border-amber-500/30 text-amber-400 flex items-center justify-center shrink-0">
              <Smartphone className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-1.5">
                <span className="text-xs font-bold text-white">Daily Chrome Adware Fixer</span>
                <span className="text-[9px] px-1.5 py-0.5 rounded font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  classes10.dex / MT Manager
                </span>
              </div>
              <p className="text-[11px] text-slate-300 mt-0.5">
                Fix apps that auto-open Chrome or advertising URLs everyday on startup
              </p>
            </div>
          </div>
        </div>

        <div className="text-[11px] text-slate-300 bg-slate-950/60 p-2.5 rounded-xl border border-slate-800 leading-relaxed">
          Upload your <strong>classes10.dex</strong> or MT Manager <strong>Smali ZIP</strong>. DroidForensics will pinpoint the rogue <code>ACTION_VIEW / com.android.chrome</code> intent launch, safely stub it, and generate a clean, crash-free <strong>classes10.dex</strong> ready to put back into MT Manager.
        </div>

        <div className="grid grid-cols-2 gap-2 pt-0.5">
          <button
            onClick={() => onSelectScenario('test-h-daily-chrome-adware')}
            className="min-h-[44px] px-3 py-2 rounded-xl bg-amber-500/20 hover:bg-amber-500/30 active:scale-98 text-amber-300 border border-amber-500/40 text-xs font-bold flex items-center justify-center space-x-1.5 transition-all shadow-sm"
          >
            <Zap className="w-4 h-4 text-amber-400 shrink-0" />
            <span className="truncate">Load Chrome Ad Demo</span>
          </button>

          {onOpenMtGuide && (
            <button
              onClick={onOpenMtGuide}
              className="min-h-[44px] px-3 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 active:scale-98 text-slate-950 text-xs font-bold flex items-center justify-center space-x-1.5 transition-all shadow-md shadow-cyan-950/40"
            >
              <Smartphone className="w-4 h-4 shrink-0" />
              <span className="truncate">MT Manager Guide</span>
            </button>
          )}
        </div>
      </div>

      {/* Collapsible Quick Start Guide */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/80 overflow-hidden transition-all">
        <button
          onClick={() => setShowGuide((prev) => !prev)}
          className="w-full p-3.5 flex items-center justify-between text-left select-none hover:bg-slate-850/50 transition-colors"
        >
          <div className="flex items-center space-x-2">
            <BookOpen className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-bold text-white">How to Use DroidForensics (Step-by-Step)</span>
          </div>
          {showGuide ? (
            <ChevronUp className="w-4 h-4 text-slate-400" />
          ) : (
            <ChevronDown className="w-4 h-4 text-slate-400" />
          )}
        </button>

        {showGuide && (
          <div className="px-3.5 pb-3.5 pt-1 border-t border-slate-800 text-xs text-slate-300 space-y-2.5 leading-relaxed">
            <div className="flex items-start space-x-2">
              <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 text-[10px] font-bold flex items-center justify-center shrink-0 mt-0.5">
                1
              </span>
              <div>
                <span className="font-bold text-white">Create a Project or Load a Test Fixture:</span> Tap <strong className="text-emerald-400">New Project</strong> to start blank, or click <strong className="text-cyan-400">Tests A–F</strong> in the header to load realistic test scenarios (Forced Update, Remote Popup, Dynamic Redirect, etc.).
              </div>
            </div>

            <div className="flex items-start space-x-2">
              <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 text-[10px] font-bold flex items-center justify-center shrink-0 mt-0.5">
                2
              </span>
              <div>
                <span className="font-bold text-white">Upload Files (Tab 2: Files):</span> Drag and drop APKs, DEX files, Smali directories, AndroidManifest.xml, or logcat dumps. The engine unpacks archives and extracts classes automatically.
              </div>
            </div>

            <div className="flex items-start space-x-2">
              <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 text-[10px] font-bold flex items-center justify-center shrink-0 mt-0.5">
                3
              </span>
              <div>
                <span className="font-bold text-white">Launch Forensic Audit (Tab 3: Forensics):</span> Choose the target behavior (Forced Update, Forced Popup, Dynamic Redirect), enter observed symptoms, and tap <strong className="text-emerald-400">Launch Gemini Forensic Audit</strong>.
              </div>
            </div>

            <div className="flex items-start space-x-2">
              <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 text-[10px] font-bold flex items-center justify-center shrink-0 mt-0.5">
                4
              </span>
              <div>
                <span className="font-bold text-white">Inspect Findings & Flow (Tabs 4 & 5):</span> Review confirmed findings with exact line numbers and Smali bytecode excerpts. Switch to Graph/URL tab to see visual caller chains and URL provenance paths.
              </div>
            </div>

            <div className="flex items-start space-x-2">
              <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 text-[10px] font-bold flex items-center justify-center shrink-0 mt-0.5">
                5
              </span>
              <div>
                <span className="font-bold text-white">Synthesize Patch (Tab 6: Patch Lab):</span> Generate a surgical, minimal Smali patch. Verify register counts and branch label safety, approve the modification, and export the patched Smali file or Markdown report.
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-4 gap-2">
        <div
          onClick={() => onNavigateTab('files')}
          className="p-2.5 rounded-xl bg-slate-900/90 border border-slate-800 text-center active:scale-95 transition-all cursor-pointer"
        >
          <div className="text-base font-extrabold text-cyan-400">{session.artifacts.length}</div>
          <div className="text-[10px] text-slate-400 truncate mt-0.5">Artifacts</div>
        </div>
        <div
          onClick={() => onNavigateTab('files')}
          className="p-2.5 rounded-xl bg-slate-900/90 border border-slate-800 text-center active:scale-95 transition-all cursor-pointer"
        >
          <div className="text-base font-extrabold text-emerald-400">{session.parsedClasses.length}</div>
          <div className="text-[10px] text-slate-400 truncate mt-0.5">Classes</div>
        </div>
        <div
          onClick={() => onNavigateTab('findings')}
          className="p-2.5 rounded-xl bg-slate-900/90 border border-slate-800 text-center active:scale-95 transition-all cursor-pointer"
        >
          <div className="text-base font-extrabold text-rose-400">
            {criticalFindings.length + highFindings.length}
          </div>
          <div className="text-[10px] text-slate-400 truncate mt-0.5">Threats</div>
        </div>
        <div
          onClick={() => onNavigateTab('flow')}
          className="p-2.5 rounded-xl bg-slate-900/90 border border-slate-800 text-center active:scale-95 transition-all cursor-pointer"
        >
          <div className="text-base font-extrabold text-amber-400">{session.urlChains.length}</div>
          <div className="text-[10px] text-slate-400 truncate mt-0.5">URL Sinks</div>
        </div>
      </div>

      {/* Investigation Status Summary */}
      {session.findings.length > 0 && (
        <div className="p-3.5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>Forensic Summary</span>
            </h3>
            <span
              className={`text-[10px] px-2 py-0.5 rounded-full font-bold ${
                session.overallConfidence === 'Confirmed'
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                  : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
              }`}
            >
              {session.overallConfidence || 'High confidence'}
            </span>
          </div>

          <p className="text-xs text-slate-200 leading-relaxed font-medium">
            {session.aiAnalysisSummary || 'Analysis generated across Dalvik bytecode and method callers.'}
          </p>

          {session.aiRootCause && (
            <div className="p-2.5 rounded-xl bg-slate-950/70 border border-slate-800 text-[11px] text-slate-300">
              <span className="font-semibold text-cyan-400">Root Cause: </span>
              {session.aiRootCause}
            </div>
          )}

          <div className="pt-1 flex justify-end">
            <button
              onClick={() => onNavigateTab('findings')}
              className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 py-1"
            >
              <span>Inspect {session.findings.length} findings</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* Acceptance Test Scenarios (Tests A-F) */}
      <div className="space-y-2">
        <div className="flex items-center justify-between px-1">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
            <Beaker className="w-4 h-4 text-cyan-400" />
            <span>Test Scenarios (Acceptance Tests A–F)</span>
          </h3>
          <span className="text-[11px] text-slate-500">1-Tap Load</span>
        </div>

        <div className="grid grid-cols-1 gap-2">
          {TEST_SCENARIOS.map((sc) => {
            const isCurrent = session.targetBehavior === sc.targetBehavior;
            return (
              <div
                key={sc.id}
                onClick={() => onSelectScenario(sc.id)}
                className={`p-3 rounded-xl border transition-all active:scale-98 cursor-pointer ${
                  isCurrent
                    ? 'bg-cyan-950/30 border-cyan-700/60 shadow-md'
                    : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center space-x-1.5">
                      <span className="text-xs font-bold text-white">{sc.name}</span>
                      {isCurrent && (
                        <span className="text-[9px] px-1.5 py-0.2 rounded bg-cyan-500 text-slate-950 font-black">
                          ACTIVE
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                      {sc.description}
                    </p>
                  </div>
                  <ArrowRight className="w-4 h-4 text-slate-500 shrink-0 ml-2 mt-1" />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
