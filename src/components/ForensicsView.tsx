import React from 'react';
import {
  SearchCode,
  ShieldAlert,
  Play,
  RotateCw,
  Sparkles,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
  ChevronRight,
  Layers,
} from 'lucide-react';
import { TargetBehaviorType, InvestigationSession } from '../types/forensics';

interface ForensicsViewProps {
  session: InvestigationSession;
  onChangeTargetBehavior: (type: TargetBehaviorType) => void;
  onChangeObserved: (text: string) => void;
  onChangeExpected: (text: string) => void;
  onRunInvestigation: () => void;
  isAnalyzing: boolean;
  onNavigateTab: (tab: any) => void;
}

export const ForensicsView: React.FC<ForensicsViewProps> = ({
  session,
  onChangeTargetBehavior,
  onChangeObserved,
  onChangeExpected,
  onRunInvestigation,
  isAnalyzing,
  onNavigateTab,
}) => {
  const behaviorTypes: { id: TargetBehaviorType; label: string; desc: string }[] = [
    {
      id: 'forced_update',
      label: 'Forced Update Mechanism',
      desc: 'Non-dismissible modal dialogs, blocking version checks, and APK download URLs.',
    },
    {
      id: 'forced_popup',
      label: 'Forced Popup / Announcement',
      desc: 'Unprompted dialogs, repeated promos, and remote JSON messages.',
    },
    {
      id: 'forced_redirect',
      label: 'Browser Redirect & Dynamic URL',
      desc: 'StringBuilder concatenated URLs, ACTION_VIEW intents, and unprompted browser launches.',
    },
    {
      id: 'unexpected_external_link',
      label: 'External Link Inspection',
      desc: 'Differentiating legitimate user clicks from automated dispatchers.',
    },
    {
      id: 'webview_navigation',
      label: 'WebView & JS Bridge Abuse',
      desc: 'shouldOverrideUrlLoading intercepts, injected scripts, and custom tabs.',
    },
    {
      id: 'remote_configuration',
      label: 'Remote Configuration Dependencies',
      desc: 'Dynamic server endpoints, feature flags, and payload parsers.',
    },
  ];

  const phases = [
    { name: 'Phase 1: Intake & Inventory', done: session.artifacts.length > 0 },
    { name: 'Phase 2: Hypothesis Generation', done: session.findings.length > 0 },
    { name: 'Phase 3: Code Tracing & Sinks', done: session.findings.length > 0 },
    { name: 'Phase 4: Remote Data Dependency', done: session.findings.length > 0 },
    { name: 'Phase 5: Confidence & Severity', done: session.findings.length > 0 },
    { name: 'Phase 6: Minimal Safe Patch', done: session.findings.some((f) => f.remediation) },
  ];

  return (
    <div className="space-y-4 pb-20">
      {/* Target Behavior Selector */}
      <div className="space-y-2">
        <label className="text-xs font-bold uppercase tracking-wider text-slate-400 px-1 flex items-center space-x-1.5">
          <ShieldAlert className="w-4 h-4 text-cyan-400" />
          <span>Select Target Forensic Behavior</span>
        </label>

        <div className="grid grid-cols-1 gap-2">
          {behaviorTypes.map((b) => {
            const isSelected = session.targetBehavior === b.id;
            return (
              <div
                key={b.id}
                onClick={() => onChangeTargetBehavior(b.id)}
                className={`p-3 rounded-xl border transition-all active:scale-98 cursor-pointer ${
                  isSelected
                    ? 'bg-cyan-950/40 border-cyan-500 shadow-md ring-1 ring-cyan-500/50'
                    : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="text-xs font-bold text-white flex items-center space-x-2">
                    <span
                      className={`w-2 h-2 rounded-full ${
                        isSelected ? 'bg-cyan-400 shadow-sm shadow-cyan-400' : 'bg-slate-600'
                      }`}
                    />
                    <span>{b.label}</span>
                  </div>
                  {isSelected && (
                    <span className="text-[10px] text-cyan-400 font-bold uppercase">Selected</span>
                  )}
                </div>
                <div className="text-[11px] text-slate-400 mt-1 pl-4 leading-relaxed">{b.desc}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Free Text Inputs for Observed and Expected */}
      <div className="space-y-3 p-3.5 rounded-2xl bg-slate-900/90 border border-slate-800">
        <div>
          <label className="block text-xs font-bold text-slate-200 mb-1">
            Observed Symptom / Suspicious Behavior
          </label>
          <textarea
            rows={2}
            value={session.observedBehavior}
            onChange={(e) => onChangeObserved(e.target.value)}
            placeholder="e.g. Non-dismissible update popup forces APK download, or dynamic link opens browser on resume..."
            className="w-full p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors resize-none"
          />
        </div>

        <div>
          <label className="block text-xs font-bold text-slate-200 mb-1">
            Expected Baseline / Normal Operation
          </label>
          <textarea
            rows={2}
            value={session.expectedBehavior}
            onChange={(e) => onChangeExpected(e.target.value)}
            placeholder="e.g. App should launch straight to MainDashboard without forced blocking dialogs..."
            className="w-full p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors resize-none"
          />
        </div>
      </div>

      {/* Run Action Button */}
      <button
        onClick={onRunInvestigation}
        disabled={isAnalyzing || session.artifacts.length === 0}
        className="w-full min-h-[50px] px-4 py-3 rounded-2xl bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 active:scale-98 text-white shadow-xl shadow-emerald-950/40 text-sm font-bold flex items-center justify-center space-x-2 transition-all disabled:opacity-50"
      >
        {isAnalyzing ? (
          <>
            <RotateCw className="w-5 h-5 animate-spin" />
            <span>Conducting Evidence-Driven Trace...</span>
          </>
        ) : (
          <>
            <SearchCode className="w-5 h-5" />
            <span>Launch Gemini Forensic Audit</span>
          </>
        )}
      </button>

      {/* 6-Phase Investigation Workflow Status */}
      <div className="p-3.5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-2.5">
        <div className="text-xs font-bold uppercase tracking-wider text-slate-400">
          Investigation Lifecycle Status
        </div>
        <div className="space-y-1.5">
          {phases.map((p, idx) => (
            <div
              key={idx}
              className="flex items-center justify-between text-xs py-1 px-2 rounded-lg bg-slate-950/60"
            >
              <span className="text-slate-300 font-medium">{p.name}</span>
              {p.done ? (
                <span className="flex items-center space-x-1 text-emerald-400 text-[11px] font-bold">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Verified</span>
                </span>
              ) : (
                <span className="text-slate-500 text-[11px]">Pending</span>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
