import React, { useState } from 'react';
import {
  Wrench,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Download,
  Check,
  Layers,
  Sparkles,
  ArrowRight,
  RotateCw,
  FolderArchive,
  Undo2,
  FileCheck,
  PlayCircle,
  FileCode,
  Cpu,
  Smartphone,
} from 'lucide-react';
import { BehavioralFinding, PatchProposal, AppliedPatchRecord } from '../types/forensics';
import { validateSmali } from '../services/patchEngine';

interface PatchLabViewProps {
  selectedFinding?: BehavioralFinding;
  availableFindings: BehavioralFinding[];
  onSelectFinding: (finding: BehavioralFinding) => void;
  onGeneratePatch: (finding: BehavioralFinding) => void;
  patchProposal?: PatchProposal;
  isGeneratingPatch: boolean;
  appliedPatches: AppliedPatchRecord[];
  onApplyPatchToWorkspace: (proposal: PatchProposal, finding: BehavioralFinding) => void;
  onAutoFixAll: () => void;
  onRevertPatches: () => void;
  onOpenDownloadCenter: () => void;
  onOpenConverter?: () => void;
  onOpenMtGuide?: () => void;
}

export const PatchLabView: React.FC<PatchLabViewProps> = ({
  selectedFinding,
  availableFindings,
  onSelectFinding,
  onGeneratePatch,
  patchProposal,
  isGeneratingPatch,
  appliedPatches,
  onApplyPatchToWorkspace,
  onAutoFixAll,
  onRevertPatches,
  onOpenDownloadCenter,
  onOpenConverter,
  onOpenMtGuide,
}) => {
  const [activeCodeTab, setActiveCodeTab] = useState<'patched' | 'original'>('patched');
  const [hasUserApproved, setHasUserApproved] = useState(false);
  const [copiedCode, setCopiedCode] = useState(false);
  const [justApplied, setJustApplied] = useState(false);

  // Validate current patch proposal using deterministic Smali engine
  const validationResult = patchProposal
    ? validateSmali(patchProposal.patchedSmali)
    : undefined;

  const copyPatch = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const handleApply = () => {
    if (!patchProposal || !selectedFinding) return;
    onApplyPatchToWorkspace(patchProposal, selectedFinding);
    setJustApplied(true);
    setTimeout(() => setJustApplied(false), 2500);
  };

  return (
    <div className="space-y-4 pb-20">
      {/* Header */}
      <div className="flex items-start justify-between px-1">
        <div>
          <h2 className="text-sm font-bold text-white tracking-tight flex items-center space-x-1.5">
            <Wrench className="w-4 h-4 text-cyan-400" />
            <span>Patch Lab & Remediation Center</span>
          </h2>
          <p className="text-[11px] text-slate-400">
            Apply surgical fixes and export clean, verified Smali ZIP, DEX & APK archives.
          </p>
        </div>

        <button
          onClick={onOpenDownloadCenter}
          className="h-9 px-2.5 rounded-xl bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 active:scale-95 text-white text-xs font-bold flex items-center space-x-1.5 transition-all shadow-md shrink-0"
        >
          <FolderArchive className="w-3.5 h-3.5" />
          <span>Download Center</span>
          {appliedPatches.length > 0 && (
            <span className="w-4 h-4 rounded-full bg-white text-slate-950 text-[10px] font-black flex items-center justify-center ml-0.5">
              {appliedPatches.length}
            </span>
          )}
        </button>
      </div>

      {/* Auto-Fix Banner & Revert Control */}
      <div className="p-3.5 rounded-2xl bg-gradient-to-br from-slate-900 to-slate-850 border border-slate-700 space-y-2.5">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-bold text-white">Automated Batch Remediation</span>
          </div>
          {appliedPatches.length > 0 && (
            <button
              onClick={onRevertPatches}
              className="text-[11px] text-rose-400 hover:text-rose-300 font-semibold flex items-center space-x-1 py-0.5"
            >
              <Undo2 className="w-3.5 h-3.5" />
              <span>Revert All ({appliedPatches.length})</span>
            </button>
          )}
        </div>

        <p className="text-[11px] text-slate-300 leading-relaxed">
          Batch-neutralize all confirmed threats (forced update dialogs, unprompted popups, dynamic browser redirects) and prepare a ready-to-install clean package.
        </p>

        <div className="flex items-center space-x-2 pt-1">
          <button
            onClick={onAutoFixAll}
            className="flex-1 min-h-[42px] px-3 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 active:scale-98 text-white text-xs font-bold flex items-center justify-center space-x-1.5 transition-all shadow-md shadow-emerald-950/40"
          >
            <PlayCircle className="w-4 h-4" />
            <span>Auto-Fix All Verified Threats</span>
          </button>
        </div>
      </div>

      {/* Applied Patches Status Card */}
      {appliedPatches.length > 0 && (
        <div className="p-3.5 rounded-2xl bg-emerald-950/30 border border-emerald-500/40 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-emerald-300 flex items-center space-x-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>Active Working Copy Modified ({appliedPatches.length} Patches)</span>
            </span>
            <button
              onClick={onOpenDownloadCenter}
              className="text-[11px] text-cyan-400 font-bold hover:underline"
            >
              Get Clean Package &rarr;
            </button>
          </div>
          <div className="space-y-1">
            {appliedPatches.map((p, idx) => (
              <div
                key={`${p.id}-${idx}`}
                className="text-[11px] text-slate-300 flex items-center justify-between p-1.5 rounded-lg bg-slate-950/60 font-mono"
              >
                <span className="truncate pr-2">
                  [{idx + 1}] {p.className} &rarr; {p.methodName}
                </span>
                <span className="text-emerald-400 text-[10px] font-bold shrink-0">APPLIED</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Target Finding Selector */}
      <div className="space-y-1.5">
        <label className="text-xs font-bold text-slate-300 px-1">
          Select Individual Finding to Inspect & Patch:
        </label>
        <select
          value={selectedFinding?.id || ''}
          onChange={(e) => {
            const found = availableFindings.find((f) => f.id === e.target.value);
            if (found) {
              onSelectFinding(found);
              setHasUserApproved(false);
            }
          }}
          className="w-full h-11 px-3 rounded-xl bg-slate-900 border border-slate-800 text-xs text-white focus:outline-none focus:border-cyan-500 truncate"
        >
          {availableFindings.map((f, idx) => (
            <option key={`${f.id}-${idx}`} value={f.id}>
              [{f.severity}] {f.title} ({f.methodName})
            </option>
          ))}
        </select>
      </div>

      {selectedFinding && (
        <div className="p-3.5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-2">
          <div className="text-xs font-bold text-white">{selectedFinding.title}</div>
          <div className="text-[11px] text-slate-400 font-mono">
            {selectedFinding.className} → {selectedFinding.methodName}
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            {selectedFinding.remediation?.description || selectedFinding.rationale}
          </p>

          <button
            onClick={() => onGeneratePatch(selectedFinding)}
            disabled={isGeneratingPatch}
            className="w-full min-h-[44px] px-3 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 active:scale-98 text-white text-xs font-bold flex items-center justify-center space-x-1.5 transition-all shadow-md shadow-cyan-950/40 disabled:opacity-50"
          >
            {isGeneratingPatch ? (
              <>
                <RotateCw className="w-4 h-4 animate-spin" />
                <span>Auditing Smali Bytecode & Synthesizing Patch...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4" />
                <span>Generate Surgical Smali Patch</span>
              </>
            )}
          </button>
        </div>
      )}

      {/* Proposed Patch Section */}
      {patchProposal && (
        <div className="space-y-3">
          {/* Before/After View */}
          <div className="p-3.5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-white uppercase tracking-wider">
                Bytecode Diff Inspector
              </span>
              <div className="flex p-0.5 bg-slate-950 rounded-lg border border-slate-800">
                <button
                  onClick={() => setActiveCodeTab('patched')}
                  className={`px-2.5 py-1 text-[11px] font-bold rounded-md transition-all ${
                    activeCodeTab === 'patched'
                      ? 'bg-emerald-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Patched Smali
                </button>
                <button
                  onClick={() => setActiveCodeTab('original')}
                  className={`px-2.5 py-1 text-[11px] font-bold rounded-md transition-all ${
                    activeCodeTab === 'original'
                      ? 'bg-slate-800 text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Original Code
                </button>
              </div>
            </div>

            <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono overflow-x-auto whitespace-pre text-emerald-400 max-h-60 leading-relaxed">
              {activeCodeTab === 'patched' ? patchProposal.patchedSmali : patchProposal.originalSmali}
            </pre>

            <div className="text-xs text-slate-300 leading-relaxed bg-slate-950/60 p-2.5 rounded-xl border border-slate-800/80">
              <span className="font-semibold text-cyan-400">Diff Rationale: </span>
              {patchProposal.diffExplanation}
            </div>

            {/* Static Bytecode Validation Status */}
            {validationResult && (
              <div className="space-y-1.5 pt-1 border-t border-slate-800">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
                    Static Bytecode Integrity Validation
                  </span>
                  <span
                    className={`text-[9px] px-2 py-0.5 rounded-full font-bold uppercase ${
                      validationResult.valid
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                        : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    }`}
                  >
                    {validationResult.validationLevel}
                  </span>
                </div>

                <div className="grid grid-cols-1 gap-1.5 text-[11px]">
                  <div className="p-2 rounded-lg bg-slate-950 border border-slate-800/80 flex items-start space-x-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold text-white">Registers: </span>
                      <span className="text-slate-300">{validationResult.registerStatus}</span>
                    </div>
                  </div>

                  <div className="p-2 rounded-lg bg-slate-950 border border-slate-800/80 flex items-start space-x-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold text-white">Branch Targets: </span>
                      <span className="text-slate-300">{validationResult.branchTargetStatus}</span>
                    </div>
                  </div>

                  <div className="p-2 rounded-lg bg-slate-950 border border-slate-800/80 flex items-start space-x-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold text-white">Exception Ranges: </span>
                      <span className="text-slate-300">{validationResult.exceptionRangeStatus}</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Regression Checklist */}
            <div className="space-y-1.5 pt-1 border-t border-slate-800">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
                Regression Testing Checklist
              </span>
              <div className="space-y-1 text-[11px] text-slate-300">
                {patchProposal.regressionTestChecklist.map((item, idx) => (
                  <div key={`reg-${idx}`} className="flex items-start space-x-2">
                    <span className="text-cyan-400 font-bold shrink-0">[{idx + 1}]</span>
                    <span>{item}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Explicit Analyst Approval Requirement */}
            <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 space-y-2">
              <div className="flex items-center space-x-2 text-amber-300 text-xs font-bold">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>Analyst Approval Required</span>
              </div>
              <p className="text-[11px] text-slate-300 leading-relaxed">
                As per safe reverse-engineering policy, modifications cannot be exported or applied until you explicitly review register safety and approve the bytecode patch.
              </p>
              <label className="flex items-center space-x-2.5 text-xs text-white font-semibold cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={hasUserApproved}
                  onChange={(e) => setHasUserApproved(e.target.checked)}
                  className="w-4 h-4 rounded border-slate-700 text-cyan-500 focus:ring-0"
                />
                <span>I approve this minimal patch and verified safety risks</span>
              </label>
            </div>

            {/* Real Action Buttons */}
            <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800">
              <button
                onClick={handleApply}
                disabled={!hasUserApproved}
                className="min-h-[44px] px-3 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 active:scale-98 text-white text-xs font-bold flex items-center justify-center space-x-1.5 transition-all shadow-md shadow-emerald-950/40 disabled:opacity-40"
              >
                {justApplied ? (
                  <>
                    <Check className="w-4 h-4 text-white" />
                    <span>Applied to Working Copy!</span>
                  </>
                ) : (
                  <>
                    <FileCheck className="w-4 h-4" />
                    <span>Apply to Working Copy</span>
                  </>
                )}
              </button>

              <button
                onClick={onOpenDownloadCenter}
                disabled={!hasUserApproved && appliedPatches.length === 0}
                className="min-h-[44px] px-3 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 active:scale-98 text-white text-xs font-bold flex items-center justify-center space-x-1.5 transition-all shadow-md shadow-cyan-950/40 disabled:opacity-40"
              >
                <Download className="w-4 h-4" />
                <span>Download Clean APK/ZIP</span>
              </button>

              {onOpenConverter && (
                <button
                  onClick={onOpenConverter}
                  disabled={!hasUserApproved && appliedPatches.length === 0}
                  className="col-span-2 min-h-[44px] px-3 py-2 rounded-xl bg-purple-900/60 hover:bg-purple-800 border border-purple-700/60 active:scale-98 text-purple-200 text-xs font-bold flex items-center justify-center space-x-1.5 transition-all shadow-md disabled:opacity-40"
                >
                  <Cpu className="w-4 h-4 text-purple-400" />
                  <span>Send Approved Smali → DEX Converter</span>
                </button>
              )}

              {onOpenMtGuide && (
                <button
                  onClick={onOpenMtGuide}
                  className="col-span-2 min-h-[44px] px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-750 border border-slate-700 active:scale-98 text-slate-200 text-xs font-semibold flex items-center justify-center space-x-1.5 transition-all shadow"
                >
                  <Smartphone className="w-4 h-4 text-emerald-400" />
                  <span>How to replace DEX inside MT Manager</span>
                </button>
              )}
            </div>

            <div className="flex justify-end pt-1">
              <button
                onClick={() => copyPatch(patchProposal.patchedSmali)}
                className="text-slate-400 hover:text-white text-xs flex items-center space-x-1 py-1"
              >
                {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedCode ? 'Copied Smali' : 'Copy Smali Code'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
