import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertOctagon,
  AlertTriangle,
  HelpCircle,
  FileCode,
  ArrowRight,
  Wrench,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Copy,
  Check,
  Search,
} from 'lucide-react';
import { BehavioralFinding, ConfidenceLevel, SeverityLevel } from '../types/forensics';

interface FindingsViewProps {
  findings: BehavioralFinding[];
  onOpenPatchLab: (finding: BehavioralFinding) => void;
  onInspectCode: (className: string, lineRange?: string) => void;
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  findings,
  onOpenPatchLab,
  onInspectCode,
}) => {
  const [expandedId, setExpandedId] = useState<string | null>(findings[0]?.id || null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [filterConfidence, setFilterConfidence] = useState<string>('all');

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  const copyExcerpt = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredFindings = findings.filter((f) => {
    if (filterConfidence === 'all') return true;
    return f.confidence.toLowerCase().includes(filterConfidence.toLowerCase());
  });

  const getConfidenceBadge = (conf: ConfidenceLevel) => {
    switch (conf) {
      case 'Confirmed':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'High confidence':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'Possible':
        return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40';
      case 'Unresolved':
        return 'bg-slate-700/60 text-slate-300 border-slate-600';
    }
  };

  const getSeverityBadge = (sev: SeverityLevel) => {
    switch (sev) {
      case 'Critical':
        return 'bg-rose-600 text-white font-extrabold';
      case 'High':
        return 'bg-amber-600 text-white font-bold';
      case 'Medium':
        return 'bg-yellow-600 text-white font-medium';
      case 'Low':
        return 'bg-blue-600 text-white font-medium';
      case 'Benign':
        return 'bg-emerald-600 text-white font-bold';
    }
  };

  return (
    <div className="space-y-4 pb-20">
      {/* Header & Filter */}
      <div className="flex items-center justify-between px-1">
        <div>
          <h2 className="text-sm font-bold text-white tracking-tight">
            Behavioral Forensic Findings ({findings.length})
          </h2>
          <p className="text-[11px] text-slate-400">
            Evidence-backed classification & execution traces
          </p>
        </div>

        <select
          value={filterConfidence}
          onChange={(e) => setFilterConfidence(e.target.value)}
          className="h-8 px-2 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-200 focus:outline-none focus:border-cyan-500"
        >
          <option value="all">All Confidence</option>
          <option value="confirmed">Confirmed</option>
          <option value="high">High Confidence</option>
          <option value="possible">Possible</option>
          <option value="unresolved">Unresolved</option>
        </select>
      </div>

      {filteredFindings.length === 0 ? (
        <div className="p-8 text-center text-xs text-slate-400 rounded-2xl bg-slate-900/60 border border-slate-800">
          No findings available. Run the forensic audit or load a test scenario to inspect results.
        </div>
      ) : (
        <div className="space-y-3">
          {filteredFindings.map((finding, idx) => {
            const isExpanded = expandedId === finding.id;

            return (
              <div
                key={`${finding.id}-${idx}`}
                className={`rounded-2xl border transition-all ${
                  isExpanded
                    ? 'bg-slate-900 border-slate-700 shadow-xl'
                    : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
                }`}
              >
                {/* Accordion Header */}
                <div
                  onClick={() => toggleExpand(finding.id)}
                  className="p-3.5 cursor-pointer select-none"
                >
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <div className="flex items-center space-x-1.5 flex-wrap gap-y-1">
                      <span
                        className={`text-[9px] px-1.5 py-0.5 rounded uppercase tracking-wider ${getSeverityBadge(
                          finding.severity
                        )}`}
                      >
                        {finding.severity}
                      </span>
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded-full font-bold border ${getConfidenceBadge(
                          finding.confidence
                        )}`}
                      >
                        {finding.confidence}
                      </span>
                    </div>

                    <div className="flex items-center text-slate-400">
                      {isExpanded ? (
                        <ChevronUp className="w-4 h-4" />
                      ) : (
                        <ChevronDown className="w-4 h-4" />
                      )}
                    </div>
                  </div>

                  <h3 className="text-xs font-bold text-white leading-snug">{finding.title}</h3>

                  <div className="flex items-center space-x-1.5 text-[11px] text-slate-400 mt-1">
                    <span className="text-cyan-400 font-mono truncate">{finding.className}</span>
                    <span>•</span>
                    <span className="font-mono truncate">{finding.methodName}</span>
                  </div>
                </div>

                {/* Expanded Details Body */}
                {isExpanded && (
                  <div className="px-3.5 pb-3.5 pt-1 border-t border-slate-800/80 space-y-3 text-xs">
                    {/* Rationale */}
                    <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800 text-slate-300 leading-relaxed">
                      <span className="font-semibold text-white">Rationale: </span>
                      {finding.rationale}
                    </div>

                    {/* Metadata Grid */}
                    <div className="grid grid-cols-1 gap-1.5 bg-slate-950/40 p-2.5 rounded-xl border border-slate-800/60 text-[11px]">
                      <div>
                        <span className="text-slate-400">Target File & Lines: </span>
                        <span className="text-slate-200 font-mono">
                          {finding.targetFile} (lines {finding.lineRange})
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400">Triggering Event: </span>
                        <span className="text-amber-400 font-semibold">{finding.triggeringEvent}</span>
                      </div>
                      <div>
                        <span className="text-slate-400">URL / Data Origin: </span>
                        <span className="text-cyan-400 font-mono truncate block">
                          {finding.urlOrigin}
                        </span>
                      </div>
                    </div>

                    {/* Smali Evidence Excerpt */}
                    <div className="space-y-1">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="font-bold text-slate-300 flex items-center space-x-1">
                          <FileCode className="w-3.5 h-3.5 text-emerald-400" />
                          <span>Exact Smali Evidence Excerpt:</span>
                        </span>
                        <button
                          onClick={() => copyExcerpt(finding.evidenceExcerpt, finding.id)}
                          className="text-slate-400 hover:text-slate-200 flex items-center space-x-1 py-0.5"
                        >
                          {copiedId === finding.id ? (
                            <>
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                              <span className="text-emerald-400 text-[10px]">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3.5 h-3.5" />
                              <span className="text-[10px]">Copy</span>
                            </>
                          )}
                        </button>
                      </div>

                      <pre className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-emerald-400 overflow-x-auto whitespace-pre leading-relaxed max-h-40">
                        {finding.evidenceExcerpt}
                      </pre>
                    </div>

                    {/* Execution Path */}
                    <div className="space-y-1">
                      <span className="font-bold text-slate-300 text-[11px]">
                        Execution Control Flow:
                      </span>
                      <div className="p-2 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-1">
                        {finding.executionPath.map((step, idx) => (
                          <div
                            key={idx}
                            className="flex items-center space-x-2 text-[11px] text-slate-300"
                          >
                            <span className="w-4 h-4 rounded-full bg-slate-800 text-cyan-400 text-[9px] font-bold flex items-center justify-center shrink-0">
                              {idx + 1}
                            </span>
                            <span className="font-mono truncate">{step}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Alternative Explanations & Missing Evidence */}
                    <div className="grid grid-cols-1 gap-2 text-[11px]">
                      <div className="p-2 rounded-lg bg-slate-950 border border-slate-800/80">
                        <span className="font-bold text-slate-400 block mb-0.5">
                          Alternative Explanations:
                        </span>
                        <span className="text-slate-300 leading-relaxed">
                          {finding.alternativeExplanations}
                        </span>
                      </div>
                      <div className="p-2 rounded-lg bg-slate-950 border border-slate-800/80">
                        <span className="font-bold text-amber-400 block mb-0.5">
                          Missing Evidence:
                        </span>
                        <span className="text-slate-300 leading-relaxed">
                          {finding.missingEvidence}
                        </span>
                      </div>
                    </div>

                    {/* Recommended Inspection Step */}
                    <div className="text-[11px] text-slate-300">
                      <span className="font-bold text-cyan-400">Next Forensic Step: </span>
                      {finding.recommendedInspection}
                    </div>

                    {/* Actions Row */}
                    <div className="pt-2 flex items-center justify-end space-x-2 border-t border-slate-800">
                      <button
                        onClick={() => onInspectCode(finding.className, finding.lineRange)}
                        className="min-h-[40px] px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center space-x-1.5 transition-all"
                      >
                        <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Inspect Code</span>
                      </button>

                      {finding.remediation && (
                        <button
                          onClick={() => onOpenPatchLab(finding)}
                          className="min-h-[40px] px-3 py-1.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold flex items-center space-x-1.5 transition-all shadow-md shadow-cyan-950/40"
                        >
                          <Wrench className="w-3.5 h-3.5" />
                          <span>Patch Lab</span>
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
