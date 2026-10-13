import React, { useState } from 'react';
import {
  GitFork,
  Link2,
  ExternalLink,
  ShieldAlert,
  ArrowRight,
  Code,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  ChevronRight,
  Eye,
} from 'lucide-react';
import {
  CallGraphNode,
  CallGraphEdge,
  UrlProvenanceChain,
} from '../types/forensics';

interface FlowUrlViewProps {
  nodes: CallGraphNode[];
  edges: CallGraphEdge[];
  urlChains: UrlProvenanceChain[];
  onSelectNode: (node: CallGraphNode) => void;
}

export const FlowUrlView: React.FC<FlowUrlViewProps> = ({
  nodes,
  edges,
  urlChains,
  onSelectNode,
}) => {
  const [activeSection, setActiveSection] = useState<'graph' | 'urls'>('graph');
  const [filterSuspiciousOnly, setFilterSuspiciousOnly] = useState(false);

  const displayedNodes = filterSuspiciousOnly ? nodes.filter((n) => n.isSuspicious) : nodes;

  const getNodeColor = (type: CallGraphNode['type'], isSuspicious?: boolean) => {
    if (isSuspicious) return 'border-rose-500 bg-rose-950/40 text-rose-300';
    switch (type) {
      case 'entry':
      case 'lifecycle':
        return 'border-cyan-500 bg-cyan-950/40 text-cyan-300';
      case 'dialog':
        return 'border-amber-500 bg-amber-950/40 text-amber-300';
      case 'network':
        return 'border-purple-500 bg-purple-950/40 text-purple-300';
      case 'sink':
        return 'border-emerald-500 bg-emerald-950/40 text-emerald-300';
      default:
        return 'border-slate-700 bg-slate-900/60 text-slate-300';
    }
  };

  return (
    <div className="space-y-4 pb-20">
      {/* Tab Switcher */}
      <div className="grid grid-cols-2 gap-1 p-1 bg-slate-900/90 rounded-xl border border-slate-800">
        <button
          onClick={() => setActiveSection('graph')}
          className={`min-h-[40px] rounded-lg text-xs font-semibold flex items-center justify-center space-x-1.5 transition-all ${
            activeSection === 'graph'
              ? 'bg-slate-800 text-cyan-400 shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <GitFork className="w-4 h-4" />
          <span>Call Graph ({nodes.length})</span>
        </button>

        <button
          onClick={() => setActiveSection('urls')}
          className={`min-h-[40px] rounded-lg text-xs font-semibold flex items-center justify-center space-x-1.5 transition-all ${
            activeSection === 'urls'
              ? 'bg-slate-800 text-cyan-400 shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Link2 className="w-4 h-4" />
          <span>URL Provenance ({urlChains.length})</span>
        </button>
      </div>

      {/* Call Graph Section */}
      {activeSection === 'graph' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between px-1">
            <span className="text-xs font-bold text-slate-300">
              Interactive Execution & Caller Nodes
            </span>
            <label className="flex items-center space-x-2 text-[11px] text-slate-400 cursor-pointer">
              <input
                type="checkbox"
                checked={filterSuspiciousOnly}
                onChange={(e) => setFilterSuspiciousOnly(e.target.checked)}
                className="rounded border-slate-700 text-cyan-500 focus:ring-0"
              />
              <span>Suspicious Only</span>
            </label>
          </div>

          {displayedNodes.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500 rounded-2xl bg-slate-900/40 border border-slate-800">
              No matching call graph nodes discovered.
            </div>
          ) : (
            <div className="space-y-2">
              {displayedNodes.map((node, idx) => {
                const outgoingEdges = edges.filter((e) => e.source === node.id);

                return (
                  <div
                    key={`${node.id}-${idx}`}
                    onClick={() => onSelectNode(node)}
                    className={`p-3 rounded-xl border transition-all active:scale-98 cursor-pointer ${getNodeColor(
                      node.type,
                      node.isSuspicious
                    )}`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-bold uppercase bg-slate-900/80">
                        {node.type}
                      </span>
                      {node.isSuspicious && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                          Suspicious
                        </span>
                      )}
                    </div>

                    <div className="text-xs font-bold text-white font-mono truncate">
                      {node.label}
                    </div>

                    <div className="text-[11px] text-slate-400 truncate mt-0.5">
                      {node.className} • {node.filePath}
                    </div>

                    {outgoingEdges.length > 0 && (
                      <div className="mt-2 pt-2 border-t border-slate-800/80 space-y-1">
                        <div className="text-[10px] uppercase font-bold text-slate-400">
                          Invocations ({outgoingEdges.length}):
                        </div>
                        {outgoingEdges.slice(0, 3).map((edge, edgeIdx) => (
                          <div
                            key={`${edge.id}-${edgeIdx}`}
                            className="flex items-center space-x-1.5 text-[11px] text-slate-300 font-mono truncate"
                          >
                            <ArrowRight className="w-3 h-3 text-cyan-400 shrink-0" />
                            <span className="truncate">{edge.target}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* URL Provenance Section */}
      {activeSection === 'urls' && (
        <div className="space-y-3">
          <div className="px-1 text-xs text-slate-400">
            Source → Transformations → Navigation Sink Provenance Chains
          </div>

          {urlChains.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500 rounded-xl bg-slate-900/40 border border-slate-800">
              No URL navigation chains detected in parsed classes.
            </div>
          ) : (
            <div className="space-y-2.5">
              {urlChains.map((chain, idx) => (
                <div
                  key={`${chain.id}-${idx}`}
                  className="p-3.5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${
                        chain.provenanceStatus === 'proven'
                          ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                          : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                      }`}
                    >
                      {chain.provenanceStatus === 'proven' ? 'Proven Chain' : 'Partially Inferred'}
                    </span>

                    {chain.isSuspicious ? (
                      <span className="text-[10px] px-2 py-0.5 rounded-full font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                        Suspicious Target
                      </span>
                    ) : (
                      <span className="text-[10px] px-2 py-0.5 rounded-full font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                        Standard Link
                      </span>
                    )}
                  </div>

                  {/* URL Target */}
                  <div className="p-2 rounded-xl bg-slate-950 border border-slate-800">
                    <span className="text-[10px] uppercase font-bold text-slate-400 block mb-0.5">
                      Destination Endpoint:
                    </span>
                    <span className="text-xs font-mono font-bold text-cyan-400 break-all">
                      {chain.url}
                    </span>
                  </div>

                  {/* Flow Trace */}
                  <div className="space-y-1.5 text-[11px]">
                    <div>
                      <span className="text-slate-400">Source: </span>
                      <span className="text-slate-200 font-medium">
                        [{chain.originType}] {chain.originSource}
                      </span>
                    </div>

                    {chain.transformations.length > 0 && (
                      <div>
                        <span className="text-slate-400">Transformations: </span>
                        <div className="p-1.5 rounded-lg bg-slate-950/60 font-mono text-[10px] text-amber-300 mt-0.5 space-y-0.5">
                          {chain.transformations.map((t, idx) => (
                            <div key={idx}>• {t}</div>
                          ))}
                        </div>
                      </div>
                    )}

                    <div>
                      <span className="text-slate-400">Navigation Sink: </span>
                      <span className="text-emerald-400 font-mono font-semibold block mt-0.5">
                        {chain.navigationSink}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
