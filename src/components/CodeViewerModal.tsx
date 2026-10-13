import React, { useState } from 'react';
import { X, Copy, Check, Search, FileCode } from 'lucide-react';

interface CodeViewerModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  content: string;
  highlightLineRange?: string; // e.g. "24-48"
}

export const CodeViewerModal: React.FC<CodeViewerModalProps> = ({
  isOpen,
  onClose,
  title,
  subtitle,
  content,
  highlightLineRange,
}) => {
  const [copied, setCopied] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  if (!isOpen) return null;

  const lines = content.split('\n');
  const [startLine, endLine] = highlightLineRange
    ? highlightLineRange.split('-').map((n) => parseInt(n.trim(), 10))
    : [undefined, undefined];

  const handleCopy = () => {
    navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex flex-col justify-end sm:justify-center p-0 sm:p-4">
      <div className="w-full max-w-lg bg-slate-900 border-t sm:border border-slate-700 rounded-t-3xl sm:rounded-2xl max-h-[90dvh] flex flex-col overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="p-3.5 border-b border-slate-800 flex items-center justify-between">
          <div className="min-w-0 pr-2">
            <div className="flex items-center space-x-1.5">
              <FileCode className="w-4 h-4 text-cyan-400 shrink-0" />
              <h3 className="text-xs font-bold text-white truncate">{title}</h3>
            </div>
            {subtitle && (
              <p className="text-[11px] text-slate-400 truncate mt-0.5">{subtitle}</p>
            )}
          </div>

          <div className="flex items-center space-x-1 shrink-0">
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
                  <span className="text-[10px]">Copy</span>
                </>
              )}
            </button>

            <button
              onClick={onClose}
              className="w-8 h-8 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Search Bar */}
        <div className="p-2 border-b border-slate-800 bg-slate-950/40">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Filter line text..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full h-8 pl-8 pr-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        {/* Code Content */}
        <div className="flex-1 overflow-y-auto p-3 bg-slate-950 font-mono text-[11px] leading-relaxed">
          {lines.map((line, idx) => {
            const lineNum = idx + 1;
            const isHighlighted =
              startLine !== undefined &&
              endLine !== undefined &&
              lineNum >= startLine &&
              lineNum <= endLine;
            const isMatch = searchTerm && line.toLowerCase().includes(searchTerm.toLowerCase());

            if (searchTerm && !isMatch) return null;

            return (
              <div
                key={idx}
                className={`flex items-start space-x-3 py-0.5 px-1.5 rounded ${
                  isHighlighted
                    ? 'bg-amber-500/15 text-amber-200 border-l-2 border-amber-400'
                    : isMatch
                    ? 'bg-cyan-500/15 text-cyan-200'
                    : 'text-slate-300'
                }`}
              >
                <span className="text-slate-600 select-none w-8 text-right shrink-0">
                  {lineNum}
                </span>
                <span className="whitespace-pre overflow-x-auto flex-1">{line}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
