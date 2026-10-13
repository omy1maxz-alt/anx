import React, { useState } from 'react';
import {
  X,
  Download,
  FolderArchive,
  FileCode,
  Package,
  FileText,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  ShieldCheck,
  RotateCw,
  ExternalLink,
} from 'lucide-react';
import { DownloadPackageItem } from '../types/forensics';
import { downloadBlob } from '../services/fileDownloader';

interface DownloadCenterSheetProps {
  isOpen: boolean;
  onClose: () => void;
  packages: DownloadPackageItem[];
  isPreparing?: boolean;
}

export const DownloadCenterSheet: React.FC<DownloadCenterSheetProps> = ({
  isOpen,
  onClose,
  packages,
  isPreparing = false,
}) => {
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [copiedHashId, setCopiedHashId] = useState<string | null>(null);
  const [downloadNotice, setDownloadNotice] = useState<{
    type: 'success' | 'error' | 'info';
    filename: string;
    message: string;
  } | null>(null);

  if (!isOpen) return null;

  const handleDownload = async (pkg: DownloadPackageItem) => {
    if (isPreparing) {
      setDownloadNotice({
        type: 'info',
        filename: pkg.filename,
        message: 'Outputs are currently assembling in the background. Please wait a moment...',
      });
      return;
    }

    try {
      setDownloadingId(pkg.id);
      setDownloadNotice(null);

      const blob = await pkg.getBlob();
      const result = await downloadBlob(blob, pkg.filename);

      if (result.success) {
        setDownloadNotice({
          type: 'success',
          filename: pkg.filename,
          message: `Download started! Check your device download manager or browser folder for "${pkg.filename}".`,
        });
      } else {
        setDownloadNotice({
          type: 'error',
          filename: pkg.filename,
          message: result.error || 'Browser blocked download stream. Tap below to retry.',
        });
      }
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      console.error('Download error:', err);
      setDownloadNotice({
        type: 'error',
        filename: pkg.filename,
        message: `Failed to generate package: ${errorMsg}`,
      });
    } finally {
      setDownloadingId(null);
    }
  };

  const handleCopyHash = (hash: string, id: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHashId(id);
    setTimeout(() => setCopiedHashId(null), 2000);
  };

  const getIcon = (id: string) => {
    if (id.startsWith('dex') || id.includes('dex')) {
      return <FileCode className="w-5 h-5 text-purple-400" />;
    }
    switch (id) {
      case 'smali_zip':
        return <FolderArchive className="w-5 h-5 text-cyan-400" />;
      case 'apk':
        return <Package className="w-5 h-5 text-emerald-400" />;
      case 'patch_diff':
        return <FileCode className="w-5 h-5 text-amber-400" />;
      default:
        return <FileText className="w-5 h-5 text-blue-400" />;
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex flex-col justify-end p-0">
      <div className="w-full max-w-md mx-auto bg-slate-900 border-t border-slate-700 rounded-t-3xl max-h-[88dvh] flex flex-col overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="w-9 h-9 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center">
              <Download className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">Forensic Download Center</h3>
              <p className="text-[11px] text-slate-400">Validated, clean reverse-engineered outputs</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg bg-slate-800 text-slate-400 hover:text-white flex items-center justify-center transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Signing / Continuity Disclosure Banner */}
        <div className="px-4 py-2.5 bg-slate-950/90 border-b border-slate-800 flex items-start space-x-2 text-[11px] text-slate-300">
          <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          <span className="leading-relaxed">
            Rebuilt outputs are verified for Dalvik bytecode integrity and signed with the standard Android test key.
          </span>
        </div>

        {/* Assembly In-Progress Banner */}
        {isPreparing && (
          <div className="mx-3.5 mt-2.5 p-3 rounded-2xl bg-cyan-950/50 border border-cyan-500/30 flex items-center space-x-3 text-cyan-200">
            <RotateCw className="w-5 h-5 text-cyan-400 animate-spin shrink-0" />
            <div className="text-xs">
              <span className="font-bold text-white block">Assembling Patched Dalvik DEX & APK...</span>
              <span className="text-[11px] text-cyan-300/80 leading-tight block">
                Compiling bytecodes, aligning classes, and test-signing outputs (~1-2s).
              </span>
            </div>
          </div>
        )}

        {/* User-Facing Download Status Toast / Banner */}
        {downloadNotice && (
          <div
            className={`mx-3.5 mt-2.5 p-3 rounded-2xl border flex items-start justify-between space-x-2 text-xs transition-all ${
              downloadNotice.type === 'success'
                ? 'bg-emerald-950/70 border-emerald-500/40 text-emerald-200'
                : downloadNotice.type === 'error'
                ? 'bg-rose-950/70 border-rose-500/40 text-rose-200'
                : 'bg-cyan-950/70 border-cyan-500/40 text-cyan-200'
            }`}
          >
            <div className="flex items-start space-x-2">
              {downloadNotice.type === 'success' ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              ) : downloadNotice.type === 'error' ? (
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              ) : (
                <RotateCw className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5 animate-spin" />
              )}
              <div className="leading-relaxed">
                <span className="font-bold block text-white">{downloadNotice.filename}</span>
                <span className="text-[11px]">{downloadNotice.message}</span>
              </div>
            </div>
            <button
              onClick={() => setDownloadNotice(null)}
              className="text-slate-400 hover:text-white p-1 shrink-0"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Package List */}
        <div className="p-3.5 overflow-y-auto space-y-3">
          {packages.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500 rounded-xl bg-slate-950/40 border border-slate-800">
              {isPreparing
                ? 'Assembling clean packages from patched Smali sources...'
                : 'No packages prepared yet. Apply patches in Patch Lab to generate clean outputs.'}
            </div>
          ) : (
            packages.map((pkg, idx) => (
              <div
                key={`${pkg.id}-${pkg.filename}-${idx}`}
                className="p-3.5 rounded-2xl bg-slate-950/80 border border-slate-800 space-y-2.5 transition-all"
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-2.5 min-w-0 pr-2">
                    <div className="p-2 rounded-xl bg-slate-900 border border-slate-800 shrink-0 mt-0.5">
                      {getIcon(pkg.id)}
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-bold text-white truncate">{pkg.label}</div>
                      <div className="text-[11px] text-slate-400 font-mono truncate">{pkg.filename}</div>
                    </div>
                  </div>

                  <span
                    className={`text-[9px] px-2 py-0.5 rounded-full font-bold uppercase shrink-0 ${
                      pkg.validationStatus === 'Validated'
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                        : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                    }`}
                  >
                    {pkg.validationStatus}
                  </span>
                </div>

                <p className="text-[11px] text-slate-300 leading-relaxed">{pkg.description}</p>

                {/* Metadata Row */}
                <div className="p-2 rounded-xl bg-slate-900/60 border border-slate-800/80 text-[10px] space-y-1">
                  <div className="flex items-center justify-between text-slate-400">
                    <span>File Size: <strong className="text-white">{(pkg.sizeBytes / 1024).toFixed(1)} KB</strong></span>
                    <span>Modified Files: <strong className="text-cyan-400">{pkg.modifiedFiles.length}</strong></span>
                  </div>

                  <div className="flex items-center justify-between text-slate-400 pt-0.5">
                    <span className="truncate pr-2 font-mono">
                      SHA256: {pkg.sha256.substring(0, 16)}...
                    </span>
                    <button
                      onClick={() => handleCopyHash(pkg.sha256, pkg.id)}
                      className="text-slate-400 hover:text-white flex items-center space-x-0.5 shrink-0"
                    >
                      {copiedHashId === pkg.id ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                      <span className="text-[9px]">{copiedHashId === pkg.id ? 'Copied' : 'Hash'}</span>
                    </button>
                  </div>
                </div>

                {/* Download Button */}
                <button
                  onClick={() => handleDownload(pkg)}
                  disabled={downloadingId === pkg.id}
                  className={`w-full min-h-[44px] px-3 py-2 rounded-xl text-white text-xs font-bold flex items-center justify-center space-x-1.5 transition-all shadow-md active:scale-98 ${
                    isPreparing
                      ? 'bg-slate-800 hover:bg-slate-750 text-cyan-300 border border-cyan-500/30'
                      : 'bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 shadow-emerald-950/40'
                  }`}
                >
                  {downloadingId === pkg.id ? (
                    <>
                      <RotateCw className="w-4 h-4 animate-spin text-white" />
                      <span>Generating Output...</span>
                    </>
                  ) : isPreparing ? (
                    <>
                      <RotateCw className="w-4 h-4 animate-spin text-cyan-400" />
                      <span>Assembling... Tap for details</span>
                    </>
                  ) : (
                    <>
                      <Download className="w-4 h-4" />
                      <span>Download {pkg.filename}</span>
                    </>
                  )}
                </button>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
