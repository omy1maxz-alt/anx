import React, { useState } from 'react';
import {
  X,
  Smartphone,
  Layers,
  FileCode,
  ShieldCheck,
  CheckCircle2,
  Copy,
  Check,
  ArrowRight,
  ExternalLink,
  HelpCircle,
  Sparkles,
  AlertTriangle,
} from 'lucide-react';

interface MtManagerGuideModalProps {
  isOpen: boolean;
  onClose: () => void;
  targetDexName?: string;
  onOpenDownloadCenter?: () => void;
}

export const MtManagerGuideModal: React.FC<MtManagerGuideModalProps> = ({
  isOpen,
  onClose,
  targetDexName = 'classes10.dex',
  onOpenDownloadCenter,
}) => {
  const [activeTab, setActiveTab] = useState<'dex_replace' | 'smali_edit' | 'signing'>('dex_replace');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  if (!isOpen) return null;

  const copyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm flex flex-col justify-end sm:justify-center p-0 sm:p-4">
      <div className="w-full max-w-lg mx-auto bg-slate-900 border-t sm:border border-slate-700 rounded-t-3xl sm:rounded-2xl max-h-[92dvh] flex flex-col overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-500/30 text-cyan-400 flex items-center justify-center shrink-0">
              <Smartphone className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-1.5">
                <h3 className="text-sm font-bold text-white">MT Manager Android Guide</h3>
                <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  Mobile
                </span>
              </div>
              <p className="text-[11px] text-slate-400">Put clean DEX or Smali back into your APK</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="w-9 h-9 rounded-xl bg-slate-800 text-slate-400 hover:text-white flex items-center justify-center transition-colors active:scale-95"
            aria-label="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Selector */}
        <div className="grid grid-cols-3 gap-1 p-2 bg-slate-950/60 border-b border-slate-800 text-xs font-semibold">
          <button
            onClick={() => setActiveTab('dex_replace')}
            className={`min-h-[44px] px-2 py-1.5 rounded-xl transition-all flex flex-col items-center justify-center text-center ${
              activeTab === 'dex_replace'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <span className="font-bold text-[11px] leading-tight">1. Replace DEX</span>
            <span className="text-[9px] text-cyan-400/80">Recommended</span>
          </button>

          <button
            onClick={() => setActiveTab('smali_edit')}
            className={`min-h-[44px] px-2 py-1.5 rounded-xl transition-all flex flex-col items-center justify-center text-center ${
              activeTab === 'smali_edit'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <span className="font-bold text-[11px] leading-tight">2. Smali ZIP</span>
            <span className="text-[9px] text-slate-400">Dex Editor Plus</span>
          </button>

          <button
            onClick={() => setActiveTab('signing')}
            className={`min-h-[44px] px-2 py-1.5 rounded-xl transition-all flex flex-col items-center justify-center text-center ${
              activeTab === 'signing'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <span className="font-bold text-[11px] leading-tight">3. Sign & Test</span>
            <span className="text-[9px] text-slate-400">Anti-Crash</span>
          </button>
        </div>

        {/* Content Body */}
        <div className="p-4 space-y-4 overflow-y-auto flex-1 text-slate-200 text-xs">
          {activeTab === 'dex_replace' && (
            <div className="space-y-3.5">
              <div className="p-3 rounded-2xl bg-cyan-950/30 border border-cyan-800/40 text-[11px] text-cyan-200 flex items-start space-x-2.5">
                <Sparkles className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                <span>
                  <strong>Easiest & Fastest Method:</strong> Replace <code className="bg-cyan-900/60 px-1 py-0.5 rounded text-white">{targetDexName}</code> directly inside the APK archive in MT Manager.
                </span>
              </div>

              {/* Step 1 */}
              <div className="p-3 rounded-2xl bg-slate-850/80 border border-slate-750 space-y-1.5">
                <div className="flex items-center space-x-2 text-cyan-400 font-bold text-xs">
                  <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-300 flex items-center justify-center text-[10px]">1</span>
                  <span>Download Clean {targetDexName}</span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed pl-7">
                  In DroidForensics, tap <strong>Download Center</strong> (or <strong>Smali→DEX</strong> tab) and download the remediated <code className="text-cyan-300">{targetDexName}</code> to your phone's <code>/Download</code> folder.
                </p>
                {onOpenDownloadCenter && (
                  <div className="pl-7 pt-1">
                    <button
                      onClick={() => {
                        onClose();
                        onOpenDownloadCenter();
                      }}
                      className="min-h-[44px] px-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 active:scale-95 text-slate-950 font-bold text-xs flex items-center space-x-1.5 transition-all shadow"
                    >
                      <span>Open Download Center</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                )}
              </div>

              {/* Step 2 */}
              <div className="p-3 rounded-2xl bg-slate-850/80 border border-slate-750 space-y-1.5">
                <div className="flex items-center space-x-2 text-cyan-400 font-bold text-xs">
                  <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-300 flex items-center justify-center text-[10px]">2</span>
                  <span>Open Target APK in MT Manager (Left Panel)</span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed pl-7">
                  Launch <strong>MT Manager</strong> on Android. In the left panel, navigate to your target APK. Tap the APK file and select <span className="text-white font-semibold underline decoration-cyan-400">"View"</span> (do NOT choose Install or Extract). This opens the APK file tree.
                </p>
              </div>

              {/* Step 3 */}
              <div className="p-3 rounded-2xl bg-slate-850/80 border border-slate-750 space-y-1.5">
                <div className="flex items-center space-x-2 text-cyan-400 font-bold text-xs">
                  <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-300 flex items-center justify-center text-[10px]">3</span>
                  <span>Navigate to Clean DEX (Right Panel)</span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed pl-7">
                  In MT Manager's <strong>Right Panel</strong>, navigate to your phone's <code className="text-amber-300">/Download</code> folder where you saved the clean <code className="text-cyan-300">{targetDexName}</code>.
                </p>
              </div>

              {/* Step 4 */}
              <div className="p-3 rounded-2xl bg-slate-850/80 border border-slate-750 space-y-1.5">
                <div className="flex items-center space-x-2 text-cyan-400 font-bold text-xs">
                  <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-300 flex items-center justify-center text-[10px]">4</span>
                  <span>Replace & Update APK</span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed pl-7">
                  Long-press <code className="text-cyan-300">{targetDexName}</code> in the right panel and tap <strong className="text-white">"Add"</strong>. Confirm "OK" to replace the file inside the left-panel APK.
                </p>
                <div className="mt-2 pl-7 p-2 rounded-xl bg-amber-500/10 border border-amber-500/30 text-[10px] text-amber-200">
                  <strong>Auto-Sign:</strong> Press back in MT Manager. When prompted <em>"Archive modified, update APK?"</em>, check <span className="text-white font-bold">"Auto-sign"</span> and tap <strong>OK</strong>.
                </div>
              </div>
            </div>
          )}

          {activeTab === 'smali_edit' && (
            <div className="space-y-3.5">
              <div className="p-3 rounded-2xl bg-indigo-950/30 border border-indigo-800/40 text-[11px] text-indigo-200 flex items-start space-x-2.5">
                <FileCode className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
                <span>
                  <strong>Smali / Dex Editor Plus Flow:</strong> If you prefer updating individual .smali files inside MT Manager's built-in Dex Editor.
                </span>
              </div>

              {/* Step 1 */}
              <div className="p-3 rounded-2xl bg-slate-850/80 border border-slate-750 space-y-1.5">
                <div className="flex items-center space-x-2 text-indigo-400 font-bold text-xs">
                  <span className="w-5 h-5 rounded-full bg-indigo-500/20 text-indigo-300 flex items-center justify-center text-[10px]">1</span>
                  <span>Open {targetDexName} in Dex Editor Plus</span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed pl-7">
                  In MT Manager, tap your target APK &rarr; tap <code className="text-indigo-300">{targetDexName}</code> &rarr; choose <strong className="text-white">"Dex Editor Plus"</strong>. Check all classes and tap OK.
                </p>
              </div>

              {/* Step 2 */}
              <div className="p-3 rounded-2xl bg-slate-850/80 border border-slate-750 space-y-1.5">
                <div className="flex items-center space-x-2 text-indigo-400 font-bold text-xs">
                  <span className="w-5 h-5 rounded-full bg-indigo-500/20 text-indigo-300 flex items-center justify-center text-[10px]">2</span>
                  <span>Search Rogue Method / Ad URL</span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed pl-7">
                  Tap the search icon in Dex Editor Plus. Search for <code className="text-cyan-300">com.android.chrome</code> or <code className="text-cyan-300">ACTION_VIEW</code>.
                </p>
                <div className="pl-7 pt-1 flex items-center space-x-2">
                  <button
                    onClick={() => copyText('com.android.chrome', 'chrome_str')}
                    className="min-h-[38px] px-2.5 rounded-lg bg-slate-800 hover:bg-slate-750 active:scale-95 text-slate-300 text-[11px] font-mono flex items-center space-x-1 border border-slate-700"
                  >
                    {copiedKey === 'chrome_str' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>Copy "com.android.chrome"</span>
                  </button>
                </div>
              </div>

              {/* Step 3 */}
              <div className="p-3 rounded-2xl bg-slate-850/80 border border-slate-750 space-y-1.5">
                <div className="flex items-center space-x-2 text-indigo-400 font-bold text-xs">
                  <span className="w-5 h-5 rounded-full bg-indigo-500/20 text-indigo-300 flex items-center justify-center text-[10px]">3</span>
                  <span>Paste Neutral Return Stub</span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed pl-7">
                  In the ad method that calls <code>startActivity</code>, replace the method body with a clean return stub:
                </p>
                <div className="pl-7 pt-1">
                  <div className="p-2.5 rounded-xl bg-slate-950 font-mono text-[10px] text-emerald-400 border border-slate-800 relative">
                    <pre className="overflow-x-auto whitespace-pre">
{`.method public static checkAndLaunchDailyAd(Landroid/content/Context;)V
    .registers 1
    return-void
.end method`}
                    </pre>
                    <button
                      onClick={() => copyText(`.method public static checkAndLaunchDailyAd(Landroid/content/Context;)V\n    .registers 1\n    return-void\n.end method`, 'stub')}
                      className="absolute top-2 right-2 p-1.5 rounded-md bg-slate-800 text-slate-300 hover:text-white"
                      title="Copy stub"
                    >
                      {copiedKey === 'stub' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                </div>
              </div>

              {/* Step 4 */}
              <div className="p-3 rounded-2xl bg-slate-850/80 border border-slate-750 space-y-1.5">
                <div className="flex items-center space-x-2 text-indigo-400 font-bold text-xs">
                  <span className="w-5 h-5 rounded-full bg-indigo-500/20 text-indigo-300 flex items-center justify-center text-[10px]">4</span>
                  <span>Save & Compile</span>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed pl-7">
                  Tap <strong>Save</strong> in editor, then press Back. MT Manager will recompile the DEX. Tap <strong>Save and Exit</strong>, then confirm APK update and Auto-Sign!
                </p>
              </div>
            </div>
          )}

          {activeTab === 'signing' && (
            <div className="space-y-3.5">
              <div className="p-3 rounded-2xl bg-emerald-950/30 border border-emerald-800/40 text-[11px] text-emerald-200 flex items-start space-x-2.5">
                <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <span>
                  <strong>Anti-Crash & Signature Verification:</strong> How to avoid <code>ClassNotFoundException</code> and install errors on Android 11+.
                </span>
              </div>

              <div className="p-3 rounded-2xl bg-slate-850/80 border border-slate-750 space-y-2">
                <h4 className="text-xs font-bold text-white flex items-center space-x-1.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>Why Did Old App Crashed on Launch?</span>
                </h4>
                <p className="text-[11px] text-slate-300 leading-relaxed">
                  When modders put code in <code className="text-cyan-300">classes10.dex</code>, that DEX also contains other essential app classes (like Application entrypoint <code className="text-cyan-300">App.smali</code>). If you assemble only 1 class, Android throws <strong className="text-rose-400">ClassNotFoundException</strong> on boot.
                </p>
                <div className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-[10px] text-emerald-300">
                  ✓ DroidForensics preserves <strong>100% of all classes</strong> in the DEX dump, ensuring zero missing classes!
                </div>
              </div>

              <div className="p-3 rounded-2xl bg-slate-850/80 border border-slate-750 space-y-2">
                <h4 className="text-xs font-bold text-white flex items-center space-x-1.5">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  <span>"App Not Installed / Signature Conflict"</span>
                </h4>
                <p className="text-[11px] text-slate-300 leading-relaxed">
                  Because modifying the DEX invalidates the developer's original cryptographic signature:
                </p>
                <ul className="text-[11px] text-slate-300 space-y-1 pl-4 list-disc">
                  <li><strong>Uninstall</strong> the old version from your phone first before installing the new APK.</li>
                  <li>In MT Manager, always leave <strong className="text-white">"Auto-sign"</strong> checked so MT Manager signs the APK with its test key.</li>
                  <li>On Android 14+, MT Manager automatically applies V1 + V2 + V3 scheme signing.</li>
                </ul>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-3.5 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between">
          <div className="text-[11px] text-slate-400">
            Target DEX: <span className="font-mono font-bold text-cyan-400">{targetDexName}</span>
          </div>

          <button
            onClick={onClose}
            className="min-h-[44px] px-4 rounded-xl bg-slate-800 hover:bg-slate-700 active:scale-95 text-xs font-bold text-white transition-all shadow"
          >
            Got it, Back to Lab
          </button>
        </div>
      </div>
    </div>
  );
};
