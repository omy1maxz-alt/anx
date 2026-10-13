import React, { useState } from 'react';
import { X, FolderPlus, FileCode, Beaker, AlertTriangle, ArrowRight, Sparkles } from 'lucide-react';
import { TargetBehaviorType } from '../types/forensics';

interface NewProjectModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirmNewProject: (projectName?: string, defaultBehavior?: TargetBehaviorType) => void;
  onOpenFixtures: () => void;
  hasExistingData: boolean;
}

export const NewProjectModal: React.FC<NewProjectModalProps> = ({
  isOpen,
  onClose,
  onConfirmNewProject,
  onOpenFixtures,
  hasExistingData,
}) => {
  const [projectName, setProjectName] = useState('');
  const [selectedBehavior, setSelectedBehavior] = useState<TargetBehaviorType>('forced_update');

  if (!isOpen) return null;

  const handleStartBlank = () => {
    onConfirmNewProject(projectName.trim() || undefined, selectedBehavior);
    onClose();
  };

  const handleStartFromFixtures = () => {
    onClose();
    onOpenFixtures();
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex flex-col justify-end sm:justify-center p-0 sm:p-4">
      <div className="w-full max-w-md mx-auto bg-slate-900 border-t sm:border border-slate-700 rounded-t-3xl sm:rounded-2xl max-h-[90dvh] flex flex-col overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="w-9 h-9 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center">
              <FolderPlus className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">Start New Forensic Project</h3>
              <p className="text-[11px] text-slate-400">Initialize a fresh investigation session</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg bg-slate-800 text-slate-400 hover:text-white flex items-center justify-center transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-4 space-y-4 overflow-y-auto">
          {hasExistingData && (
            <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-start space-x-2.5 text-xs text-amber-200">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <span>
                Starting a new project will clear the current session&apos;s findings and artifact inventory.
              </span>
            </div>
          )}

          {/* Project Name Input */}
          <div className="space-y-1.5">
            <label className="text-xs font-bold text-slate-200">
              Project / Target APK Name (Optional)
            </label>
            <input
              type="text"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              placeholder="e.g. TargetApp_v2.1_ModAudit"
              className="w-full h-10 px-3 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
            />
          </div>

          {/* Target Behavior Selection */}
          <div className="space-y-1.5">
            <label className="text-xs font-bold text-slate-200">
              Initial Behavior Focus
            </label>
            <select
              value={selectedBehavior}
              onChange={(e) => setSelectedBehavior(e.target.value as TargetBehaviorType)}
              className="w-full h-10 px-3 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-cyan-500 transition-colors"
            >
              <option value="forced_update">Forced Update Mechanism</option>
              <option value="forced_popup">Forced Popup / Announcement</option>
              <option value="forced_redirect">Browser Redirect & Dynamic URL</option>
              <option value="unexpected_external_link">Unexpected External Link</option>
              <option value="webview_navigation">WebView & JS Bridge Navigation</option>
              <option value="remote_configuration">Remote Configuration Dependency</option>
              <option value="unwanted_ads_overlay">Unwanted Ads / Overlay UI</option>
            </select>
          </div>

          {/* Choice Cards */}
          <div className="space-y-2 pt-1">
            <button
              onClick={handleStartBlank}
              className="w-full p-3.5 rounded-2xl bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 active:scale-98 text-left text-white shadow-lg shadow-emerald-950/40 transition-all flex items-center justify-between"
            >
              <div>
                <div className="text-xs font-bold flex items-center space-x-1.5">
                  <FolderPlus className="w-4 h-4" />
                  <span>Start Blank Project</span>
                </div>
                <div className="text-[11px] text-emerald-100 mt-0.5">
                  Ready to upload your own APK, DEX, Smali, or Manifest files
                </div>
              </div>
              <ArrowRight className="w-4 h-4 shrink-0 ml-2" />
            </button>

            <button
              onClick={handleStartFromFixtures}
              className="w-full p-3.5 rounded-2xl bg-slate-850 hover:bg-slate-800 active:scale-98 text-left text-slate-200 border border-slate-700 transition-all flex items-center justify-between"
            >
              <div>
                <div className="text-xs font-bold flex items-center space-x-1.5 text-cyan-300">
                  <Beaker className="w-4 h-4" />
                  <span>Load Acceptance Test Fixture (A–F)</span>
                </div>
                <div className="text-[11px] text-slate-400 mt-0.5">
                  Preloaded realistic Smali scenarios for forced updates, popups, and redirects
                </div>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 shrink-0 ml-2" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
