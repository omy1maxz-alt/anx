import React from 'react';
import {
  LayoutDashboard,
  FolderTree,
  SearchCode,
  ShieldCheck,
  GitFork,
  Wrench,
  Cpu,
} from 'lucide-react';

export type ActiveTab = 'dashboard' | 'files' | 'forensics' | 'findings' | 'flow' | 'patch' | 'converter';

interface BottomNavProps {
  activeTab: ActiveTab;
  onChangeTab: (tab: ActiveTab) => void;
  findingsCount: number;
  filesCount: number;
}

export const BottomNav: React.FC<BottomNavProps> = ({
  activeTab,
  onChangeTab,
  findingsCount,
  filesCount,
}) => {
  const tabs = [
    { id: 'dashboard' as ActiveTab, label: 'Dash', icon: LayoutDashboard },
    { id: 'files' as ActiveTab, label: 'Files', icon: FolderTree, count: filesCount },
    { id: 'forensics' as ActiveTab, label: 'Forensics', icon: SearchCode },
    { id: 'findings' as ActiveTab, label: 'Findings', icon: ShieldCheck, count: findingsCount },
    { id: 'flow' as ActiveTab, label: 'Graph', icon: GitFork },
    { id: 'patch' as ActiveTab, label: 'Patch Lab', icon: Wrench },
    { id: 'converter' as ActiveTab, label: 'Smali→DEX', icon: Cpu },
  ];

  return (
    <nav className="fixed bottom-0 left-0 right-0 z-40 bg-slate-900/95 backdrop-blur-lg border-t border-slate-800 px-0.5 py-1.5 pb-[max(0.375rem,env(safe-area-inset-bottom))] text-white select-none shadow-2xl">
      <div className="grid grid-cols-7 gap-0.5 max-w-lg mx-auto">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onChangeTab(tab.id)}
              className={`flex flex-col items-center justify-center min-h-[48px] py-1 px-1 rounded-xl transition-all relative ${
                isActive
                  ? 'text-cyan-400 bg-cyan-950/40 border border-cyan-800/40 font-semibold shadow-inner'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
              aria-label={tab.label}
            >
              <div className="relative">
                <Icon className={`w-5 h-5 ${isActive ? 'scale-110 text-cyan-400' : 'text-slate-400'}`} />
                {typeof tab.count === 'number' && tab.count > 0 && (
                  <span
                    className={`absolute -top-1.5 -right-2 px-1 min-w-[14px] h-[14px] text-[9px] font-bold rounded-full flex items-center justify-center ${
                      tab.id === 'findings'
                        ? 'bg-rose-500 text-white shadow-sm shadow-rose-900'
                        : 'bg-cyan-500 text-slate-950 font-black'
                    }`}
                  >
                    {tab.count}
                  </span>
                )}
              </div>
              <span className="text-[10px] mt-1 tracking-tight truncate max-w-full">
                {tab.label}
              </span>
            </button>
          );
        })}
      </div>
    </nav>
  );
};
