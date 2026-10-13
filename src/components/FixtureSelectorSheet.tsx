import React from 'react';
import { X, Beaker, ArrowRight, CheckCircle2 } from 'lucide-react';
import { TEST_SCENARIOS, TestScenario } from '../services/testFixtures';

interface FixtureSelectorSheetProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectScenario: (scenario: TestScenario) => void;
  currentScenarioId?: string;
}

export const FixtureSelectorSheet: React.FC<FixtureSelectorSheetProps> = ({
  isOpen,
  onClose,
  onSelectScenario,
  currentScenarioId,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex flex-col justify-end p-0">
      <div className="w-full max-w-md mx-auto bg-slate-900 border-t border-slate-700 rounded-t-3xl max-h-[85dvh] flex flex-col overflow-hidden shadow-2xl">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 text-cyan-400 flex items-center justify-center">
              <Beaker className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-xs font-bold text-white">Acceptance Scenarios (Tests A–F)</h3>
              <p className="text-[11px] text-slate-400">Harmless reverse-engineering test fixtures</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg bg-slate-800 text-slate-400 hover:text-white flex items-center justify-center"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-3 overflow-y-auto space-y-2">
          {TEST_SCENARIOS.map((sc) => {
            const isSelected = currentScenarioId === sc.id;

            return (
              <div
                key={sc.id}
                onClick={() => {
                  onSelectScenario(sc);
                  onClose();
                }}
                className={`p-3.5 rounded-2xl border transition-all active:scale-98 cursor-pointer ${
                  isSelected
                    ? 'bg-cyan-950/40 border-cyan-500 shadow-md ring-1 ring-cyan-500/40'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-bold text-white">{sc.name}</span>
                      {isSelected && (
                        <span className="text-[9px] px-1.5 py-0.2 rounded bg-cyan-500 text-slate-950 font-black">
                          ACTIVE
                        </span>
                      )}
                    </div>

                    <p className="text-[11px] text-slate-300 mt-1 leading-relaxed">
                      {sc.description}
                    </p>

                    <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center space-x-2 text-[10px] text-slate-400">
                      <span className="text-cyan-400 font-semibold uppercase">
                        {sc.targetBehavior}
                      </span>
                      <span>•</span>
                      <span>{sc.smaliFiles.length} Smali classes</span>
                    </div>
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
