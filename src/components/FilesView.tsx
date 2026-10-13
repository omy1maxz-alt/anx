import React, { useRef, useState } from 'react';
import {
  UploadCloud,
  FileCode,
  FileText,
  FolderArchive,
  Search,
  CheckCircle2,
  AlertTriangle,
  Eye,
  Trash2,
  Package,
  Layers,
  Cpu,
  Smartphone,
} from 'lucide-react';
import { UploadedArtifact, SmaliClass, ManifestData } from '../types/forensics';

interface FilesViewProps {
  artifacts: UploadedArtifact[];
  classes: SmaliClass[];
  manifest?: ManifestData;
  onUploadFiles: (files: FileList | File[]) => void;
  onSelectClass: (smaliClass: SmaliClass) => void;
  onSelectArtifact: (artifact: UploadedArtifact) => void;
  onRemoveArtifact: (artifactId: string) => void;
  onOpenSmaliToDex?: () => void;
  onOpenMtGuide?: () => void;
}

export const FilesView: React.FC<FilesViewProps> = ({
  artifacts,
  classes,
  manifest,
  onUploadFiles,
  onSelectClass,
  onSelectArtifact,
  onRemoveArtifact,
  onOpenSmaliToDex,
  onOpenMtGuide,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeFilter, setActiveFilter] = useState<'all' | 'artifacts' | 'classes'>('all');

  const filteredClasses = classes.filter(
    (c) =>
      c.simpleName.toLowerCase().includes(searchTerm.toLowerCase()) ||
      c.package.toLowerCase().includes(searchTerm.toLowerCase()) ||
      c.methods.some((m) => m.name.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      onUploadFiles(e.dataTransfer.files);
    }
  };

  return (
    <div className="space-y-4 pb-20">
      {/* Upload Box */}
      <div
        onDragOver={handleDragOver}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className="p-5 rounded-2xl border-2 border-dashed border-slate-700 hover:border-cyan-500 bg-slate-900/60 hover:bg-slate-900/90 text-center transition-all cursor-pointer active:scale-98"
      >
        <input
          ref={fileInputRef}
          type="file"
          multiple
          accept=".apk,.dex,.smali,.xml,.zip,.java,.kt,.log,.txt,.json"
          className="hidden"
          onChange={(e) => {
            if (e.target.files && e.target.files.length > 0) {
              onUploadFiles(e.target.files);
            }
          }}
        />
        <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center mx-auto mb-2.5">
          <UploadCloud className="w-6 h-6" />
        </div>
        <div className="text-xs font-bold text-white">Tap or Drag Files to Upload</div>
        <div className="text-[11px] text-slate-400 mt-1 max-w-xs mx-auto">
          Supports <span className="text-cyan-400">.apk</span>, <span className="text-cyan-400">.dex</span>, <span className="text-cyan-400">.smali</span>, <span className="text-cyan-400">AndroidManifest.xml</span>, <span className="text-cyan-400">.zip</span> archives & logs
        </div>
      </div>

      {/* Smali ZIP -> DEX Assembler Card */}
      <div className="p-3.5 rounded-2xl bg-gradient-to-r from-cyan-950/40 to-slate-900 border border-cyan-800/40 flex items-center justify-between gap-3 shadow-sm">
        <div className="flex items-center space-x-3 min-w-0">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center shrink-0">
            <Cpu className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center space-x-1.5">
              <span className="text-xs font-bold text-white truncate">Smali ZIP → DEX Assembler</span>
              <span className="text-[9px] px-1.5 py-0.2 rounded font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                DEX 035
              </span>
            </div>
            <p className="text-[11px] text-slate-400 truncate mt-0.5">
              Compile .smali archives or {classes.length} workspace classes to DEX
            </p>
          </div>
        </div>
        <div className="flex items-center space-x-1.5 shrink-0">
          {onOpenMtGuide && (
            <button
              onClick={onOpenMtGuide}
              className="min-h-[44px] px-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 active:scale-95 text-slate-200 border border-slate-700 font-semibold text-xs flex items-center space-x-1 transition-all"
              title="MT Manager Mobile Guide"
            >
              <Smartphone className="w-3.5 h-3.5 text-emerald-400" />
              <span className="hidden xs:inline">MT Guide</span>
            </button>
          )}
          <button
            onClick={() => onOpenSmaliToDex && onOpenSmaliToDex()}
            className="min-h-[44px] px-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 active:scale-95 text-slate-950 font-bold text-xs flex items-center space-x-1 transition-all shrink-0 shadow-md shadow-cyan-950/40"
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>Assemble</span>
          </button>
        </div>
      </div>

      {/* Manifest Overview Badge */}
      {manifest && (
        <div className="p-3.5 rounded-2xl bg-slate-900/90 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Package className="w-4 h-4 text-emerald-400" />
              <span className="text-xs font-bold text-white truncate max-w-[200px]">
                {manifest.packageName}
              </span>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono font-bold">
              v{manifest.versionName || manifest.versionCode || '1.0'}
            </span>
          </div>
          <div className="grid grid-cols-3 gap-2 text-center text-[10px] pt-1 border-t border-slate-800">
            <div>
              <span className="text-slate-400">Components: </span>
              <span className="font-bold text-white">{manifest.components.length}</span>
            </div>
            <div>
              <span className="text-slate-400">Permissions: </span>
              <span className="font-bold text-white">{manifest.permissions.length}</span>
            </div>
            <div>
              <span className="text-slate-400">Min SDK: </span>
              <span className="font-bold text-white">{manifest.minSdkVersion || '21'}</span>
            </div>
          </div>
        </div>
      )}

      {/* Filter Tabs & Search */}
      <div className="space-y-2">
        <div className="relative">
          <Search className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
          <input
            type="text"
            placeholder="Search classes, methods, or strings..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full h-10 pl-9 pr-3 rounded-xl bg-slate-900 border border-slate-800 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
          />
        </div>

        <div className="grid grid-cols-3 gap-1 p-1 bg-slate-900/80 rounded-xl border border-slate-800">
          <button
            onClick={() => setActiveFilter('all')}
            className={`min-h-[36px] rounded-lg text-xs font-semibold transition-all ${
              activeFilter === 'all'
                ? 'bg-slate-800 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All ({artifacts.length + classes.length})
          </button>
          <button
            onClick={() => setActiveFilter('artifacts')}
            className={`min-h-[36px] rounded-lg text-xs font-semibold transition-all ${
              activeFilter === 'artifacts'
                ? 'bg-slate-800 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Artifacts ({artifacts.length})
          </button>
          <button
            onClick={() => setActiveFilter('classes')}
            className={`min-h-[36px] rounded-lg text-xs font-semibold transition-all ${
              activeFilter === 'classes'
                ? 'bg-slate-800 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Classes ({classes.length})
          </button>
        </div>
      </div>

      {/* Artifact Inventory List */}
      {(activeFilter === 'all' || activeFilter === 'artifacts') && (
        <div className="space-y-2">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-400 px-1">
            Artifact Inventory ({artifacts.length})
          </div>

          {artifacts.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-500 rounded-xl bg-slate-900/40 border border-slate-800">
              No files uploaded yet. Drag an APK or tap a test scenario.
            </div>
          ) : (
            <div className="space-y-1.5">
              {artifacts.map((art, idx) => (
                <div
                  key={`${art.id}-${idx}`}
                  className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 flex items-center justify-between transition-all"
                >
                  <div
                    onClick={() => onSelectArtifact(art)}
                    className="min-w-0 flex-1 cursor-pointer pr-2"
                  >
                    <div className="flex items-center space-x-2">
                      <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-bold uppercase bg-slate-800 text-cyan-400 border border-slate-700">
                        {art.format}
                      </span>
                      <span className="text-xs font-bold text-white truncate">{art.name}</span>
                    </div>
                    <div className="flex items-center space-x-2 text-[11px] text-slate-400 mt-1">
                      <span>{(art.size / 1024).toFixed(1)} KB</span>
                      <span>•</span>
                      <span className="truncate text-slate-300">{art.coverage}</span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-1 shrink-0">
                    {(art.format === 'zip' || art.format === 'smali') && onOpenSmaliToDex && (
                      <button
                        onClick={() => onOpenSmaliToDex()}
                        className="w-9 h-9 rounded-lg bg-cyan-950/60 hover:bg-cyan-900/60 text-cyan-400 border border-cyan-800/40 flex items-center justify-center transition-all"
                        title="Assemble to DEX"
                        aria-label="Assemble to DEX"
                      >
                        <Cpu className="w-4 h-4" />
                      </button>
                    )}
                    <button
                      onClick={() => onSelectArtifact(art)}
                      className="w-9 h-9 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 flex items-center justify-center transition-all"
                      title="Inspect artifact contents"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => onRemoveArtifact(art.id)}
                      className="w-9 h-9 rounded-lg bg-slate-800 hover:bg-rose-900/40 text-slate-400 hover:text-rose-400 flex items-center justify-center transition-all"
                      title="Remove artifact"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Discovered Smali Classes List */}
      {(activeFilter === 'all' || activeFilter === 'classes') && (
        <div className="space-y-2">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-400 px-1">
            Dalvik Smali Classes ({filteredClasses.length})
          </div>

          {filteredClasses.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-500 rounded-xl bg-slate-900/40 border border-slate-800">
              No matching Smali classes found.
            </div>
          ) : (
            <div className="space-y-1.5">
              {filteredClasses.map((cls, idx) => (
                <div
                  key={`${cls.filePath || 'smali'}-${cls.name}-${idx}`}
                  onClick={() => onSelectClass(cls)}
                  className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 active:scale-98 cursor-pointer transition-all flex items-center justify-between"
                >
                  <div className="min-w-0 flex-1 pr-2">
                    <div className="flex items-center space-x-1.5">
                      <FileCode className="w-4 h-4 text-emerald-400 shrink-0" />
                      <span className="text-xs font-bold text-white truncate">
                        {cls.simpleName}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 truncate mt-0.5">
                      {cls.package || 'default'} • {cls.methods.length} methods • {cls.fields.length} fields
                    </div>
                  </div>
                  <Eye className="w-4 h-4 text-slate-500 shrink-0" />
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
