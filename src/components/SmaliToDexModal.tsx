/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef } from 'react';
import {
  X,
  FileCode,
  Cpu,
  UploadCloud,
  CheckCircle2,
  AlertTriangle,
  Download,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Layers,
  Sparkles,
  Terminal,
  FileArchive,
  RefreshCw,
} from 'lucide-react';
import JSZip from 'jszip';
import { SmaliClass, UploadedArtifact } from '../types/forensics';
import {
  assembleSmaliZipToDex,
  assembleClassesToDex,
  SmaliToDexResult,
} from '../services/smaliToDexAssembler';
import { downloadBlob } from '../services/fileDownloader';
import { TEST_SCENARIOS } from '../services/testFixtures';

interface SmaliToDexModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentClasses: SmaliClass[];
  onAddArtifact?: (artifact: UploadedArtifact) => void;
  onRegisterDexDownload?: (dexResult: SmaliToDexResult, filename: string) => void;
}

export const SmaliToDexModal: React.FC<SmaliToDexModalProps> = ({
  isOpen,
  onClose,
  currentClasses,
  onAddArtifact,
  onRegisterDexDownload,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [sourceMode, setSourceMode] = useState<'upload' | 'workspace' | 'preset'>('upload');
  const [uploadedZipFile, setUploadedZipFile] = useState<File | null>(null);
  const [isAssembling, setIsAssembling] = useState(false);
  const [assembleProgressStep, setAssembleProgressStep] = useState<string>('');
  const [assemblyResult, setAssemblyResult] = useState<SmaliToDexResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [showLogDetails, setShowLogDetails] = useState(false);
  const [showClassList, setShowClassList] = useState(false);
  const [outputFileName, setOutputFileName] = useState('classes.dex');

  if (!isOpen) return null;

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleFileSelect = (file: File) => {
    if (!file.name.toLowerCase().endsWith('.zip')) {
      setErrorMessage('Please select a .zip archive containing .smali files.');
      return;
    }
    setUploadedZipFile(file);
    setErrorMessage(null);
    setAssemblyResult(null);
    const baseName = file.name.replace(/\.[^/.]+$/, '');
    setOutputFileName(`${baseName}_classes.dex`);
  };

  const handleGeneratePresetZip = async () => {
    try {
      setIsAssembling(true);
      setAssembleProgressStep('Generating sample Smali ZIP archive...');
      setErrorMessage(null);

      // Create sample zip from TEST_SCENARIOS[0]
      const scenario = TEST_SCENARIOS[0];
      const zip = new JSZip();

      for (const f of scenario.smaliFiles) {
        zip.file(f.name, f.content);
      }
      zip.file('README.txt', 'DroidForensics Sample Smali Source Archive\nContains Dalvik smali code for testing smali-to-dex compilation.');

      const zipBlob = await zip.generateAsync({ type: 'blob' });
      const sampleFile = new File([zipBlob], `${scenario.manifest.packageName}.smali.zip`, {
        type: 'application/zip',
      });

      setUploadedZipFile(sampleFile);
      setSourceMode('upload');
      setOutputFileName('classes.dex');
      setIsAssembling(false);
    } catch (err: any) {
      setIsAssembling(false);
      setErrorMessage(`Failed to create sample Smali ZIP: ${err.message}`);
    }
  };

  const runAssembly = async () => {
    setErrorMessage(null);
    setIsAssembling(true);
    setAssemblyResult(null);

    try {
      let result: SmaliToDexResult;

      if (sourceMode === 'upload') {
        if (!uploadedZipFile) {
          throw new Error('Please upload a Smali ZIP file first.');
        }
        setAssembleProgressStep('Extracting Smali files from ZIP archive...');
        const buffer = await uploadedZipFile.arrayBuffer();

        setAssembleProgressStep('Parsing Dalvik bytecode & verifying registers...');
        result = await assembleSmaliZipToDex(buffer, uploadedZipFile.name);
      } else {
        // Workspace mode
        if (currentClasses.length === 0) {
          throw new Error('No Smali classes currently loaded in workspace. Upload files or load a test scenario first.');
        }
        setAssembleProgressStep(`Assembling ${currentClasses.length} workspace classes...`);
        result = await assembleClassesToDex(currentClasses, 'current-workspace');
      }

      setAssembleProgressStep('Computing Adler-32 and SHA-1 DEX signatures...');
      await new Promise((r) => setTimeout(r, 200)); // smooth mobile transition

      setAssemblyResult(result);
      setIsAssembling(false);

      // Notify parent about download item and artifact
      if (onRegisterDexDownload) {
        onRegisterDexDownload(result, outputFileName);
      }

      if (onAddArtifact) {
        const artifact: UploadedArtifact = {
          id: `art-dex-${Date.now()}`,
          name: outputFileName,
          size: result.size,
          format: 'dex',
          status: 'parsed',
          coverage: `Assembled from Smali: ${result.classCount} classes, ${result.methodCount} methods, Adler-32 ${result.adler32}`,
          rawBuffer: result.uint8.buffer.slice(0) as ArrayBuffer,
        };
        onAddArtifact(artifact);
      }
    } catch (err: any) {
      setIsAssembling(false);
      setErrorMessage(err.message || 'DEX assembly failed. Please check Smali syntax and register declarations.');
    }
  };

  const handleDownloadDex = async () => {
    if (!assemblyResult) return;
    const filename = outputFileName || 'classes.dex';
    await downloadBlob(assemblyResult.blob, filename);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center p-0 sm:p-4 bg-slate-950/80 backdrop-blur-md animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-800 rounded-t-3xl sm:rounded-2xl max-w-lg w-full max-h-[92vh] flex flex-col shadow-2xl overflow-hidden pb-[max(1rem,env(safe-area-inset-bottom))]">
        {/* Modal Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between shrink-0 bg-slate-900/90">
          <div className="flex items-center space-x-2.5">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-emerald-500 flex items-center justify-center text-white shadow-md shadow-cyan-950/40">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-sm font-bold text-white">Smali ZIP → DEX Assembler</h3>
                <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  DEX 035
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Compile decompiled Smali files directly into Dalvik Executable
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-10 h-10 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center transition-all"
            aria-label="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-4 overflow-y-auto space-y-4 flex-1 overscroll-contain">
          {/* Source Selector Tabs */}
          <div className="grid grid-cols-2 gap-1.5 p-1 bg-slate-950/60 rounded-xl border border-slate-800">
            <button
              onClick={() => {
                setSourceMode('upload');
                setAssemblyResult(null);
                setErrorMessage(null);
              }}
              className={`min-h-[44px] px-2 rounded-lg text-xs font-semibold flex items-center justify-center space-x-1.5 transition-all ${
                sourceMode === 'upload'
                  ? 'bg-slate-800 text-cyan-300 shadow-sm border border-cyan-700/50'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileArchive className="w-4 h-4" />
              <span>Upload Smali ZIP</span>
            </button>
            <button
              onClick={() => {
                setSourceMode('workspace');
                setAssemblyResult(null);
                setErrorMessage(null);
                setOutputFileName('patched_classes.dex');
              }}
              className={`min-h-[44px] px-2 rounded-lg text-xs font-semibold flex items-center justify-center space-x-1.5 transition-all ${
                sourceMode === 'workspace'
                  ? 'bg-slate-800 text-emerald-300 shadow-sm border border-emerald-700/50'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Layers className="w-4 h-4" />
              <span>Current Workspace ({currentClasses.length})</span>
            </button>
          </div>

          {/* Mode 1: Upload Smali ZIP */}
          {sourceMode === 'upload' && (
            <div className="space-y-3">
              <input
                ref={fileInputRef}
                type="file"
                accept=".zip"
                className="hidden"
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    handleFileSelect(e.target.files[0]);
                  }
                }}
              />

              {!uploadedZipFile ? (
                <div
                  onClick={() => fileInputRef.current?.click()}
                  className="p-6 rounded-2xl border-2 border-dashed border-cyan-800/60 hover:border-cyan-400 bg-cyan-950/10 hover:bg-cyan-950/20 text-center cursor-pointer transition-all active:scale-98"
                >
                  <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center mx-auto mb-2">
                    <UploadCloud className="w-6 h-6" />
                  </div>
                  <div className="text-xs font-bold text-white">Tap to Select Smali ZIP Archive</div>
                  <div className="text-[11px] text-slate-400 mt-1 max-w-xs mx-auto">
                    Archive containing <code className="text-cyan-400 font-mono">.smali</code> files (e.g. from baksmali, apktool, or d2j)
                  </div>
                </div>
              ) : (
                <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between">
                  <div className="flex items-center space-x-3 min-w-0 pr-2">
                    <div className="w-9 h-9 rounded-lg bg-cyan-500/10 text-cyan-400 flex items-center justify-center shrink-0">
                      <FileArchive className="w-5 h-5" />
                    </div>
                    <div className="min-w-0">
                      <div className="text-xs font-bold text-white truncate">{uploadedZipFile.name}</div>
                      <div className="text-[11px] text-slate-400">
                        {(uploadedZipFile.size / 1024).toFixed(1)} KB • Ready to assemble
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    className="h-9 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 transition-all shrink-0"
                  >
                    Change
                  </button>
                </div>
              )}

              {/* Sample Preset Button */}
              <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-950/50 border border-slate-800/80 text-[11px]">
                <span className="text-slate-400">Need a sample Smali ZIP archive to test?</span>
                <button
                  onClick={handleGeneratePresetZip}
                  className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 font-semibold flex items-center space-x-1 transition-all active:scale-95"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Load Sample ZIP</span>
                </button>
              </div>
            </div>
          )}

          {/* Mode 2: Current Workspace */}
          {sourceMode === 'workspace' && (
            <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white">In-Memory Smali Classes</span>
                <span className="text-xs font-mono font-bold text-emerald-400">
                  {currentClasses.length} Loaded
                </span>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                Assembles the current working copy (including any applied security remediation patches) directly into a clean Dalvik Executable.
              </p>
              {currentClasses.length === 0 && (
                <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-900/40 text-amber-300 text-xs flex items-center space-x-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>No classes loaded. Please load a test fixture or upload files first.</span>
                </div>
              )}
            </div>
          )}

          {/* Output Filename Config */}
          <div className="space-y-1">
            <label className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
              Output Filename
            </label>
            <input
              type="text"
              value={outputFileName}
              onChange={(e) => setOutputFileName(e.target.value)}
              className="w-full h-10 px-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
              placeholder="classes.dex"
            />
          </div>

          {/* Error Banner */}
          {errorMessage && (
            <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-900/60 text-rose-300 text-xs flex items-start space-x-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="flex-1 text-[11px] leading-relaxed">{errorMessage}</div>
            </div>
          )}

          {/* Action Button */}
          {!assemblyResult && (
            <button
              onClick={runAssembly}
              disabled={isAssembling || (sourceMode === 'upload' && !uploadedZipFile) || (sourceMode === 'workspace' && currentClasses.length === 0)}
              className={`w-full min-h-[48px] rounded-xl font-bold text-xs flex items-center justify-center space-x-2 transition-all shadow-lg ${
                isAssembling || (sourceMode === 'upload' && !uploadedZipFile) || (sourceMode === 'workspace' && currentClasses.length === 0)
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700/50'
                  : 'bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 active:scale-98 text-slate-950 font-black shadow-cyan-950/40'
              }`}
            >
              {isAssembling ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>{assembleProgressStep || 'Assembling DEX...'}</span>
                </>
              ) : (
                <>
                  <Cpu className="w-4 h-4" />
                  <span>Assemble to DEX</span>
                </>
              )}
            </button>
          )}

          {/* Assembly Result Display */}
          {assemblyResult && (
            <div className="space-y-3 pt-2">
              {/* Success Badge Card */}
              <div className="p-3.5 rounded-2xl bg-emerald-950/30 border border-emerald-800/60 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    <span className="text-xs font-bold text-emerald-300">
                      DEX Assembly Verified
                    </span>
                  </div>
                  <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                    Dalvik 035 OK
                  </span>
                </div>

                {/* Key Metrics Grid */}
                <div className="grid grid-cols-4 gap-1.5 text-center">
                  <div className="p-2 rounded-xl bg-slate-900/80 border border-slate-800">
                    <div className="text-[10px] text-slate-400">Size</div>
                    <div className="text-xs font-mono font-bold text-white mt-0.5">
                      {(assemblyResult.size / 1024).toFixed(1)} KB
                    </div>
                  </div>
                  <div className="p-2 rounded-xl bg-slate-900/80 border border-slate-800">
                    <div className="text-[10px] text-slate-400">Classes</div>
                    <div className="text-xs font-mono font-bold text-white mt-0.5">
                      {assemblyResult.classCount}
                    </div>
                  </div>
                  <div className="p-2 rounded-xl bg-slate-900/80 border border-slate-800">
                    <div className="text-[10px] text-slate-400">Methods</div>
                    <div className="text-xs font-mono font-bold text-white mt-0.5">
                      {assemblyResult.methodCount}
                    </div>
                  </div>
                  <div className="p-2 rounded-xl bg-slate-900/80 border border-slate-800">
                    <div className="text-[10px] text-slate-400">Strings</div>
                    <div className="text-xs font-mono font-bold text-white mt-0.5">
                      {assemblyResult.stringCount}
                    </div>
                  </div>
                </div>

                {/* Hashes & Fingerprints */}
                <div className="space-y-1.5 pt-1 text-[11px] font-mono">
                  <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900/90 border border-slate-800/80">
                    <span className="text-slate-400">Adler-32:</span>
                    <div className="flex items-center space-x-1.5">
                      <span className="text-cyan-300 font-bold">{assemblyResult.adler32}</span>
                      <button
                        onClick={() => copyToClipboard(assemblyResult.adler32, 'adler')}
                        className="p-1 hover:text-white text-slate-400 transition-colors"
                        title="Copy Adler-32"
                      >
                        {copiedKey === 'adler' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900/90 border border-slate-800/80">
                    <span className="text-slate-400">SHA-1:</span>
                    <div className="flex items-center space-x-1.5">
                      <span className="text-slate-200 truncate max-w-[170px]">
                        {assemblyResult.sha1}
                      </span>
                      <button
                        onClick={() => copyToClipboard(assemblyResult.sha1, 'sha1')}
                        className="p-1 hover:text-white text-slate-400 transition-colors"
                        title="Copy SHA-1"
                      >
                        {copiedKey === 'sha1' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900/90 border border-slate-800/80">
                    <span className="text-slate-400">SHA-256:</span>
                    <div className="flex items-center space-x-1.5">
                      <span className="text-slate-200 truncate max-w-[170px]">
                        {assemblyResult.sha256}
                      </span>
                      <button
                        onClick={() => copyToClipboard(assemblyResult.sha256, 'sha256')}
                        className="p-1 hover:text-white text-slate-400 transition-colors"
                        title="Copy SHA-256"
                      >
                        {copiedKey === 'sha256' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                </div>

                {/* Primary Download Button */}
                <button
                  onClick={handleDownloadDex}
                  className="w-full min-h-[48px] rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 active:scale-98 text-slate-950 font-black text-xs flex items-center justify-center space-x-2 transition-all shadow-lg shadow-emerald-950/40"
                >
                  <Download className="w-4 h-4" />
                  <span>Download {outputFileName}</span>
                </button>
              </div>

              {/* Class Inspection Accordion */}
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 overflow-hidden">
                <button
                  onClick={() => setShowClassList(!showClassList)}
                  className="w-full p-3 flex items-center justify-between text-xs font-semibold text-slate-300 hover:text-white transition-colors"
                >
                  <div className="flex items-center space-x-2">
                    <FileCode className="w-4 h-4 text-emerald-400" />
                    <span>Included Classes ({assemblyResult.classes.length})</span>
                  </div>
                  {showClassList ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
                {showClassList && (
                  <div className="p-3 pt-0 space-y-1.5 border-t border-slate-800/80 max-h-48 overflow-y-auto">
                    {assemblyResult.classes.map((c, i) => (
                      <div
                        key={`${c.name}-${i}`}
                        className="p-2 rounded-lg bg-slate-900 border border-slate-800/80 text-[11px] flex items-center justify-between"
                      >
                        <span className="font-mono text-cyan-300 truncate max-w-[240px]">
                          {c.name}
                        </span>
                        <span className="text-slate-400 text-[10px]">
                          {c.methods.length} methods
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Build Log Accordion */}
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 overflow-hidden">
                <button
                  onClick={() => setShowLogDetails(!showLogDetails)}
                  className="w-full p-3 flex items-center justify-between text-xs font-semibold text-slate-300 hover:text-white transition-colors"
                >
                  <div className="flex items-center space-x-2">
                    <Terminal className="w-4 h-4 text-cyan-400" />
                    <span>Assembler Pipeline Log ({assemblyResult.buildLog.length} events)</span>
                  </div>
                  {showLogDetails ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
                {showLogDetails && (
                  <div className="p-3 pt-0 border-t border-slate-800/80">
                    <div className="p-2 rounded-lg bg-slate-950 font-mono text-[10px] text-slate-300 space-y-1 max-h-48 overflow-y-auto">
                      {assemblyResult.buildLog.map((log, i) => (
                        <div key={i} className="leading-tight">
                          {log}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Reset to Build Another */}
              <button
                onClick={() => {
                  setAssemblyResult(null);
                  setUploadedZipFile(null);
                }}
                className="w-full min-h-[44px] rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 transition-all flex items-center justify-center space-x-1.5"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Assemble Another Archive</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
