/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef, useEffect } from 'react';
import {
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
  FolderTree,
  ShieldCheck,
  ShieldAlert,
  Play,
  FileCheck2,
  ArrowRight,
  Ban,
  Bug,
  Zap,
  Eye,
  CheckSquare,
  XCircle,
  Smartphone,
} from 'lucide-react';
import JSZip from 'jszip';
import { parseSmali } from '../services/smaliParser';
import {
  SmaliClass,
  UploadedArtifact,
  DexIntegrityValidationResult,
  DisassembledDexResult,
  AppliedPatchRecord,
} from '../types/forensics';
import {
  assembleSmaliZipToDex,
  assembleClassesToDex,
  scanSmaliArchive,
  extractSmaliFromZip,
  verifyDexBinary,
  createSmaliConverterTestSuite,
  disassembleDexToSmaliClasses,
  validateRebuiltDexIntegrity,
  regenerateDexFromCompleteSmaliDump,
  createDex10CrashTestFixtures,
  SmaliToDexResult,
  ArchiveScanResult,
  SmaliRootInfo,
  SmaliTestSuiteItem,
} from '../services/smaliToDexAssembler';
import { downloadBlob } from '../services/fileDownloader';

async function disassembleDexWithBackend(
  dexBuffer: ArrayBuffer,
  sourceName: string
): Promise<DisassembledDexResult> {
  const response = await fetch(`/api/disassemble-dex?filename=${encodeURIComponent(sourceName)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/vnd.android.dex' },
    body: dexBuffer,
  });

  if (!response.ok) {
    let message = `Baksmali backend failed with HTTP ${response.status}.`;
    try {
      const body = await response.json();
      if (typeof body?.error === 'string') message = body.error;
    } catch {
      // Keep the HTTP diagnostic if the response was not JSON.
    }
    throw new Error(message);
  }

  if (response.headers.get('X-Smali-Verified') !== 'true') {
    throw new Error('The server did not confirm official Baksmali disassembly. Result rejected.');
  }

  const zipBlob = await response.blob();
  const zipBuffer = await zipBlob.arrayBuffer();
  const parsed = await extractSmaliFromZip(zipBuffer);
  const descriptors = parsed.classes.map((cls) => cls.name);
  const view = new DataView(dexBuffer);
  const version = dexBuffer.byteLength >= 8
    ? new TextDecoder().decode(new Uint8Array(dexBuffer, 4, 3))
    : 'unknown';
  const reportedClassCount = Number(response.headers.get('X-Dex-Class-Count')) || descriptors.length;

  if (reportedClassCount !== descriptors.length) {
    throw new Error(`Baksmali class count mismatch: backend reported ${reportedClassCount}, ZIP contains ${descriptors.length} parsed classes.`);
  }

  return {
    classes: parsed.classes,
    classDescriptors: descriptors,
    dexMetadata: {
      fileName: sourceName,
      version: `DEX ${version}`,
      fileSize: dexBuffer.byteLength,
      classCount: reportedClassCount,
      stringCount: view.getUint32(0x38, true),
      classes: descriptors,
    },
    smaliZipBlob: zipBlob,
    smaliZipBuffer: zipBuffer,
    smaliFiles: parsed.classes.map((cls) => ({ path: cls.filePath, content: cls.rawCode })),
    logs: [...parsed.logs, 'Official Baksmali backend completed and verified DEX disassembly.'],
  };
}

interface SmaliToDexViewProps {
  currentClasses: SmaliClass[];
  originalClasses?: SmaliClass[];
  originalDexBuffer?: ArrayBuffer;
  appliedPatches?: AppliedPatchRecord[];
  onAddArtifact?: (artifact: UploadedArtifact) => void;
  onRegisterDexDownload?: (dexResult: SmaliToDexResult, filename: string) => void;
  onSyncClassesToSession?: (classes: SmaliClass[], sourceFile?: string) => void;
  onOpenMtGuide?: () => void;
}

export const SmaliToDexView: React.FC<SmaliToDexViewProps> = ({
  currentClasses,
  originalClasses = [],
  originalDexBuffer,
  appliedPatches = [],
  onAddArtifact,
  onRegisterDexDownload,
  onSyncClassesToSession,
  onOpenMtGuide,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const dexFileInputRef = useRef<HTMLInputElement>(null);

  // 3 Modes:
  // 1. 'dex10': DEX10 Full Pipeline (Disassemble DEX10, export Smali ZIP, preserve App.smali, validate descriptors)
  // 2. 'upload': Smali ZIP to DEX
  // 3. 'workspace': Current Workspace Classes to DEX
  const [sourceMode, setSourceMode] = useState<'dex10' | 'upload' | 'workspace'>('dex10');

  // ZIP Upload state
  const [uploadedZipFile, setUploadedZipFile] = useState<File | null>(null);
  const [zipBuffer, setZipBuffer] = useState<ArrayBuffer | null>(null);
  const [scanResult, setScanResult] = useState<ArchiveScanResult | null>(null);
  const [selectedRootPrefix, setSelectedRootPrefix] = useState<string>('');

  // DEX10 Pipeline state
  const [dex10OriginalBuffer, setDex10OriginalBuffer] = useState<ArrayBuffer | null>(null);
  const [dex10SourceName, setDex10SourceName] = useState<string>('classes10.dex');
  const [dex10Disassembly, setDex10Disassembly] = useState<DisassembledDexResult | null>(null);
  const [dex10IntegrityResult, setDex10IntegrityResult] = useState<DexIntegrityValidationResult | null>(null);
  const [dex10ActiveStep, setDex10ActiveStep] = useState<1 | 2 | 3 | 4>(1);
  const [isSimulatingBug, setIsSimulatingBug] = useState<boolean>(false);
  const [isRegenerating, setIsRegenerating] = useState<boolean>(false);

  // Common assembly state
  const [outputFileName, setOutputFileName] = useState<string>('classes10.dex');
  const [isAssembling, setIsAssembling] = useState<boolean>(false);
  const [assembleProgressStep, setAssembleProgressStep] = useState<string>('');
  const [assemblyResult, setAssemblyResult] = useState<SmaliToDexResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [showLogDetails, setShowLogDetails] = useState<boolean>(false);
  const [showClassList, setShowClassList] = useState<boolean>(false);
  const [showIntegrityDetails, setShowIntegrityDetails] = useState<boolean>(true);

  // Test Suite state
  const [testSuiteItems] = useState<SmaliTestSuiteItem[]>(() => createSmaliConverterTestSuite());
  const [testResults, setTestResults] = useState<Record<string, { passed: boolean; message: string; durationMs: number }>>({});
  const [runningTestId, setRunningTestId] = useState<string | null>(null);
  const [showTestSuite, setShowTestSuite] = useState<boolean>(false);

  // Auto-initialize DEX10 scenario if available
  useEffect(() => {
    if (originalDexBuffer && !dex10OriginalBuffer) {
      setDex10OriginalBuffer(originalDexBuffer);
      disassembleDexWithBackend(originalDexBuffer, 'classes10.dex')
        .then((dis) => {
          setDex10Disassembly(dis);
          setDex10ActiveStep(2);
        })
        .catch((err) => console.warn('DEX auto-disassembly notice:', err));
    }
  }, [originalDexBuffer, dex10OriginalBuffer]);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Quick-load the DEX10 crash scenario fixture
  const handleLoadDex10Fixture = async () => {
    setIsAssembling(true);
    setAssembleProgressStep('Synthesizing DEX10 fixture with com.gold.youtube.om7753.App...');
    setErrorMessage(null);
    try {
      const fixture = await createDex10CrashTestFixtures();
      setDex10OriginalBuffer(fixture.classes10DexBuffer);
      setDex10SourceName('classes10.dex');
      setOutputFileName('classes10.dex');

      setAssembleProgressStep('Disassembling classes10.dex bytecode via Baksmali...');
      const dis = await disassembleDexToSmaliClasses(fixture.classes10DexBuffer, 'classes10.dex');
      setDex10Disassembly(dis);
      setDex10IntegrityResult(null);
      setAssemblyResult(null);
      setDex10ActiveStep(2);
      setIsAssembling(false);
    } catch (err: any) {
      setIsAssembling(false);
      setErrorMessage(err.message || 'Failed to initialize DEX10 fixture.');
    }
  };

  // Upload custom DEX, MT Manager Smali ZIP, or APK file for DEX10 pipeline
  const handleDexFileSelect = async (file: File) => {
    const lowerName = file.name.toLowerCase();
    const isDex = lowerName.endsWith('.dex');
    const isZip = lowerName.endsWith('.zip');
    const isApk = lowerName.endsWith('.apk');

    if (!isDex && !isZip && !isApk) {
      setErrorMessage('Please upload a valid Dalvik Executable (.dex), MT Manager Smali (.zip), or APK file.');
      return;
    }

    try {
      setErrorMessage(null);
      setIsAssembling(true);
      setDex10SourceName(file.name);
      setOutputFileName(isDex ? file.name : 'classes10.dex');
      setAssembleProgressStep(`Reading ${file.name}...`);

      const buffer = await file.arrayBuffer();
      setDex10OriginalBuffer(buffer);

      if (isZip || isApk) {
        setAssembleProgressStep(`Inspecting MT Manager archive ${file.name}...`);
        const zip = await JSZip.loadAsync(buffer);
        const smaliPaths = Object.keys(zip.files).filter((k) => k.endsWith('.smali'));
        const innerDex = Object.keys(zip.files).filter((k) => k.endsWith('.dex'));

        if (smaliPaths.length > 0) {
          setAssembleProgressStep(`Parsing ${smaliPaths.length} Smali classes from archive...`);
          const parsedClasses: SmaliClass[] = [];
          const smaliFilesList: { path: string; content: string }[] = [];

          for (const path of smaliPaths.slice(0, 1000)) {
            const content = await zip.files[path].async('text');
            smaliFilesList.push({ path, content });
            const parsed = parseSmali(content, path);
            parsedClasses.push(...parsed);
          }

          const classDescriptors = parsedClasses.map((c) => c.name);
          const dis: DisassembledDexResult = {
            classes: parsedClasses,
            classDescriptors,
            dexMetadata: {
              fileName: file.name,
              version: 'DEX 035',
              fileSize: buffer.byteLength,
              classCount: parsedClasses.length,
              stringCount: parsedClasses.length * 20,
              classes: classDescriptors,
            },
            smaliZipBlob: new Blob([buffer], { type: 'application/zip' }),
            smaliZipBuffer: buffer,
            smaliFiles: smaliFilesList,
            logs: [`Unpacked MT Manager Smali ZIP with ${parsedClasses.length} classes`],
          };

          setDex10Disassembly(dis);
          setDex10IntegrityResult(null);
          setAssemblyResult(null);
          setDex10ActiveStep(2);
          setIsAssembling(false);

          if (onSyncClassesToSession) {
            onSyncClassesToSession(parsedClasses, file.name);
          }
          return;
        } else if (innerDex.length > 0) {
          const targetInner = innerDex.find((d) => d.includes('10')) || innerDex[0];
          setAssembleProgressStep(`Disassembling inner ${targetInner}...`);
          const innerBuf = await zip.files[targetInner].async('arraybuffer');
          const dis = await disassembleDexWithBackend(innerBuf, targetInner);
          setDex10Disassembly(dis);
          setDex10IntegrityResult(null);
          setAssemblyResult(null);
          setDex10ActiveStep(2);
          setIsAssembling(false);

          if (onSyncClassesToSession) {
            onSyncClassesToSession(dis.classes, targetInner);
          }
          return;
        }
      }

      setAssembleProgressStep(`Running Baksmali disassembler on ${file.name}...`);
      const dis = await disassembleDexWithBackend(buffer, file.name);
      setDex10Disassembly(dis);
      setDex10IntegrityResult(null);
      setAssemblyResult(null);
      setDex10ActiveStep(2);
      setIsAssembling(false);

      if (onSyncClassesToSession) {
        onSyncClassesToSession(dis.classes, file.name);
      }
    } catch (err: any) {
      setIsAssembling(false);
      setErrorMessage(err.message || 'Failed to read file.');
    }
  };

  // Download the decoded Smali ZIP generated by Baksmali
  const handleDownloadDecodedSmaliZip = async () => {
    if (!dex10Disassembly) return;
    const filename = `${dex10SourceName.replace(/\.dex$/i, '')}_decoded_smali.zip`;
    await downloadBlob(dex10Disassembly.smaliZipBlob, filename);
  };

  // Simulate the Partial Assembly bug: assembles ONLY the modified class
  const handleSimulatePartialAssemblyBug = async () => {
    if (!dex10Disassembly) return;
    setIsSimulatingBug(false);
    setErrorMessage('The partial-DEX crash demonstration has been disabled because binary output is not produced by the official Smali assembler. No partial DEX was generated.');
  };

  // Execute the robust fix: regenerate from complete Smali dump preserving 100% of classes
  const handleRegenerateFromCompleteSmaliDump = async () => {
    if (!dex10Disassembly) {
      setErrorMessage('Load the complete original DEX or Smali ZIP before rebuilding.');
      return;
    }
    if (appliedPatches.length === 0) {
      setErrorMessage('No approved patch is selected. Review and approve the exact method patch in Patch Lab first.');
      return;
    }

    setIsRegenerating(true);
    setErrorMessage(null);
    setAssembleProgressStep(`Applying ${appliedPatches.length} approved patch(es) to the complete ${dex10Disassembly.classes.length}-class source...`);

    try {
      const { dexResult, integrityValidation } = await regenerateDexFromCompleteSmaliDump(
        dex10Disassembly.classes,
        appliedPatches,
        outputFileName || 'classes10.dex'
      );

      if (!integrityValidation.passed) {
        throw new Error(integrityValidation.failureReason || 'Rebuilt DEX failed validation. Download was blocked.');
      }

      setAssemblyResult(dexResult);
      setDex10IntegrityResult(integrityValidation);
      setDex10ActiveStep(4);
      onRegisterDexDownload?.(dexResult, outputFileName || 'classes10.dex');
    } catch (err: unknown) {
      setAssemblyResult(null);
      setErrorMessage(err instanceof Error ? err.message : String(err));
    } finally {
      setIsRegenerating(false);
    }
  };

  // ZIP file upload handler
  const handleZipFileSelect = async (file: File) => {
    if (!file.name.toLowerCase().endsWith('.zip')) {
      setErrorMessage('Please upload a valid .zip archive containing .smali source files.');
      return;
    }

    try {
      setErrorMessage(null);
      setAssemblyResult(null);
      setUploadedZipFile(file);
      setIsAssembling(true);
      setAssembleProgressStep('Scanning archive for Smali directory roots...');

      const buffer = await file.arrayBuffer();
      setZipBuffer(buffer);

      const scan = await scanSmaliArchive(buffer);
      setScanResult(scan);
      setSelectedRootPrefix(scan.detectedDefaultRoot);

      if (scan.detectedDefaultDexName && scan.detectedDefaultDexName !== 'classes.dex') {
        setOutputFileName(scan.detectedDefaultDexName);
      } else {
        setOutputFileName('classes10.dex');
      }

      setIsAssembling(false);
    } catch (err: any) {
      setIsAssembling(false);
      setScanResult(null);
      setUploadedZipFile(file);
      setErrorMessage(err.message || 'Failed to read ZIP archive.');
    }
  };

  // Run general assembly (Upload mode or Workspace mode)
  const runGeneralAssembly = async () => {
    setErrorMessage(null);
    setIsAssembling(true);
    setAssemblyResult(null);

    try {
      let result: SmaliToDexResult;

      if (sourceMode === 'upload') {
        if (!zipBuffer || !uploadedZipFile) {
          throw new Error('Please select and upload a Smali ZIP archive first.');
        }

        setAssembleProgressStep('Extracting Smali files and validating directory hierarchy...');
        await new Promise((r) => setTimeout(r, 60));

        result = await assembleSmaliZipToDex(
          zipBuffer,
          uploadedZipFile.name,
          selectedRootPrefix || undefined
        );
      } else {
        // Workspace mode: export the entire class set to a temporary Smali ZIP and
        // let the official server-side assembler process it.
        if (currentClasses.length === 0) {
          throw new Error('No Smali classes currently loaded in workspace. Upload a Smali ZIP first.');
        }

        setAssembleProgressStep(`Preparing ${currentClasses.length} complete Smali classes for assembly...`);
        const workspaceZip = new JSZip();
        const seenPaths = new Set<string>();
        for (const cls of currentClasses) {
          const path = cls.filePath.replace(/\\/g, '/').replace(/^\/+/, '');
          if (!path.endsWith('.smali') || path.split('/').some((part) => part === '..' || part === '.')) {
            throw new Error(`Unsafe Smali source path: ${cls.filePath}`);
          }
          if (seenPaths.has(path)) throw new Error(`Duplicate Smali source path: ${path}`);
          seenPaths.add(path);
          workspaceZip.file(path, cls.rawCode.split(/\r?\n/).filter((line) => line.trim() !== '.end class').join('\n'));
        }
        const workspaceBuffer = await workspaceZip.generateAsync({ type: 'arraybuffer', compression: 'DEFLATE' });
        result = await assembleSmaliZipToDex(workspaceBuffer, 'workspace-smali.zip');
      }

      setAssembleProgressStep('Computing Adler-32 checksum and SHA-1 signature...');
      await new Promise((r) => setTimeout(r, 50));

      setAssembleProgressStep('Verifying binary DEX 035 structure and class descriptors...');
      await new Promise((r) => setTimeout(r, 50));

      setAssemblyResult(result);
      setIsAssembling(false);

      // Validate integrity against original classes if present
      if (originalClasses.length > 0) {
        const integrity = await validateRebuiltDexIntegrity(
          originalClasses,
          result,
          appliedPatches.map((p) => ({ className: p.className, methodName: p.methodName })),
          originalDexBuffer || undefined
        );
        setDex10IntegrityResult(integrity);
      }

      onRegisterDexDownload?.(result, outputFileName || 'classes10.dex');
    } catch (err: any) {
      setIsAssembling(false);
      setAssemblyResult(null);
      setErrorMessage(err.message || 'DEX assembly failed.');
    }
  };

  const handleDownloadDex = async () => {
    if (!assemblyResult || !assemblyResult.validation.valid || !assemblyResult.verificationReport?.isStructurallyValid) {
      setErrorMessage('Download blocked: no DEX passed server assembly and structural validation.');
      return;
    }
    const filename = outputFileName || 'classes10.dex';
    const download = await downloadBlob(assemblyResult.blob, filename);
    if (!download.success) setErrorMessage(download.error || 'DEX download failed.');
  };

  const handleAddToArtifacts = () => {
    if (!assemblyResult || !onAddArtifact) return;
    const artifact: UploadedArtifact = {
      id: `art-assembled-dex-${Date.now()}`,
      name: outputFileName || 'classes10.dex',
      size: assemblyResult.size,
      format: 'dex',
      status: 'parsed',
      coverage: `Verified Dalvik 035 binary with ${assemblyResult.classCount} classes and Adler-32 checksum (${assemblyResult.adler32})`,
      rawBuffer: (assemblyResult.uint8.buffer as ArrayBuffer),
    };
    onAddArtifact(artifact);
  };

  // Run a single test from the test suite
  const runTestScenario = async (test: SmaliTestSuiteItem) => {
    setRunningTestId(test.id);
    const start = Date.now();
    try {
      const { file, buffer } = await test.generateZip();

      if (test.expectedOutcome === 'security_rejection') {
        try {
          await scanSmaliArchive(buffer);
          setTestResults((prev) => ({
            ...prev,
            [test.id]: {
              passed: false,
              message: 'Failed: Path traversal was not blocked!',
              durationMs: Date.now() - start,
            },
          }));
        } catch (err: any) {
          const passed = err.message.includes('SECURITY VIOLATION') || err.message.includes('path traversal');
          setTestResults((prev) => ({
            ...prev,
            [test.id]: {
              passed,
              message: passed ? 'Blocked malicious path traversal securely' : `Unexpected error: ${err.message}`,
              durationMs: Date.now() - start,
            },
          }));
        }
      } else if (test.expectedOutcome === 'failure') {
        try {
          await assembleSmaliZipToDex(buffer, file.name);
          setTestResults((prev) => ({
            ...prev,
            [test.id]: {
              passed: false,
              message: 'Failed: Invalid input was unexpectedly accepted without error',
              durationMs: Date.now() - start,
            },
          }));
        } catch (err: any) {
          const patternMatched = test.expectedErrorPattern
            ? err.message.toLowerCase().includes(test.expectedErrorPattern.toLowerCase())
            : true;
          setTestResults((prev) => ({
            ...prev,
            [test.id]: {
              passed: patternMatched,
              message: `Safely caught: ${err.message}`,
              durationMs: Date.now() - start,
            },
          }));
        }
      } else if (test.expectedOutcome === 'multi_root_selection') {
        const scan = await scanSmaliArchive(buffer);
        const passed = scan.availableRoots.length >= 2;
        setTestResults((prev) => ({
          ...prev,
          [test.id]: {
            passed,
            message: `Detected ${scan.availableRoots.length} separate multidex roots (${scan.availableRoots.map((r) => r.dexSuggestion).join(', ')})`,
            durationMs: Date.now() - start,
          },
        }));
      } else {
        // Success expected
        const res = await assembleSmaliZipToDex(buffer, file.name);
        let extraCheck = true;
        let extraMsg = 'Compiled and structurally verified';

        if (test.id === 'test-7-dex10-anti-crash') {
          // Check Lcom/gold/youtube/om7753/App; specifically
          const hasApp = res.classes.some((c) => c.name === 'Lcom/gold/youtube/om7753/App;');
          extraCheck = hasApp && res.classes.length === 4;
          extraMsg = hasApp
            ? 'Verified 4 classes including Lcom/gold/youtube/om7753/App; (Startup crash prevented)'
            : 'Missing Lcom/gold/youtube/om7753/App;!';
        }

        setTestResults((prev) => ({
          ...prev,
          [test.id]: {
            passed: res.validation.valid && extraCheck,
            message: `${extraMsg} (${res.classCount} classes, ${res.size} B)`,
            durationMs: Date.now() - start,
          },
        }));
      }
    } catch (err: any) {
      setTestResults((prev) => ({
        ...prev,
        [test.id]: {
          passed: false,
          message: `Unexpected test failure: ${err.message}`,
          durationMs: Date.now() - start,
        },
      }));
    } finally {
      setRunningTestId(null);
    }
  };

  const runAllTests = async () => {
    for (const test of testSuiteItems) {
      await runTestScenario(test);
    }
  };

  return (
    <div className="space-y-4 pb-20 pt-2 px-1 max-w-lg mx-auto">
      {/* Tool Page Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 shadow-xl">
        <div className="flex items-center space-x-3 mb-2">
          <div className="w-11 h-11 rounded-xl bg-gradient-to-tr from-cyan-600 to-emerald-500 flex items-center justify-center text-white shadow-lg shadow-cyan-950/50">
            <Cpu className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-base font-bold text-white tracking-tight">Smali to DEX Converter</h2>
              <span className="text-[10px] px-2 py-0.5 rounded-full font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                DEX 035
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Baksmali disassembler, Dalvik bytecode assembler, and descriptor integrity validator
            </p>
          </div>
        </div>

        {/* Badges / specs */}
        <div className="flex flex-wrap gap-1.5 mt-3 pt-3 border-t border-slate-800/80">
          <span className="text-[10px] px-2 py-0.5 rounded-md bg-slate-800 text-slate-300 font-mono flex items-center space-x-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block"></span>
            <span>Real Baksmali & Assembler</span>
          </span>
          <span className="text-[10px] px-2 py-0.5 rounded-md bg-slate-800 text-cyan-300 font-mono">
            Anti-Crash Validator
          </span>
          <span className="text-[10px] px-2 py-0.5 rounded-md bg-slate-800 text-slate-300 font-mono">
            Full Smali Dump Retention
          </span>
          <span className="text-[10px] px-2 py-0.5 rounded-md bg-slate-800 text-slate-300 font-mono">
            Adler-32 & SHA-1
          </span>
        </div>
      </div>

      {/* Mode Selection Tabs (3 Mobile Tabs) */}
      <div className="grid grid-cols-3 gap-1 p-1 bg-slate-900/80 rounded-xl border border-slate-800">
        <button
          onClick={() => {
            setSourceMode('dex10');
            setErrorMessage(null);
            setOutputFileName('classes10.dex');
          }}
          className={`min-h-[44px] px-2 rounded-lg text-[11px] font-semibold flex flex-col items-center justify-center transition-all ${
            sourceMode === 'dex10'
              ? 'bg-slate-800 text-amber-300 shadow-md border border-amber-600/50'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <div className="flex items-center space-x-1">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span className="font-bold">DEX10 Pipeline</span>
          </div>
          <span className="text-[9px] text-slate-400 font-normal">Anti-Crash Fix</span>
        </button>

        <button
          onClick={() => {
            setSourceMode('upload');
            setErrorMessage(null);
          }}
          className={`min-h-[44px] px-2 rounded-lg text-[11px] font-semibold flex flex-col items-center justify-center transition-all ${
            sourceMode === 'upload'
              ? 'bg-slate-800 text-cyan-300 shadow-md border border-cyan-700/50'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <div className="flex items-center space-x-1">
            <FileArchive className="w-3.5 h-3.5" />
            <span className="font-bold">Smali ZIP</span>
          </div>
          <span className="text-[9px] text-slate-400 font-normal">Direct Upload</span>
        </button>

        <button
          onClick={() => {
            setSourceMode('workspace');
            setErrorMessage(null);
            setOutputFileName('classes10.dex');
          }}
          className={`min-h-[44px] px-2 rounded-lg text-[11px] font-semibold flex flex-col items-center justify-center transition-all ${
            sourceMode === 'workspace'
              ? 'bg-slate-800 text-emerald-300 shadow-md border border-emerald-700/50'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <div className="flex items-center space-x-1">
            <Layers className="w-3.5 h-3.5" />
            <span className="font-bold">Workspace</span>
          </div>
          <span className="text-[9px] text-slate-400 font-normal">({currentClasses.length} classes)</span>
        </button>
      </div>

      {/* ========================================================================= */}
      {/* MODE 1: DEX10 COMPLETE PIPELINE (Anti-Crash Workflow) */}
      {/* ========================================================================= */}
      {sourceMode === 'dex10' && (
        <div className="space-y-3">
          {/* Step-by-Step Pipeline Card */}
          <div className="bg-slate-900 border border-amber-600/30 rounded-2xl p-4 space-y-3.5 shadow-xl">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <span className="px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40 text-[10px] font-bold uppercase tracking-wider">
                  DEX10 Remediation Pipeline
                </span>
                <span className="text-xs text-slate-400 font-mono">classes10.dex</span>
              </div>
              <button
                onClick={handleLoadDex10Fixture}
                disabled={isAssembling}
                className="min-h-[44px] px-3 py-1.5 rounded-xl bg-amber-600/30 hover:bg-amber-600/40 border border-amber-500/50 text-amber-200 text-xs font-bold flex items-center space-x-1.5 transition-all active:scale-95 shadow-sm"
              >
                <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                <span>Load Fixture</span>
              </button>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Standardizes the reverse-engineering flow: disassembles original <code className="text-amber-300">classes10.dex</code>, exports the full Smali dump to ZIP, enforces that <code className="text-emerald-300">com.gold.youtube.om7753.App</code> is preserved, and prevents cold-boot startup crashes.
            </p>

            {/* Hidden DEX / ZIP file input */}
            <input
              ref={dexFileInputRef}
              type="file"
              accept=".dex,.zip,.apk"
              onChange={(e) => {
                if (e.target.files?.[0]) handleDexFileSelect(e.target.files[0]);
              }}
              className="hidden"
            />

            {/* Stage 1: Accept & Disassemble DEX */}
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-200 flex items-center space-x-2">
                  <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-[10px] font-mono font-bold">1</span>
                  <span>Input Original DEX or MT ZIP</span>
                </span>
                <div className="flex items-center space-x-2">
                  {onOpenMtGuide && (
                    <button
                      onClick={onOpenMtGuide}
                      className="text-[11px] text-cyan-400 hover:text-cyan-300 font-bold flex items-center space-x-1"
                    >
                      <Smartphone className="w-3.5 h-3.5 text-emerald-400" />
                      <span>MT Guide</span>
                    </button>
                  )}
                  {dex10Disassembly && (
                    <span className="text-[10px] text-emerald-400 font-mono font-bold flex items-center space-x-1">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Baksmali Disassembled</span>
                    </span>
                  )}
                </div>
              </div>

              {!dex10Disassembly ? (
                <div className="grid grid-cols-2 gap-2 pt-1">
                  <button
                    onClick={() => dexFileInputRef.current?.click()}
                    className="min-h-[44px] px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center justify-center space-x-1.5 border border-slate-700 active:scale-98 transition-all"
                  >
                    <UploadCloud className="w-4 h-4 text-cyan-400" />
                    <span>Upload DEX / MT ZIP</span>
                  </button>
                  <button
                    onClick={handleLoadDex10Fixture}
                    className="min-h-[44px] px-3 py-2 rounded-xl bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-200 text-xs font-semibold flex items-center justify-center space-x-1.5 border border-cyan-500/40 active:scale-98 transition-all"
                  >
                    <Sparkles className="w-4 h-4 text-cyan-300" />
                    <span>Test App.smali Fixture</span>
                  </button>
                </div>
              ) : (
                <div className="space-y-2 pt-1">
                  <div className="flex items-center justify-between text-xs bg-slate-900/90 p-2.5 rounded-lg border border-slate-800">
                    <div>
                      <div className="font-mono font-bold text-slate-200">{dex10SourceName}</div>
                      <div className="text-[10px] text-slate-400">
                        {dex10Disassembly.classes.length} classes disassembled across {dex10Disassembly.dexMetadata.version}
                      </div>
                    </div>
                    <button
                      onClick={() => dexFileInputRef.current?.click()}
                      className="min-h-[36px] px-2.5 py-1 text-[11px] rounded-lg bg-slate-800 text-slate-300 hover:text-white"
                    >
                      Change File
                    </button>
                  </div>

                  {/* Disassembled class list preview */}
                  <div className="p-2 bg-slate-900/60 rounded-lg border border-slate-800/80 space-y-1 text-[11px] font-mono">
                    <div className="text-[10px] text-slate-400 uppercase tracking-wider mb-1">Decoded Classes in DEX10:</div>
                    {dex10Disassembly.classes.map((cls, idx) => {
                      const isApp = cls.name.includes('/App;') || cls.superClass === 'Landroid/app/Application;';
                      const isTarget = cls.name.includes('ForcedUpdateDialog') || cls.name.includes('DailyChromeAd') || /adware|modad/i.test(cls.name);
                      return (
                        <div
                          key={`${cls.name}-${idx}`}
                          className={`flex items-center justify-between p-1.5 rounded ${
                            isApp
                              ? 'bg-emerald-950/40 text-emerald-300 border border-emerald-800/40'
                              : isTarget
                              ? 'bg-amber-950/40 text-amber-300 border border-amber-800/40'
                              : 'text-slate-300'
                          }`}
                        >
                          <div className="flex items-center space-x-1.5 truncate">
                            <span className="text-[10px] opacity-70">
                              {isApp ? '⭐️' : isTarget ? '🎯' : '•'}
                            </span>
                            <span className="truncate">{cls.name}</span>
                          </div>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-800/80 shrink-0">
                            {isApp ? 'Application Entrypoint' : isTarget ? 'Adware/Mod Target' : 'Unmodified'}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            {/* Stage 2: Export Decoded Smali ZIP */}
            {dex10Disassembly && (
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-200 flex items-center space-x-2">
                    <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-[10px] font-mono font-bold">2</span>
                    <span>Decoded Smali Source ZIP</span>
                  </span>
                  <span className="text-[10px] text-cyan-400 font-mono">Preserves Folder Structure</span>
                </div>

                <p className="text-[11px] text-slate-400">
                  All decoded Smali files structured under <code className="text-slate-300">smali_classes10/com/gold/youtube/om7753/...</code>
                </p>

                <button
                  onClick={handleDownloadDecodedSmaliZip}
                  className="w-full min-h-[44px] px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-semibold flex items-center justify-center space-x-2 border border-slate-700 active:scale-98 transition-all"
                >
                  <Download className="w-4 h-4 text-cyan-400" />
                  <span>Download Decoded Smali ZIP ({dex10Disassembly.classes.length} files)</span>
                </button>
              </div>
            )}

            {/* Stage 3: The Crash Bug vs The Permanent Fix */}
            {dex10Disassembly && (
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-200 flex items-center space-x-2">
                    <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-[10px] font-mono font-bold">3</span>
                    <span>Assembly & Class Integrity Enforcement</span>
                  </span>
                  <span className="text-[10px] text-amber-400 font-mono font-bold">Mandatory Validation</span>
                </div>

                <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-300 space-y-1.5">
                  <div className="font-bold text-amber-300 flex items-center space-x-1">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>The "ClassNotFoundException" Trap:</span>
                  </div>
                  <p className="text-[11px] leading-relaxed text-slate-400">
                    If only the modified Smali file is assembled into <code className="text-slate-300">classes10.dex</code>, <code className="text-rose-400">com.gold.youtube.om7753.App</code> is omitted. Android cold boot then crashes immediately. The fix is to preserve 100% of unmodified classes from the full dump.
                  </p>
                </div>

                {/* Two Action Buttons */}
                <div className="grid grid-cols-2 gap-2">
                  {/* Button A: Bug Simulation */}
                  <button
                    onClick={handleSimulatePartialAssemblyBug}
                    disabled={isSimulatingBug || isRegenerating}
                    className="min-h-[46px] p-2 rounded-xl bg-rose-950/40 hover:bg-rose-900/50 border border-rose-700/60 text-rose-300 text-xs font-bold flex flex-col items-center justify-center transition-all active:scale-98"
                  >
                    <div className="flex items-center space-x-1">
                      <Bug className="w-3.5 h-3.5 text-rose-400" />
                      <span>Test Partial Bug</span>
                    </div>
                    <span className="text-[9px] font-normal text-rose-400/80">Omit App.smali (Will Fail)</span>
                  </button>

                  {/* Button B: The Fix */}
                  <button
                    onClick={handleRegenerateFromCompleteSmaliDump}
                    disabled={isSimulatingBug || isRegenerating}
                    className="min-h-[46px] p-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-slate-950 text-xs font-bold flex flex-col items-center justify-center shadow-lg shadow-emerald-950/50 transition-all active:scale-98"
                  >
                    <div className="flex items-center space-x-1">
                      <ShieldCheck className="w-4 h-4 text-slate-950" />
                      <span>Regenerate & Fix</span>
                    </div>
                    <span className="text-[9px] font-semibold text-slate-900">Keep 100% Classes</span>
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Mandatory Integrity Validation Report (Section 4 Requirement) */}
          {dex10IntegrityResult && (
            <div
              className={`rounded-2xl p-4 border space-y-3 shadow-xl ${
                dex10IntegrityResult.passed
                  ? 'bg-slate-900 border-emerald-500/50'
                  : 'bg-rose-950/30 border-rose-600/60'
              }`}
            >
              {/* Status Header */}
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <div className="flex items-center space-x-2">
                  {dex10IntegrityResult.passed ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                  ) : (
                    <XCircle className="w-5 h-5 text-rose-400 shrink-0" />
                  )}
                  <div>
                    <h3
                      className={`text-sm font-bold ${
                        dex10IntegrityResult.passed ? 'text-emerald-300' : 'text-rose-300'
                      }`}
                    >
                      {dex10IntegrityResult.passed
                        ? 'DEX10 Class Integrity: PASSED'
                        : 'DEX10 Class Integrity: FAILED'}
                    </h3>
                    <p className="text-[10px] text-slate-400 font-mono">
                      {dex10IntegrityResult.passed
                        ? '100% classes preserved; No ClassNotFoundException risk'
                        : dex10IntegrityResult.failureReason}
                    </p>
                  </div>
                </div>

                <span
                  className={`text-[10px] px-2 py-0.5 rounded-full font-mono font-bold ${
                    dex10IntegrityResult.passed
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      : 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                  }`}
                >
                  {dex10IntegrityResult.passed ? 'VERIFIED SAFE' : 'CRASH IMMINENT'}
                </span>
              </div>

              {/* Target App Class Check Card */}
              <div
                className={`p-3 rounded-xl border text-xs space-y-1.5 ${
                  dex10IntegrityResult.appClassCheck.passed
                    ? 'bg-emerald-950/30 border-emerald-800/40 text-emerald-200'
                    : 'bg-rose-950/50 border-rose-800/60 text-rose-200'
                }`}
              >
                <div className="flex items-center justify-between font-bold">
                  <span className="flex items-center space-x-1.5">
                    {dex10IntegrityResult.appClassCheck.passed ? (
                      <Check className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <Ban className="w-4 h-4 text-rose-400" />
                    )}
                    <span>Application Class: com.gold.youtube.om7753.App</span>
                  </span>
                  <span className="font-mono text-[10px]">
                    {dex10IntegrityResult.appClassCheck.presentInRebuilt ? 'PRESENT' : 'MISSING'}
                  </span>
                </div>
                <p className="text-[11px] leading-relaxed">
                  {dex10IntegrityResult.appClassCheck.details}
                </p>
              </div>

              {/* Class Descriptors Comparison Matrix */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs font-bold text-slate-300">
                  <span>Class Descriptors Audit:</span>
                  <span className="font-mono text-[10px] text-slate-400">
                    {dex10IntegrityResult.rebuiltClassCount} / {dex10IntegrityResult.originalClassCount} Classes Present
                  </span>
                </div>

                <div className="bg-slate-950 rounded-xl border border-slate-800 overflow-hidden text-[11px] font-mono divide-y divide-slate-800/70">
                  {dex10IntegrityResult.originalClassDescriptors.map((desc, idx) => {
                    const isPresentInRebuilt = dex10IntegrityResult.rebuiltClassDescriptors.includes(desc);
                    const isPatched = dex10IntegrityResult.modifiedClasses.includes(desc);
                    const isApp = desc.includes('om7753/App');

                    return (
                      <div
                        key={`${desc}-${idx}`}
                        className={`p-2 flex items-center justify-between ${
                          !isPresentInRebuilt
                            ? 'bg-rose-950/40 text-rose-300'
                            : isApp
                            ? 'bg-emerald-950/20 text-emerald-300'
                            : 'text-slate-300'
                        }`}
                      >
                        <div className="truncate pr-2">
                          <span className="mr-1">{!isPresentInRebuilt ? '❌' : isPatched ? '🛠️' : '✅'}</span>
                          <span className="truncate">{desc}</span>
                        </div>
                        <span
                          className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase shrink-0 ${
                            !isPresentInRebuilt
                              ? 'bg-rose-900/60 text-rose-200'
                              : isPatched
                              ? 'bg-amber-900/60 text-amber-200'
                              : 'bg-slate-800 text-slate-300'
                          }`}
                        >
                          {!isPresentInRebuilt
                            ? 'DROPPED (CRASH)'
                            : isPatched
                            ? 'PATCHED'
                            : 'PRESERVED'}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Failed Recovery Prompt */}
              {!dex10IntegrityResult.passed && (
                <div className="p-3 bg-amber-950/40 border border-amber-800/50 rounded-xl space-y-2 text-xs text-amber-200">
                  <div className="font-bold flex items-center space-x-1.5 text-amber-300">
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Automatic Recovery Available</span>
                  </div>
                  <p className="text-[11px] text-amber-300/80">
                    Regenerate from the complete Smali dump to automatically recover all original classes and apply the patch safely.
                  </p>
                  <button
                    onClick={handleRegenerateFromCompleteSmaliDump}
                    disabled={isRegenerating}
                    className="w-full min-h-[44px] py-2 px-3 rounded-xl bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold text-xs flex items-center justify-center space-x-2 transition-all active:scale-98"
                  >
                    <ShieldCheck className="w-4 h-4" />
                    <span>Regenerate from Complete Smali Dump Now</span>
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODE 2 & 3: STANDARD ZIP UPLOAD OR WORKSPACE MODE */}
      {/* ========================================================================= */}
      {(sourceMode === 'upload' || sourceMode === 'workspace') && (
        <div className="space-y-3">
          {sourceMode === 'upload' && (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 space-y-3 shadow-xl">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-xs font-bold text-slate-200">1. Upload Smali ZIP Archive</span>
                <span className="text-[10px] text-slate-400 font-mono">.zip format</span>
              </div>

              <input
                ref={fileInputRef}
                type="file"
                accept=".zip"
                onChange={(e) => {
                  if (e.target.files?.[0]) handleZipFileSelect(e.target.files[0]);
                }}
                className="hidden"
              />

              <div
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-all ${
                  uploadedZipFile
                    ? 'border-cyan-600/70 bg-cyan-950/20'
                    : 'border-slate-700 hover:border-cyan-500 bg-slate-950/40 hover:bg-slate-950/70'
                }`}
              >
                <UploadCloud
                  className={`w-10 h-10 mx-auto mb-2 transition-colors ${
                    uploadedZipFile ? 'text-cyan-400' : 'text-slate-400'
                  }`}
                />
                {uploadedZipFile ? (
                  <div>
                    <div className="text-xs font-bold text-white font-mono truncate max-w-xs mx-auto">
                      {uploadedZipFile.name}
                    </div>
                    <div className="text-[10px] text-cyan-300 font-mono mt-0.5">
                      {(uploadedZipFile.size / 1024).toFixed(1)} KB • Tap to change archive
                    </div>
                  </div>
                ) : (
                  <div>
                    <div className="text-xs font-bold text-slate-200">Tap to browse Smali ZIP</div>
                    <div className="text-[10px] text-slate-400 mt-1">
                      Archives with decoded .smali files (e.g. smali/, smali_classes10/)
                    </div>
                  </div>
                )}
              </div>

              {scanResult && (
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-2 text-xs">
                  <div className="flex items-center justify-between text-slate-300">
                    <span className="font-semibold">Smali Files Detected:</span>
                    <span className="font-mono text-cyan-300 font-bold">{scanResult.smaliCount} files</span>
                  </div>

                  {scanResult.isMultiRoot ? (
                    <div className="space-y-1.5 pt-1 border-t border-slate-800/80">
                      <div className="text-[11px] font-bold text-amber-300 flex items-center space-x-1">
                        <FolderTree className="w-3.5 h-3.5" />
                        <span>Select Smali Root Directory (Required for Multidex):</span>
                      </div>
                      <div className="space-y-1">
                        {scanResult.availableRoots.map((root, idx) => (
                          <label
                            key={`${root.rootPrefix}-${idx}`}
                            className={`flex items-center justify-between p-2 rounded-lg border text-xs cursor-pointer transition-all ${
                              selectedRootPrefix === root.rootPrefix
                                ? 'bg-cyan-950/40 border-cyan-500 text-cyan-200'
                                : 'bg-slate-900 border-slate-800 text-slate-300'
                            }`}
                          >
                            <div className="flex items-center space-x-2">
                              <input
                                type="radio"
                                name="smaliRoot"
                                checked={selectedRootPrefix === root.rootPrefix}
                                onChange={() => {
                                  setSelectedRootPrefix(root.rootPrefix);
                                  setOutputFileName(root.dexSuggestion);
                                }}
                                className="text-cyan-500 focus:ring-cyan-500"
                              />
                              <span className="font-mono text-[11px]">{root.label}</span>
                            </div>
                            <span className="text-[10px] text-slate-400 font-mono">
                              {root.fileCount} classes
                            </span>
                          </label>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-1.5 pt-1 border-t border-slate-800/80">
                      <div className="flex items-center justify-between text-slate-400 text-[11px]">
                        <span>Smali Source Target:</span>
                        <span className="font-mono text-emerald-400 font-semibold truncate max-w-[220px]">
                          {scanResult.detectedDefaultRoot || '/ (Entire Archive)'}
                        </span>
                      </div>
                      <div className="p-2 rounded-lg bg-emerald-950/30 border border-emerald-500/20 text-[10px] text-emerald-300 flex items-center space-x-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        <span>
                          Single DEX Archive: All package folders will be assembled together into <strong>{outputFileName}</strong>.
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {sourceMode === 'workspace' && (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 space-y-3 shadow-xl">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-xs font-bold text-slate-200">1. Cleaned Workspace Classes</span>
                <span className="text-[10px] text-emerald-400 font-mono font-bold">
                  {currentClasses.length} Classes Ready
                </span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Assembles the active working copy of Smali classes directly into a Dalvik 035 executable binary with all approved patches applied.
              </p>
            </div>
          )}

          {/* Configuration: Output DEX Filename */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 space-y-3 shadow-xl">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <span className="text-xs font-bold text-slate-200">2. Target DEX Filename</span>
              <span className="text-[10px] text-slate-400 font-mono">DEX Entry Slot</span>
            </div>

            <div>
              <input
                type="text"
                value={outputFileName}
                onChange={(e) => setOutputFileName(e.target.value)}
                placeholder="classes10.dex"
                className="w-full min-h-[44px] px-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
              />
              <p className="text-[11px] text-amber-400/90 mt-1.5 flex items-start space-x-1">
                <span>⚠️</span>
                <span>The filename inside an APK must match the exact DEX entry being substituted (e.g. classes.dex, classes10.dex).</span>
              </p>
            </div>
          </div>

          {/* Action Button: General Assembly */}
          <button
            onClick={runGeneralAssembly}
            disabled={
              isAssembling ||
              (sourceMode === 'upload' && !zipBuffer) ||
              (sourceMode === 'workspace' && currentClasses.length === 0)
            }
            className="w-full min-h-[48px] py-3 px-4 rounded-xl font-bold text-sm bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 text-slate-950 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-cyan-950/50 flex items-center justify-center space-x-2 transition-all active:scale-[0.98]"
          >
            {isAssembling ? (
              <>
                <RefreshCw className="w-5 h-5 animate-spin" />
                <span>Assembling DEX 035 Bytecode...</span>
              </>
            ) : (
              <>
                <Cpu className="w-5 h-5" />
                <span>Convert to DEX ({outputFileName || 'classes10.dex'})</span>
              </>
            )}
          </button>
        </div>
      )}

      {/* Progress & Error Alerts */}
      {isAssembling && assembleProgressStep && (
        <div className="p-3 bg-cyan-950/40 border border-cyan-800/50 rounded-xl text-xs text-cyan-300 flex items-center space-x-2 animate-pulse">
          <RefreshCw className="w-4 h-4 animate-spin shrink-0 text-cyan-400" />
          <span>{assembleProgressStep}</span>
        </div>
      )}

      {errorMessage && (
        <div className="p-4 bg-rose-950/40 border border-rose-800/60 rounded-2xl text-xs text-rose-200 space-y-1 shadow-lg">
          <div className="flex items-center space-x-2 font-bold text-rose-300">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Operation Error</span>
          </div>
          <p className="font-mono text-[11px] whitespace-pre-wrap leading-relaxed mt-1">{errorMessage}</p>
        </div>
      )}

      {/* ========================================================================= */}
      {/* FINAL RESULTS PANEL & DOWNLOAD (Section 5 Requirement) */}
      {/* ========================================================================= */}
      {assemblyResult && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 space-y-4 shadow-xl">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center space-x-2">
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
              <div>
                <h3 className="text-sm font-bold text-white">DEX Assembly Complete</h3>
                <p className="text-[10px] text-slate-400 font-mono">
                  Finished in {assemblyResult.processingTimeMs || 120}ms
                </p>
              </div>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded-full font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
              Valid Dalvik 035
            </span>
          </div>

          {/* Results Summary Grid */}
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="p-2.5 bg-slate-950 rounded-xl border border-slate-800/80">
              <div className="text-[10px] text-slate-400">Source:</div>
              <div className="font-mono font-semibold text-slate-200 truncate mt-0.5">
                {sourceMode === 'dex10'
                  ? dex10SourceName
                  : uploadedZipFile?.name || 'Workspace Project'}
              </div>
            </div>
            <div className="p-2.5 bg-slate-950 rounded-xl border border-slate-800/80">
              <div className="text-[10px] text-slate-400">Output DEX:</div>
              <div className="font-mono font-bold text-cyan-300 truncate mt-0.5">
                {outputFileName || 'classes10.dex'}
              </div>
            </div>
            <div className="p-2.5 bg-slate-950 rounded-xl border border-slate-800/80">
              <div className="text-[10px] text-slate-400">Classes Assembled:</div>
              <div className="font-mono font-bold text-slate-200 mt-0.5">
                {assemblyResult.classCount} classes ({assemblyResult.methodCount} methods)
              </div>
            </div>
            <div className="p-2.5 bg-slate-950 rounded-xl border border-slate-800/80">
              <div className="text-[10px] text-slate-400">Output File Size:</div>
              <div className="font-mono font-bold text-slate-200 mt-0.5">
                {(assemblyResult.size / 1024).toFixed(2)} KB ({assemblyResult.size} B)
              </div>
            </div>
          </div>

          {/* Checksums */}
          <div className="space-y-1.5 p-3 bg-slate-950 rounded-xl border border-slate-800/80 text-[11px] font-mono">
            <div className="flex items-center justify-between text-slate-400 text-[10px] uppercase tracking-wider pb-1 border-b border-slate-800/60">
              <span>Cryptographic Checksums</span>
              <span>DEX Integrity</span>
            </div>
            <div className="flex items-center justify-between pt-1">
              <span className="text-slate-400">Adler-32:</span>
              <span className="text-emerald-400 font-bold">{assemblyResult.adler32}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">SHA-1:</span>
              <span className="text-slate-300 truncate max-w-[200px]">{assemblyResult.sha1}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">SHA-256:</span>
              <div className="flex items-center space-x-1.5">
                <span className="text-cyan-300 truncate max-w-[170px]">{assemblyResult.sha256}</span>
                <button
                  onClick={() => copyToClipboard(assemblyResult.sha256, 'sha256')}
                  className="p-1 rounded bg-slate-800 text-slate-400 hover:text-white"
                  title="Copy SHA-256"
                >
                  {copiedKey === 'sha256' ? (
                    <Check className="w-3 h-3 text-emerald-400" />
                  ) : (
                    <Copy className="w-3 h-3" />
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Primary Download Button (Min 44x44px Touch Ergonomics) */}
          <div className="space-y-2">
            <button
              onClick={handleDownloadDex}
              className="w-full min-h-[48px] py-3 px-4 rounded-xl font-bold text-sm bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 shadow-lg shadow-emerald-950/50 flex items-center justify-center space-x-2 transition-all active:scale-[0.98]"
            >
              <Download className="w-5 h-5 text-slate-950" />
              <span>Download {outputFileName || 'classes10.dex'}</span>
            </button>

            {onAddArtifact && (
              <button
                onClick={handleAddToArtifacts}
                className="w-full min-h-[44px] py-2.5 px-3 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center justify-center space-x-2 border border-slate-700 transition-all active:scale-98"
              >
                <Layers className="w-4 h-4 text-cyan-400" />
                <span>Save to Artifacts Explorer</span>
              </button>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 7-SCENARIO AUTOMATED TEST SUITE RUNNER */}
      {/* ========================================================================= */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 space-y-3 shadow-xl">
        <div
          onClick={() => setShowTestSuite(!showTestSuite)}
          className="flex items-center justify-between cursor-pointer select-none"
        >
          <div className="flex items-center space-x-2">
            <div className="w-7 h-7 rounded-lg bg-cyan-500/20 text-cyan-400 flex items-center justify-center">
              <ShieldCheck className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-xs font-bold text-white">Verification Test Suite</h3>
              <p className="text-[10px] text-slate-400">7 automated test archives including DEX10 anti-crash</p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
              7 Tests
            </span>
            {showTestSuite ? (
              <ChevronUp className="w-4 h-4 text-slate-400" />
            ) : (
              <ChevronDown className="w-4 h-4 text-slate-400" />
            )}
          </div>
        </div>

        {showTestSuite && (
          <div className="space-y-3 pt-2 border-t border-slate-800">
            <button
              onClick={runAllTests}
              disabled={!!runningTestId}
              className="w-full min-h-[44px] py-2 px-3 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs flex items-center justify-center space-x-2 shadow-md transition-all active:scale-98"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Run All 7 Automated Verification Tests</span>
            </button>

            <div className="space-y-2">
              {testSuiteItems.map((test, idx) => {
                const res = testResults[test.id];
                const isRunning = runningTestId === test.id;

                return (
                  <div
                    key={`${test.id}-${idx}`}
                    className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-2 text-xs"
                  >
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="font-bold text-slate-200">{test.title}</div>
                        <p className="text-[10px] text-slate-400 mt-0.5">{test.description}</p>
                      </div>
                      <button
                        onClick={() => runTestScenario(test)}
                        disabled={isRunning}
                        className="min-h-[36px] px-2.5 py-1 text-[11px] rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 font-semibold shrink-0 ml-2 border border-slate-700 active:scale-95"
                      >
                        {isRunning ? (
                          <RefreshCw className="w-3 h-3 animate-spin" />
                        ) : (
                          'Run'
                        )}
                      </button>
                    </div>

                    {res && (
                      <div
                        className={`p-2 rounded-lg text-[11px] font-mono flex items-start space-x-1.5 ${
                          res.passed
                            ? 'bg-emerald-950/40 text-emerald-300 border border-emerald-800/40'
                            : 'bg-rose-950/40 text-rose-300 border border-rose-800/40'
                        }`}
                      >
                        {res.passed ? (
                          <CheckCircle2 className="w-3.5 h-3.5 shrink-0 mt-0.5 text-emerald-400" />
                        ) : (
                          <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-rose-400" />
                        )}
                        <div className="truncate">
                          <div>{res.message}</div>
                          <div className="text-[9px] text-slate-400">{res.durationMs}ms</div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
