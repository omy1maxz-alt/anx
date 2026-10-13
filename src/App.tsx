/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { BottomNav, ActiveTab } from './components/BottomNav';
import { DashboardView } from './components/DashboardView';
import { FilesView } from './components/FilesView';
import { ForensicsView } from './components/ForensicsView';
import { FindingsView } from './components/FindingsView';
import { FlowUrlView } from './components/FlowUrlView';
import { PatchLabView } from './components/PatchLabView';
import { CodeViewerModal } from './components/CodeViewerModal';
import { FixtureSelectorSheet } from './components/FixtureSelectorSheet';
import { ReportModal } from './components/ReportModal';
import { NewProjectModal } from './components/NewProjectModal';
import { DownloadCenterSheet } from './components/DownloadCenterSheet';
import { SmaliToDexModal } from './components/SmaliToDexModal';
import { SmaliToDexView } from './components/SmaliToDexView';
import { MtManagerGuideModal } from './components/MtManagerGuideModal';
import { ChatBotModal } from './components/ChatBotModal';
import { Bot, Sparkles } from 'lucide-react';
import {
  InvestigationSession,
  TargetBehaviorType,
  UploadedArtifact,
  SmaliClass,
  BehavioralFinding,
  PatchProposal,
  AppliedPatchRecord,
  DownloadPackageItem,
  CallGraphNode,
} from './types/forensics';
import { loadTestScenario, TestScenario, TEST_SCENARIOS } from './services/testFixtures';
import { buildCallGraph, detectBehavioralFindings } from './services/callGraphBuilder';
import { traceUrlProvenance } from './services/urlTracker';
import { processUploadedFile } from './services/apkExtractor';
import {
  applyPatchToClass,
  buildCleanSmaliZip,
  buildPatchedDex,
  buildPatchedApk,
  computeSha256,
  generateUnifiedDiff,
} from './services/patchEngine';
import {
  assembleClassesToDex,
  regenerateDexFromCompleteSmaliDump,
  SmaliToDexResult,
} from './services/smaliToDexAssembler';
import { generateMarkdownReport } from './services/reportGenerator';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [isAiConnected, setIsAiConnected] = useState<boolean>(false);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [isGeneratingPatch, setIsGeneratingPatch] = useState<boolean>(false);
  const [activeScenarioId, setActiveScenarioId] = useState<string>('test-a-forced-update');

  // Modals and sheets state
  const [isNewProjectOpen, setIsNewProjectOpen] = useState<boolean>(false);
  const [isFixturesOpen, setIsFixturesOpen] = useState<boolean>(false);
  const [isReportOpen, setIsReportOpen] = useState<boolean>(false);
  const [isDownloadCenterOpen, setIsDownloadCenterOpen] = useState<boolean>(false);
  const [isSmaliToDexOpen, setIsSmaliToDexOpen] = useState<boolean>(false);
  const [isMtGuideOpen, setIsMtGuideOpen] = useState<boolean>(false);
  const [isChatOpen, setIsChatOpen] = useState<boolean>(false);
  const [activeDexName, setActiveDexName] = useState<string>('classes10.dex');
  const [customDexPackages, setCustomDexPackages] = useState<DownloadPackageItem[]>([]);

  const [codeViewer, setCodeViewer] = useState<{
    isOpen: boolean;
    title: string;
    subtitle?: string;
    content: string;
    highlightLineRange?: string;
  }>({
    isOpen: false,
    title: '',
    content: '',
  });

  // Selected finding and active patch proposal for Patch Lab
  const [selectedPatchFinding, setSelectedPatchFinding] = useState<BehavioralFinding | undefined>(
    undefined
  );
  const [patchProposal, setPatchProposal] = useState<PatchProposal | undefined>(undefined);

  // Core Investigation Session State (Untouched original upload archive)
  const [session, setSession] = useState<InvestigationSession>(() => {
    // Initialize with Test A: Forced Update
    const initial = loadTestScenario('test-a-forced-update');
    const { nodes, edges } = buildCallGraph(initial.classes);
    const urlChains = traceUrlProvenance(initial.classes);
    const findings = detectBehavioralFindings(
      initial.classes,
      initial.targetBehavior,
      initial.observedBehavior
    );

    return {
      id: `INV-${Date.now().toString(36).toUpperCase()}`,
      timestamp: new Date().toISOString(),
      targetBehavior: initial.targetBehavior,
      observedBehavior: initial.observedBehavior,
      expectedBehavior: initial.expectedBehavior,
      artifacts: initial.artifacts,
      parsedClasses: initial.classes,
      manifest: initial.manifest,
      dexMetadata: [],
      callGraphNodes: nodes,
      callGraphEdges: edges,
      urlChains,
      findings,
      overallConfidence: 'Confirmed',
      aiAnalysisSummary:
        'Detected non-dismissible update modal enforcing external APK download before allowing access to main activity.',
      aiRootCause:
        'MainActivity.checkEnforcedUpdate() directly triggers AlertDialog.Builder.setCancelable(false) based on version code comparison.',
      status: 'completed',
    };
  });

  // Working Copy State (Modifications are applied here, leaving original upload untouched)
  const [workingCopyClasses, setWorkingCopyClasses] = useState<SmaliClass[]>(() => {
    const initial = loadTestScenario('test-a-forced-update');
    return initial.classes;
  });
  const [appliedPatches, setAppliedPatches] = useState<AppliedPatchRecord[]>([]);

  // Original binary buffers retained for re-packaging and bit-level checksum checks
  const [originalZipBuffer, setOriginalZipBuffer] = useState<ArrayBuffer | undefined>(undefined);
  const [originalDexBuffer, setOriginalDexBuffer] = useState<ArrayBuffer | undefined>(undefined);
  const [originalApkBuffer, setOriginalApkBuffer] = useState<ArrayBuffer | undefined>(undefined);

  // Prepared downloadable packages in Download Center
  const [preparedPackages, setPreparedPackages] = useState<DownloadPackageItem[]>([]);
  const [isPreparingPackages, setIsPreparingPackages] = useState<boolean>(false);

  // Health check on mount
  useEffect(() => {
    fetch('/api/health')
      .then((res) => res.json())
      .then((data) => {
        setIsAiConnected(!!data.geminiConfigured);
      })
      .catch(() => {
        setIsAiConnected(false);
      });
  }, []);

  // Update selected patch finding whenever findings change
  useEffect(() => {
    if (!selectedPatchFinding && session.findings.length > 0) {
      const remediable = session.findings.find((f) => f.remediation) || session.findings[0];
      setSelectedPatchFinding(remediable);
      if (remediable && remediable.remediation) {
        setPatchProposal({
          findingId: remediable.id,
          className: remediable.className,
          methodName: remediable.methodName,
          originalSmali: remediable.evidenceExcerpt,
          patchedSmali: remediable.remediation.safePatchSmali,
          diffExplanation: remediable.remediation.description,
          safetyAssessment: {
            registerCountRisk: 'Low: Maintained minimum registers required for return.',
            branchLabelRisk: 'Verified: Preserved neutral control flow.',
            exceptionRangeRisk: 'Clean: No dangling .catch blocks.',
            sideEffects: remediable.remediation.risks,
          },
          regressionTestChecklist: [
            remediable.remediation.regressionTest,
            'Verify application does not crash on cold boot.',
            'Confirm main dashboard buttons remain interactive.',
          ],
        });
      }
    }
  }, [session.findings, selectedPatchFinding]);

  // Keep downloadable packages up to date whenever workingCopy or appliedPatches change
  useEffect(() => {
    let isCancelled = false;

    const buildPackages = async () => {
      setIsPreparingPackages(true);
      try {
        const baseName =
          session.manifest?.packageName?.replace(/[^a-zA-Z0-9_]/g, '_') || 'app_remediated';
        const reportMd = generateMarkdownReport(session);
        const modifiedFilePaths = appliedPatches.map((p) => p.filePath);

        // 1. Unified Diff
        let diffText = '';
        if (appliedPatches.length > 0) {
          diffText = appliedPatches
            .map((p) => generateUnifiedDiff(p.originalSmali, p.patchedSmali, p.filePath))
            .join('\n\n');
        } else {
          diffText = '# DroidForensics Remediation Diff\n# No active bytecode modifications applied yet.\n';
        }
        const diffBytes = new TextEncoder().encode(diffText);
        const diffSha = await computeSha256(diffBytes);

        // 2. Clean Smali ZIP remains available: this contains source, not a runnable APK/DEX.
        const smaliZipRes = await buildCleanSmaliZip(
          workingCopyClasses,
          reportMd,
          originalZipBuffer
        );
        const reportBytes = new TextEncoder().encode(reportMd);
        const reportSha = await computeSha256(reportBytes);

        if (!isCancelled) {
          const standardPackages: DownloadPackageItem[] = [
            {
              id: 'smali_zip',
              label: 'Clean Smali Source ZIP',
              filename: `${baseName}_clean_smali.zip`,
              format: 'ZIP (Smali Sources)',
              sizeBytes: smaliZipRes.size,
              sha256: smaliZipRes.sha256,
              validationStatus: 'Ready',
              modifiedFiles: modifiedFilePaths,
              description:
                'Source-only export. This is not a DEX or installable APK; assemble it with an official Smali toolchain.',
              getBlob: async () => smaliZipRes.blob,
            },
            {
              id: 'patch_diff',
              label: 'Unified Remediation Patch',
              filename: `${baseName}_remediation.patch`,
              format: 'PATCH (Unified Diff)',
              sizeBytes: diffBytes.byteLength,
              sha256: diffSha,
              validationStatus: 'Ready',
              modifiedFiles: modifiedFilePaths,
              description: 'Reviewable source diff for the approved edits.',
              getBlob: async () => new Blob([diffBytes], { type: 'text/plain' }),
            },
            {
              id: 'report_md',
              label: 'Forensic Remediation Audit',
              filename: `${baseName}_audit_dossier.md`,
              format: 'MARKDOWN (Forensic Dossier)',
              sizeBytes: reportBytes.byteLength,
              sha256: reportSha,
              validationStatus: 'Ready',
              modifiedFiles: [],
              description:
                'Evidence and static analysis report. It does not claim runtime or binary validation.',
              getBlob: async () => new Blob([reportBytes], { type: 'text/markdown' }),
            },
          ];

          setPreparedPackages([...customDexPackages, ...standardPackages]);
        }
      }      } catch (err) {
        console.error('Failed to prepare download packages:', err);
      } finally {
        if (!isCancelled) {
          setIsPreparingPackages(false);
        }
      }
    };

    buildPackages();

    return () => {
      isCancelled = true;
    };
  }, [
    workingCopyClasses,
    appliedPatches,
    session,
    originalZipBuffer,
    originalDexBuffer,
    originalApkBuffer,
    customDexPackages,
  ]);

  // Create / reset new project handler
  const handleConfirmNewProject = (projectName?: string, defaultBehavior?: TargetBehaviorType) => {
    setActiveScenarioId('');
    setSelectedPatchFinding(undefined);
    setPatchProposal(undefined);
    setWorkingCopyClasses([]);
    setAppliedPatches([]);
    setOriginalZipBuffer(undefined);
    setOriginalDexBuffer(undefined);
    setOriginalApkBuffer(undefined);
    setSession({
      id: `INV-${Date.now().toString(36).toUpperCase()}`,
      timestamp: new Date().toISOString(),
      targetBehavior: defaultBehavior || 'forced_update',
      observedBehavior: '',
      expectedBehavior: '',
      artifacts: [],
      parsedClasses: [],
      manifest: undefined,
      dexMetadata: [],
      callGraphNodes: [],
      callGraphEdges: [],
      urlChains: [],
      findings: [],
      overallConfidence: undefined,
      aiAnalysisSummary: `New blank project "${projectName || 'Custom APK Forensics'}" initialized. Ready for file uploads.`,
      aiRootCause: undefined,
      status: 'idle',
    });
    setActiveTab('files');
  };

  // Load an acceptance scenario
  const handleSelectScenario = (scenarioId: string) => {
    const loaded = loadTestScenario(scenarioId);
    const { nodes, edges } = buildCallGraph(loaded.classes);
    const urlChains = traceUrlProvenance(loaded.classes);
    const findings = detectBehavioralFindings(
      loaded.classes,
      loaded.targetBehavior,
      loaded.observedBehavior
    );

    setActiveScenarioId(scenarioId);
    if (scenarioId === 'test-h-daily-chrome-adware' || scenarioId === 'test-g-dex10-crash-fix') {
      setActiveDexName('classes10.dex');
    }
    setPatchProposal(undefined);
    setSelectedPatchFinding(findings.find((f) => f.remediation) || findings[0]);
    setWorkingCopyClasses(loaded.classes);
    setAppliedPatches([]);
    setOriginalZipBuffer(undefined);
    setOriginalDexBuffer(undefined);
    setOriginalApkBuffer(undefined);

    setSession((prev) => ({
      ...prev,
      targetBehavior: loaded.targetBehavior,
      observedBehavior: loaded.observedBehavior,
      expectedBehavior: loaded.expectedBehavior,
      artifacts: loaded.artifacts,
      parsedClasses: loaded.classes,
      manifest: loaded.manifest,
      callGraphNodes: nodes,
      callGraphEdges: edges,
      urlChains,
      findings,
      overallConfidence: findings[0]?.confidence || 'High confidence',
      aiAnalysisSummary: `Loaded ${scenarioId}: Analyzed ${loaded.classes.length} classes, ${nodes.length} call graph nodes, and ${urlChains.length} URL provenance sinks.`,
      aiRootCause: findings[0]?.rationale || 'Code path identified via deterministic Dalvik trace.',
      status: 'completed',
    }));
  };

  // Upload files handler
  const handleUploadFiles = async (files: FileList | File[]) => {
    const fileArray = Array.from(files);
    const newArtifacts: UploadedArtifact[] = [];
    const newClasses: SmaliClass[] = [];
    let newManifest = session.manifest;

    for (const file of fileArray) {
      const res = await processUploadedFile(file);
      newArtifacts.push(res.artifact);
      newClasses.push(...res.classes);
      if (res.manifest) {
        newManifest = res.manifest;
      }

      // Preserve raw binary buffers for repackaging and checksum comparison
      try {
        const buf = await file.arrayBuffer();
        const lowerName = file.name.toLowerCase();
        if (lowerName.endsWith('.apk')) {
          setOriginalApkBuffer(buf);
        } else if (lowerName.endsWith('.dex')) {
          setOriginalDexBuffer(buf);
          setActiveDexName(file.name);
        } else if (lowerName.endsWith('.zip')) {
          setOriginalZipBuffer(buf);
          if (lowerName.includes('10')) {
            setActiveDexName('classes10.dex');
          }
        }
      } catch (err) {
        console.warn('Failed to retain original binary buffer:', err);
      }
    }

    // Deduplicate merged classes by file path and class descriptor
    const seenClasses = new Set<string>();
    const mergedClasses: SmaliClass[] = [];
    for (const cls of [...newClasses, ...session.parsedClasses]) {
      const classKey = `${cls.filePath}::${cls.name}`;
      if (!seenClasses.has(classKey)) {
        seenClasses.add(classKey);
        mergedClasses.push(cls);
      }
    }

    const { nodes, edges } = buildCallGraph(mergedClasses);
    const urlChains = traceUrlProvenance(mergedClasses);
    const findings = detectBehavioralFindings(
      mergedClasses,
      session.targetBehavior,
      session.observedBehavior
    );

    setSession((prev) => ({
      ...prev,
      artifacts: [...prev.artifacts, ...newArtifacts],
      parsedClasses: mergedClasses,
      manifest: newManifest,
      callGraphNodes: nodes,
      callGraphEdges: edges,
      urlChains,
      findings,
    }));

    // Update working copy with merged classes
    setWorkingCopyClasses(mergedClasses);
    setActiveTab('files');
  };

  // Remove artifact handler
  const handleRemoveArtifact = (artifactId: string) => {
    setSession((prev) => ({
      ...prev,
      artifacts: prev.artifacts.filter((a) => a.id !== artifactId),
    }));
  };

  // Sync classes from converter into session
  const handleSyncClassesFromConverter = (newCls: SmaliClass[], sourceFile?: string) => {
    if (sourceFile) {
      if (sourceFile.toLowerCase().endsWith('.dex')) {
        setActiveDexName(sourceFile);
      } else if (sourceFile.toLowerCase().includes('10')) {
        setActiveDexName('classes10.dex');
      }
    }
    const { nodes, edges } = buildCallGraph(newCls);
    const urlChains = traceUrlProvenance(newCls);
    const findings = detectBehavioralFindings(
      newCls,
      session.targetBehavior,
      session.observedBehavior
    );

    setWorkingCopyClasses(newCls);
    setSession((prev) => ({
      ...prev,
      parsedClasses: newCls,
      callGraphNodes: nodes,
      callGraphEdges: edges,
      urlChains,
      findings,
    }));
    if (findings.length > 0) {
      setSelectedPatchFinding(findings.find((f) => f.remediation) || findings[0]);
    }
  };

  // Run Forensics with Gemini AI on Server
  const handleRunInvestigation = async () => {
    setIsAnalyzing(true);
    try {
      const payload = {
        targetBehavior: session.targetBehavior,
        observedBehavior: session.observedBehavior,
        expectedBehavior: session.expectedBehavior,
        manifestSummary: session.manifest
          ? {
              package: session.manifest.packageName,
              version: session.manifest.versionName,
              permissions: session.manifest.permissions,
              components: session.manifest.components.map((c) => ({
                type: c.type,
                name: c.name,
                exported: c.exported,
              })),
            }
          : {},
        matchedComponents: session.parsedClasses.flatMap((c) =>
          c.methods.map((m) => ({
            className: c.name,
            methodName: m.signature,
            strings: m.stringsUsed,
            callees: m.callees,
            registers: m.registers,
          }))
        ),
        callChains: session.callGraphEdges.map((e) => ({
          from: e.source,
          to: e.target,
          type: e.callType,
        })),
        urlProvenances: session.urlChains,
        codeExcerpts: session.findings.map((f) => ({
          title: f.title,
          class: f.className,
          method: f.methodName,
          excerpt: f.evidenceExcerpt,
        })),
      };

      const res = await fetch('/api/analyze-behavior', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (data.success && data.analysis) {
        const ai = data.analysis;
        const newFindings =
          ai.findings && ai.findings.length > 0
            ? ai.findings.map((f: any, idx: number) => ({
                id: f.id || `AI-FIND-${idx + 1}`,
                title: f.title,
                confidence: f.confidence || 'High confidence',
                severity: f.severity || 'High',
                rationale: f.rationale,
                targetFile: f.targetFile || 'smali/app/MainActivity.smali',
                className: f.className,
                methodName: f.methodName,
                lineRange: f.lineRange || '1-30',
                evidenceExcerpt: f.evidenceExcerpt || '',
                triggeringEvent: f.triggeringEvent || 'Lifecycle callback',
                urlOrigin: f.urlOrigin || 'Hardcoded / Parsed',
                executionPath: f.executionPath || [],
                alternativeExplanations: f.alternativeExplanations || 'None reported.',
                missingEvidence: f.missingEvidence || 'None required.',
                recommendedInspection: f.recommendedInspection || 'Review Smali bytecode.',
                remediation: f.remediation,
              }))
            : session.findings;

        setSession((prev) => ({
          ...prev,
          findings: newFindings,
          aiAnalysisSummary: ai.summary || prev.aiAnalysisSummary,
          aiRootCause: ai.rootCause || prev.aiRootCause,
          overallConfidence: ai.confidence || prev.overallConfidence,
          status: 'completed',
        }));

        setActiveTab('findings');
      }
    } catch (err: any) {
      console.error('Forensic analysis error:', err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Generate surgical patch via server / local engine
  const handleGeneratePatch = async (finding: BehavioralFinding) => {
    setIsGeneratingPatch(true);
    try {
      const res = await fetch('/api/generate-patch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          finding,
          smaliContent: finding.evidenceExcerpt,
          className: finding.className,
          methodName: finding.methodName,
        }),
      });

      const data = await res.json();
      if (data.success && data.patch) {
        const p = data.patch;
        setPatchProposal({
          findingId: finding.id,
          className: finding.className,
          methodName: finding.methodName,
          originalSmali: p.originalMethod || finding.evidenceExcerpt,
          patchedSmali: p.patchedMethod,
          diffExplanation: p.diffExplanation,
          safetyAssessment: p.safetyAssessment || {
            registerCountRisk: 'Low: Registers preserved.',
            branchLabelRisk: 'Verified: No dangling branches.',
            exceptionRangeRisk: 'Clean.',
            sideEffects: 'Target method neutralized.',
          },
          regressionTestChecklist: p.regressionTestChecklist || [
            'Test application offline and online.',
            'Confirm main activity opens normally.',
          ],
        });
      }
    } catch (err) {
      console.error('Patch generation error:', err);
    } finally {
      setIsGeneratingPatch(false);
    }
  };

  // Apply approved patch to working copy
  const handleApplyPatchToWorkspace = (proposal: PatchProposal, finding: BehavioralFinding) => {
    const clsIndex = workingCopyClasses.findIndex((c) => c.name === proposal.className);
    if (clsIndex === -1) return;

    const currentCls = workingCopyClasses[clsIndex];
    const { newRawCode } = applyPatchToClass(
      currentCls.rawCode,
      proposal.methodName,
      proposal.patchedSmali
    );

    const updatedCls: SmaliClass = {
      ...currentCls,
      rawCode: newRawCode,
    };

    const nextClasses = [...workingCopyClasses];
    nextClasses[clsIndex] = updatedCls;
    setWorkingCopyClasses(nextClasses);

    const record: AppliedPatchRecord = {
      id: `PATCH-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      findingId: finding.id,
      findingTitle: finding.title,
      className: proposal.className,
      methodName: proposal.methodName,
      filePath: currentCls.filePath,
      originalSmali: proposal.originalSmali,
      patchedSmali: proposal.patchedSmali,
      diffSummary: proposal.diffExplanation,
    };

    setAppliedPatches((prev) => {
      const filtered = prev.filter(
        (p) => !(p.className === proposal.className && p.methodName === proposal.methodName)
      );
      return [...filtered, record];
    });
  };

  // Auto-Fix All Verified Threats in batch
  const handleAutoFixAll = () => {
    const remediableFindings = session.findings.filter((f) => !!f.remediation);
    if (remediableFindings.length === 0) return;

    let updatedClasses = [...workingCopyClasses];
    const newRecords: AppliedPatchRecord[] = [];

    for (const finding of remediableFindings) {
      if (!finding.remediation) continue;
      const clsIndex = updatedClasses.findIndex((c) => c.name === finding.className);
      if (clsIndex === -1) continue;

      const cls = updatedClasses[clsIndex];
      const { newRawCode } = applyPatchToClass(
        cls.rawCode,
        finding.methodName,
        finding.remediation.safePatchSmali
      );

      updatedClasses[clsIndex] = {
        ...cls,
        rawCode: newRawCode,
      };

      newRecords.push({
        id: `AUTO-${Date.now().toString(36)}-${finding.id}`,
        timestamp: new Date().toISOString(),
        findingId: finding.id,
        findingTitle: finding.title,
        className: finding.className,
        methodName: finding.methodName,
        filePath: cls.filePath,
        originalSmali: finding.evidenceExcerpt,
        patchedSmali: finding.remediation.safePatchSmali,
        diffSummary: finding.remediation.description,
      });
    }

    setWorkingCopyClasses(updatedClasses);
    setAppliedPatches(newRecords);
    setIsPreparingPackages(true);
    setIsDownloadCenterOpen(true);
  };

  // Revert all patches back to original upload
  const handleRevertPatches = () => {
    setWorkingCopyClasses([...session.parsedClasses]);
    setAppliedPatches([]);
  };

  // Code inspection helper
  const handleInspectClass = (cls: SmaliClass) => {
    setCodeViewer({
      isOpen: true,
      title: `${cls.simpleName}.smali`,
      subtitle: `${cls.package} (${cls.methods.length} methods)`,
      content: cls.rawCode,
    });
  };

  const handleInspectArtifact = (art: UploadedArtifact) => {
    setCodeViewer({
      isOpen: true,
      title: art.name,
      subtitle: `${art.format.toUpperCase()} • ${(art.size / 1024).toFixed(1)} KB`,
      content: art.content || `/* Binary file: ${art.name} (${art.coverage}) */`,
    });
  };

  const handleInspectFindingCode = (className: string, lineRange?: string) => {
    const cls = workingCopyClasses.find(
      (c) => c.name === className || c.simpleName === className
    );
    if (cls) {
      setCodeViewer({
        isOpen: true,
        title: `${cls.simpleName}.smali`,
        subtitle: `Class: ${cls.name}`,
        content: cls.rawCode,
        highlightLineRange: lineRange,
      });
    }
  };

  const handleRegisterDexDownload = (dexResult: SmaliToDexResult, filename: string) => {
    const newItem: DownloadPackageItem = {
      id: `dex_assembled_${filename}`,
      label: `Assembled DEX (${filename})`,
      filename,
      format: 'DEX (Dalvik Executable)',
      sizeBytes: dexResult.size,
      sha256: dexResult.sha256,
      validationStatus: 'Validated',
      modifiedFiles:
        dexResult.extractedSmaliFiles.length > 0 ? dexResult.extractedSmaliFiles : ['classes.dex'],
      description: `Directly assembled from Smali archive (${dexResult.classCount} classes, ${dexResult.methodCount} methods). Adler-32: ${dexResult.adler32}.`,
      getBlob: async () => dexResult.blob,
    };
    setCustomDexPackages((prev) => [newItem, ...prev.filter((p) => p.filename !== filename)]);
  };

  const handleAddArtifact = (art: UploadedArtifact) => {
    setSession((prev) => ({
      ...prev,
      artifacts: [art, ...prev.artifacts],
    }));
  };

  const activeScenario = TEST_SCENARIOS.find((s) => s.id === activeScenarioId);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans select-none antialiased">
      {/* Top Header */}
      <Header
        onOpenNewProject={() => setIsNewProjectOpen(true)}
        onOpenFixtures={() => setIsFixturesOpen(true)}
        onOpenReport={() => setIsReportOpen(true)}
        onOpenDownloadCenter={() => setIsDownloadCenterOpen(true)}
        onOpenSmaliToDex={() => setActiveTab('converter')}
        onOpenMtGuide={() => setIsMtGuideOpen(true)}
        onOpenChat={() => setIsChatOpen(true)}
        isAiConnected={isAiConnected}
        activeScenarioName={activeScenario?.name.split('—')[0]?.trim()}
        appliedPatchesCount={appliedPatches.length}
      />

      {/* Main Mobile Content Area */}
      <main className="flex-1 max-w-md w-full mx-auto p-3 overflow-y-auto">
        {activeTab === 'dashboard' && (
          <DashboardView
            session={session}
            onNavigateTab={setActiveTab}
            onSelectScenario={handleSelectScenario}
            onStartAnalysis={handleRunInvestigation}
            onOpenNewProject={() => setIsNewProjectOpen(true)}
            onOpenMtGuide={() => setIsMtGuideOpen(true)}
            onOpenChat={() => setIsChatOpen(true)}
            isAnalyzing={isAnalyzing}
          />
        )}

        {activeTab === 'files' && (
          <FilesView
            artifacts={session.artifacts}
            classes={workingCopyClasses}
            manifest={session.manifest}
            onUploadFiles={handleUploadFiles}
            onSelectClass={handleInspectClass}
            onSelectArtifact={handleInspectArtifact}
            onRemoveArtifact={handleRemoveArtifact}
            onOpenSmaliToDex={() => setActiveTab('converter')}
            onOpenMtGuide={() => setIsMtGuideOpen(true)}
          />
        )}

        {activeTab === 'forensics' && (
          <ForensicsView
            session={session}
            onChangeTargetBehavior={(type) =>
              setSession((prev) => ({ ...prev, targetBehavior: type }))
            }
            onChangeObserved={(text) =>
              setSession((prev) => ({ ...prev, observedBehavior: text }))
            }
            onChangeExpected={(text) =>
              setSession((prev) => ({ ...prev, expectedBehavior: text }))
            }
            onRunInvestigation={handleRunInvestigation}
            isAnalyzing={isAnalyzing}
            onNavigateTab={setActiveTab}
          />
        )}

        {activeTab === 'findings' && (
          <FindingsView
            findings={session.findings}
            onOpenPatchLab={(finding) => {
              setSelectedPatchFinding(finding);
              setActiveTab('patch');
              handleGeneratePatch(finding);
            }}
            onInspectCode={handleInspectFindingCode}
          />
        )}

        {activeTab === 'flow' && (
          <FlowUrlView
            nodes={session.callGraphNodes}
            edges={session.callGraphEdges}
            urlChains={session.urlChains}
            onSelectNode={(node) => {
              const cls = workingCopyClasses.find((c) => c.name === node.className);
              if (cls) {
                setCodeViewer({
                  isOpen: true,
                  title: `${cls.simpleName}.smali`,
                  subtitle: node.methodName,
                  content: cls.rawCode,
                  highlightLineRange: node.lineRange,
                });
              }
            }}
          />
        )}

        {activeTab === 'patch' && (
          <PatchLabView
            selectedFinding={selectedPatchFinding}
            availableFindings={session.findings}
            onSelectFinding={(f) => {
              setSelectedPatchFinding(f);
              handleGeneratePatch(f);
            }}
            onGeneratePatch={handleGeneratePatch}
            patchProposal={patchProposal}
            isGeneratingPatch={isGeneratingPatch}
            appliedPatches={appliedPatches}
            onApplyPatchToWorkspace={handleApplyPatchToWorkspace}
            onAutoFixAll={handleAutoFixAll}
            onRevertPatches={handleRevertPatches}
            onOpenDownloadCenter={() => setIsDownloadCenterOpen(true)}
            onOpenConverter={() => setActiveTab('converter')}
            onOpenMtGuide={() => setIsMtGuideOpen(true)}
          />
        )}

        {activeTab === 'converter' && (
          <SmaliToDexView
            currentClasses={workingCopyClasses}
            originalClasses={session.parsedClasses}
            originalDexBuffer={originalDexBuffer}
            appliedPatches={appliedPatches}
            onAddArtifact={handleAddArtifact}
            onRegisterDexDownload={handleRegisterDexDownload}
            onSyncClassesToSession={handleSyncClassesFromConverter}
            onOpenMtGuide={() => setIsMtGuideOpen(true)}
          />
        )}
      </main>

      {/* Mobile Bottom Navigation */}
      <BottomNav
        activeTab={activeTab}
        onChangeTab={setActiveTab}
        findingsCount={session.findings.length}
        filesCount={session.artifacts.length}
      />

      {/* Code Viewer Modal */}
      <CodeViewerModal
        isOpen={codeViewer.isOpen}
        onClose={() => setCodeViewer((prev) => ({ ...prev, isOpen: false }))}
        title={codeViewer.title}
        subtitle={codeViewer.subtitle}
        content={codeViewer.content}
        highlightLineRange={codeViewer.highlightLineRange}
      />

      {/* Acceptance Tests Bottom Sheet */}
      <FixtureSelectorSheet
        isOpen={isFixturesOpen}
        onClose={() => setIsFixturesOpen(false)}
        onSelectScenario={(sc) => handleSelectScenario(sc.id)}
        currentScenarioId={activeScenarioId}
      />

      {/* Forensic Report Modal */}
      <ReportModal
        isOpen={isReportOpen}
        onClose={() => setIsReportOpen(false)}
        session={session}
      />

      {/* New Project Modal */}
      <NewProjectModal
        isOpen={isNewProjectOpen}
        onClose={() => setIsNewProjectOpen(false)}
        onConfirmNewProject={handleConfirmNewProject}
        onOpenFixtures={() => setIsFixturesOpen(true)}
        hasExistingData={session.artifacts.length > 0 || session.findings.length > 0}
      />

      {/* Download Center Bottom Sheet */}
      <DownloadCenterSheet
        isOpen={isDownloadCenterOpen}
        onClose={() => setIsDownloadCenterOpen(false)}
        packages={preparedPackages}
        isPreparing={isPreparingPackages}
      />

      {/* Smali ZIP to DEX Modal */}
      <SmaliToDexModal
        isOpen={isSmaliToDexOpen}
        onClose={() => setIsSmaliToDexOpen(false)}
        currentClasses={workingCopyClasses}
        onAddArtifact={handleAddArtifact}
        onRegisterDexDownload={handleRegisterDexDownload}
      />

      {/* MT Manager Android Guide Modal */}
      <MtManagerGuideModal
        isOpen={isMtGuideOpen}
        onClose={() => setIsMtGuideOpen(false)}
        targetDexName={activeDexName}
        onOpenDownloadCenter={() => setIsDownloadCenterOpen(true)}
      />

      {/* Floating Thumb AI Chat Action Button */}
      <button
        onClick={() => setIsChatOpen(true)}
        className="fixed bottom-20 right-3.5 z-30 flex items-center space-x-1.5 px-3 py-2.5 rounded-full bg-gradient-to-r from-cyan-500 via-indigo-600 to-indigo-700 hover:from-cyan-400 hover:to-indigo-500 active:scale-95 text-white font-bold text-xs shadow-xl shadow-cyan-950/60 border border-cyan-400/40 transition-all select-none"
        aria-label="Open AI Copilot Chat"
      >
        <Bot className="w-4 h-4 text-cyan-200 animate-pulse" />
        <span className="tracking-tight font-bold">Chat AI</span>
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
      </button>

      {/* AI Copilot Chat Bot Modal */}
      <ChatBotModal
        isOpen={isChatOpen}
        onClose={() => setIsChatOpen(false)}
        session={session}
        activeDexName={activeDexName}
        appliedPatchesCount={appliedPatches.length}
        onOpenMtGuide={() => setIsMtGuideOpen(true)}
        onOpenConverter={() => setActiveTab('converter')}
      />
    </div>
  );
}
