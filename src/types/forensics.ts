export type TargetBehaviorType =
  | 'forced_update'
  | 'forced_popup'
  | 'forced_redirect'
  | 'unexpected_external_link'
  | 'webview_navigation'
  | 'remote_configuration'
  | 'unwanted_ads_overlay'
  | 'custom_behavior';

export type ConfidenceLevel = 'Confirmed' | 'High confidence' | 'Possible' | 'Unresolved';

export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Benign';

export interface SmaliInstruction {
  raw: string;
  op: string;
  args?: string;
  lineNumber?: number;
  isInvoke?: boolean;
  isStringConst?: boolean;
  isBranch?: boolean;
  isReturn?: boolean;
  targetMethod?: string;
  targetClass?: string;
  stringValue?: string;
  branchLabel?: string;
}

export interface SmaliMethod {
  name: string;
  signature: string;
  returnType: string;
  parameters: string[];
  accessFlags: string[];
  registers: number;
  instructions: SmaliInstruction[];
  sourceLineStart?: number;
  sourceLineEnd?: number;
  callees: string[]; // List of method signatures called
  stringsUsed: string[];
  intentsTriggered: string[];
  isLifecycleTrigger?: boolean;
  rawCode: string;
}

export interface SmaliClass {
  name: string; // e.g. Lcom/example/app/MainActivity;
  package: string;
  simpleName: string;
  superClass?: string;
  interfaces: string[];
  sourceFile?: string;
  methods: SmaliMethod[];
  fields: { name: string; type: string; accessFlags: string[] }[];
  rawCode: string;
  filePath: string;
}

export interface ManifestComponent {
  type: 'activity' | 'service' | 'receiver' | 'provider';
  name: string;
  exported: boolean;
  permission?: string;
  intentFilters: {
    actions: string[];
    categories: string[];
    data?: { scheme?: string; host?: string; path?: string };
  }[];
}

export interface ManifestData {
  packageName: string;
  versionCode?: number | string;
  versionName?: string;
  minSdkVersion?: number | string;
  targetSdkVersion?: number | string;
  permissions: string[];
  components: ManifestComponent[];
  rawXml?: string;
}

export interface DexMetadata {
  fileName: string;
  version: string;
  fileSize: number;
  classCount: number;
  stringCount: number;
  classes: string[];
}

export interface UploadedArtifact {
  id: string;
  name: string;
  size: number;
  format: 'apk' | 'dex' | 'smali' | 'manifest' | 'java_kt' | 'logcat' | 'json' | 'zip' | 'unknown';
  status: 'pending' | 'parsed' | 'error';
  coverage: string; // e.g. "100% analyzed", "Classes extracted"
  extractedFileCount?: number;
  content?: string;
  rawBuffer?: ArrayBuffer;
  error?: string;
}

export interface CallGraphNode {
  id: string;
  label: string;
  className: string;
  methodName: string;
  type: 'entry' | 'lifecycle' | 'intermediate' | 'network' | 'dialog' | 'sink';
  isSuspicious?: boolean;
  filePath: string;
  lineRange?: string;
  snippet?: string;
}

export interface CallGraphEdge {
  id: string;
  source: string;
  target: string;
  callType: 'invoke-virtual' | 'invoke-static' | 'invoke-direct' | 'invoke-interface' | 'callback' | 'inferred';
  evidenceInstruction?: string;
  lineNumber?: number;
}

export interface UrlProvenanceChain {
  id: string;
  url: string;
  originType: 'hardcoded' | 'dynamically_assembled' | 'remote_json' | 'decoded_base64' | 'unknown';
  originSource: string; // e.g. "MainActivity.smali line 42"
  transformations: string[]; // e.g. ["StringBuilder.append()", "Base64.decode()"]
  intermediateMethods: string[];
  navigationSink: string; // e.g. "Intent.ACTION_VIEW -> Context.startActivity()"
  provenanceStatus: 'proven' | 'partially_inferred' | 'missing_source';
  isSuspicious: boolean;
}

export interface FindingRemediation {
  description: string;
  affectedClass: string;
  affectedMethod: string;
  safePatchSmali: string;
  risks: string;
  regressionTest: string;
}

export interface BehavioralFinding {
  id: string;
  title: string;
  confidence: ConfidenceLevel;
  severity: SeverityLevel;
  rationale: string;
  targetFile: string;
  className: string;
  methodName: string;
  lineRange: string;
  evidenceExcerpt: string;
  triggeringEvent: string;
  urlOrigin: string;
  executionPath: string[];
  alternativeExplanations: string;
  missingEvidence: string;
  recommendedInspection: string;
  remediation?: FindingRemediation;
}

export interface InvestigationSession {
  id: string;
  timestamp: string;
  targetBehavior: TargetBehaviorType;
  observedBehavior: string;
  expectedBehavior: string;
  artifacts: UploadedArtifact[];
  parsedClasses: SmaliClass[];
  manifest?: ManifestData;
  dexMetadata: DexMetadata[];
  callGraphNodes: CallGraphNode[];
  callGraphEdges: CallGraphEdge[];
  urlChains: UrlProvenanceChain[];
  findings: BehavioralFinding[];
  aiAnalysisSummary?: string;
  aiRootCause?: string;
  overallConfidence?: ConfidenceLevel;
  status: 'idle' | 'analyzing' | 'completed' | 'error';
  errorMessage?: string;
}

export interface PatchProposal {
  findingId: string;
  className: string;
  methodName: string;
  originalSmali: string;
  patchedSmali: string;
  diffExplanation: string;
  safetyAssessment: {
    registerCountRisk: string;
    branchLabelRisk: string;
    exceptionRangeRisk: string;
    sideEffects: string;
  };
  regressionTestChecklist: string[];
  approvedByAnalyst?: boolean;
}

export interface AppliedPatchRecord {
  id: string;
  timestamp: string;
  findingId: string;
  findingTitle: string;
  className: string;
  methodName: string;
  filePath: string;
  originalSmali: string;
  patchedSmali: string;
  diffSummary: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  registerStatus: string;
  branchTargetStatus: string;
  exceptionRangeStatus: string;
  integrityChecksum?: string;
  validationLevel: 'Static Bytecode Verified' | 'Syntax Verified' | 'Validation Failed';
}

export interface DownloadPackageItem {
  id: string;
  label: string;
  filename: string;
  format: string;
  sizeBytes: number;
  sha256: string;
  originalSha256?: string;
  validationStatus: 'Validated' | 'Unvalidated' | 'Ready';
  modifiedFiles: string[];
  description: string;
  getBlob: () => Promise<Blob>;
}

export interface DexIntegrityValidationResult {
  passed: boolean;
  originalClassCount: number;
  rebuiltClassCount: number;
  originalClassDescriptors: string[];
  rebuiltClassDescriptors: string[];
  missingClasses: string[];
  addedClasses: string[];
  modifiedClasses: string[];
  unmodifiedClasses: string[];
  appClassCheck: {
    targetDescriptor: string;
    existedInOriginal: boolean;
    presentInRebuilt: boolean;
    passed: boolean;
    details: string;
  };
  duplicateClasses: string[];
  assemblerErrors: string[];
  isDexMalformed: boolean;
  intendedPatchPresent: boolean;
  sha256Original: string;
  sha256Rebuilt: string;
  validationLog: string[];
  failureReason?: string;
}

export interface DisassembledDexResult {
  classes: SmaliClass[];
  classDescriptors: string[];
  dexMetadata: DexMetadata;
  smaliZipBlob: Blob;
  smaliZipBuffer: ArrayBuffer;
  smaliFiles: { path: string; content: string }[];
  logs: string[];
}

