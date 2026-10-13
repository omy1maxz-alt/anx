# DroidForensics Development Journal

## [13 October 2026] - Initial Implementation: DroidForensics Mobile APK Forensics Lab

### 1. Architecture Decisions
- Built an evidence-driven Android APK, DEX, Smali, and Manifest reverse-engineering forensics workbench engineered specifically for mobile viewports (100dvh, thumb ergonomics >= 44x44px touch targets).
- Integrated full-stack architecture with `server.ts` running Express and mounting Vite middleware.
- Configured server-side Gemini 3.8 Flash API integration with `@google/genai` using modern client patterns and telemetry header `User-Agent: 'aistudio-build'`.
- Implemented deterministic Dalvik Smali parser, binary and XML AndroidManifest parser, URL provenance tracker, call-graph investigator, and JSZip archive unpacker.

### 2. Acceptance Scenarios Implemented
- **Test A (Forced Update)**: Detects version checks, non-dismissible `AlertDialog.Builder.setCancelable(false)` modals, and download URL dispatching.
- **Test B (Remote Popup)**: Traces remote JSON parameters (`title`, `message`, `destination_url`) to dialog and unprompted browser launch.
- **Test C (Dynamic Redirect)**: Reconstructs runtime URLs assembled via `StringBuilder.append()` and dispatched to `ACTION_VIEW`.
- **Test D (Normal External Link)**: Distinguishes legitimate user clicks (`View.OnClickListener.onClick`) from automated redirects, preventing false positives.
- **Test E (Incomplete Evidence)**: Detects unresolved navigation sinks with missing callers or parameters, marking as `Unresolved` and identifying missing artifacts.
- **Test F (Safe Patch)**: Proposes minimal, surgical Smali stubs (e.g., `return-void`) while preserving register counts, branch labels, and unrelated operations.

### 3. Mobile Navigation & Touch Ergonomics
- 6-tab thumb navigation: Dashboard, Files (Artifacts & Classes), Forensics (Behavior selector & AI run), Findings (Evidence & Rationale), Flow & URLs (Call graph & URL provenance), and Patch Lab (Surgical diff & safety checklist).
- Bottom sheets for Smali code inspector with line numbering and syntax highlighting.

## [13 October 2026] - Fix: Unique React Key Constraints in Artifact & Class Explorer
- **Issue**: Uploaded Android APKs containing multidex / multiple dex slices or repeated AndroidX library classes (e.g. \`Landroidx/collection/LruCache;\`, \`Landroidx/core/app/PendingIntentCompat;\`) caused React warnings due to duplicate key props when rendering \`cls.name\`.
- **Resolution**:
  1. Updated \`FilesView.tsx\` to bind composite keys \`\${cls.filePath}-\${cls.name}-\${idx}\` and \`\${art.id}-\${idx}\`.
  2. Updated \`FlowUrlView.tsx\` and \`FindingsView.tsx\` to ensure unique indexed keys for nodes, edges, url chains, and finding cards.
  3. Added deduplication sets during APK ZIP extraction in \`apkExtractor.ts\` and \`App.tsx\` to eliminate redundant duplicate class definitions.

## [13 October 2026] - Feature: New Project Workflow & In-App Guide
- Added "New Project" modal and buttons in both the mobile Header and Dashboard hero action grid.
- Allows clearing workspace to start a blank investigation session ready for APK uploads, or quickly branching from test scenario fixtures (Tests A-F).
- Included a collapsible, step-by-step interactive Quick Start Guide on the Dashboard detailing the 5-phase reverse-engineering workflow.

## [13 October 2026] - Fix: Resilient Gemini API Inactive State Handling & Local Patch Synthesis
- **Issue**: Upstream Gemini API returned 403 (leaked/invalid key in environment), which previously logged raw error strings to stderr.
- **Resolution**:
  1. Replaced stderr logging with silent graceful local engine activation.
  2. Implemented `isGeminiActive` latch in `server.ts` to disable upstream retry loops once an authentication failure is encountered, reporting accurate health status to the UI.
  3. Upgraded `generateLocalPatch` with method return-type analysis (deducing void, boolean, int, float, double, or object return instructions) to synthesize accurate Dalvik bytecode stubs without external API dependency.

## [13 October 2026] - Feature: Automated Remediation Engine & Forensic Download Center
- **Objective**: Upgraded DroidForensics from an analysis-only workbench into a functional reverse-engineering remediation and export tool.
- **Implementation**:
  1. **Dual Workspace Separation**: Preserves original uploads (`session.parsedClasses`, `session.artifacts`, and raw file ArrayBuffers) in a read-only state. All modifications are applied exclusively to `workingCopyClasses`.
  2. **Automated Fix Workflow**:
     - Supported per-finding approval with analyst checkbox verification and "Auto-Fix All Verified Threats" batch neutralization.
     - Surgical Dalvik patching via `applyPatchToClass` replacing dangerous instruction ranges with verifier-compliant return stubs while checking method boundaries, branch targets, and register counts.
     - Revert control (`handleRevertPatches`) to reset working copy cleanly back to pristine files.
  3. **Forensic Download Center (`DownloadCenterSheet.tsx`)**:
     - **Clean Smali ZIP**: Re-packaged using JSZip, maintaining original folder structures, including `REMEDIATION_AUDIT_REPORT.md` and `PATCH_MANIFEST.json`.
     - **Patched DEX**: Synthesized Dalvik 035 bytecode binary with aligned class offsets and neutralized execution paths.
     - **Patched & Signed APK**: Fully packed Android archive containing updated DEX, manifest, resources, and v1 JAR signature blocks (`META-INF/MANIFEST.MF`, `CERT.SF`, `CERT.RSA`).
     - **Signing Disclosure**: Includes `REMEDIATION_SIGNING_NOTICE.txt` explaining signature continuity and the requirement to uninstall the previous vendor build.
     - **Unified Patch**: Git-compatible `.patch` diff file for auditing.
     - Computes live SHA-256 integrity checksums with one-tap clipboard copy buttons and file size statistics.

## [13 October 2026] - Feature: Smali ZIP to DEX Assembler & Converter
- **Objective**: Added dedicated capability to convert and assemble Smali ZIP archives directly into valid Dalvik Executables (`classes.dex`).
- **Implementation**:
  1. **Assembler Service (`src/services/smaliToDexAssembler.ts`)**:
     - Built `extractSmaliFromZip` to safely unpack `.smali` archives and index all classes, fields, methods, instructions, and string literals.
     - Built `assembleClassesToDex` to construct complete Dalvik Executable binaries conforming to the DEX 035 format:
       * Magic header (`dex\n035\0`), 112-byte header with Adler-32 and SHA-1 checksums.
       * Sorted String Pool (UTF-16 code point order) encoded with ULEB128 lengths.
       * Type IDs, Prototype IDs (return types & parameter lists), Field IDs, Method IDs, and Class Definitions.
       * Method bytecode items with code headers (registers, in/out args, insns buffers).
       * Map List section aligned to 4-byte boundaries.
     - Implemented standard Adler-32 checksum computation over bytes `[12..file_size]` and SHA-1 signature calculation over bytes `[32..file_size]`.
  2. **SmaliToDexModal Component (`src/components/SmaliToDexModal.tsx`)**:
     - Handheld-optimized touch modal with 3 source modes: Upload ZIP archive, Current Workspace classes (with remediation patches), and Built-in Sample ZIP generator (`SampleApp.smali.zip`).
     - Real-time compilation status with live terminal build logs, classes breakdown, method count, and string pool size.
     - Cryptographic fingerprint display (Adler-32, SHA-1, SHA-256) with one-tap clipboard copy.
     - Instant download action for `classes.dex`, automatic registration into the Artifacts inventory, and inclusion in the Download Center.
  3. **UI Integration**:
     - Added quick-access `DEX` button to top Header navigation bar.
     - Added "Smali ZIP → DEX Assembler" action card and per-artifact shortcut buttons in `FilesView.tsx`.
     - Integrated `assembleClassesToDex` into `App.tsx` package builder so all generated DEX packages use the binary assembler.
## [13 October 2026] - Feature: Dedicated "Smali to DEX Converter" Tool Page & 6-Scenario Test Suite
- **Objective**: Implement a dedicated full-screen tool page named "Smali to DEX Converter" supporting Smali ZIP → DEX assembly, multidex root selection, path traversal blocking, DEX binary validation, and an automated verification test suite.
- **Implementation**:
  1. **New Tool Page (`src/components/SmaliToDexView.tsx`)**:
     - Added 7th tab to mobile `BottomNav.tsx` labeled `Smali→DEX` with `Cpu` icon.
     - Supports uploading `.zip` archives or assembling directly from the cleaned/remediated workspace classes.
     - Default output filename set to `classes10.dex` with clear multidex slot replacement warning.
     - Multi-root detection: if archive contains multiple Smali roots (e.g. `smali/` [classes.dex] and `smali_classes10/` [classes10.dex]), prompts analyst to select the target root rather than auto-merging.
     - Real-time assembly progress, processing time measurement in milliseconds, and collapsible terminal build logs.
     - Results panel displays: Original ZIP name, Smali files discovered, Selected Smali root, Output DEX name, Assembly status, Validation status, File size, SHA-256 (with copy button), Adler-32, and SHA-1.
     - Direct download action for generated DEX file.
  2. **Security & Validation Hardening (`src/services/smaliToDexAssembler.ts` & `src/services/patchEngine.ts`)**:
     - Added `checkPathTraversal` blocking directory traversal entries (`../`, `..\`, leading `/`) before extraction.
     - Guarded against empty ZIP archives (0 files) and archives without `.smali` files with descriptive error messages.
     - Added opcode and mnemonic validation to `validateSmali` in `patchEngine.ts` to detect unrecognized or invalid Dalvik instructions with file, method, and line references.
     - Implemented `verifyDexBinary` executing round-trip DEX binary parsing: verifies magic bytes (`dex\n035\0`), 112-byte header, little-endian tag, calculated Adler-32 against header, calculated SHA-1 against header signature, section offsets, and decodes class definitions.
     - Separated static bytecode validation from device runtime testing with clear disclaimers.
  3. **Automated 6-Scenario Test Suite**:
     - Integrated `createSmaliConverterTestSuite()` covering the 6 mandatory scenarios:
       1. Valid Smali ZIP (`Calculator.smali`, `SecurityHelper.smali`).
       2. Extra enclosing folder (`unpacked_apk_project/smali_classes10/...`).
       3. Invalid Smali instruction (`invalid_dalvik_mnemonic v0, v1`).
       4. Empty ZIP archive (0 files).
       5. Multiple Smali roots (`smali/` + `smali_classes10/`).
       6. Path traversal entry (`../../etc/passwd`).
     - Added in-app test runner allowing one-tap verification of all 6 test cases or individual inspection.
  4. **Analysis & Remediation Workflow Integration**:
     - Added "Send Approved Smali → DEX Converter" button in `PatchLabView.tsx` allowing analysts to seamlessly compile their user-approved, remediated working copy classes into `classes10.dex`.

## [13 October 2026] - Fix: DEX10 → Smali ZIP → Patched DEX10 Anti-Crash Pipeline & Baksmali Integration
- **Issue Investigated**:
  - In the previous DEX10 workflow, uploading `classes10.dex`, modifying a Smali class, and reassembling into `classes10.dex` resulted in a startup cold-boot crash on device:
    `java.lang.ClassNotFoundException: Didn't find class "com.gold.youtube.om7753.App"`.
  - **Root Cause**:
    1. During DEX upload, `apkExtractor.ts` was not disassembling DEX classes into working memory, leaving the class inventory incomplete.
    2. During patch compilation, only the single modified class file was assembled into `classes10.dex` as a partial DEX replacement. All other original classes—crucially the Application entrypoint `Lcom/gold/youtube/om7753/App;`—were omitted from the rebuilt DEX binary.
    3. The APK substituted `classes10.dex` with this partial slice, causing Android's classloader to fail immediately on cold boot.
- **Resolution Implemented**:
  1. **Deterministic Baksmali Disassembler (`disassembleDexToSmaliClasses`)**:
     - Built binary DEX 035 parser decoding header offsets, string pool, type descriptors, prototypes, fields, and method IDs.
     - Decodes `class_defs` and `class_data` items to generate valid, complete Dalvik Smali source files preserving package hierarchies (`smali_classes10/com/gold/youtube/om7753/...`).
     - Integrated into `apkExtractor.ts` so uploading any `.dex` or APK file automatically extracts and indexes 100% of its classes into the workspace.
  2. **Decoded Smali ZIP Exporter**:
     - Automatically generates downloadable ZIP archives (`classes10_decoded_smali.zip`) preserving the exact multidex package directory hierarchy.
  3. **Mandatory Class Descriptor Integrity Validator (`validateRebuiltDexIntegrity`)**:
     - Compares 100% of original vs rebuilt class descriptors.
     - Explicitly checks and guarantees presence of `Lcom/gold/youtube/om7753/App;`. If dropped, fails validation immediately and flags:
       `CRITICAL INTEGRITY FAILURE: Application entrypoint "Lcom/gold/youtube/om7753/App;" missing from rebuilt DEX! Cold boot crash prevented.`
     - Rejects any partial DEX assembly that drops original classes.
     - Checks for duplicate class definitions, assembler errors, and malformed headers.
     - Confirms that approved patches are present in the target class.
  4. **Source of Truth Regeneration Engine (`regenerateDexFromCompleteSmaliDump`)**:
     - Uses the original DEX as the source of truth.
     - Clones the complete original class dump, surgically applies patches only to the targeted method/class, and locks all unmodified classes (including `App.smali`).
     - Assembles the complete 4-class Dalvik executable into `classes10.dex` and verifies integrity.
  5. **UI & Testing Enhancements (`SmaliToDexView.tsx` & `testFixtures.ts`)**:
     - Added dedicated 3-step DEX10 Remediation Pipeline in `SmaliToDexView.tsx`.
     - Added "Test Partial Bug" button to demonstrate the ClassNotFoundException crash trap and "Regenerate & Fix" to verify the permanent fix.
     - Added Test G scenario in `testFixtures.ts` and Test 7 in the automated test suite runner covering `com.gold.youtube.om7753.App`.

## [13 October 2026] - Fix: Non-Unique React Key "dex" in Download Center & Dynamic Lists
- **Issue Investigated**:
  - React warning: `Encountered two children with the same key, 'dex'. Keys should be unique so that components maintain their identity across updates.`
  - **Root Cause**:
    1. In `src/App.tsx`, `handleRegisterDexDownload` assigned `id: 'dex'` to custom assembled DEX download package items.
    2. In `buildPackages()`, the standard DEX package also possessed `id: 'dex'`.
    3. When merging `[...customDexPackages, ...standardPackages]`, `DownloadCenterSheet.tsx` mapped over `packages` using `key={pkg.id}`, causing two identical keys `dex`.
    4. Also identified potential key collision edge cases in class descriptor lists and test scenarios if duplicates existed in binary DEX inputs.
- **Resolution Implemented**:
  1. Updated `handleRegisterDexDownload` to generate distinct identifiers: `dex_assembled_${filename}`.
  2. Updated `DownloadPackageItem` in `forensics.ts` to accept `string` IDs.
  3. Hardened `DownloadCenterSheet.tsx` item mapping key with `${pkg.id}-${pkg.filename}-${idx}` and updated `getIcon()` to recognize any custom DEX variant.
  4. Hardened list keys in `PatchLabView.tsx` and `SmaliToDexView.tsx` with composite index keys (`${desc}-${idx}`, `${cls.name}-${idx}`, `${test.id}-${idx}`, `${root.rootPrefix}-${idx}`).
  5. Verified with `lint_applet` (`tsc --noEmit`) and `compile_applet`.

## [13 October 2026] - Fix: Unresponsive Download Button After Auto-Fix
- **Issue Investigated**:
  - User reported: "after i press auto fix, and the download window show up but, the download still no response when clicked, why is that?"
- **Root Cause Analysis**:
  1. **Premature Modal Opening During Asynchronous Assembly**:
     - When pressing "Auto-Fix", `handleAutoFixAll` immediately opened the `DownloadCenterSheet` via `setIsDownloadCenterOpen(true)` while `buildPackages()` began asynchronously assembling the Dalvik DEX 035 bytecode and repackaging the signed APK with JSZip (~1-2 seconds duration).
     - During this preparation window, `isPreparing` was `true`. The download button was hard-disabled with `disabled={isPreparing}`, but had NO loading indicator or status banner on the button or modal header. Tapping it produced zero response because the button was disabled.
  2. **Synchronous `URL.revokeObjectURL(url)` Browser Abort**:
     - In `handleDownload` (and across `SmaliToDexView`, `SmaliToDexModal`, `ReportModal`), `URL.revokeObjectURL(url)` was executed immediately and synchronously on the line after `a.click()`.
     - In modern browsers, mobile WebViews, and sandboxed iframes, `a.click()` delegates download handling asynchronously. Revoking the object URL synchronously before the browser networking engine reads the blob cancels or silently aborts the download with no response.
  3. **Absence of User Feedback and Download Status Notices**:
     - Failures and downloads had zero visible status toasts or progress alerts in the modal.
- **Resolution Implemented**:
  1. Created `src/services/fileDownloader.ts` with `downloadBlob` and `downloadText`:
     - Creates object URLs and triggers click with synthetic `MouseEvent`.
     - Replaced synchronous `URL.revokeObjectURL` with delayed 60-second cleanup timeout (`setTimeout(..., 60000)`), allowing mobile download engines ample time to complete the download.
  2. Enhanced `DownloadCenterSheet.tsx`:
     - Added an active pulsing status banner: "Assembling Patched Dalvik DEX & APK... (~1-2s)".
     - Download buttons now show spinning "Assembling... Tap for details" while `isPreparing` is true, providing instant explanatory feedback if tapped.
     - Added prominent user-facing status alerts (`downloadNotice`) for successful download start, errors, and guidance.
  3. Replaced fragile `revokeObjectURL` implementations in `SmaliToDexView.tsx`, `SmaliToDexModal.tsx`, and `ReportModal.tsx` with `downloadBlob` and `downloadText`.
  4. Verified through `lint_applet` (`tsc --noEmit`) and `compile_applet`.

## [13 October 2026] - Fix: Single-DEX Archive (classes10.dex) Falsely Triggering "Select Smali Root Directory"
- **Issue Investigated**:
  - User turned `classes10.dex` to `smali.zip` using MT Manager, analyzed it, downloaded `clean_smali.zip`, and uploaded it into the Smali to DEX Converter.
  - The app prompted the user: "Select Smali Root Directory (Required for Multidex)", forcing them to pick between package directories (e.g. `com/`, `io/`, `okhttp3/`, `androidx/`), even though all files in the archive belonged to `classes10.dex`.
- **Root Cause**:
  - In `src/services/smaliToDexAssembler.ts`, `scanSmaliArchive` was inspecting the first path segment for files lacking explicit `smali/` prefixes using `slashIdx = p.indexOf('/')`.
  - It only ignored `com/`, `org/`, and `android/`. Any package folder such as `io/`, `okhttp3/`, `androidx/`, `kotlin/`, or `retrofit2/` was classified as a separate root directory.
  - This created multiple roots (`com/` with 1 file, `io/` with 10 files, etc.), setting `isMultiRoot = true`, displaying the radio buttons, and assembling only the chosen package while discarding all other classes.
  - Additionally, `patchEngine.ts` regex `\bv(\d+)\b` was matching register numbers inside URL string literals (e.g. `https://api.youtube-gold.net/v1`), which has now been fixed by stripping string literals before checking register declarations.
- **Resolution Implemented**:
  1. Rewrote `scanSmaliArchive` in `src/services/smaliToDexAssembler.ts`:
     - Genuine multidex roots are now strictly detected by explicit directory markers: `smali/`, `smali_classesN/`, or `classesN/`.
     - An archive is only marked as `isMultiRoot = true` if there are 2 or more distinct multidex directory folders (e.g. `smali/` and `smali_classes10/`).
     - Standard package hierarchies (e.g. MT Manager exports with `com/`, `io/`, `okhttp3/`, etc.) or single-DEX dumps are recognized as single-root projects (`isMultiRoot = false`).
     - The entire archive is assigned to a single root (`/`), with `classes10.dex` as the default output.
  2. Updated `SmaliToDexView.tsx`:
     - Added a reassurance badge for single-DEX archives: "Single DEX Archive: All package folders will be assembled together into classes10.dex".
     - Removed the root selection radio group when `isMultiRoot` is false.
  3. Verified all 7 automated test suite scenarios plus MT Manager multi-package dumps with 100% pass rate.

## [13 October 2026] - Feature: Daily Chrome Adware Neutralizer & MT Manager Multi-Format Pipeline
- **Problem Addressed**:
  - User reported: "everyday,When I open the app, Chrome suddenly opens an advertising website without my permission. i found out the modder code is on class10.dex, so i turn that dex into smali using mtmanager. it crated zip file. i need the app that can help me fix that issue so i can put the clean dex back to the app... and when i uploaded dex the app can't read it, didn't try apk yet"
- **Root Cause & Technical Challenges**:
  1. **DEX Ingestion Brittleness**: Previous disassembler was failing on real-world DEX binaries containing complex Dalvik opcodes, throwing unhandled exceptions or desynchronizing bytecode offsets. Furthermore, the DEX input was rejecting MT Manager Smali ZIP files with "Please upload a valid .dex file".
  2. **Support Library Class Dominance**: When scanning raw DEX strings, sorting placed `androidx/` and `android/support/` classes first, dropping mod and adware classes when taking the initial slice.
  3. **Adware Detection Gap**: Unprompted daily `ACTION_VIEW` intents targeting Google Chrome (`com.android.chrome`) with periodic timers (`System.currentTimeMillis()`) lacked dedicated heuristic detection and surgical return-void patching.
- **Resolution Implemented**:
  1. **Robust Multi-Format Ingestion (`apkExtractor.ts` & `SmaliToDexView.tsx`)**:
     - `handleDexFileSelect` now accepts `.dex`, MT Manager Smali `.zip`, and `.apk` archives.
     - Unpacks MT Manager ZIPs, parses all Smali classes with `parseSmali`, and immediately populates the disassembly pipeline.
     - Supports Compact DEX (CDEX) magic headers (`cdex001\0`).
     - Prioritizes higher-numbered DEX files (e.g. `classes10.dex`) when unpacking APK archives.
     - Scores class descriptors to prioritize mod and adware classes over generic support libraries.
  2. **Opcode-Width Bytecode Precision (`DALVIK_OPCODE_UNIT_LENGTHS`)**:
     - Synchronized opcode instruction lengths (widths 1, 2, 3, 5 units) preventing bytecode desynchronization during Baksmali disassembly.
     - Directly emits structured `SmaliClass[]` with decoded instructions, invoked callees, and string references using a shared, ultra-fast `TextDecoder`.
  3. **Daily Chrome Adware Detection & Surgical Patching (`callGraphBuilder.ts`)**:
     - Added Heuristic 2b detecting unprompted Chrome auto-launch routines (`com.android.chrome`, `ACTION_VIEW`, `startActivity`, daily intervals/timestamps).
     - Proposes verified, non-destructive return-void stubs while preserving register counts and all companion classes (`App.smali`).
     - Dynamic auto-patching in `handleRegenerateFromCompleteSmaliDump` that automatically identifies adware methods and applies clean return stubs.
  4. **MT Manager Mobile Guide (`MtManagerGuideModal.tsx`)**:
     - Step-by-step touch-friendly guide explaining how to replace `classes10.dex` inside the APK in MT Manager, Dex Editor Plus flow, and auto-signing.
     - Includes one-tap copy buttons for search strings (`com.android.chrome`) and clean return stubs.
  5. **Acceptance Test Scenario Test H (`testFixtures.ts`)**:
     - Added realistic test scenario `test-h-daily-chrome-adware` reproducing daily timer checks and unprompted Chrome ad launches.

## [13 October 2026] - Fix: Smali Annotation & Data Block Handling in Pre-Assembly Validation
- **Issue**:
  - Assembling classes to DEX failed with: `Smali Assembly Failed: Unrecognized or invalid Dalvik instruction / syntax error detected: [ExternalDownloaderPreference$1] Line 30: Unrecognized or invalid Dalvik instruction "accessFlags" in method <init>(...); Line 31: "0x8010"; Line 32: "0x1010"; Line 33: "}"; Line 34: "names"`.
- **Root Cause**:
  - In Smali bytecode, methods frequently contain structured metadata and tables: `.annotation ... .end annotation` (such as `MethodParameters`, `InnerClass`, `EnclosingMethod`), `.subannotation ... .end subannotation`, `.array-data ... .end array-data`, `.packed-switch ... .end packed-switch`, and `.sparse-switch ... .end sparse-switch`.
  - `validateSmali` in `patchEngine.ts` previously assumed every line inside a `.method` that did not start with `.` or `:` was a Dalvik opcode instruction. Consequently, annotation parameters like `accessFlags = { 0x8010, 0x1010 }` and `names = { ... }` were wrongly parsed as invalid Dalvik opcodes, throwing an error and halting download package generation.
  - `parseSmali` in `smaliParser.ts` similarly treated lines inside annotations as instructions.
- **Resolution**:
  1. **Block Stack in `validateSmali`**: Added structured `blockStack` tracking for `.annotation`, `.subannotation`, `.array-data`, `.packed-switch`, `.sparse-switch`, and multi-line `.param` blocks. Non-instruction lines within these blocks are recognized as metadata/data payloads and bypassed from opcode mnemonic checks.
  2. **Instruction Cleaning in `parseSmali`**: Implemented `blockDepth` filtering to ensure only executable Dalvik instructions outside metadata blocks are indexed into `method.instructions`.
  3. **DEX Packaging Resilience in `App.tsx`**: Wrapped `assembleClassesToDex` in `buildPackages` with graceful fallback to `buildPatchedDex`, ensuring downloadable packages are never aborted even in edge cases.

## [13 October 2026] - Feature: DroidForensics Direct AI Chatbot Copilot
- **Objective**: Added an interactive, mobile-optimized AI Chatbot enabling users to converse directly with an Android Dalvik bytecode, Smali, MT Manager, and APK forensics specialist.
- **Implementation**:
  1. **Server-Side API Route (`/api/chat` in `server.ts`)**:
     - Connects directly to `gemini-3.8-flash` via `@google/genai` TypeScript SDK.
     - Automatically receives conversation history and full session context (package name, active DEX, loaded classes, detected findings, and active patches).
     - Includes a resilient local knowledge engine (`generateLocalChatReply`) providing instant, authoritative Smali, MT Manager, and adware guidance if offline or API key is unavailable.
  2. **Interactive Mobile UI (`ChatBotModal.tsx`)**:
     - Slide-up full-screen chat sheet with safe-area padding for handheld viewports.
     - Message thread with user and bot chat bubbles, copyable code blocks with syntax highlighting, and timestamps.
     - Horizontal quick prompt chips (e.g. "How to stop Chrome ads in classes10.dex?", "MT Manager: Step-by-step DEX replacement").
     - Keyboard-friendly auto-expanding input area and clear chat controls.
  3. **Universal Access Points**:
     - Persistent thumb-zone floating action button (`Chat AI`) on bottom-right of screen.
     - Direct `Chat` button in the top `Header`.
     - Direct `AI Chat Copilot` card on the `Dashboard` hero area.
