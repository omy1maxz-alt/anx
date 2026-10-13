# Changelog

All notable changes to DroidForensics are documented in this file.

## [1.0.0] - 2026-10-13

### Added
- **Full-Stack Express & Vite Server**: `server.ts` with server-side `@google/genai` Gemini 3.8 Flash endpoints `/api/analyze-behavior` and `/api/generate-patch`.
- **Dalvik Smali Bytecode Parser**: Parses classes, methods, registers, invokes (`invoke-virtual/static/direct/interface`), string constants, branching labels, and line mappings.
- **AndroidManifest Parser**: Decodes plaintext XML and binary AXML chunks, extracting package, permissions, and exported components.
- **URL Provenance Tracker**: Traces literal URLs, `StringBuilder.append()` dynamic concatenation, Base64 decoding, and remote JSON payloads to Android navigation sinks (`Uri.parse`, `Intent(ACTION_VIEW)`, `startActivity`, `WebView.loadUrl`).
- **Call Graph Builder**: Correlates lifecycle events (`onCreate`, `onResume`, `onClick`) with intermediate methods and sinks.
- **Acceptance Test Fixtures (A–F)**: Built-in harmless fixtures for Forced Updates (A), Remote Popups (B), Dynamic Redirects (C), Legitimate Links (D), Incomplete Evidence (E), and Safe Patch Lab (F).
- **Patch Lab**: Safe Smali remediation tool with before/after diffs, register count preservation checks, branch label risk flags, and regression test checklists.
- **Forensic Report Generator**: Generates and exports comprehensive Markdown and JSON forensic reports.
- **Strict Mobile-First UI**: Optimized exclusively for handheld touchscreens with >= 44x44px touch targets, safe area paddings, and bottom sheets.

## [1.0.1] - 2026-10-13

### Fixed
- Fixed duplicate key warnings in `FilesView.tsx` by using composite unique keys (`${cls.filePath}-${cls.name}-${idx}`) for Dalvik Smali class items.
- Added class deduplication filtering when unpacking APK ZIP archives and multidex slices.
- Ensured unique indexed key bindings for call graph nodes, edges, URL provenance chains, and finding cards.

## [1.0.2] - 2026-10-13

### Added
- **New Project Button**: Added accessible New Project buttons in the top Header and Dashboard hero action bar.
- **New Project Dialog**: Modal supporting starting a fresh blank investigation session with custom naming and initial behavior focus, or loading preconfigured acceptance test fixtures.
- **In-App Step-by-Step Guide**: Added an interactive collapsible workflow guide on the Dashboard explaining how to use all 6 tabs of DroidForensics.

## [1.0.3] - 2026-10-13

### Fixed
- Fixed unhandled upstream 403 API key error logging by implementing an active-state latch (`isGeminiActive`) and routing directly to the deterministic forensic engine.
- Enhanced `generateLocalPatch` with Dalvik method return type inference (`return-void`, `return v0`, `return-wide v0`, `return-object v0`) ensuring exact, verifier-safe bytecode stubs.
- Updated `/api/health` to reflect local fallback state in the header status indicator.

## [1.1.0] - 2026-10-13

### Added
- **Isolated Working Copy Workspace**: Preserves original uploaded APK, DEX, and Smali files unchanged while maintaining a mutable working copy for remediation.
- **Automated Fix & Batch Neutralization Workflow**:
  - Surgical Dalvik Smali patching that replaces threat sinks with verifier-safe return stubs while preserving register declarations, method boundaries, and exception ranges.
  - "Auto-Fix All Verified Threats" button to batch-remediate confirmed threats across all decompiled classes.
  - Revert control ("Revert All Patches") to reset the working copy back to original files.
- **Forensic Download Center**:
  - **Clean Smali ZIP**: Re-packaged ZIP archive preserving original directory structure, complete with `REMEDIATION_AUDIT_REPORT.md` and `PATCH_MANIFEST.json`.
  - **Patched DEX**: Dalvik 035 binary with aligned class descriptors and neutralized method bytecode.
  - **Patched & Test-Signed APK**: Rebuilt package archive with standard AOSP evaluation test keys, v1 JAR signatures (`META-INF/MANIFEST.MF`, `CERT.SF`, `CERT.RSA`), and `REMEDIATION_SIGNING_NOTICE.txt` explaining signature continuity.
  - **Unified Patch Diff**: Multi-file git-compatible `.patch` diff detailing replaced lines and risk assessments.
## [1.3.0] - 2026-10-13

### Added
- **Dedicated "Smali to DEX Converter" Tool Page (`SmaliToDexView.tsx`)**:
  - Accessible via dedicated 7th navigation tab (`Smali→DEX`), Header quick button, and Files view card.
  - Supports uploading Smali ZIP archives or assembling directly from cleaned workspace classes.
  - Output filename selection defaulting to `classes10.dex` with APK multidex slot warnings.
  - Interactive multi-root Smali directory selector (requiring explicit analyst selection instead of auto-merging).
  - Live progress display and millisecond performance timer.
  - Results panel showing original ZIP name, discovered Smali files count, selected root, output DEX name, status, file size, SHA-256 (with copy button), Adler-32, SHA-1, and download link.
- **Security & Validation Hardening**:
  - Path traversal attack blocking (`checkPathTraversal`) rejecting `../`, `..\`, and root-escaped entries.
  - Empty archive and non-Smali project validation guards.
  - Dalvik opcode and mnemonic validation in `validateSmali` reporting file, method, and line references.
  - Round-trip DEX binary parser (`verifyDexBinary`) checking magic bytes, 112-byte header, endianness, Adler-32, SHA-1, and class definitions.
  - Clear structural validation vs runtime device testing disclaimers.
- **Automated 6-Scenario Test Suite (`createSmaliConverterTestSuite`)**:
  - Interactive test runner for: Valid Smali ZIP, Extra Enclosing Folder, Invalid Smali Instruction, Empty ZIP, Multiple Smali Roots, and Path Traversal Attack.
  - One-tap "Run All 6 Verification Tests" and "Load Into UI" actions.
- **Analysis to Converter Bridge**:
  - Added "Send Approved Smali → DEX Converter" action button in `PatchLabView.tsx`.

## [1.4.0] - 2026-10-13

### Fixed
- **DEX10 ClassNotFoundException Cold-Boot Crash**:
  - Resolved startup crash (`java.lang.ClassNotFoundException: Didn't find class "com.gold.youtube.om7753.App"`) caused by assembling only modified Smali files as a partial DEX replacement.
  - Implemented real Baksmali DEX disassembler (`disassembleDexToSmaliClasses`) to decode all classes from uploaded DEX binaries and export complete Smali source ZIP archives preserving directory paths (`smali_classes10/com/gold/youtube/om7753/...`).
  - Implemented Mandatory Class Integrity Validator (`validateRebuiltDexIntegrity`) comparing 100% of original vs rebuilt class descriptors, strictly checking `Lcom/gold/youtube/om7753/App;`, and rejecting partial or incomplete assemblies.
  - Implemented Full Smali Dump Regeneration Engine (`regenerateDexFromCompleteSmaliDump`) using original DEX as the source of truth, merging approved patches into the complete class inventory, and locking all unmodified classes.
  - Integrated 3-stage interactive DEX10 Remediation Pipeline in `SmaliToDexView.tsx` with one-tap bug simulation and permanent fix verification.
  - Added Test G fixture (`com.gold.youtube.om7753.App`) and Test 7 in the automated test suite runner.



## [1.3.1] - 2026-10-13

### Fixed
- Fixed non-unique React key warning (`Encountered two children with the same key, 'dex'`) when registering assembled DEX artifacts alongside standard patched DEX packages.
- Hardened package item keys in `DownloadCenterSheet.tsx` using composite `${pkg.id}-${pkg.filename}-${idx}` keys.
- Enhanced `getIcon()` in Download Center to support custom dynamic DEX IDs (`dex_assembled_*`).
- Ensured composite keys across descriptor comparison lists, test items, and multi-root selectors in `SmaliToDexView.tsx`.

## [1.4.1] - 2026-10-13

### Fixed
- **Unresponsive Download Action in Download Center**:
  - Replaced immediate synchronous `URL.revokeObjectURL(url)` calls in `handleDownload` with asynchronous delayed cleanup (60 seconds) via a new centralized downloader service (`src/services/fileDownloader.ts`).
  - Added an active assembly banner and spinning indicators to `DownloadCenterSheet.tsx` when packages are compiling in the background (`isPreparing = true`), preventing silent disabled states.
  - Added interactive feedback notifications on download tap and detailed error reporting.
  - Updated `SmaliToDexView.tsx`, `SmaliToDexModal.tsx`, and `ReportModal.tsx` to use the unified mobile/iframe-resilient download utility.

## [1.4.2] - 2026-10-13

### Fixed
- **Root Directory False-Positive for Single-DEX Archives (`classes10.dex`)**:
  - Fixed `scanSmaliArchive` classifying top-level Java/Kotlin package folders (e.g. `io/`, `okhttp3/`, `androidx/`, `kotlin/`) as distinct multidex roots.
  - An archive is now recognized as multi-root only when containing 2 or more distinct multidex directory folders (e.g. `smali/` and `smali_classes10/`).
  - Standard single-DEX archives (such as MT Manager exports or `clean_smali.zip`) are automatically recognized as a single root, assembling all package directories together into `classes10.dex` without prompting the user.
  - Fixed register analysis regex in `patchEngine.ts` matching register identifiers (`v1`, `v2`) inside URL string literals or comments.

## [1.5.0] - 2026-10-13

### Added
- **Daily Chrome Auto-Launch Adware Detection & Remediation**:
  - Heuristic detecting unprompted `ACTION_VIEW` intent dispatch targeting Chrome (`com.android.chrome`), external ad URLs, and periodic/daily interval timers (`System.currentTimeMillis()`, SharedPreferences).
  - One-tap surgical remediation that stubs the offending method with `return-void` while preserving register count and clean bytecode.
  - Test H scenario (`test-h-daily-chrome-adware`) with complete reproducible smali classes.
- **Resilient Multi-Format DEX & MT Manager ZIP Ingestion**:
  - Accepts raw `.dex`, Compact DEX (`cdex`), MT Manager exported Smali `.zip`, and `.apk` archives directly.
  - Unpacks Smali classes and automatically indexes them into the workspace and disassembly pipeline.
  - Prioritizes higher-numbered DEX files (e.g. `classes10.dex`) when unpacking APK archives.
  - Smart scoring that prioritizes mod and adware classes over generic Android support/AndroidX libraries.
- **Opcode-Width Precision Baksmali Disassembly**:
  - `DALVIK_OPCODE_UNIT_LENGTHS` instruction length lookup table preventing stream desynchronization on real-world DEX files.
  - Direct emission of structured `SmaliClass[]` models without redundant regex passes.
- **MT Manager Android Interactive Guide Modal (`MtManagerGuideModal.tsx`)**:
  - Touch-optimized walkthrough for replacing `classes10.dex` inside MT Manager on Android, Dex Editor Plus manual editing, and V1/V2/V3 auto-signing.
  - One-tap copy buttons for search keywords (`com.android.chrome`, `ACTION_VIEW`) and safe return stubs.

## [1.5.1] - 2026-10-13

### Fixed
- **Smali Annotation & Metadata Block Handling in Pre-Assembly Validation**:
  - Fixed pre-assembly validation failure on classes containing Dalvik annotations, inner classes, or method parameter attributes (e.g. `ExternalDownloaderPreference$1`, `accessFlags = { 0x8010, 0x1010 }`).
  - Added structured block-stack tracking in `validateSmali` for `.annotation`, `.subannotation`, `.array-data`, `.packed-switch`, `.sparse-switch`, and multi-line `.param` blocks so data payloads are not flagged as invalid Dalvik opcodes.
  - Added `blockDepth` filtering in `parseSmali` ensuring instructions list only contains actual executable Dalvik bytecode.
  - Added graceful fallback to `buildPatchedDex` in `App.tsx`'s package preparation pipeline, guaranteeing download packages are always successfully prepared.

## [1.6.0] - 2026-10-13

### Added
- **Direct AI Chatbot Copilot (`ChatBotModal.tsx`)**:
  - Direct conversation interface to chat with the DroidForensics AI Copilot about APKs, DEX files, Smali code, Chrome adware, and MT Manager workflows.
  - Full-screen mobile layout with safe-area paddings, message bubbles, timestamps, and quick suggestion chips.
  - Code snippet boxes with one-tap copy-to-clipboard buttons and syntax styling.
  - Backed by server-side `/api/chat` using `gemini-3.8-flash` with conversation history and active session context injection.
  - Local knowledge engine fallback providing instant Smali and MT Manager guidance when offline or without API keys.
  - Floating action button (`Chat AI`), top Header button, and Dashboard quick card for 1-tap access.


## [1.6.1] - 2026-10-13

### Fixed
- **Dev Server Pre-Warming & Startup Crash**:
  - Fixed syntax error in `server.ts` regex literals where `\\//i` escaped the terminating delimiter, causing `TS1109` expression expected error.
  - Fixed duplicate closing brace in `src/App.tsx`'s `buildPackages` effect.
  - Fixed TypeScript compiler errors in `SmaliToDexView.tsx` and `smaliToDexAssembler.ts`.
  - Re-authenticated health check and dev server on port 3000 (`/api/health` and `/api/chat` operational).
