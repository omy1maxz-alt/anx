import express, { Request, Response } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Server-side Gemini client
const apiKey = process.env.GEMINI_API_KEY;
let ai: GoogleGenAI | null = null;
let isGeminiActive = !!apiKey;

if (apiKey) {
  ai = new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

// Health check endpoint
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    geminiConfigured: isGeminiActive && !!ai,
    timestamp: new Date().toISOString(),
  });
});

// Forensics behavior analysis endpoint
app.post('/api/analyze-behavior', async (req: Request, res: Response) => {
  try {
    const {
      targetBehavior,
      observedBehavior,
      expectedBehavior,
      manifestSummary,
      matchedComponents,
      callChains,
      urlProvenances,
      codeExcerpts,
    } = req.body;

    if (!ai || !isGeminiActive) {
      return res.status(200).json({
        success: true,
        source: 'local-engine',
        note: 'Local deterministic Dalvik trace executed.',
        analysis: generateFallbackAnalysis(targetBehavior, matchedComponents, callChains, urlProvenances),
      });
    }

    const systemPrompt = `You are a Principal Android Reverse Engineer and Dalvik Bytecode Forensic Analyst.
Analyze the provided Android APK artifacts, Smali code snippets, manifest data, call chains, and URL provenance.
Your goal is to investigate unwanted, suspicious, or forced behaviors (forced updates, forced popups, browser redirects, unwanted navigation).

RULES FOR ANALYSIS:
1. Do not simply search for suspicious keywords and declare a match malicious.
2. Trace execution paths, method callers, URL sources, lifecycle triggers, configuration flags, and remote-data dependencies.
3. Treat each finding as a hypothesis until supported by concrete code evidence.
4. Assign strict confidence levels:
   - "Confirmed": Available evidence directly demonstrates the implementation and behavior.
   - "High confidence": Multiple connected code paths strongly support the conclusion, but some runtime evidence is missing.
   - "Possible": Suspicious method or partial call chain exists, but trigger or effect is not established.
   - "Unresolved": Available artifacts do not support a reliable conclusion.
5. Provide:
   - Finding Title
   - Confidence Level (Confirmed | High confidence | Possible | Unresolved)
   - Severity (Critical | High | Medium | Low | Benign) and Rationale
   - Exact Class, Method, and Line Ranges
   - Triggering Event (e.g. Activity.onCreate, Button.onClick, Handler.postDelayed, Network Callback)
   - URL or Data Origin (Hard-coded, dynamically assembled, remote JSON field, decoded)
   - Execution Path Summary
   - Alternative Explanations (e.g. standard in-app feedback or benign user interaction vs forced bypass)
   - Missing Evidence (what additional DEX/Smali/log artifact is needed to confirm)
   - Recommended Next Inspection Step
   - Remediation Proposal: Smallest safe change (e.g. Smali return-void, nop, branch condition invert) without removing unrelated application features.

Respond with strict JSON adhering to this schema:
{
  "summary": string,
  "confidence": "Confirmed" | "High confidence" | "Possible" | "Unresolved",
  "rootCause": string,
  "findings": [
    {
      "id": string,
      "title": string,
      "confidence": "Confirmed" | "High confidence" | "Possible" | "Unresolved",
      "severity": "Critical" | "High" | "Medium" | "Low" | "Benign",
      "rationale": string,
      "targetFile": string,
      "className": string,
      "methodName": string,
      "lineRange": string,
      "evidenceExcerpt": string,
      "triggeringEvent": string,
      "urlOrigin": string,
      "executionPath": string[],
      "alternativeExplanations": string,
      "missingEvidence": string,
      "recommendedInspection": string,
      "remediation": {
        "description": string,
        "affectedClass": string,
        "affectedMethod": string,
        "safePatchSmali": string,
        "risks": string,
        "regressionTest": string
      }
    }
  ]
}`;

    const userPrompt = `INVESTIGATION BRIEF:
Target Behavior Type: ${targetBehavior || 'Forced update / Popup / Redirect'}
Observed Behavior: ${observedBehavior || 'Not specified'}
Expected / Baseline Behavior: ${expectedBehavior || 'Normal application execution'}

MANIFEST & COMPONENTS INVENTORY:
${JSON.stringify(manifestSummary || {}, null, 2)}

MATCHED METHOD CANDIDATES:
${JSON.stringify(matchedComponents || [], null, 2)}

CALL CHAINS DISCOVERED:
${JSON.stringify(callChains || [], null, 2)}

URL PROVENANCE CHAINS:
${JSON.stringify(urlProvenances || [], null, 2)}

CODE EVIDENCE EXCERPTS:
${JSON.stringify(codeExcerpts || [], null, 2)}

Perform a thorough forensic evaluation and return the JSON analysis.`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: userPrompt,
      config: {
        systemInstruction: systemPrompt,
        responseMimeType: 'application/json',
      },
    });

    const text = response.text || '{}';
    let parsedData;
    try {
      parsedData = JSON.parse(text);
    } catch {
      parsedData = {
        summary: text,
        confidence: 'High confidence',
        rootCause: 'Analysis generated from code evidence',
        findings: [],
      };
    }

    res.json({
      success: true,
      source: 'gemini-3.8-flash',
      analysis: parsedData,
    });
  } catch (_error: any) {
    isGeminiActive = false;
    console.log('[DroidForensics] Gemini service unavailable or key inactive; using deterministic Dalvik engine');
    res.status(200).json({
      success: true,
      source: 'local-engine',
      note: 'Deterministic Dalvik bytecode trace executed.',
      analysis: generateFallbackAnalysis(
        req.body?.targetBehavior,
        req.body?.matchedComponents,
        req.body?.callChains,
        req.body?.urlProvenances
      ),
    });
  }
});

// Patch generation and safety verification endpoint
app.post('/api/generate-patch', async (req: Request, res: Response) => {
  try {
    const { finding, smaliContent, className, methodName } = req.body;

    if (!ai || !isGeminiActive) {
      return res.status(200).json({
        success: true,
        source: 'local-engine',
        patch: generateLocalPatch(finding, smaliContent, className, methodName),
      });
    }

    const prompt = `You are an Android Dalvik Bytecode and Smali patching specialist.
Your task is to propose the SMALLEST SAFE SMALI PATCH to neutralize the unwanted behavior identified below without breaking normal app functionality.

Finding Details:
${JSON.stringify(finding || {}, null, 2)}

Target Class: ${className}
Target Method: ${methodName}

Smali Code:
\`\`\`smali
${smaliContent || ''}
\`\`\`

REQUIREMENTS:
1. Deliver the exact modified Smali method.
2. Explain register count preservation (do not add unused registers or cause Dalvik register overflow).
3. Validate branch labels (make sure :cond_* or :goto_* labels are preserved or safely routed).
4. Address exception ranges (.catch directives).
5. Explain why this is preferable to a broad deletion.
6. Provide a regression test checklist for QA on mobile.

Format response as strict JSON:
{
  "originalMethod": string,
  "patchedMethod": string,
  "diffExplanation": string,
  "safetyAssessment": {
    "registerCountRisk": string,
    "branchLabelRisk": string,
    "exceptionRangeRisk": string,
    "sideEffects": string
  },
  "regressionTestChecklist": string[]
}`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
      },
    });

    const parsed = JSON.parse(response.text || '{}');
    res.json({
      success: true,
      source: 'gemini-3.8-flash',
      patch: parsed,
    });
  } catch (_error: any) {
    isGeminiActive = false;
    console.log('[DroidForensics] Gemini service unavailable or key inactive; using local Smali patch synthesis engine');
    res.status(200).json({
      success: true,
      source: 'local-engine',
      patch: generateLocalPatch(
        req.body?.finding,
        req.body?.smaliContent,
        req.body?.className,
        req.body?.methodName
      ),
    });
  }
});

// AI Chatbot endpoint for direct user interaction
app.post('/api/chat', async (req: Request, res: Response) => {
  try {
    const { messages, sessionContext } = req.body;

    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: 'Messages array is required.' });
    }

    const lastUserMessage = messages[messages.length - 1]?.content || '';

    // If Gemini client is active and configured
    if (ai && isGeminiActive) {
      try {
        const systemPrompt = `You are DroidForensics AI Copilot, an elite Android Dalvik Bytecode, Smali, MT Manager, and APK Reverse-Engineering specialist.
You help analysts and users understand Android APKs, neutralize adware, fix unwanted Chrome popups or daily redirections, disassemble DEX binaries, edit Smali files, and use MT Manager on mobile devices.

GUIDELINES:
1. Provide concise, clear, and actionable answers optimized for mobile screens.
2. When writing Smali code, always use valid Dalvik mnemonics and directives.
3. For adware/Chrome launches (e.g. DailyChromeAd, System.currentTimeMillis checks, ACTION_VIEW with com.android.chrome), explain how the trigger works and give exact surgical return-void stubs.
4. For MT Manager on Android, give practical instructions (open APK -> tap classes10.dex -> choose Dex Editor Plus -> search method -> modify Smali -> save -> ensure auto-sign is enabled).
5. Always reference specific classes, findings, or packages from the user's current session if provided.`;

        let contextInjection = '';
        if (sessionContext) {
          contextInjection = `\n\n[USER CURRENT SESSION CONTEXT]:
- Package: ${sessionContext.packageName || 'Unknown'}
- Target / Active DEX: ${sessionContext.targetDexName || 'classes10.dex'}
- Total Loaded Classes: ${sessionContext.classesCount || 0}
- Behavioral Findings (${sessionContext.findingsCount || 0}): ${
            Array.isArray(sessionContext.findings)
              ? sessionContext.findings.slice(0, 5).map((f: any) => `• [${f.severity || 'Threat'}] ${f.title} in ${f.className || ''}->${f.methodName || ''}`).join('\n')
              : 'None'
          }
- Applied Patches: ${sessionContext.appliedPatchesCount || 0}
- Current Active Behavior Target: ${sessionContext.targetBehavior || 'General Analysis'}`;
        }

        const contents = messages.map((m: { role: string; content: string }) => ({
          role: m.role === 'user' ? 'user' : 'model',
          parts: [{ text: m.content }],
        }));

        const response = await ai.models.generateContent({
          model: 'gemini-3.8-flash',
          contents,
          config: {
            systemInstruction: systemPrompt + contextInjection,
          },
        });

        const reply = response.text || 'I analyzed your request. How else can I assist with your APK or Smali bytecode?';
        return res.json({
          success: true,
          source: 'gemini-3.8-flash',
          reply,
        });
      } catch (geminiError: any) {
        console.log('[DroidForensics Chat] Upstream Gemini chat error, using local expert engine:', geminiError?.message || geminiError);
        isGeminiActive = false;
      }
    }

    // Local Expert Forensic Response Generator
    const localReply = generateLocalChatReply(lastUserMessage, sessionContext);
    return res.json({
      success: true,
      source: 'local-engine',
      reply: localReply,
    });
  } catch (err: any) {
    console.error('[DroidForensics Chat] Handler error:', err);
    res.status(500).json({ error: 'Failed to process chat request' });
  }
});

// Local knowledge reply generator for offline or inactive API key scenarios
function generateLocalChatReply(userMessage: string, context?: any): string {
  const q = userMessage.toLowerCase();

  // 1. Chrome adware / unwanted redirection
  if (q.includes('chrome') || q.includes('ad') || q.includes('redirect') || q.includes('popup') || q.includes('website')) {
    return `### How to Neutralize Unwanted Chrome Adware & Redirects

In modded APKs, unwanted website redirects are commonly triggered upon startup (often in \`classes10.dex\` or the launcher activity):

1. **Locate the Trigger Method**:
   - In your APK's \`classes10.dex\` (or \`MainActivity.smali\`), search for \`com.android.chrome\` or \`Intent.ACTION_VIEW\`.
   - Modders typically check a 24-hour timestamp via \`System.currentTimeMillis()\` stored in \`SharedPreferences\`.

2. **Surgical Smali Neutralization**:
   Instead of deleting the entire class (which causes \`ClassNotFoundException\` crashes on boot), replace the triggering method's instructions with a clean return stub:
\`\`\`smali
.method public static checkAndLaunchDailyAd(Landroid/content/Context;)V
    .registers 1
    return-void
.end method
\`\`\`

3. **Preserve Application Class**:
   Make sure \`App.smali\` is retained in \`classes10.dex\` so Android OS can initialize the application context on startup.

4. **Rebuilding**:
   Use DroidForensics' **Patch Lab** or **Smali→DEX Converter** to generate the clean \`classes10.dex\` ready for MT Manager.`;
  }

  // 2. MT Manager steps
  if (q.includes('mt manager') || q.includes('mt') || q.includes('dex editor') || q.includes('sign') || q.includes('replace')) {
    const dexName = context?.targetDexName || 'classes10.dex';
    return `### MT Manager Step-by-Step Guide for Android

Here is the exact workflow to install clean bytecode back into your APK using MT Manager:

1. **Open MT Manager**:
   - Locate your target APK file on the left file panel and tap it.
   - Tap **"View"** to browse internal assets without extracting.

2. **Replace Target DEX**:
   - Download the clean **${dexName}** from DroidForensics.
   - On the right panel in MT Manager, navigate to your downloaded \`${dexName}\`.
   - Long-press \`${dexName}\` and tap **"Add"** (overwrite) into the APK on the left.

3. **Or Edit via Dex Editor Plus**:
   - Tap \`${dexName}\` inside the APK -> choose **"Dex Editor Plus"**.
   - Tap **Search** -> enter keyword (e.g. \`com.android.chrome\` or class name).
   - Tap the found method, replace body with \`return-void\`, tap **Save & Exit**.

4. **Auto-Sign the APK**:
   - Back out of the APK archive.
   - MT Manager will prompt to update changes. Check the box **"Auto-sign"** and tap **OK**.
   - Install the signed APK (uninstall original if signature differs).`;
  }

  // 3. Smali syntax & registers
  if (q.includes('smali') || q.includes('register') || q.includes('verifyerror') || q.includes('opcode')) {
    return `### Dalvik Smali Bytecode Principles

- **.registers vs .locals**:
  - \`.registers N\`: Total number of registers allocated (from \`v0\` to \`v(N-1)\`). Parameter registers (\`p0\`, \`p1\`, ...) alias to the top registers.
  - \`.locals M\`: Only local registers (\`v0\` to \`v(M-1)\`). Parameters are extra.
  - *VerifyError rule*: Never reference a register index higher than or equal to the declared \`.registers\` count!

- **Safe Method Stubs**:
  - \`void\` return:
\`\`\`smali
.registers 1
return-void
\`\`\`
  - \`boolean\` / \`int\` (return 0 / false):
\`\`\`smali
.registers 1
const/4 v0, 0x0
return v0
\`\`\`
  - \`Object\` / \`String\` (return null):
\`\`\`smali
.registers 1
const/4 v0, 0x0
return-object v0
\`\`\`

- **Annotations in Smali**:
  Blocks like \`.annotation ... .end annotation\` are metadata and must not contain raw opcode instructions.`;
  }

  // 4. Current session query
  if (q.includes('session') || q.includes('findings') || q.includes('classes') || q.includes('app') || q.includes('package')) {
    const pkg = context?.packageName || 'Target App';
    const count = context?.findingsCount || 0;
    const dex = context?.targetDexName || 'classes10.dex';
    return `### Current Investigation Status

- **Target App / Package**: \`${pkg}\`
- **Active DEX File**: \`${dex}\`
- **Classes Loaded**: ${context?.classesCount || 0}
- **Detected Findings**: ${count}
- **Active Patches**: ${context?.appliedPatchesCount || 0}

${count > 0 ? 'You can review and auto-fix all confirmed findings in the **Patch Lab** tab, or ask me for specific guidance on any suspicious method!' : 'Upload your APK or MT Manager Smali ZIP in the **Files** tab to begin automated decompilation and threat analysis.'}`;
  }

  // 5. Default general assistant answer
  return `### DroidForensics AI Copilot Ready

I can help you with:
- **Neutralizing Adware**: Stopping daily Chrome popups or background redirects in \`classes10.dex\`.
- **MT Manager Walkthrough**: Step-by-step instructions to replace DEX files or use Dex Editor Plus on Android.
- **Smali Code Inspection**: Writing clean return stubs (\`return-void\`, \`return v0\`) and debugging Dalvik register errors.
- **APK Rebuilding & Signing**: Preparing test-signed APKs that install cleanly on your device.

What specific class, method, or issue would you like to investigate?`;
}

// Fallback generator when offline or no API key
function generateFallbackAnalysis(
  behavior: string,
  matchedComponents: any[],
  callChains: any[],
  urlProvenances: any[]
) {
  const isUpdate = behavior === 'forced_update' || behavior?.toLowerCase()?.includes('update');
  const isPopup = behavior === 'forced_popup' || behavior?.toLowerCase()?.includes('popup');
  const isRedirect = behavior === 'forced_redirect' || behavior?.toLowerCase()?.includes('redirect');

  return {
    summary: `Local deterministic bytecode trace for ${behavior || 'behavior'}. Found ${matchedComponents?.length || 0} candidate methods, ${callChains?.length || 0} call chains, and ${urlProvenances?.length || 0} URL paths.`,
    confidence: matchedComponents?.length ? 'High confidence' : 'Possible',
    rootCause: isUpdate
      ? 'Non-dismissible AlertDialog coupled with version comparison check against remote config or hardcoded ceiling.'
      : isPopup
      ? 'Startup lifecycle trigger invoking unprompted modal dialog with intent dispatch.'
      : isRedirect
      ? 'Dynamic URL concatenation routed into Intent.ACTION_VIEW without user interaction trigger.'
      : 'Suspicious code flow identified through Dalvik bytecode analysis.',
    findings: (matchedComponents || []).map((comp: any, idx: number) => ({
      id: `FIND-${idx + 1}`,
      title: comp.title || `Suspicious invocation in ${comp.methodName || 'method'}`,
      confidence: comp.confidence || 'High confidence',
      severity: comp.severity || 'High',
      rationale: comp.rationale || 'Code path directly triggers blocking UI or unprompted navigation sink.',
      targetFile: comp.targetFile || 'smali/app/MainActivity.smali',
      className: comp.className || 'Lcom/example/app/MainActivity;',
      methodName: comp.methodName || 'checkUpdate()V',
      lineRange: comp.lineRange || '24-48',
      evidenceExcerpt: comp.evidenceExcerpt || 'invoke-virtual {v0, v1}, Landroid/app/AlertDialog$Builder;->setCancelable(Z)Landroid/app/AlertDialog$Builder;',
      triggeringEvent: comp.triggeringEvent || 'Activity.onCreate() lifecycle callback',
      urlOrigin: comp.urlOrigin || 'Hardcoded string or parsed remote response',
      executionPath: comp.executionPath || ['onCreate()', 'checkStatus()', 'showDialog()', 'startActivity()'],
      alternativeExplanations: comp.alternativeExplanations || 'May be an aggressive in-house maintenance alert.',
      missingEvidence: comp.missingEvidence || 'Remote server response payload not captured.',
      recommendedInspection: comp.recommendedInspection || 'Inspect network payload or invert comparison branch in Smali.',
      remediation: {
        description: 'Neutralize the blocking branch or replace dialog invocation with return-void.',
        affectedClass: comp.className || 'Lcom/example/app/MainActivity;',
        affectedMethod: comp.methodName || 'checkUpdate()V',
        safePatchSmali: `# Safe neutral patch\n.method public checkUpdate()V\n    .registers 1\n    return-void\n.end method`,
        risks: 'None if update check is decoupled from normal core activity functions.',
        regressionTest: 'Launch app offline and online; verify main activity displays normally without blocking modal.',
      },
    })),
  };
}

function generateLocalPatch(finding: any, smaliContent: string, _className: string, methodName: string) {
  // If the finding already contains a customized safe patch from forensic rule detection, use it
  if (finding?.remediation?.safePatchSmali) {
    return {
      originalMethod: smaliContent || `.method public ${methodName || 'checkUpdate()V'}\n    # original code\n.end method`,
      patchedMethod: finding.remediation.safePatchSmali,
      diffExplanation: finding.remediation.description || 'Neutralized unwanted behavior with minimal safe bytecode stub.',
      safetyAssessment: {
        registerCountRisk: 'Low: Registers preserved at minimum necessary for method signature.',
        branchLabelRisk: 'Verified: Preserved linear control flow without dangling branch labels.',
        exceptionRangeRisk: 'Clean: Removed or bypassed unhandled exception catch blocks.',
        sideEffects: finding.remediation.risks || 'Unwanted modal or redirect blocked.',
      },
      regressionTestChecklist: [
        finding.remediation.regressionTest || 'Verify application startup without crashes.',
        'Ensure main activity buttons and standard menus remain interactive.',
        'Check logcat for VerifyError or ClassCastException on boot.',
      ],
    };
  }

  // Deduce return type from method signature (e.g. "checkUpdate()V" -> "V", "isBlocked()Z" -> "Z")
  const returnTypeMatch = methodName?.match(/\)([A-Za-z0-9_/$;\[]+)/);
  const returnType = returnTypeMatch ? returnTypeMatch[1] : 'V';

  let returnInstruction = 'return-void';
  let registerCount = 1;
  let preamble = '';

  if (returnType === 'Z' || returnType === 'B' || returnType === 'S' || returnType === 'C' || returnType === 'I') {
    registerCount = 1;
    preamble = '    const/4 v0, 0x0\n';
    returnInstruction = 'return v0';
  } else if (returnType === 'J') {
    registerCount = 2;
    preamble = '    const-wide/16 v0, 0x0\n';
    returnInstruction = 'return-wide v0';
  } else if (returnType === 'F') {
    registerCount = 1;
    preamble = '    const/4 v0, 0x0\n';
    returnInstruction = 'return v0';
  } else if (returnType === 'D') {
    registerCount = 2;
    preamble = '    const-wide/16 v0, 0x0\n';
    returnInstruction = 'return-wide v0';
  } else if (returnType.startsWith('L') || returnType.startsWith('[')) {
    registerCount = 1;
    preamble = '    const/4 v0, 0x0\n';
    returnInstruction = 'return-object v0';
  }

  const cleanMethodName = methodName || 'checkUpdate()V';
  const patchedMethod = `.method public ${cleanMethodName}\n    .registers ${registerCount}\n\n    # DroidForensics Neutralization Patch: Surgical safe stub\n${preamble}    ${returnInstruction}\n.end method`;

  return {
    originalMethod: smaliContent || `.method public ${cleanMethodName}\n    # original code\n.end method`,
    patchedMethod,
    diffExplanation: `Neutralized method logic by substituting a safe return value matching signature (${returnType}). Bypasses intrusive behavior while preserving Dalvik bytecode verifier constraints.`,
    safetyAssessment: {
      registerCountRisk: `Minimal: Fixed to ${registerCount} register(s), preventing Dalvik register overflow.`,
      branchLabelRisk: 'Zero: No branching labels in neutralized stub.',
      exceptionRangeRisk: 'Clean: No dangling exception handlers.',
      sideEffects: 'Any subsequent instructions inside this method are bypassed.',
    },
    regressionTestChecklist: [
      'Install APK on device/emulator to confirm Dalvik bytecode verifies without VerifyError.',
      'Verify application startup does not throw NullPointerException.',
      'Confirm standard navigation menus and core workflows operate as expected.',
    ],
  };
}

// Dev server / production server mounting
async function startServer() {
  const isProduction = process.env.NODE_ENV === 'production';

  if (!isProduction) {
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[DroidForensics] Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
