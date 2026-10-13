import { SmaliClass, SmaliMethod, SmaliInstruction } from '../types/forensics';

const LIFECYCLE_METHODS = new Set([
  'onCreate',
  'onStart',
  'onResume',
  'onPause',
  'onStop',
  'onDestroy',
  'onRestart',
  'onClick',
  'onReceive',
  'onHandleIntent',
  'doInBackground',
  'onPostExecute',
  'run',
  'shouldOverrideUrlLoading',
  'onCreateWindow',
]);

export function parseSmali(smaliText: string, filePath: string = 'unknown.smali'): SmaliClass[] {
  // MT Manager / third-party generators sometimes append ".end class", which is not a
  // valid Smali directive. Normalize it out instead of passing invalid text downstream.
  const normalizedSmaliText = smaliText
    .split(/\r?\n/)
    .filter((line) => line.trim() !== '.end class')
    .join('\n');
  const lines = normalizedSmaliText.split(/\r?\n/);
  const classes: SmaliClass[] = [];

  let currentClass: Partial<SmaliClass> | null = null;
  let currentMethod: Partial<SmaliMethod> | null = null;
  let methodLines: string[] = [];
  let currentLineNumber: number | undefined = undefined;
  let blockDepth = 0;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();

    if (!trimmed || trimmed.startsWith('#')) {
      if (currentMethod) {
        methodLines.push(rawLine);
      }
      continue;
    }

    // Check .class
    if (trimmed.startsWith('.class ')) {
      if (currentClass) {
        classes.push(finalizeClass(currentClass, filePath));
      }

      const parts = trimmed.split(/\s+/);
      const classDescriptor = parts[parts.length - 1]; // e.g. Lcom/example/app/MainActivity;
      const cleanName = classDescriptor.replace(/;$/, '');
      const pathParts = cleanName.replace(/^L/, '').split('/');
      const simpleName = pathParts[pathParts.length - 1] || 'Unknown';
      const pkg = pathParts.slice(0, -1).join('.');

      currentClass = {
        name: classDescriptor,
        package: pkg,
        simpleName,
        interfaces: [],
        fields: [],
        methods: [],
        rawCode: normalizedSmaliText,
        filePath,
      };
      continue;
    }

    if (!currentClass) {
      continue;
    }

    // Check .super
    if (trimmed.startsWith('.super ')) {
      const parts = trimmed.split(/\s+/);
      currentClass.superClass = parts[1];
      continue;
    }

    // Check .implements
    if (trimmed.startsWith('.implements ')) {
      const parts = trimmed.split(/\s+/);
      currentClass.interfaces = currentClass.interfaces || [];
      currentClass.interfaces.push(parts[1]);
      continue;
    }

    // Check .source
    if (trimmed.startsWith('.source ')) {
      const match = trimmed.match(/\.source\s+"([^"]+)"/);
      if (match) {
        currentClass.sourceFile = match[1];
      }
      continue;
    }

    // Check .field
    if (trimmed.startsWith('.field ')) {
      const fieldMatch = trimmed.match(/\.field\s+(?:([\w\s]+)\s+)?([a-zA-Z0-9_$]+):([^\s]+)/);
      if (fieldMatch) {
        currentClass.fields = currentClass.fields || [];
        currentClass.fields.push({
          accessFlags: fieldMatch[1] ? fieldMatch[1].split(/\s+/) : [],
          name: fieldMatch[2],
          type: fieldMatch[3],
        });
      }
      continue;
    }

    // Check .method
    if (trimmed.startsWith('.method ')) {
      methodLines = [rawLine];
      const match = trimmed.match(/\.method\s+(?:([\w\s]+)\s+)?([a-zA-Z0-9_$<>]+)\(([^)]*)\)(.+)/);
      const accessFlags = match && match[1] ? match[1].split(/\s+/) : [];
      const methodName = match ? match[2] : 'unknown';
      const paramStr = match ? match[3] : '';
      const returnType = match ? match[4] : 'V';

      currentMethod = {
        name: methodName,
        signature: `${methodName}(${paramStr})${returnType}`,
        returnType,
        parameters: paramStr ? parseSmaliParams(paramStr) : [],
        accessFlags,
        registers: 0,
        instructions: [],
        sourceLineStart: i + 1,
        callees: [],
        stringsUsed: [],
        intentsTriggered: [],
        isLifecycleTrigger: LIFECYCLE_METHODS.has(methodName),
      };
      continue;
    }

    // Inside a method
    if (currentMethod) {
      methodLines.push(rawLine);

      // Track .line
      if (trimmed.startsWith('.line ')) {
        const lineNum = parseInt(trimmed.substring(6).trim(), 10);
        if (!isNaN(lineNum)) {
          currentLineNumber = lineNum;
        }
        continue;
      }

      // Track .registers or .locals
      if (trimmed.startsWith('.registers ')) {
        const regs = parseInt(trimmed.substring(11).trim(), 10);
        currentMethod.registers = isNaN(regs) ? 0 : regs;
        continue;
      }
      if (trimmed.startsWith('.locals ')) {
        const locs = parseInt(trimmed.substring(8).trim(), 10);
        currentMethod.registers = isNaN(locs) ? 0 : locs;
        continue;
      }

      // Check .end method
      if (trimmed.startsWith('.end method')) {
        currentMethod.sourceLineEnd = i + 1;
        currentMethod.rawCode = methodLines.join('\n');
        if (currentClass.methods) {
          currentClass.methods.push(currentMethod as SmaliMethod);
        }
        currentMethod = null;
        methodLines = [];
        blockDepth = 0;
        continue;
      }

      // Track block depth for .annotation, .subannotation, .array-data, .packed-switch, .sparse-switch, .param
      if (
        trimmed.startsWith('.annotation') ||
        trimmed.startsWith('.subannotation') ||
        trimmed.startsWith('.array-data') ||
        trimmed.startsWith('.packed-switch') ||
        trimmed.startsWith('.sparse-switch') ||
        (trimmed.startsWith('.param') && !trimmed.includes(','))
      ) {
        blockDepth++;
        continue;
      }
      if (trimmed.startsWith('.end ') && !trimmed.startsWith('.end method')) {
        blockDepth = Math.max(0, blockDepth - 1);
        continue;
      }
      if (blockDepth > 0) {
        continue;
      }

      // Skip directives and labels from instruction parsing
      if (trimmed.startsWith('.') || trimmed.startsWith(':')) {
        continue;
      }

      // Parse instruction
      const instruction = parseInstruction(trimmed, currentLineNumber);
      if (instruction) {
        currentMethod.instructions = currentMethod.instructions || [];
        currentMethod.instructions.push(instruction);

        if (instruction.isInvoke && instruction.targetMethod) {
          currentMethod.callees = currentMethod.callees || [];
          currentMethod.callees.push(`${instruction.targetClass || ''}->${instruction.targetMethod}`);
        }

        if (instruction.isStringConst && instruction.stringValue) {
          currentMethod.stringsUsed = currentMethod.stringsUsed || [];
          currentMethod.stringsUsed.push(instruction.stringValue);
          if (instruction.stringValue.includes('android.intent.action.')) {
            currentMethod.intentsTriggered = currentMethod.intentsTriggered || [];
            currentMethod.intentsTriggered.push(instruction.stringValue);
          }
        }
      }
    }
  }

  if (currentClass) {
    classes.push(finalizeClass(currentClass, filePath));
  }

  return classes;
}

function parseInstruction(line: string, lineNumber?: number): SmaliInstruction | null {
  if (!line || line.startsWith('.')) return null;

  const spaceIdx = line.indexOf(' ');
  const op = spaceIdx !== -1 ? line.substring(0, spaceIdx) : line;
  const args = spaceIdx !== -1 ? line.substring(spaceIdx + 1).trim() : '';

  const isInvoke = op.startsWith('invoke-');
  const isStringConst = op.startsWith('const-string');
  const isBranch = op.startsWith('if-') || op === 'goto' || op === 'goto/16' || op === 'goto/32';
  const isReturn = op.startsWith('return');

  let targetMethod: string | undefined;
  let targetClass: string | undefined;
  let stringValue: string | undefined;
  let branchLabel: string | undefined;

  if (isInvoke) {
    // e.g. {v0, v1}, Landroid/app/AlertDialog$Builder;->setCancelable(Z)Landroid/app/AlertDialog$Builder;
    const arrowIdx = args.indexOf('->');
    if (arrowIdx !== -1) {
      const preArrow = args.substring(0, arrowIdx);
      const postArrow = args.substring(arrowIdx + 2);
      const classMatch = preArrow.match(/(L[\w$/]+;)/);
      if (classMatch) {
        targetClass = classMatch[1];
      }
      targetMethod = postArrow.trim();
    }
  } else if (isStringConst) {
    // e.g. v0, "https://example.com/update"
    const quoteStart = args.indexOf('"');
    const quoteEnd = args.lastIndexOf('"');
    if (quoteStart !== -1 && quoteEnd > quoteStart) {
      stringValue = args.substring(quoteStart + 1, quoteEnd);
    }
  } else if (isBranch) {
    const colonIdx = args.lastIndexOf(':');
    if (colonIdx !== -1) {
      branchLabel = args.substring(colonIdx).trim();
    }
  }

  return {
    raw: line,
    op,
    args,
    lineNumber,
    isInvoke,
    isStringConst,
    isBranch,
    isReturn,
    targetMethod,
    targetClass,
    stringValue,
    branchLabel,
  };
}

function parseSmaliParams(paramStr: string): string[] {
  const params: string[] = [];
  let i = 0;
  while (i < paramStr.length) {
    const ch = paramStr[i];
    if (ch === 'L') {
      const end = paramStr.indexOf(';', i);
      if (end !== -1) {
        params.push(paramStr.substring(i, end + 1));
        i = end + 1;
      } else {
        i++;
      }
    } else if (ch === '[') {
      let arrayDim = '';
      while (i < paramStr.length && paramStr[i] === '[') {
        arrayDim += '[';
        i++;
      }
      if (i < paramStr.length && paramStr[i] === 'L') {
        const end = paramStr.indexOf(';', i);
        if (end !== -1) {
          params.push(arrayDim + paramStr.substring(i, end + 1));
          i = end + 1;
        } else {
          i++;
        }
      } else if (i < paramStr.length) {
        params.push(arrayDim + paramStr[i]);
        i++;
      }
    } else {
      params.push(ch);
      i++;
    }
  }
  return params;
}

function finalizeClass(c: Partial<SmaliClass>, filePath: string): SmaliClass {
  return {
    name: c.name || 'LUnknownClass;',
    package: c.package || '',
    simpleName: c.simpleName || 'UnknownClass',
    superClass: c.superClass,
    interfaces: c.interfaces || [],
    sourceFile: c.sourceFile,
    methods: c.methods || [],
    fields: c.fields || [],
    rawCode: c.rawCode || '',
    filePath,
  };
}
