import { SmaliClass, UrlProvenanceChain } from '../types/forensics';

export function traceUrlProvenance(classes: SmaliClass[]): UrlProvenanceChain[] {
  const chains: UrlProvenanceChain[] = [];
  let chainCounter = 1;

  for (const cls of classes) {
    for (const method of cls.methods) {
      let activeUrlString: string | null = null;
      let urlOriginType: UrlProvenanceChain['originType'] = 'hardcoded';
      let transformations: string[] = [];
      let originLine = method.sourceLineStart || 1;
      let hasUriParse = false;
      let hasStartActivity = false;
      let hasWebViewLoad = false;
      let hasIntentView = false;
      let hasStringBuilder = false;
      let hasBase64 = false;
      let hasJsonExtract = false;
      let jsonKey = '';

      for (const inst of method.instructions) {
        // String constants
        if (inst.isStringConst && inst.stringValue) {
          const val = inst.stringValue;
          if (val.startsWith('http://') || val.startsWith('https://') || val.startsWith('market://') || val.startsWith('intent://')) {
            activeUrlString = val;
            urlOriginType = 'hardcoded';
            originLine = inst.lineNumber || originLine;
          } else if (val === 'android.intent.action.VIEW') {
            hasIntentView = true;
          } else if (val.toLowerCase().includes('url') || val.toLowerCase().includes('link') || val.toLowerCase().includes('download')) {
            jsonKey = val;
          } else if (/^[A-Za-z0-9+/=]{16,}$/.test(val) && !val.includes(' ')) {
            // Check possible Base64 encoded URL
            try {
              const decoded = atob(val);
              if (decoded.startsWith('http://') || decoded.startsWith('https://')) {
                activeUrlString = decoded;
                urlOriginType = 'decoded_base64';
                hasBase64 = true;
                transformations.push(`Base64.decode("${val}") -> "${decoded}"`);
                originLine = inst.lineNumber || originLine;
              }
            } catch {
              // Not valid base64
            }
          }
        }

        // Method invocations
        if (inst.isInvoke && inst.targetMethod) {
          const m = inst.targetMethod;

          if (m.includes('StringBuilder;->append') || m.includes('StringBuffer;->append')) {
            hasStringBuilder = true;
            if (!transformations.includes('StringBuilder.append() concatenation')) {
              transformations.push('StringBuilder.append() concatenation');
            }
          }

          if (m.includes('JSONObject;->getString') || m.includes('JSONObject;->optString')) {
            hasJsonExtract = true;
            if (jsonKey) {
              transformations.push(`JSONObject.getString("${jsonKey}") payload extraction`);
            } else {
              transformations.push('JSONObject.getString() dynamic remote payload');
            }
          }

          if (m.includes('Uri;->parse')) {
            hasUriParse = true;
          }

          if (m.includes('Context;->startActivity') || m.includes('Activity;->startActivity')) {
            hasStartActivity = true;
          }

          if (m.includes('WebView;->loadUrl') || m.includes('loadUrl(Ljava/lang/String;)V')) {
            hasWebViewLoad = true;
          }
        }
      }

      // Check if StringBuilder was used to construct dynamic URL
      if (hasStringBuilder && !activeUrlString && method.stringsUsed.some((s) => s.startsWith('http') || s.includes('.com') || s.includes('.org') || s.includes('api/'))) {
        const matchingParts = method.stringsUsed.filter((s) => s.includes('/') || s.includes('.') || s.startsWith('http'));
        activeUrlString = matchingParts.join('') || 'Dynamic URL assembled via StringBuilder';
        urlOriginType = 'dynamically_assembled';
      }

      // Check remote json
      if (hasJsonExtract && !activeUrlString) {
        activeUrlString = jsonKey ? `Remote JSON payload field ["${jsonKey}"]` : 'Remote JSON response parameter';
        urlOriginType = 'remote_json';
      }

      // If we found a URL or a navigation sink
      if (activeUrlString || (hasUriParse && hasStartActivity) || hasWebViewLoad) {
        let sink = 'Unresolved sink';
        if (hasStartActivity && (hasIntentView || hasUriParse)) {
          sink = 'Intent(ACTION_VIEW) -> Context.startActivity() (External Browser)';
        } else if (hasWebViewLoad) {
          sink = 'WebView.loadUrl() (In-App WebView)';
        } else if (hasStartActivity) {
          sink = 'Context.startActivity(Intent)';
        }

        const isProven = !!activeUrlString && (hasStartActivity || hasWebViewLoad);
        const isSuspicious =
          urlOriginType === 'remote_json' ||
          urlOriginType === 'decoded_base64' ||
          urlOriginType === 'dynamically_assembled' ||
          (activeUrlString?.includes('update') ?? false) ||
          (activeUrlString?.includes('download') ?? false) ||
          (activeUrlString?.includes('track') ?? false) ||
          (activeUrlString?.includes('aff') ?? false);

        chains.push({
          id: `URL-CHAIN-${chainCounter++}`,
          url: activeUrlString || 'Dynamic / Inferred URL Parameter',
          originType: urlOriginType,
          originSource: `${cls.simpleName}.smali (line ~${originLine}) in ${method.name}`,
          transformations,
          intermediateMethods: [
            `${cls.simpleName}->${method.name}`,
            ...(hasUriParse ? ['Uri.parse(String)'] : []),
            ...(hasIntentView ? ['new Intent("android.intent.action.VIEW", Uri)'] : []),
          ],
          navigationSink: sink,
          provenanceStatus: isProven ? 'proven' : 'partially_inferred',
          isSuspicious,
        });
      }
    }
  }

  return chains;
}
