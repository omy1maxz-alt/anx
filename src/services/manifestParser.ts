import { ManifestData, ManifestComponent } from '../types/forensics';

export function parseManifest(input: string | ArrayBuffer): ManifestData {
  if (typeof input === 'string') {
    return parseXmlManifest(input);
  } else {
    // ArrayBuffer - try binary AXML parser or decode as UTF-8
    try {
      const decoded = new TextDecoder('utf-8', { fatal: false }).decode(input);
      if (decoded.includes('<manifest') || decoded.includes('package=')) {
        return parseXmlManifest(decoded);
      }
      return parseBinaryAxml(new Uint8Array(input));
    } catch {
      return parseBinaryAxml(new Uint8Array(input));
    }
  }
}

function parseXmlManifest(xmlString: string): ManifestData {
  const result: ManifestData = {
    packageName: 'unknown.package',
    permissions: [],
    components: [],
    rawXml: xmlString,
  };

  // Extract package
  const pkgMatch = xmlString.match(/package\s*=\s*["']([^"']+)["']/i);
  if (pkgMatch) {
    result.packageName = pkgMatch[1];
  }

  // Extract versionCode
  const vcMatch = xmlString.match(/android:versionCode\s*=\s*["']([^"']+)["']/i);
  if (vcMatch) {
    result.versionCode = vcMatch[1];
  }

  // Extract versionName
  const vnMatch = xmlString.match(/android:versionName\s*=\s*["']([^"']+)["']/i);
  if (vnMatch) {
    result.versionName = vnMatch[1];
  }

  // Extract minSdkVersion & targetSdkVersion
  const minSdkMatch = xmlString.match(/android:minSdkVersion\s*=\s*["']([^"']+)["']/i);
  if (minSdkMatch) {
    result.minSdkVersion = minSdkMatch[1];
  }
  const targetSdkMatch = xmlString.match(/android:targetSdkVersion\s*=\s*["']([^"']+)["']/i);
  if (targetSdkMatch) {
    result.targetSdkVersion = targetSdkMatch[1];
  }

  // Extract permissions
  const permRegex = /<uses-permission[^>]+android:name\s*=\s*["']([^"']+)["'][^>]*\/?>/gi;
  let permMatch;
  while ((permMatch = permRegex.exec(xmlString)) !== null) {
    if (!result.permissions.includes(permMatch[1])) {
      result.permissions.push(permMatch[1]);
    }
  }

  // Extract components (activities, services, receivers, providers)
  const componentTags: Array<'activity' | 'service' | 'receiver' | 'provider'> = [
    'activity',
    'service',
    'receiver',
    'provider',
  ];

  for (const tag of componentTags) {
    const compRegex = new RegExp(`<${tag}\\b([\\s\\S]*?)(?:<\\/${tag}>|\\/>)`, 'gi');
    let compMatch;
    while ((compMatch = compRegex.exec(xmlString)) !== null) {
      const compBody = compMatch[0];
      const nameMatch = compBody.match(/android:name\s*=\s*["']([^"']+)["']/i);
      const exportedMatch = compBody.match(/android:exported\s*=\s*["'](true|false)["']/i);
      const permMatchInComp = compBody.match(/android:permission\s*=\s*["']([^"']+)["']/i);

      if (nameMatch) {
        const component: ManifestComponent = {
          type: tag,
          name: nameMatch[1],
          exported: exportedMatch ? exportedMatch[1].toLowerCase() === 'true' : false,
          permission: permMatchInComp ? permMatchInComp[1] : undefined,
          intentFilters: [],
        };

        // Extract intent-filters
        const filterRegex = /<intent-filter\b([\s\S]*?)<\/intent-filter>/gi;
        let filterMatch;
        while ((filterMatch = filterRegex.exec(compBody)) !== null) {
          const filterBody = filterMatch[1];
          const actions: string[] = [];
          const categories: string[] = [];
          let dataObj: { scheme?: string; host?: string; path?: string } | undefined;

          const actionRegex = /<action[^>]+android:name\s*=\s*["']([^"']+)["']/gi;
          let aMatch;
          while ((aMatch = actionRegex.exec(filterBody)) !== null) {
            actions.push(aMatch[1]);
          }

          const catRegex = /<category[^>]+android:name\s*=\s*["']([^"']+)["']/gi;
          let cMatch;
          while ((cMatch = catRegex.exec(filterBody)) !== null) {
            categories.push(cMatch[1]);
          }

          const dataRegex = /<data\b([^>]*)\/?>/gi;
          let dMatch;
          while ((dMatch = dataRegex.exec(filterBody)) !== null) {
            const dataAttrs = dMatch[1];
            const schemeM = dataAttrs.match(/android:scheme\s*=\s*["']([^"']+)["']/i);
            const hostM = dataAttrs.match(/android:host\s*=\s*["']([^"']+)["']/i);
            const pathM = dataAttrs.match(/android:path\s*=\s*["']([^"']+)["']/i);
            dataObj = {
              scheme: schemeM ? schemeM[1] : undefined,
              host: hostM ? hostM[1] : undefined,
              path: pathM ? pathM[1] : undefined,
            };
          }

          component.intentFilters.push({
            actions,
            categories,
            data: dataObj,
          });

          // Implicit export rule: If intent-filter exists and android:exported is not explicitly false, it is often exported
          if (!exportedMatch && actions.length > 0) {
            component.exported = true;
          }
        }

        result.components.push(component);
      }
    }
  }

  return result;
}

// Lightweight binary AXML string extractor for raw APK manifests
function parseBinaryAxml(bytes: Uint8Array): ManifestData {
  const result: ManifestData = {
    packageName: 'app.package.binary',
    permissions: [],
    components: [],
    rawXml: '<!-- Decoded from Android Binary XML Chunk Header -->\n<manifest package="extracted">',
  };

  // Collect printable UTF-8 or ASCII strings from the string pool chunk
  const strings: string[] = [];
  let current = '';
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    if (byte >= 32 && byte <= 126) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= 3) {
        strings.push(current);
      }
      current = '';
    }
  }
  if (current.length >= 3) strings.push(current);

  // Scan extracted strings for package, permissions, and components
  for (const s of strings) {
    if (s.includes('android.permission.') && !result.permissions.includes(s)) {
      result.permissions.push(s);
    }
    if ((s.endsWith('Activity') || s.includes('.activity.')) && !s.includes('android.')) {
      result.components.push({
        type: 'activity',
        name: s,
        exported: false,
        intentFilters: [],
      });
    }
  }

  // Try to find package name (longest dot-separated lower-case identifier)
  const pkgCandidates = strings.filter(
    (s) => s.includes('.') && /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/.test(s) && !s.startsWith('android.')
  );
  if (pkgCandidates.length > 0) {
    result.packageName = pkgCandidates[0];
  }

  return result;
}
