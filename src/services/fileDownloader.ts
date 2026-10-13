/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Universal Mobile-Safe & iFrame-Resilient File Downloader
 * 
 * Fixes common browser issues where immediate `URL.revokeObjectURL()`
 * causes the browser's download manager to cancel or abort downloads silently.
 */
export async function downloadBlob(
  blob: Blob,
  filename: string
): Promise<{ success: boolean; error?: string }> {
  try {
    if (!blob || blob.size === 0) {
      throw new Error('Cannot download empty file (0 bytes).');
    }

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.setAttribute('download', filename);
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.style.display = 'none';
    document.body.appendChild(a);

    // Dispatch real mouse click event for maximum browser & mobile compatibility
    try {
      const clickEvent = new MouseEvent('click', {
        bubbles: true,
        cancelable: true,
        view: window,
      });
      a.dispatchEvent(clickEvent);
    } catch {
      a.click();
    }

    // CRITICAL: Do NOT revokeObjectURL immediately!
    // Asynchronous download engines in Chromium, Safari, and mobile WebViews
    // fetch the blob URL after the call stack clears. Immediate revocation aborts the download.
    setTimeout(() => {
      try {
        if (document.body.contains(a)) {
          document.body.removeChild(a);
        }
        URL.revokeObjectURL(url);
      } catch (e) {
        // Ignore cleanup errors
      }
    }, 60000);

    return { success: true };
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    console.error(`[fileDownloader] Failed to download "${filename}":`, errorMsg);
    return { success: false, error: errorMsg };
  }
}

/**
 * Convenience helper to download text or json directly
 */
export async function downloadText(
  content: string,
  filename: string,
  mimeType: string = 'text/plain;charset=utf-8'
): Promise<{ success: boolean; error?: string }> {
  const blob = new Blob([content], { type: mimeType });
  return downloadBlob(blob, filename);
}
