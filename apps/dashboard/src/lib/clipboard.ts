/**
 * Safe clipboard utility for CloudDecept Dashboard.
 * Works across secure contexts (HTTPS/localhost) and plain HTTP (IP access),
 * preventing 'Cannot read properties of undefined (reading writeText)' errors.
 */

export async function safeCopyToClipboard(text: string): Promise<boolean> {
  if (!text || typeof text !== 'string') return false;

  // 1. Try modern navigator.clipboard API if available (secure context / localhost)
  if (
    typeof window !== 'undefined' &&
    window.navigator &&
    window.navigator.clipboard &&
    typeof window.navigator.clipboard.writeText === 'function'
  ) {
    try {
      await window.navigator.clipboard.writeText(text);
      return true;
    } catch {
      // If permission denied or blocked, fall through to fallback
    }
  }

  // 2. Fallback using document.execCommand('copy') for plain HTTP (Oracle VM IP access)
  if (typeof document !== 'undefined') {
    try {
      const textArea = document.createElement('textarea');
      textArea.value = text;
      textArea.style.position = 'fixed';
      textArea.style.left = '-999999px';
      textArea.style.top = '-999999px';
      textArea.setAttribute('readonly', '');
      textArea.setAttribute('aria-hidden', 'true');
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();

      const successful = document.execCommand('copy');
      document.body.removeChild(textArea);
      if (successful) return true;
    } catch (err) {
      console.warn('Fallback clipboard copy failed:', err);
    }
  }

  return false;
}
