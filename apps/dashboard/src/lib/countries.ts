/**
 * Canonical country code to full name utility for CloudDecept Dashboard.
 * Uses standard Intl.DisplayNames with graceful fallbacks.
 */

let regionNames: Intl.DisplayNames | null = null;

try {
  if (typeof Intl !== 'undefined' && typeof Intl.DisplayNames === 'function') {
    regionNames = new Intl.DisplayNames(['en'], { type: 'region' });
  }
} catch {
  regionNames = null;
}

// Common aliases and overrides
const COUNTRY_OVERRIDES: Record<string, string> = {
  US: 'United States',
  GB: 'United Kingdom',
  UK: 'United Kingdom',
  CN: 'China',
  NL: 'Netherlands',
  DE: 'Germany',
  FR: 'France',
  RU: 'Russia',
  IN: 'India',
  PK: 'Pakistan',
  ID: 'Indonesia',
  KR: 'South Korea',
  JP: 'Japan',
  BR: 'Brazil',
  CA: 'Canada',
  AU: 'Australia',
  SG: 'Singapore',
  VN: 'Vietnam',
  TH: 'Thailand',
  IR: 'Iran',
  UA: 'Ukraine',
  TR: 'Turkey',
  TW: 'Taiwan',
  HK: 'Hong Kong',
};

/**
 * Returns full country name from an ISO-2 country code, or returns the name itself.
 * If null, empty, or unknown, gracefully returns "Unknown".
 */
export function getCountryName(codeOrName?: string | null): string {
  if (!codeOrName || typeof codeOrName !== 'string') {
    return 'Unknown';
  }

  const trimmed = codeOrName.trim();
  if (trimmed === '' || trimmed.toLowerCase() === 'unknown' || trimmed.toLowerCase() === 'null') {
    return 'Unknown';
  }

  // Check 2-letter uppercase ISO code
  if (trimmed.length === 2) {
    const upper = trimmed.toUpperCase();
    if (COUNTRY_OVERRIDES[upper]) {
      return COUNTRY_OVERRIDES[upper];
    }
    if (regionNames) {
      try {
        const resolved = regionNames.of(upper);
        if (resolved) return resolved;
      } catch {
        // Fall through
      }
    }
    return upper;
  }

  // Already a full name or unrecognized length
  return trimmed;
}
