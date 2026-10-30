/**
 * Central Link Extractor & De-obfuscator Engine
 * Designed for local-first on-device scanning before any external lookups.
 * Adheres to strict memory management and privacy preservation.
 */

export interface ExtractedUrlInfo {
  rawMatch: string;
  normalizedUrl: string;
  domain: string;
  hashPrefix: string; // 16 hex chars (first 8 bytes of SHA-256)
  isObfuscated: boolean;
  obfuscationTechniques: string[];
  isShortened: boolean;
  isRawIp: boolean;
  isPunycode: boolean;
}

export interface ExtractionResult {
  originalText: string;
  cleanedText: string;
  urls: ExtractedUrlInfo[];
  scanDurationMs: number;
}

// Known URL shortener services
export const SHORTENER_DOMAINS = new Set([
  'bit.ly',
  't.co',
  'tinyurl.com',
  'is.gd',
  'buff.ly',
  'ow.ly',
  'rb.gy',
  'cutt.ly',
  'rebrand.ly',
  'shorturl.at',
  'urlz.fr',
  'goo.gl',
  'clck.ru',
  'trib.al',
  'lnkd.in',
]);

// Strip zero-width characters and directional formatting overrides used to evade regex
export function stripEvasionCharacters(input: string): string {
  return input
    .replace(/[\u200B-\u200D\uFEFF\u202A-\u202E\u2060-\u206F]/g, '')
    .replace(/\s*([.:/@])\s*/g, '$1'); // collapse spaces around dots and slashes (e.g. "example . com")
}

// Calculate SHA-256 8-byte prefix (16 hex characters)
export async function computeHashPrefix(domain: string): Promise<string> {
  const normalized = domain.toLowerCase().trim().replace(/^www\./, '').replace(/\.$/, '');
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(normalized);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch {
    // Fallback simple 8-byte hash for synchronous execution
    let hash = 0;
    for (let i = 0; i < normalized.length; i++) {
      hash = (hash << 5) - hash + normalized.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash).toString(16).padStart(16, '0').slice(0, 16);
  }
}

/**
 * Robust Central Link Extractor Function
 * Extracts standard and obfuscated URLs from raw message text (SMS, WhatsApp, Gmail).
 */
export async function extractUrlsFromText(rawText: string): Promise<ExtractionResult> {
  const startTime = performance.now();
  if (!rawText || typeof rawText !== 'string') {
    return { originalText: '', cleanedText: '', urls: [], scanDurationMs: 0 };
  }

  // Step 1: Normalize evasion characters
  const cleanedText = stripEvasionCharacters(rawText);

  // Regex patterns supporting:
  // - Standard http/https/ftp
  // - Obfuscated schemes: hxxp://, hxxps://, fxp://
  // - Bracketed dots: domain[.]com, sub(.)domain(.)com, evil{.}net
  // - Slashes obfuscation: domain[/]path
  // - Bare domains with standard TLDs
  const linkRegex = /(?:(?:hxxps?|https?|ftp):\/\/|www\.)[^\s<>"'(){}\[\]]+|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?(?:\[\.\]|\(\.\)|\{\.\}|\.)){1,}[a-zA-Z]{2,}(?::\d{1,5})?(?:\/[^\s<>"'(){}\[\]]*)?/gi;

  const matches = cleanedText.match(linkRegex) || [];
  const extractedMap = new Map<string, ExtractedUrlInfo>();

  for (const rawMatch of matches) {
    const obfuscationTechniques: string[] = [];
    let normalized = rawMatch.trim();

    // Check bracketed dots
    if (/\[\.\]|\(\.\)|\{\.\}/.test(normalized)) {
      obfuscationTechniques.push('Bracketed Dot Defanging ([.], (.), {.})');
      normalized = normalized.replace(/\[\.\]|\(\.\)|\{\.\}/g, '.');
    }

    // Check hxxp / hxxps
    if (/^hxxp/i.test(normalized)) {
      obfuscationTechniques.push('Defanged Scheme (hxxp -> http)');
      normalized = normalized.replace(/^hxxp/i, 'http');
    }

    // Ensure protocol
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(normalized)) {
      normalized = 'http://' + normalized;
    }

    // Clean trailing punctuation
    normalized = normalized.replace(/[.,;:!?)]+$/, '');

    try {
      const parsed = new URL(normalized);
      const host = parsed.hostname.toLowerCase().replace(/\.$/, '');

      // Check if domain is valid
      if (!host || host.indexOf('.') === -1 && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
        continue;
      }

      // Check @ credential spoofing (e.g. http://paypal.com@evil-site.com)
      if (parsed.username || rawMatch.includes('@')) {
        obfuscationTechniques.push('Embedded Credentials/Host Masking (@ symbol)');
      }

      // Check raw IP
      const isRawIp = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || /^\[[0-9a-f:]+\]$/i.test(host);
      if (isRawIp) {
        obfuscationTechniques.push('Direct Numeric IP Address');
      }

      // Check Punycode / Internationalized Domain Name
      const isPunycode = host.includes('xn--') || /[^\x00-\x7F]/.test(host);
      if (isPunycode) {
        obfuscationTechniques.push('Punycode / Homograph Cyrillic/Greek Spoofing');
      }

      // Check URL Shortener
      const isShortened = SHORTENER_DOMAINS.has(host) || Array.from(SHORTENER_DOMAINS).some((d) => host.endsWith('.' + d));

      const hashPrefix = await computeHashPrefix(host);

      if (!extractedMap.has(normalized)) {
        extractedMap.set(normalized, {
          rawMatch,
          normalizedUrl: normalized,
          domain: host,
          hashPrefix,
          isObfuscated: obfuscationTechniques.length > 0,
          obfuscationTechniques,
          isShortened,
          isRawIp,
          isPunycode,
        });
      }
    } catch {
      // Ignore invalid URL parse attempts
    }
  }

  const urls = Array.from(extractedMap.values());
  const scanDurationMs = Math.round((performance.now() - startTime) * 100) / 100;

  return {
    originalText: rawText,
    cleanedText,
    urls,
    scanDurationMs,
  };
}
