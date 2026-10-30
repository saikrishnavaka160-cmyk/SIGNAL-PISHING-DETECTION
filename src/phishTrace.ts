/**
 * PhishTrace Forensics Engine
 *
 * Dedicated to explainable, responsive URL text forensics for authorized education
 * and defensive triage. Operates strictly on URL text without any network requests.
 *
 * MANDATORY SAFETY GUARANTEES:
 * - NO network calls (no fetch, no XHR, no DNS lookups).
 * - Only HTTP and HTTPS protocol schemes allowed.
 * - Explicit input bounds (<= 2048 characters).
 * - Identifies and flags embedded credentials / userinfo.
 * - Detects reserved / local / loopback IP spaces with clear warnings.
 * - Generates synthetic redirect examples clearly marked as simulations.
 * - Exports cryptographically verifiable cases with SHA-256 integrity hashes.
 * - Never claims a clean URL is "safe" (low score = no heuristic indicators found).
 */

export type SignalSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type SignalCategory = 'protocol' | 'host' | 'structure' | 'keywords' | 'obfuscation' | 'reputation';

export interface PhishTraceSignal {
  id: string;
  name: string;
  severity: SignalSeverity;
  points: number;
  category: SignalCategory;
  explanation: string;
  evidence: string;
}

export interface ParsedUrlComponents {
  raw: string;
  sanitized: string;
  protocol: string;
  hostname: string;
  port: string | null;
  pathname: string;
  search: string;
  searchParams: Array<{ key: string; value: string }>;
  hash: string;
  apexDomain: string;
  subdomains: string[];
  tld: string;
  isIpv4: boolean;
  isIpv6: boolean;
  isReservedIp: boolean;
  isDemoFixture: boolean;
  hasCredentials: boolean;
  hasPunycode: boolean;
  entropy: number;
}

export interface SyntheticRedirectHop {
  hop: number;
  type: 'initial' | 'synthetic_tracker' | 'synthetic_target';
  url: string;
  domain: string;
  role: string;
  note: string;
}

export interface PhishTraceCase {
  caseId: string;
  analyzedAt: string;
  engineVersion: string;
  inputUrl: string;
  sanitizedUrl: string;
  components: ParsedUrlComponents;
  score: number;
  riskBand: 'Low' | 'Suspicious' | 'High';
  verdictText: string;
  signals: PhishTraceSignal[];
  syntheticRedirects: SyntheticRedirectHop[];
  domainHashPrefix: string;
  disclaimers: string[];
  caseIntegritySha256: string;
}

// Maximum allowed URL length to prevent buffer overruns / ReDoS
export const MAX_URL_LENGTH = 2048;

// Known URL shortener services for synthetic redirect classification
export const KNOWN_SHORTENERS = new Set([
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

// High abuse TLDs often correlated with disposable phishing landing sites
export const HIGH_ABUSE_TLDS = new Set([
  'xyz',
  'top',
  'tk',
  'ml',
  'ga',
  'cf',
  'gq',
  'buzz',
  'icu',
  'cam',
  'sbs',
  'work',
  'rest',
  'cfd',
  'monster',
]);

// Brand impersonation keyword targets
export const TARGET_BRAND_KEYWORDS = [
  'paypal',
  'apple',
  'google',
  'microsoft',
  'netflix',
  'amazon',
  'chase',
  'wellsfargo',
  'bankofamerica',
  'citibank',
  'binance',
  'coinbase',
  'meta',
  'facebook',
  'instagram',
  'whatsapp',
  'dhl',
  'fedex',
  'usps',
];

// Sensitive credential & authentication tokens
export const SENSITIVE_KEYWORDS = [
  'login',
  'signin',
  'sign-in',
  'log-in',
  'verify',
  'verification',
  'secure',
  'account-update',
  'update-billing',
  'confirm-identity',
  'password',
  'reset',
  'wallet',
  'seed-phrase',
  'banking',
  'auth',
  'oauth',
  'session',
];

/**
 * Calculates Shannon entropy of a string (measures randomness).
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const frequencies: Record<string, number> = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

/**
 * Checks if an IPv4 address belongs to private/loopback/carrier-grade reserved ranges.
 */
export function isReservedIpAddress(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return false;
  }
  const [a, b] = parts;
  if (a === 127) return true; // Loopback 127.0.0.0/8
  if (a === 10) return true; // Private 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // Private 172.16.0.0/12
  if (a === 192 && b === 168) return true; // Private 192.168.0.0/16
  if (a === 169 && b === 254) return true; // Link-local / Cloud Metadata 169.254.0.0/16
  if (a === 0) return true; // Zero address 0.0.0.0/8
  if (a >= 224 && a <= 239) return true; // Multicast
  return false;
}

/**
 * Normalizes defanged URL notation (e.g. hxxp, [.], etc.)
 */
export function normalizeDefangedUrl(rawInput: string): { normalized: string; wasDefanged: boolean } {
  let wasDefanged = false;
  let text = rawInput.trim();

  // Strip zero-width / bidirectional evasion characters
  const stripped = text.replace(/[\u200B-\u200D\uFEFF\u202A-\u202E\u2060-\u206F]/g, '');
  if (stripped !== text) {
    wasDefanged = true;
    text = stripped;
  }

  // Bracketed dots [.] or (.) or {.}
  if (/\[\.\]|\(\.\)|\{\.\}/.test(text)) {
    wasDefanged = true;
    text = text.replace(/\[\.\]|\(\.\)|\{\.\}/g, '.');
  }

  // Defanged protocols hxxp / hxxps
  if (/^hxxps?:\/\//i.test(text)) {
    wasDefanged = true;
    text = text.replace(/^hxxp/i, 'http');
  }

  return { normalized: text, wasDefanged };
}

/**
 * Extracts apex domain and subdomains from a hostname.
 */
export function parseDomainHierarchy(hostname: string): { apexDomain: string; subdomains: string[]; tld: string } {
  const cleanHost = hostname.toLowerCase().replace(/\.$/, '');
  const parts = cleanHost.split('.');

  if (parts.length <= 1) {
    return { apexDomain: cleanHost, subdomains: [], tld: '' };
  }

  // Handle common two-part ccTLDs (e.g. .co.uk, .com.au, .gov.in)
  const isSecondLevelCctld =
    parts.length > 2 &&
    ['co', 'com', 'org', 'net', 'gov', 'edu'].includes(parts[parts.length - 2]) &&
    parts[parts.length - 1].length === 2;

  let apexParts: string[];
  let subParts: string[];

  if (isSecondLevelCctld && parts.length >= 3) {
    apexParts = parts.slice(-3);
    subParts = parts.slice(0, -3);
  } else {
    apexParts = parts.slice(-2);
    subParts = parts.slice(0, -2);
  }

  const apexDomain = apexParts.join('.');
  const tld = parts[parts.length - 1];

  return { apexDomain, subdomains: subParts, tld };
}

/**
 * Computes 16-hex character SHA-256 hash prefix for pseudonymous lookup.
 */
export async function computeDomainHashPrefix(domain: string): Promise<string> {
  const normalized = domain.toLowerCase().trim().replace(/^www\./, '').replace(/\.$/, '');
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(normalized);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch {
    // Fallback sync hash
    let hash = 0;
    for (let i = 0; i < normalized.length; i++) {
      hash = (hash << 5) - hash + normalized.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash).toString(16).padStart(16, '0').slice(0, 16);
  }
}

/**
 * Core Parser and Forensics Analyzer
 */
export function validateUrlInput(input: string): {
  valid: boolean;
  error?: string;
  isReservedIp?: boolean;
  hasCredentials?: boolean;
} {
  if (!input || typeof input !== 'string') {
    return { valid: false, error: 'URL input is required.' };
  }
  if (input.length > MAX_URL_LENGTH) {
    return { valid: false, error: `URL length exceeds maximum bound of ${MAX_URL_LENGTH} characters.` };
  }
  const { normalized } = normalizeDefangedUrl(input);
  let urlToParse = normalized;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i.test(urlToParse)) {
    urlToParse = 'https://' + urlToParse;
  }
  let parsed: URL;
  try {
    parsed = new URL(urlToParse);
  } catch {
    return { valid: false, error: 'Malformed URL syntax.' };
  }
  const proto = parsed.protocol.toLowerCase();
  if (proto !== 'http:' && proto !== 'https:') {
    return { valid: false, error: `Prohibited protocol '${proto}'. Only HTTP or HTTPS schemes are supported.` };
  }
  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  const isIpv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname);
  const isReservedIp = isIpv4 ? isReservedIpAddress(hostname) : hostname === 'localhost' || hostname === '::1';
  const hasCredentials = Boolean(parsed.username || parsed.password || input.includes('@'));
  return { valid: true, isReservedIp, hasCredentials };
}

export async function analyzeUrlForensics(input: string, isDemoFixture = false): Promise<PhishTraceCase> {
  if (!input || typeof input !== 'string') {
    throw new Error('URL input is required.');
  }

  if (input.length > MAX_URL_LENGTH) {
    throw new Error(`URL length exceeds maximum bound of ${MAX_URL_LENGTH} characters.`);
  }

  const { normalized, wasDefanged } = normalizeDefangedUrl(input);

  // Enforce protocol check: must start with http:// or https:// (or add http:// if bare domain)
  let urlToParse = normalized;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i.test(urlToParse)) {
    urlToParse = 'https://' + urlToParse;
  }

  let parsed: URL;
  try {
    parsed = new URL(urlToParse);
  } catch {
    throw new Error('Malformed URL syntax. Could not parse URL structure.');
  }

  // Reject non-web protocols
  const proto = parsed.protocol.toLowerCase();
  if (proto !== 'http:' && proto !== 'https:') {
    throw new Error(`Prohibited protocol '${proto}'. Only HTTP and HTTPS schemes are supported.`);
  }

  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  const isIpv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname);
  const isIpv6 = /^\[[0-9a-f:]+\]$/i.test(hostname) || (hostname.includes(':') && !hostname.includes('.'));
  const isReservedIp = isIpv4 ? isReservedIpAddress(hostname) : hostname === 'localhost' || hostname === '::1';
  const hasCredentials = Boolean(parsed.username || parsed.password || input.includes('@'));
  const hasPunycode = hostname.includes('xn--') || /[^\x00-\x7F]/.test(hostname);

  const { apexDomain, subdomains, tld } = parseDomainHierarchy(hostname);

  const searchParams: Array<{ key: string; value: string }> = [];
  parsed.searchParams.forEach((val, key) => {
    searchParams.push({ key, value: val });
  });

  const pathAndQuery = parsed.pathname + parsed.search;
  const entropy = calculateShannonEntropy(pathAndQuery);

  const components: ParsedUrlComponents = {
    raw: input,
    sanitized: parsed.toString(),
    protocol: proto,
    hostname,
    port: parsed.port || null,
    pathname: parsed.pathname,
    search: parsed.search,
    searchParams,
    hash: parsed.hash,
    apexDomain,
    subdomains,
    tld,
    isIpv4,
    isIpv6,
    isReservedIp,
    isDemoFixture,
    hasCredentials,
    hasPunycode,
    entropy,
  };

  const signals: PhishTraceSignal[] = [];

  // --- HEURISTIC SIGNALS EVALUATION ---

  // 1. Defanged notation
  if (wasDefanged) {
    signals.push({
      id: 'SIGNAL_DEFANGED_NOTATION',
      name: 'Defanged Security Notation',
      severity: 'info',
      points: 1,
      category: 'obfuscation',
      explanation: 'URL contains defanged brackets ([.]) or hxxp notation typical of security triage samples.',
      evidence: input,
    });
  }

  // 2. Embedded credentials / userinfo
  if (hasCredentials) {
    signals.push({
      id: 'SIGNAL_EMBEDDED_CREDENTIALS',
      name: 'Embedded Credentials / Host Masking',
      severity: 'critical',
      points: 4,
      category: 'obfuscation',
      explanation: 'The authority section contains an "@" symbol or userinfo credentials. Attackers use this to trick users into mistaking the fake brand for the true destination host.',
      evidence: parsed.username ? `${parsed.username}@${hostname}` : `@${hostname}`,
    });
  }

  // 3. Raw IP address host
  if (isIpv4 || isIpv6) {
    signals.push({
      id: 'SIGNAL_RAW_IP_HOST',
      name: 'Direct Numeric IP Address',
      severity: 'high',
      points: 3,
      category: 'host',
      explanation: 'The link connects to a raw numeric IP address rather than a registered domain name, bypassing DNS reputation controls.',
      evidence: hostname,
    });
  }

  // 4. Reserved / Localhost IP
  if (isReservedIp && !isDemoFixture) {
    signals.push({
      id: 'SIGNAL_RESERVED_LOCAL_IP',
      name: 'Reserved / Private Network Host',
      severity: 'critical',
      points: 4,
      category: 'host',
      explanation: 'Hostname resolves to an internal loopback, private RFC-1918, or cloud metadata address (169.254.169.254).',
      evidence: hostname,
    });
  }

  // 5. High-abuse TLD
  if (HIGH_ABUSE_TLDS.has(tld)) {
    signals.push({
      id: 'SIGNAL_HIGH_ABUSE_TLD',
      name: `High-Abuse Top-Level Domain (.${tld})`,
      severity: 'medium',
      points: 2,
      category: 'host',
      explanation: `The .${tld} top-level domain has historically elevated abuse rates for short-lived phishing campaigns.`,
      evidence: `.${tld}`,
    });
  }

  // 6. Deep subdomain nesting
  if (subdomains.length >= 3) {
    signals.push({
      id: 'SIGNAL_DEEP_SUBDOMAINS',
      name: 'Excessive Subdomain Nesting',
      severity: 'medium',
      points: 2,
      category: 'structure',
      explanation: `Hostname has ${subdomains.length} subdomain tiers (${subdomains.join('.')}). Attackers use deep nesting to push the real apex domain off mobile screens.`,
      evidence: subdomains.join('.'),
    });
  }

  // 7. Brand impersonation in subdomains
  for (const brand of TARGET_BRAND_KEYWORDS) {
    // If brand is present in subdomains or path, but NOT the apex domain
    const brandInSub = subdomains.some((s) => s.includes(brand));
    const brandInApex = apexDomain.includes(brand);
    if (brandInSub && !brandInApex) {
      signals.push({
        id: `SIGNAL_BRAND_IMPERSONATION_${brand.toUpperCase()}`,
        name: `Brand Impersonation (${brand.toUpperCase()})`,
        severity: 'critical',
        points: 4,
        category: 'keywords',
        explanation: `The brand name '${brand}' is embedded in subdomains, while the true apex domain is '${apexDomain}'.`,
        evidence: `Subdomains: ${subdomains.join('.')} | Apex: ${apexDomain}`,
      });
      break;
    }
  }

  // 8. Sensitive credential path keywords
  const matchedKeywords = SENSITIVE_KEYWORDS.filter((kw) => pathAndQuery.toLowerCase().includes(kw));
  if (matchedKeywords.length > 0) {
    signals.push({
      id: 'SIGNAL_CREDENTIAL_KEYWORDS',
      name: 'Credential Harvesting Path Keywords',
      severity: 'high',
      points: 2,
      category: 'keywords',
      explanation: `Path and parameters contain sensitive authentication keywords (${matchedKeywords.slice(0, 3).join(', ')}).`,
      evidence: matchedKeywords.join(', '),
    });
  }

  // 9. URL shortener service
  const isShortener = KNOWN_SHORTENERS.has(hostname) || Array.from(KNOWN_SHORTENERS).some((s) => hostname.endsWith('.' + s));
  if (isShortener) {
    signals.push({
      id: 'SIGNAL_URL_SHORTENER',
      name: 'URL Shortener Gateway',
      severity: 'medium',
      points: 2,
      category: 'structure',
      explanation: 'Destination is masked behind a public link shortening gateway. The ultimate destination cannot be determined without network resolution (prohibited by policy).',
      evidence: hostname,
    });
  }

  // 10. Punycode / IDN Homographs
  if (hasPunycode) {
    signals.push({
      id: 'SIGNAL_PUNYCODE_HOMOGRAPH',
      name: 'Punycode / Homograph Character Encoding',
      severity: 'high',
      points: 3,
      category: 'obfuscation',
      explanation: 'Hostname uses Internationalized Domain Name (Punycode "xn--") or non-ASCII characters that can visually spoof legitimate brand domains.',
      evidence: hostname,
    });
  }

  // 11. Non-standard port
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    signals.push({
      id: 'SIGNAL_NON_STANDARD_PORT',
      name: `Non-Standard Web Port (:${parsed.port})`,
      severity: 'medium',
      points: 2,
      category: 'protocol',
      explanation: `Web connection requests an unusual port (:${parsed.port}) rather than standard HTTPS (:443) or HTTP (:80).`,
      evidence: `:${parsed.port}`,
    });
  }

  // 12. High-entropy path/parameter string
  if (entropy > 4.2 && pathAndQuery.length > 35) {
    signals.push({
      id: 'SIGNAL_HIGH_ENTROPY_PARAM',
      name: 'High Entropy Token / Identifier',
      severity: 'low',
      points: 1,
      category: 'structure',
      explanation: `Path/query contains high-entropy randomized strings (Shannon entropy: ${entropy}), characteristic of targeted phishing tokens or disposable payloads.`,
      evidence: `Entropy: ${entropy} (len: ${pathAndQuery.length})`,
    });
  }

  // Calculate composite score
  const score = signals.reduce((sum, s) => sum + s.points, 0);
  const riskBand: 'Low' | 'Suspicious' | 'High' = score >= 7 ? 'High' : score >= 3 ? 'Suspicious' : 'Low';

  let verdictText = 'No elevated heuristic signals identified.';
  if (riskBand === 'High') {
    verdictText = 'Multiple high-confidence phishing indicators detected.';
  } else if (riskBand === 'Suspicious') {
    verdictText = 'Suspicious structural indicators warrant manual verification.';
  }

  // Synthetic Redirect Graph modeling (clearly labeled as synthetic simulations)
  const syntheticRedirects: SyntheticRedirectHop[] = [];
  syntheticRedirects.push({
    hop: 1,
    type: 'initial',
    url: parsed.toString(),
    domain: hostname,
    role: isShortener ? 'Shortener Ingress' : 'Initial Scanned URI',
    note: isShortener ? 'URL Shortener Gateway (Synthetic hop)' : 'Analyzed entrypoint',
  });

  if (isShortener) {
    syntheticRedirects.push({
      hop: 2,
      type: 'synthetic_tracker',
      url: `https://synthetic-analytics-gateway.local/track?id=${Math.abs(hostname.length * 1337)}`,
      domain: 'synthetic-analytics-gateway.local',
      role: 'Synthetic Telemetry Intermediary',
      note: 'SYNTHETIC SIMULATION — Actual intermediate redirect unknown (no-network policy).',
    });
    syntheticRedirects.push({
      hop: 3,
      type: 'synthetic_target',
      url: `https://${apexDomain}/synthetic-destination-payload`,
      domain: apexDomain,
      role: 'Hypothetical Landing Target',
      note: 'SYNTHETIC MODEL ONLY — Real destination requires authorized sandbox crawl.',
    });
  }

  const domainHashPrefix = await computeDomainHashPrefix(hostname);

  const disclaimers = [
    'Static text forensics only: PhishTrace never connects to, fetches, or crawls remote websites.',
    'A low score does not guarantee safety. New or evasive campaigns may not trigger heuristic rules.',
    'A rule score is an indicator count, not a statistical probability of malice.',
    'All redirect graph hops are synthetic pedagogical models and do not represent observed network traffic.',
    'Domain hash prefixes (16 hex chars) are pseudonymous rather than anonymous.',
  ];

  // Cryptographic Case Integrity
  const caseId = `CASE-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;
  const analyzedAt = new Date().toISOString();

  const casePayloadForHash = JSON.stringify({
    caseId,
    analyzedAt,
    inputUrl: input,
    sanitizedUrl: parsed.toString(),
    score,
    riskBand,
    signalsCount: signals.length,
    domainHashPrefix,
  });

  const encoder = new TextEncoder();
  const digestBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(casePayloadForHash));
  const caseIntegritySha256 = Array.from(new Uint8Array(digestBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  return {
    caseId,
    analyzedAt,
    engineVersion: 'PhishTrace Forensics v1.0',
    inputUrl: input,
    sanitizedUrl: parsed.toString(),
    components,
    score,
    riskBand,
    verdictText,
    signals,
    syntheticRedirects,
    domainHashPrefix,
    disclaimers,
    caseIntegritySha256,
  };
}

/**
 * Verifies the cryptographic integrity of an exported PhishTrace case.
 */
export async function verifyCaseIntegrity(phishCase: PhishTraceCase): Promise<boolean> {
  try {
    const casePayloadForHash = JSON.stringify({
      caseId: phishCase.caseId,
      analyzedAt: phishCase.analyzedAt,
      inputUrl: phishCase.inputUrl,
      sanitizedUrl: phishCase.sanitizedUrl,
      score: phishCase.score,
      riskBand: phishCase.riskBand,
      signalsCount: phishCase.signals.length,
      domainHashPrefix: phishCase.domainHashPrefix,
    });

    const encoder = new TextEncoder();
    const digestBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(casePayloadForHash));
    const computedHash = Array.from(new Uint8Array(digestBuffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    return computedHash.toLowerCase() === phishCase.caseIntegritySha256.toLowerCase();
  } catch {
    return false;
  }
}
