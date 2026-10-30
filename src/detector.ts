import { AnalysisResult, DatasetReport, SignalItem } from './types';

export const TITLES: Record<string, string> = {
  urgent_language: "Urgent or threatening language",
  credential_request: "Sensitive information mentioned",
  payment_request: "Payment-related language",
  authentication_failure: "Authentication failure reported",
  link_text_mismatch: "Displayed link differs from destination",
  ip_address_link: "Link uses a raw IP address",
  shortened_link: "Destination hidden by a URL shortener",
  unusual_domain_encoding: "Unusual domain encoding",
  unencrypted_link: "Unencrypted HTTP link",
  brand_sender_mismatch: "Brand and sender do not match",
  risky_attachment: "Potentially risky attachment",
};

const patterns = {
  urgency: /\b(?:urgent|immediately|action required|final notice|within\s+\d+\s+hours?|account (?:will be )?(?:suspended|closed|locked)|unusual (?:sign[- ]in|activity)|limited time|avoid (?:interruption|suspension))\b/i,
  credentials: /\b(?:password|login credentials|sign in to|verify your account|confirm your identity|one[- ]time (?:password|code)|security code|social security number|bank details|credit card details)\b/i,
  payment: /\b(?:wire transfer|gift card|payment overdue|invoice attached|update (?:your )?payment|refund pending|payment failed)\b/i,
  auth: /\b(?:spf|dkim|dmarc)=(?:fail|softfail|permerror)\b/i,
  url: /\b(?:https?:\/\/|www\.)[^\s<>"']+/gi,
};

const shorteners = [
  "bit.ly", "buff.ly", "cutt.ly", "is.gd", "ow.ly", "rb.gy", "rebrand.ly", "shorturl.at", "t.co", "tinyurl.com", "urlz.fr"
];

const brands: Record<string, string[]> = {
  amazon: ["amazon.com", "amazon.co.uk", "amazon.in"],
  apple: ["apple.com", "icloud.com"],
  google: ["google.com", "googlemail.com"],
  microsoft: ["microsoft.com", "microsoftonline.com"],
  paypal: ["paypal.com"],
  netflix: ["netflix.com"],
};

const risky = [
  ".ade", ".adp", ".app", ".bat", ".cmd", ".com", ".cpl", ".dll", ".exe", ".hta", ".iso", ".js", ".jse", ".lnk", ".msi", ".ps1", ".scr", ".vbe", ".vbs", ".wsf"
];

export function splitHeaders(raw: string): { headers: Record<string, string>; body: string } {
  const split = raw.search(/\r?\n\r?\n/);
  const head = split < 0 ? "" : raw.slice(0, split);
  const body = split < 0 ? raw : raw.slice(split).replace(/^\r?\n\r?\n/, "");
  const headers: Record<string, string> = {};
  let current = "";

  head.replace(/\r\n/g, "\n").split("\n").forEach((line) => {
    if (/^\s/.test(line) && current) {
      headers[current] += " " + line.trim();
    } else {
      const match = line.match(/^([^:]+):\s*(.*)$/);
      if (match) {
        current = match[1].toLowerCase();
        headers[current] = match[2];
      }
    }
  });

  return { headers, body };
}

export function decodeBody(body: string, encoding?: string): string {
  if (/quoted-printable/i.test(encoding || "")) {
    return body
      .replace(/=\r?\n/g, "")
      .replace(/=([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  }
  if (/base64/i.test(encoding || "")) {
    try {
      const binary = atob(body.replace(/\s/g, ""));
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    } catch {
      return body;
    }
  }
  return body;
}

export interface ParsedMail {
  from: string;
  subject: string;
  auth: string;
  body: string;
  anchors: Array<{ href: string; text: string }>;
  attachments: string[];
}

export function parseMail(raw: string): ParsedMail {
  const initial = splitHeaders(raw);
  const headers = initial.headers;
  const boundaryMatch = (headers["content-type"] || "").match(/boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))/i);
  const boundary = boundaryMatch ? (boundaryMatch[1] || boundaryMatch[2]) : null;
  const chunks = boundary ? initial.body.split("--" + boundary) : [initial.body];
  const plain: string[] = [];
  const html: string[] = [];
  const anchors: Array<{ href: string; text: string }> = [];
  const attachments: string[] = [];

  chunks.forEach((chunk) => {
    const part = boundary ? splitHeaders(chunk.replace(/^\r?\n/, "")) : { headers, body: chunk };
    const type = (part.headers["content-type"] || "text/plain").toLowerCase();
    const disposition = part.headers["content-disposition"] || "";
    const filenameMatch = (disposition + " " + type).match(/filename\*?=(?:utf-8''|")?([^";\r\n]+)/i);

    if (filenameMatch) {
      attachments.push(filenameMatch[1].replace(/["']/g, "").trim());
    }
    if (/attachment/i.test(disposition)) return;

    const decoded = decodeBody(part.body, part.headers["content-transfer-encoding"]);
    if (type.indexOf("text/html") >= 0) {
      html.push(decoded);
    } else if (type.indexOf("text/plain") >= 0 || !boundary) {
      plain.push(decoded);
    }
  });

  const visible: string[] = [];
  html.forEach((fragment) => {
    try {
      const doc = new DOMParser().parseFromString(fragment, "text/html");
      visible.push(doc.body ? doc.body.textContent || "" : "");
      doc.querySelectorAll("a").forEach((a) => {
        anchors.push({
          href: a.getAttribute("href") || "",
          text: a.textContent || "",
        });
      });
    } catch {
      // Fallback
    }
  });

  return {
    from: headers.from || "",
    subject: headers.subject || "",
    auth: [headers["authentication-results"] || "", headers["arc-authentication-results"] || ""].join(" "),
    body: plain.concat(visible).join("\n").trim() || initial.body,
    anchors,
    attachments: Array.from(new Set(attachments)),
  };
}

export function cleanUrl(value: string): string {
  return value.replace(/[.,;:!?)\]}]+$/g, "");
}

export function hostForUrl(value: string): string | null {
  let candidate = cleanUrl((value || "").trim());
  if (!candidate || /\s/.test(candidate.split("/")[0]) || candidate.charAt(0) === "/") return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate)) {
    if (candidate.split("/")[0].indexOf(".") < 0) return null;
    candidate = "http://" + candidate;
  }
  try {
    return new URL(candidate).hostname.replace(/\.$/, "").toLowerCase() || null;
  } catch {
    return null;
  }
}

export function matches(host: string, domain: string): boolean {
  return host === domain || host.slice(-(domain.length + 1)) === "." + domain;
}

export function shownDomain(label: string): string | null {
  const found = (label || "").trim().match(patterns.url);
  const candidate = found ? found[0] : (label || "").trim();
  return !candidate || /\s/.test(candidate) || candidate.indexOf(".") < 0 ? null : hostForUrl(candidate);
}

export function senderInfo(sender: string): { name: string; domain: string } {
  const bracket = sender.match(/<([^>]+)>/);
  const address = bracket ? bracket[1] : ((sender.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i) || [])[0] || "");
  return {
    name: bracket ? sender.slice(0, sender.indexOf("<")).replace(/^["']|["']$/g, "").trim() : "",
    domain: address.indexOf("@") >= 0 ? address.split("@").pop()!.toLowerCase().replace(/\.$/, "") : "",
  };
}

export function analyzeEmail(raw: string, overrideSender?: string | null): AnalysisResult {
  const mail = parseMail(raw);
  const sender = (overrideSender && overrideSender.trim()) ? overrideSender.trim() : mail.from;
  const from = senderInfo(sender);
  const detectorText = mail.subject + "\n" + mail.body;
  const signals: SignalItem[] = [];

  function add(code: string, points: number, description: string) {
    if (!signals.some((s) => s.code === code)) {
      signals.push({ code, points, description });
    }
  }

  if (patterns.urgency.test(detectorText)) {
    add("urgent_language", 2, "Uses pressure or a threatening deadline to prompt a quick response.");
  }
  if (patterns.credentials.test(detectorText)) {
    add("credential_request", 2, "Mentions passwords, sign-in details, or sensitive identity information.");
  }
  if (patterns.payment.test(detectorText)) {
    add("payment_request", 2, "Mentions a payment, transfer, refund, or payment update.");
  }
  if (patterns.auth.test(mail.auth)) {
    add("authentication_failure", 3, "An authentication-results header reports SPF, DKIM, or DMARC failure.");
  }

  const allText = sender + "\n" + detectorText;
  let urls = (allText.match(patterns.url) || []).map(cleanUrl);
  urls = urls.concat(
    mail.anchors
      .map((a) => a.href)
      .filter((u) => /^https?:\/\//i.test(u) || /^www\./i.test(u))
  );
  urls = Array.from(new Set(urls.filter((u) => !!hostForUrl(u))));
  const hosts = Array.from(new Set(urls.map(hostForUrl).filter((h): h is string => Boolean(h))));

  for (let a = 0; a < mail.anchors.length; a++) {
    const target = hostForUrl(mail.anchors[a].href);
    const displayed = shownDomain(mail.anchors[a].text);
    if (target && displayed && !matches(target, displayed) && !matches(displayed, target)) {
      add("link_text_mismatch", 3, "A link's displayed domain differs from its destination domain.");
      break;
    }
  }

  if (hosts.some((h) => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h) || /^\[[0-9a-f:]+\]$/i.test(h))) {
    add("ip_address_link", 3, "A link uses a raw IP address instead of a domain name.");
  }
  if (hosts.some((h) => shorteners.some((d) => matches(h, d)))) {
    add("shortened_link", 2, "A URL shortener hides the link's final destination.");
  }
  if (hosts.some((h) => h.split(".").some((p) => p.indexOf("xn--") === 0) || /[^\x00-\x7F]/.test(h))) {
    add("unusual_domain_encoding", 2, "A link uses an internationalized or punycode domain that merits review.");
  }
  if (urls.some((u) => /^http:\/\//i.test(/^www\./i.test(u) ? "http://" + u : u))) {
    add("unencrypted_link", 1, "At least one link uses unencrypted HTTP.");
  }

  if (from.name && from.domain) {
    Object.keys(brands).some((brand) => {
      if (from.name.toLowerCase().indexOf(brand) >= 0 && !brands[brand].some((d) => matches(from.domain, d))) {
        add(
          "brand_sender_mismatch",
          2,
          "The sender display name mentions " +
            brand.charAt(0).toUpperCase() +
            brand.slice(1) +
            ", but the sender domain is " +
            from.domain +
            "."
        );
        return true;
      }
      return false;
    });
  }

  if (mail.attachments.some((f) => risky.some((ext) => f.toLowerCase().endsWith(ext)))) {
    add("risky_attachment", 3, "The message includes an attachment type that can run code or scripts.");
  }

  const score = signals.reduce((sum, s) => sum + s.points, 0);

  return {
    risk: score >= 7 ? "High" : score >= 3 ? "Suspicious" : "Low",
    score,
    sender,
    signals,
    linkDomains: hosts,
    attachments: mail.attachments,
  };
}

export function parseCSV(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;

  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const next = text[i + 1];

    if (quoted) {
      if (c === '"' && next === '"') {
        field += '"';
        i++;
      } else if (c === '"') {
        quoted = false;
      } else {
        field += c;
      }
    } else if (c === '"' && field.length === 0) {
      quoted = true;
    } else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n") {
      row.push(field.replace(/\r$/, ""));
      rows.push(row);
      row = [];
      field = "";
    } else {
      field += c;
    }
  }

  if (field.length || row.length) {
    row.push(field.replace(/\r$/, ""));
    rows.push(row);
  }

  return rows.filter((r) => !(r.length === 1 && r[0] === ""));
}

export const TEXT_COLUMNS = ["email", "message", "body", "text", "content", "raw_email", "mail"];
export const LABEL_COLUMNS = ["label", "class", "target", "category", "is_phishing"];

export function normalizeLabel(value: string): boolean | null {
  const v = String(value || "").trim().toLowerCase();
  if (["1", "phishing", "phish", "malicious", "fraudulent", "unsafe"].indexOf(v) >= 0) return true;
  if (["0", "legitimate", "legit", "ham", "benign", "safe"].indexOf(v) >= 0) return false;
  return null;
}

export function analyzeDataset(
  csvRaw: string,
  requestedText: string,
  requestedLabel: string,
  threshold: number
): { report?: DatasetReport; error?: string } {
  const rows = parseCSV(csvRaw);
  if (rows.length < 2) {
    return { error: "The CSV needs a header row and at least one data row." };
  }

  const headers = rows[0].map((h) => h.replace(/^\uFEFF/, "").trim());
  const byLower: Record<string, string> = {};
  headers.forEach((h) => {
    byLower[h.toLowerCase()] = h;
  });

  const reqText = requestedText.trim();
  const reqLabel = requestedLabel.trim();
  const textCol = reqText ? byLower[reqText.toLowerCase()] : TEXT_COLUMNS.map((x) => byLower[x]).find(Boolean);
  const labelCol = reqLabel ? byLower[reqLabel.toLowerCase()] : LABEL_COLUMNS.map((x) => byLower[x]).find(Boolean);

  if (!textCol) {
    return {
      error: reqText ? "Email text column not found. Check its name." : "Couldn't detect the email text column. Enter its name above.",
    };
  }
  if (reqLabel && !labelCol) {
    return { error: "Label column not found. Check its name." };
  }

  const textIndex = headers.indexOf(textCol);
  const labelIndex = labelCol ? headers.indexOf(labelCol) : -1;

  const risks = { High: 0, Suspicious: 0, Low: 0 };
  const counts: Record<string, number> = {};
  let scanned = 0;
  let blank = 0;
  let skipped = 0;
  let tp = 0;
  let fp = 0;
  let fn = 0;
  let tn = 0;
  let evaluated = 0;
  let total = 0;

  for (let i = 1; i < rows.length; i++) {
    const raw = (rows[i][textIndex] || "").trim();
    if (!raw) {
      blank++;
      continue;
    }
    const result = analyzeEmail(raw, null);
    scanned++;
    total += result.score;
    risks[result.risk]++;
    result.signals.forEach((signal) => {
      counts[signal.code] = (counts[signal.code] || 0) + 1;
    });

    if (labelIndex >= 0) {
      const actual = normalizeLabel(rows[i][labelIndex]);
      if (actual === null) {
        skipped++;
      } else {
        evaluated++;
        const predicted = result.score >= threshold;
        if (actual && predicted) tp++;
        else if (!actual && predicted) fp++;
        else if (actual && !predicted) fn++;
        else tn++;
      }
    }
  }

  if (!scanned) {
    return { error: "No non-empty email rows were found in that column." };
  }

  const indicatorList = Object.keys(counts)
    .map((code) => ({ code, count: counts[code] }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);

  const report: DatasetReport = {
    scanned,
    blank,
    skipped,
    risks,
    average: total / scanned,
    indicators: indicatorList,
    threshold,
  };

  if (labelIndex >= 0) {
    const precision = tp + fp ? tp / (tp + fp) : 0;
    const recall = tp + fn ? tp / (tp + fn) : 0;
    report.evaluation = {
      evaluated,
      tp,
      fp,
      fn,
      tn,
      accuracy: evaluated ? ((tp + tn) / evaluated).toFixed(3) : "—",
      precision: evaluated ? precision.toFixed(3) : "—",
      recall: evaluated ? recall.toFixed(3) : "—",
      f1: evaluated ? (precision + recall ? ((2 * precision * recall) / (precision + recall)).toFixed(3) : "0.000") : "—",
    };
  }

  return { report };
}
