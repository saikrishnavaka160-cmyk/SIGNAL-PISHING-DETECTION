import { analyzeEmail } from '../detector';
import { AnalysisResult } from '../types';

export interface GmailHeader {
  name: string;
  value: string;
}

export interface GmailPart {
  partId?: string;
  mimeType: string;
  filename?: string;
  headers?: GmailHeader[];
  body?: {
    size: number;
    data?: string;
    attachmentId?: string;
  };
  parts?: GmailPart[];
}

export interface GmailRawMessage {
  id: string;
  threadId: string;
  labelIds?: string[];
  snippet?: string;
  internalDate?: string;
  payload?: {
    partId?: string;
    mimeType: string;
    filename?: string;
    headers?: GmailHeader[];
    body?: {
      size: number;
      data?: string;
    };
    parts?: GmailPart[];
  };
}

export interface ParsedGmailEmail {
  id: string;
  threadId: string;
  snippet: string;
  date: string;
  from: string;
  to: string;
  subject: string;
  bodyText: string;
  bodyHtml: string;
  labelIds: string[];
  spfStatus: string;
  dkimStatus: string;
  dmarcStatus: string;
  attachments: Array<{ filename: string; mimeType: string; size: number }>;
  extractedUrls: string[];
  analysis: AnalysisResult;
}

function base64UrlDecode(input: string): string {
  try {
    let clean = input.replace(/-/g, '+').replace(/_/g, '/');
    while (clean.length % 4 !== 0) {
      clean += '=';
    }
    const binary = atob(clean);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  } catch {
    return '';
  }
}

function extractParts(part: GmailPart, textAcc: string[], htmlAcc: string[], attachmentsAcc: Array<{ filename: string; mimeType: string; size: number }>) {
  if (part.filename && part.filename.length > 0) {
    attachmentsAcc.push({
      filename: part.filename,
      mimeType: part.mimeType,
      size: part.body?.size || 0,
    });
  }

  if (part.mimeType === 'text/plain' && part.body?.data) {
    textAcc.push(base64UrlDecode(part.body.data));
  } else if (part.mimeType === 'text/html' && part.body?.data) {
    htmlAcc.push(base64UrlDecode(part.body.data));
  }

  if (part.parts && Array.isArray(part.parts)) {
    part.parts.forEach((subPart) => extractParts(subPart, textAcc, htmlAcc, attachmentsAcc));
  }
}

export function parseGmailMessage(raw: GmailRawMessage): ParsedGmailEmail {
  const headers = raw.payload?.headers || [];
  const getHeader = (name: string): string => {
    const found = headers.find((h) => h.name.toLowerCase() === name.toLowerCase());
    return found ? found.value : '';
  };

  const from = getHeader('From');
  const to = getHeader('To');
  const subject = getHeader('Subject') || '(No Subject)';
  const date = getHeader('Date') || (raw.internalDate ? new Date(parseInt(raw.internalDate, 10)).toLocaleString() : '');
  const authResults = [getHeader('Authentication-Results'), getHeader('ARC-Authentication-Results'), getHeader('Received-SPF')].join(' ');

  let spfStatus = 'neutral';
  if (/spf=pass/i.test(authResults)) spfStatus = 'pass';
  else if (/spf=(?:fail|softfail)/i.test(authResults)) spfStatus = 'fail';

  let dkimStatus = 'neutral';
  if (/dkim=pass/i.test(authResults)) dkimStatus = 'pass';
  else if (/dkim=(?:fail|neutral|none)/i.test(authResults)) dkimStatus = 'fail';

  let dmarcStatus = 'neutral';
  if (/dmarc=pass/i.test(authResults)) dmarcStatus = 'pass';
  else if (/dmarc=(?:fail)/i.test(authResults)) dmarcStatus = 'fail';

  const textAcc: string[] = [];
  const htmlAcc: string[] = [];
  const attachmentsAcc: Array<{ filename: string; mimeType: string; size: number }> = [];

  if (raw.payload) {
    if (raw.payload.body?.data) {
      if (raw.payload.mimeType === 'text/html') {
        htmlAcc.push(base64UrlDecode(raw.payload.body.data));
      } else {
        textAcc.push(base64UrlDecode(raw.payload.body.data));
      }
    }
    if (raw.payload.parts) {
      raw.payload.parts.forEach((p) => extractParts(p, textAcc, htmlAcc, attachmentsAcc));
    }
  }

  const plainText = textAcc.join('\n').trim();
  const htmlContent = htmlAcc.join('\n').trim();

  // Extract URLs safely using regex without ever executing or fetching them
  const urlRegex = /\b(?:https?:\/\/)[^\s<>"']+/gi;
  const foundUrls = new Set<string>();

  const matches1 = (plainText + ' ' + subject).match(urlRegex) || [];
  matches1.forEach((u) => foundUrls.add(u.replace(/[.,;:!?)\]}]+$/g, '')));

  // Extract href from HTML
  if (htmlContent && typeof DOMParser !== 'undefined') {
    try {
      const doc = new DOMParser().parseFromString(htmlContent, 'text/html');
      doc.querySelectorAll('a').forEach((a) => {
        const href = a.getAttribute('href');
        if (href && /^https?:\/\//i.test(href)) {
          foundUrls.add(href.replace(/[.,;:!?)\]}]+$/g, ''));
        }
      });
    } catch {
      // Fallback
    }
  }

  // Format into standard RFC 822 text for detector.ts analysis
  const syntheticRfc822 = [
    `From: ${from}`,
    `Subject: ${subject}`,
    `Date: ${date}`,
    `Authentication-Results: ${authResults}`,
    '',
    plainText || raw.snippet || '(empty message content)',
  ].join('\n');

  const analysis = analyzeEmail(syntheticRfc822, from);

  return {
    id: raw.id,
    threadId: raw.threadId,
    snippet: raw.snippet || '',
    date,
    from,
    to,
    subject,
    bodyText: plainText || raw.snippet || '',
    bodyHtml: htmlContent,
    labelIds: raw.labelIds || [],
    spfStatus,
    dkimStatus,
    dmarcStatus,
    attachments: attachmentsAcc,
    extractedUrls: Array.from(foundUrls),
    analysis,
  };
}

export async function fetchInboxMessages(
  accessToken: string,
  options: { maxResults?: number; query?: string } = {}
): Promise<ParsedGmailEmail[]> {
  const maxResults = options.maxResults || 15;
  const q = options.query ? encodeURIComponent(options.query) : 'in:inbox';
  const url = `https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=${maxResults}&q=${q}`;

  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
  });

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Gmail API request failed (${res.status}): ${errorText}`);
  }

  const listData = await res.json();
  const messagesList: Array<{ id: string; threadId: string }> = listData.messages || [];

  if (messagesList.length === 0) {
    return [];
  }

  // Batch-fetch message details (up to 15 concurrent)
  const fetchPromises = messagesList.slice(0, maxResults).map(async (item) => {
    try {
      const detailRes = await fetch(
        `https://gmail.googleapis.com/gmail/v1/users/me/messages/${item.id}?format=full`,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: 'application/json',
          },
        }
      );
      if (!detailRes.ok) return null;
      const rawMsg: GmailRawMessage = await detailRes.json();
      return parseGmailMessage(rawMsg);
    } catch (e) {
      console.error(`Failed to fetch message ${item.id}`, e);
      return null;
    }
  });

  const parsed = await Promise.all(fetchPromises);
  return parsed.filter((m): m is ParsedGmailEmail => m !== null);
}

export async function applyPhishingLabel(accessToken: string, messageId: string): Promise<void> {
  // 1. Get or create 'Signal-Phishing-Suspect' label
  const labelsRes = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/labels', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  let labelId: string | null = null;
  if (labelsRes.ok) {
    const labelsData = await labelsRes.json();
    const existing = (labelsData.labels || []).find(
      (l: { name: string; id: string }) => l.name === 'Signal-Suspicious'
    );
    if (existing) {
      labelId = existing.id;
    }
  }

  if (!labelId) {
    const createRes = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/labels', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: 'Signal-Suspicious',
        labelListVisibility: 'labelShow',
        messageListVisibility: 'show',
      }),
    });
    if (createRes.ok) {
      const created = await createRes.json();
      labelId = created.id;
    }
  }

  // Modify message
  if (labelId) {
    await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}/modify`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        addLabelIds: [labelId],
      }),
    });
  }
}

export async function archiveGmailMessage(accessToken: string, messageId: string): Promise<void> {
  await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}/modify`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      removeLabelIds: ['INBOX'],
    }),
  });
}

export async function trashGmailMessage(accessToken: string, messageId: string): Promise<void> {
  await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}/trash`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });
}
