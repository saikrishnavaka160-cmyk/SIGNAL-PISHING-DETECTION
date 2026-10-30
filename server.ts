import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import { checkDomainHashPrefixes, getAllMaliciousDomains, addMaliciousDomain } from './src/db/domains.ts';
import { requireAuth, AuthRequest } from './src/middleware/auth.ts';
import { getOrCreateUser } from './src/db/users.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

app.use(cors());
app.use(express.json());

// Helper to compute first 8 bytes (16 hex chars) of SHA-256 hash of normalized domain
function getDomainHashPrefix(domain: string): string {
  const normalized = domain.toLowerCase().trim().replace(/^www\./, '').replace(/\.$/, '');
  return crypto.createHash('sha256').update(normalized).digest('hex').slice(0, 16);
}

// Extract hostname safely from raw URL string
function extractDomain(inputUrl: string): string | null {
  try {
    let target = inputUrl.trim();
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) {
      target = 'http://' + target;
    }
    const parsed = new URL(target);
    return parsed.hostname.toLowerCase().replace(/\.$/, '');
  } catch {
    return null;
  }
}

// 1. Check domain hash prefixes against Cloud SQL blocklist
// Privacy enforcement: Raw URLs are strictly rejected. Only validated 16-hex hash prefixes are accepted.
app.post('/api/check-urls', async (req, res) => {
  try {
    const { urls, prefixes } = req.body;

    // Safety rule: Never accept raw URLs to prevent logging or tracking user destinations
    if (urls && Array.isArray(urls) && urls.length > 0) {
      return res.status(400).json({
        error: 'Raw URLs are rejected by privacy policy. Submit only validated 16-hex SHA-256 hash prefixes (pseudonymous).',
      });
    }

    if (!Array.isArray(prefixes) || prefixes.length === 0) {
      return res.json({ matches: [], checkedCount: 0 });
    }

    // Validate that each prefix is exactly 16 hexadecimal characters (8 bytes of SHA-256)
    const validPrefixes = prefixes
      .map((p: string) => String(p).toLowerCase().trim())
      .filter((p: string) => /^[0-9a-f]{16}$/.test(p));

    if (validPrefixes.length === 0) {
      return res.status(400).json({
        error: 'Invalid hash prefixes. Each prefix must be exactly 16 hexadecimal characters.',
      });
    }

    const uniquePrefixes = Array.from(new Set(validPrefixes));
    const dbMatches = await checkDomainHashPrefixes(uniquePrefixes);

    const matches = dbMatches.map((row) => ({
      hashPrefix: row.domainHashPrefix,
      threatType: row.threatType || 'phishing',
      createdAt: row.createdAt,
    }));

    return res.json({
      matches,
      checkedCount: uniquePrefixes.length,
      isMalicious: matches.length > 0,
      privacyNotice: '16-hex prefixes are pseudonymous rather than anonymous.',
    });
  } catch (error: any) {
    console.error('Error checking hash prefixes:', error);
    return res.status(500).json({ error: error.message || 'Lookup failed' });
  }
});

// 2. URL Resolution Endpoint: REMOVED / DISABLED BY SAFETY POLICY
// Never automatically visit, resolve, preview, crawl, or follow a submitted URL.
app.post('/api/resolve-url', (_req, res) => {
  return res.status(410).json({
    disabled: true,
    error: 'Live network URL resolution is prohibited by safety policy.',
    message: 'To protect user privacy and prevent automated exploitation, URLs are analyzed solely via static text heuristics. The actual destination is unknown without external network access.',
    synthetic: true,
  });
});

// 3. List malicious domain hash prefixes in Cloud SQL
app.get('/api/malicious-domains', async (_req, res) => {
  try {
    const list = await getAllMaliciousDomains();
    return res.json({ domains: list });
  } catch (error: any) {
    console.error('Error fetching blocklist:', error);
    return res.status(500).json({ error: 'Failed to fetch blocklist' });
  }
});

// 4. Authenticated addition to Cloud SQL blocklist
app.post('/api/malicious-domains', requireAuth, async (req: AuthRequest, res) => {
  try {
    const { domain, threatType } = req.body;
    if (!domain) {
      return res.status(400).json({ error: 'Domain or hash prefix is required' });
    }

    // Sync user profile
    if (req.user?.uid && req.user?.email) {
      await getOrCreateUser(req.user.uid, req.user.email);
    }

    const clean = domain.trim();
    const hashPrefix = clean.length === 16 && /^[0-9a-f]{16}$/i.test(clean)
      ? clean
      : getDomainHashPrefix(clean);

    const inserted = await addMaliciousDomain(hashPrefix, threatType || 'phishing');
    return res.status(201).json({ success: true, item: inserted, hashPrefix });
  } catch (error: any) {
    console.error('Error adding malicious domain:', error);
    return res.status(500).json({ error: error.message || 'Failed to add entry' });
  }
});

// User session info
app.get('/api/me', requireAuth, async (req: AuthRequest, res) => {
  try {
    if (req.user?.uid && req.user?.email) {
      const user = await getOrCreateUser(req.user.uid, req.user.email);
      return res.json({ user });
    }
    return res.status(401).json({ error: 'Not authenticated' });
  } catch (error: any) {
    return res.status(500).json({ error: error.message || 'Failed to get user' });
  }
});

// Mount Vite or serve static assets
async function startServer() {
  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Signal Security Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
