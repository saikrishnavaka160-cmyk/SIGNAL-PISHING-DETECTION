import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeUrlForensics,
  verifyCaseIntegrity,
  calculateShannonEntropy,
  isReservedIpAddress,
  normalizeDefangedUrl,
  MAX_URL_LENGTH,
} from './phishTrace.ts';

test('URL Bounds: rejects URL longer than maximum length', async () => {
  const longUrl = 'https://example.com/' + 'a'.repeat(MAX_URL_LENGTH + 10);
  await assert.rejects(
    async () => {
      await analyzeUrlForensics(longUrl);
    },
    {
      message: `URL length exceeds maximum bound of ${MAX_URL_LENGTH} characters.`,
    }
  );
});

test('Protocol validation: rejects prohibited non-web schemes', async () => {
  const prohibitedSchemes = ['javascript:alert(1)', 'data:text/html,test', 'file:///etc/passwd'];
  for (const p of prohibitedSchemes) {
    await assert.rejects(async () => {
      await analyzeUrlForensics(p);
    });
  }
});

test('Defanged notation: normalizes bracketed dots and hxxp', async () => {
  const sample = 'hxxps://secure-paypal[.]com/verify-account';
  const { normalized, wasDefanged } = normalizeDefangedUrl(sample);
  assert.equal(wasDefanged, true);
  assert.equal(normalized, 'https://secure-paypal.com/verify-account');

  const report = await analyzeUrlForensics(sample);
  assert.equal(report.signals.some((s) => s.id === 'SIGNAL_DEFANGED_NOTATION'), true);
});

test('Embedded credentials: flags username/password host masking', async () => {
  const spoofUrl = 'https://paypal.com@login-secure-verification.xyz/login';
  const report = await analyzeUrlForensics(spoofUrl);
  assert.equal(report.components.hasCredentials, true);
  assert.equal(report.signals.some((s) => s.id === 'SIGNAL_EMBEDDED_CREDENTIALS'), true);
  assert.equal(report.riskBand, 'High');
});

test('Reserved IP address detection: flags private and loopback ranges', () => {
  assert.equal(isReservedIpAddress('127.0.0.1'), true);
  assert.equal(isReservedIpAddress('192.168.1.1'), true);
  assert.equal(isReservedIpAddress('10.0.0.5'), true);
  assert.equal(isReservedIpAddress('169.254.169.254'), true);
  assert.equal(isReservedIpAddress('8.8.8.8'), false);
  assert.equal(isReservedIpAddress('93.184.216.34'), false);
});

test('Brand in subdomain: identifies apex domain vs brand token mismatch', async () => {
  const deceptiveUrl = 'https://paypal.com.account-update.xyz/verify';
  const report = await analyzeUrlForensics(deceptiveUrl);
  const brandSignal = report.signals.find((s) => s.id.startsWith('SIGNAL_BRAND_IMPERSONATION'));
  assert.ok(brandSignal, 'Should detect brand in subdomain');
  assert.equal(brandSignal?.severity, 'critical');
  assert.equal(report.components.apexDomain, 'account-update.xyz');
});

test('Synthetic redirect modeling: marks shorteners with synthetic simulation note', async () => {
  const shortenerUrl = 'https://bit.ly/secure-login-3921';
  const report = await analyzeUrlForensics(shortenerUrl);
  assert.ok(report.syntheticRedirects.length > 1, 'Shortener should generate synthetic hops');
  assert.equal(report.syntheticRedirects[0].role, 'Shortener Ingress');
  assert.ok(
    report.syntheticRedirects[1].note.includes('SYNTHETIC SIMULATION'),
    'Intermediate hops must be explicitly marked as synthetic simulations'
  );
});

test('Cryptographic case integrity: SHA-256 hash verifies tamper-free cases', async () => {
  const testUrl = 'https://chase.com.security-alert.top/signin';
  const report = await analyzeUrlForensics(testUrl);

  assert.equal(report.caseIntegritySha256.length, 64, 'SHA-256 must be 64 hex characters');

  // Verification succeeds on untampered case
  const isValid = await verifyCaseIntegrity(report);
  assert.equal(isValid, true);

  // Tampering with score invalidates verification
  const tamperedCase = { ...report, score: 0 };
  const isTamperedValid = await verifyCaseIntegrity(tamperedCase);
  assert.equal(isTamperedValid, false);
});

test('Shannon entropy calculation: correctly computes randomness', () => {
  assert.equal(calculateShannonEntropy('aaaaa'), 0);
  assert.ok(calculateShannonEntropy('a1b2c3d4e5f6g7h8') > 3.5);
});

test('validateUrlInput helper: parses and validates schemes and bounds safely', async () => {
  const { validateUrlInput } = await import('./phishTrace.ts');
  const validResult = validateUrlInput('https://example.com/login');
  assert.equal(validResult.valid, true);

  const invalidProto = validateUrlInput('javascript:alert(1)');
  assert.equal(invalidProto.valid, false);

  const credResult = validateUrlInput('https://user:pass@evil.com');
  assert.equal(credResult.hasCredentials, true);

  const reservedResult = validateUrlInput('http://127.0.0.1/admin');
  assert.equal(reservedResult.isReservedIp, true);
});
