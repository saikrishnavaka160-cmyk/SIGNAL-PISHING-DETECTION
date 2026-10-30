import React, { useState, useEffect } from 'react';
import {
  analyzeUrlForensics,
  verifyCaseIntegrity,
  PhishTraceCase,
  MAX_URL_LENGTH,
} from '../phishTrace.ts';

interface PhishTraceViewProps {
  showToast: (msg: string) => void;
}

const HISTORY_STORAGE_KEY = 'signal_phishtrace_history';

export const PhishTraceView: React.FC<PhishTraceViewProps> = ({ showToast }) => {
  const [urlInput, setUrlInput] = useState('');
  const [isDemoFixture, setIsDemoFixture] = useState(false);
  const [activeCase, setActiveCase] = useState<PhishTraceCase | null>(null);
  const [history, setHistory] = useState<Array<{ id: string; url: string; score: number; risk: string; timestamp: string }>>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [integrityStatus, setIntegrityStatus] = useState<'verified' | 'tampered' | null>(null);
  const [scoreWidth, setScoreWidth] = useState<number>(0);

  // Smoothly animate score bar on analysis
  useEffect(() => {
    if (activeCase) {
      setScoreWidth(0);
      const timer = setTimeout(() => {
        setScoreWidth(Math.min(100, Math.max(5, (activeCase.score / 12) * 100)));
      }, 35);
      return () => clearTimeout(timer);
    } else {
      setScoreWidth(0);
    }
  }, [activeCase]);

  // Load local history on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(HISTORY_STORAGE_KEY);
      if (stored) {
        setHistory(JSON.parse(stored));
      }
    } catch {
      // LocalStorage error fallback
    }
  }, []);

  const saveToHistory = (c: PhishTraceCase) => {
    try {
      const newEntry = {
        id: c.caseId,
        url: c.inputUrl.length > 50 ? c.inputUrl.slice(0, 50) + '…' : c.inputUrl,
        score: c.score,
        risk: c.riskBand,
        timestamp: new Date(c.analyzedAt).toLocaleTimeString(),
      };
      const updated = [newEntry, ...history.filter((h) => h.id !== c.caseId)].slice(0, 15);
      setHistory(updated);
      localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(updated));
    } catch {
      // Ignore
    }
  };

  const clearHistory = () => {
    setHistory([]);
    try {
      localStorage.removeItem(HISTORY_STORAGE_KEY);
    } catch {
      // Ignore
    }
    showToast('Local investigation history cleared.');
  };

  // Educational Triage Samples
  const DEMO_FIXTURES = [
    {
      label: 'Brand Subdomain Masking',
      url: 'https://paypal.com.account-verification-alert.xyz/signin',
      description: 'Places paypal.com in subdomain of .xyz apex domain.',
    },
    {
      label: 'Embedded Credential Authority',
      url: 'https://apple.com@secure-identity-login.top/verify',
      description: 'Uses @ symbol to mask destination host from mobile users.',
    },
    {
      label: 'Defanged URL Shortener',
      url: 'hxxps://bit[.]ly/account-review-3921',
      description: 'Security triage bracket notation ([.]) hiding shortener.',
    },
    {
      label: 'Raw Numeric IP Address',
      url: 'http://192.168.1.50:8080/banking/login',
      description: 'Direct numeric address with non-standard web port 8080.',
    },
    {
      label: 'Punycode Homograph',
      url: 'https://xn--pple-43d.com/support/login',
      description: 'Internationalized character spoofing brand glyphs.',
    },
    {
      label: 'Benign Education Resource',
      url: 'https://www.cisa.gov/resources-tools/resources',
      description: 'Government cybersecurity guidance resource.',
    },
  ];

  const handleSelectFixture = (f: { url: string; label: string }) => {
    setUrlInput(f.url);
    setIsDemoFixture(true);
    setErrorMessage(null);
    executeAnalysis(f.url, true);
  };

  const executeAnalysis = async (rawUrl: string, fixtureFlag = isDemoFixture) => {
    if (!rawUrl.trim()) {
      setErrorMessage('Please enter a URL to inspect.');
      return;
    }

    setErrorMessage(null);
    setIsAnalyzing(true);
    setIntegrityStatus(null);

    try {
      // PURE STATIC ANALYSIS: Absolutely NO network calls
      const resultCase = await analyzeUrlForensics(rawUrl.trim(), fixtureFlag);
      setActiveCase(resultCase);
      saveToHistory(resultCase);
      showToast('Static forensics complete. Zero network requests made.');
    } catch (err: any) {
      setErrorMessage(err.message || 'Analysis failed due to malformed input.');
      setActiveCase(null);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleExportCase = () => {
    if (!activeCase) return;
    const jsonStr = JSON.stringify(activeCase, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishtrace-${activeCase.caseId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Exported integrity-checkable case JSON.');
  };

  const handleVerifyIntegrity = async () => {
    if (!activeCase) return;
    const isValid = await verifyCaseIntegrity(activeCase);
    setIntegrityStatus(isValid ? 'verified' : 'tampered');
    if (isValid) {
      showToast('✓ Cryptographic case integrity verified (SHA-256 match).');
    } else {
      showToast('⚠️ Case integrity check failed: payload does not match SHA-256 hash.');
    }
  };

  return (
    <section className="view" id="phishtrace-view">
      <div className="subpage-heading">
        <div className="eyebrow">
          <span className="eyebrow-line"></span> URL FORENSICS & TRIAGE WORKSPACE
        </div>
        <h1>PhishTrace Forensics.</h1>
        <p>
          Explainable, zero-network URL text analysis for defensive education. Every signal is visible, every redirect
          path is a synthetic pedagogical model, and investigation cases are verifiable via SHA-256.
        </p>
      </div>

      {/* Safety Compliance Notice Banner */}
      <div
        style={{
          background: '#000000',
          color: '#ffffff',
          borderRadius: '8px',
          padding: '12px 16px',
          marginBottom: '20px',
          fontSize: '11px',
          lineHeight: '1.5',
          border: '1.5px solid #334155',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
        }}
      >
        <span style={{ fontSize: '20px' }}>🛡️</span>
        <div style={{ flex: 1 }}>
          <strong style={{ display: 'block', color: '#facc15', fontSize: '11.5px' }}>
            ZERO-NETWORK GUARANTEE & DEFENSIVE MANDATE
          </strong>
          PhishTrace performs purely static string and syntactic forensics on URL text. It will never fetch, ping, resolve,
          or crawl any submitted address. Clean scores indicate an absence of specific heuristics—never a proof of safety.
        </div>
      </div>

      {/* Main Grid: Input & Inspector */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(420px, 1.15fr) minmax(340px, 0.85fr)', gap: '18px' }}>
        {/* Left: Input Panel */}
        <section className="panel" style={{ padding: '24px' }}>
          <div className="panel-title-row">
            <div>
              <div className="section-kicker">01 · TARGET URL INPUT</div>
              <h2>Submit URL for Static Forensics</h2>
            </div>
            <button
              className="text-button"
              type="button"
              onClick={() => {
                setUrlInput('');
                setActiveCase(null);
                setErrorMessage(null);
                setIntegrityStatus(null);
              }}
            >
              Clear
            </button>
          </div>

          <p className="muted-copy">
            Paste suspicious links or defanged threat samples (e.g. <code>hxxps://domain[.]com/verify</code>). Input is
            strictly bounded to 2,048 characters.
          </p>

          {/* Preset Triage Fixtures */}
          <div style={{ marginBottom: '14px' }}>
            <span style={{ fontSize: '10px', fontWeight: 800, display: 'block', marginBottom: '6px' }}>
              AUTHORIZED TRIAGE TEST FIXTURES:
            </span>
            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
              {DEMO_FIXTURES.map((fixture, idx) => (
                <button
                  key={idx}
                  type="button"
                  className="button-secondary"
                  style={{ fontSize: '9.5px', height: '28px', padding: '0 8px' }}
                  onClick={() => handleSelectFixture(fixture)}
                >
                  {fixture.label} ↗
                </button>
              ))}
            </div>
          </div>

          {/* URL Input Form */}
          <label className="field-label" htmlFor="phishtrace-url-input">
            TARGET URL TEXT (HTTP/HTTPS ONLY)
          </label>
          <input
            id="phishtrace-url-input"
            type="text"
            className="text-input"
            placeholder="https://example[.]com/account/login?token=abc"
            value={urlInput}
            maxLength={MAX_URL_LENGTH}
            onChange={(e) => setUrlInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') executeAnalysis(urlInput);
            }}
          />

          <div className="input-footer">
            <label style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer', fontSize: '10px' }}>
              <input
                type="checkbox"
                checked={isDemoFixture}
                onChange={(e) => setIsDemoFixture(e.target.checked)}
              />
              <span>Label as Authorized Demo Fixture (allows RFC-1918 training models)</span>
            </label>
            <span>
              {urlInput.length} / {MAX_URL_LENGTH} chars
            </span>
          </div>

          {errorMessage && (
            <div
              style={{
                marginTop: '12px',
                padding: '10px 14px',
                borderRadius: '6px',
                background: '#fee2e2',
                border: '1.5px solid #dc2626',
                color: '#991b1b',
                fontSize: '11px',
                fontWeight: 600,
              }}
            >
              ⚠️ {errorMessage}
            </div>
          )}

          <div className="action-row">
            <button
              type="button"
              className="button-primary"
              style={{ width: '100%', height: '42px', fontSize: '11.5px' }}
              onClick={() => executeAnalysis(urlInput)}
              disabled={isAnalyzing}
            >
              <span className="button-spark">✳</span>
              {isAnalyzing ? 'Evaluating Heuristics...' : 'Run Static Forensics Analysis →'}
            </button>
          </div>

          {/* Local Investigation History */}
          <div style={{ marginTop: '24px', borderTop: '1.5px solid #cbd5e1', paddingTop: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <strong style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.8px' }}>
                Local Triage History ({history.length})
              </strong>
              {history.length > 0 && (
                <button type="button" className="text-button" onClick={clearHistory}>
                  Clear History
                </button>
              )}
            </div>

            {history.length === 0 ? (
              <p style={{ fontSize: '10px', color: '#64748b', margin: 0 }}>
                No recent investigations saved in browser memory.
              </p>
            ) : (
              <div style={{ display: 'grid', gap: '6px', maxHeight: '160px', overflowY: 'auto' }}>
                {history.map((h) => (
                  <div
                    key={h.id}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      padding: '7px 10px',
                      borderRadius: '6px',
                      background: '#f8fafc',
                      border: '1px solid #cbd5e1',
                      fontSize: '10px',
                    }}
                  >
                    <span style={{ fontFamily: 'monospace', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '220px' }}>
                      {h.url}
                    </span>
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                      <span
                        style={{
                          fontWeight: 800,
                          fontSize: '8.5px',
                          padding: '2px 6px',
                          borderRadius: '4px',
                          background: h.risk === 'High' ? '#fee2e2' : h.risk === 'Suspicious' ? '#fef3c7' : '#dcfce7',
                          color: h.risk === 'High' ? '#b91c1c' : h.risk === 'Suspicious' ? '#b45309' : '#15803d',
                        }}
                      >
                        {h.risk} ({h.score} pts)
                      </span>
                      <span style={{ color: '#64748b', fontSize: '9px' }}>{h.timestamp}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>

        {/* Right: Results Panel */}
        <section className="panel result-panel phishtrace-result-panel" id="phishtrace-result-panel" style={{ padding: '24px', display: activeCase ? 'block' : 'flex' }}>
          {!activeCase ? (
            <div className="empty-state" style={{ minHeight: '440px', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <div className="empty-art">
                <div className="empty-ring ring-a"></div>
                <div className="empty-ring ring-b"></div>
                <div style={{ fontSize: '42px', zIndex: 2 }}>🔍</div>
              </div>
              <h2>Forensics Case Viewer</h2>
              <p>
                Submit a target URL or choose a triage test fixture<br />to inspect signals and export a case report.
              </p>
            </div>
          ) : (
            <div>
              {/* Top Meta & Verdict */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div className="result-label">PHISHTRACE REPORT #{activeCase.caseId}</div>
                  <h2 className="result-title" style={{ margin: '6px 0 2px' }}>
                    {activeCase.verdictText}
                  </h2>
                  <p className="result-subtitle" style={{ fontFamily: 'monospace' }}>
                    Apex: {activeCase.components.apexDomain} | Hash: {activeCase.domainHashPrefix}
                  </p>
                </div>
                <span className={`risk-pill risk-${activeCase.riskBand.toLowerCase()}`}>
                  {activeCase.riskBand.toUpperCase()} RISK
                </span>
              </div>

              {/* Score Metric Card */}
              <div className="score-card" style={{ marginTop: '14px' }}>
                <div className="score-card-head">
                  <span>Forensic Heuristic Score</span>
                  <div className="score-value">
                    {activeCase.score} <small>points</small>
                  </div>
                </div>
                <div className="score-track">
                  <div
                    className={`score-fill ${activeCase.riskBand === 'High' ? 'high' : activeCase.riskBand === 'Suspicious' ? 'suspicious' : ''}`}
                    style={{ width: `${scoreWidth}%` }}
                  ></div>
                </div>
                <div className="score-scale-small">
                  <span>Low (0–2 pts)</span>
                  <span>Suspicious (3–6 pts)</span>
                  <span>High Risk (7+ pts)</span>
                </div>
              </div>

              {/* Parsed Structure Matrix */}
              <div style={{ marginTop: '16px' }}>
                <div className="signals-heading">
                  <strong>Parsed URL Decomposition</strong>
                  <span>Shannon Entropy: {activeCase.components.entropy}</span>
                </div>
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(2, 1fr)',
                    gap: '8px',
                    fontSize: '10px',
                    background: '#f8fafc',
                    padding: '10px',
                    borderRadius: '8px',
                    border: '1.5px solid #cbd5e1',
                  }}
                >
                  <div><strong>Protocol:</strong> {activeCase.components.protocol}</div>
                  <div><strong>Hostname:</strong> {activeCase.components.hostname}</div>
                  <div><strong>Apex Domain:</strong> {activeCase.components.apexDomain}</div>
                  <div><strong>TLD:</strong> .{activeCase.components.tld || 'none'}</div>
                  <div><strong>Subdomains:</strong> {activeCase.components.subdomains.length ? activeCase.components.subdomains.join('.') : 'none'}</div>
                  <div><strong>Has Credentials (@):</strong> {activeCase.components.hasCredentials ? 'YES (Masked)' : 'No'}</div>
                  <div><strong>Path:</strong> {activeCase.components.pathname || '/'}</div>
                  <div><strong>Query Params:</strong> {activeCase.components.searchParams.length} detected</div>
                </div>
              </div>

              {/* Detected Signals List */}
              <div style={{ marginTop: '16px' }}>
                <div className="signals-heading">
                  <strong>Triggered Heuristic Signals</strong>
                  <span>{activeCase.signals.length} indicator{activeCase.signals.length === 1 ? '' : 's'}</span>
                </div>
                <div className="signal-list" style={{ maxHeight: '200px' }}>
                  {activeCase.signals.length === 0 ? (
                    <div className="no-signals">
                      No elevated heuristic indicators found by static inspection rules.
                    </div>
                  ) : (
                    activeCase.signals.map((sig) => (
                      <div
                        key={sig.id}
                        className={`signal-item ${sig.points >= 3 ? 'critical' : ''}`}
                      >
                        <span className="signal-icon">{sig.points >= 3 ? '!' : '↗'}</span>
                        <div>
                          <strong>{sig.name}</strong>
                          <p>{sig.explanation}</p>
                          <div style={{ fontSize: '9px', color: '#475569', marginTop: '2px', fontFamily: 'monospace' }}>
                            Evidence: {sig.evidence}
                          </div>
                        </div>
                        <span className="points">+{sig.points}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Synthetic Redirect Path Graph (Pedagogical Model) */}
              <div style={{ marginTop: '16px' }}>
                <div className="signals-heading">
                  <strong>Synthetic Redirect Path Model</strong>
                  <span style={{ color: '#b45309', fontWeight: 800 }}>Simulated Example</span>
                </div>
                <div
                  style={{
                    background: '#ffffff',
                    border: '1.5px solid #cbd5e1',
                    borderRadius: '8px',
                    padding: '12px',
                    fontSize: '10px',
                  }}
                >
                  <div style={{ display: 'grid', gap: '8px' }}>
                    {activeCase.syntheticRedirects.map((hop) => (
                      <div
                        key={hop.hop}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '10px',
                          background: hop.type === 'initial' ? '#f1f5f9' : '#fef3c7',
                          padding: '6px 10px',
                          borderRadius: '6px',
                        }}
                      >
                        <span
                          style={{
                            background: '#000000',
                            color: '#ffffff',
                            width: '20px',
                            height: '20px',
                            borderRadius: '50%',
                            display: 'grid',
                            placeItems: 'center',
                            fontSize: '9.5px',
                            fontWeight: 800,
                          }}
                        >
                          {hop.hop}
                        </span>
                        <div style={{ flex: 1 }}>
                          <strong>{hop.role}:</strong> {hop.domain}
                          <small style={{ display: 'block', color: '#475569', fontSize: '8.5px' }}>
                            {hop.note}
                          </small>
                        </div>
                      </div>
                    ))}
                  </div>
                  <p style={{ margin: '8px 0 0', fontSize: '8.5px', color: '#64748b', fontStyle: 'italic' }}>
                    ⚠️ Pedagogical model only. No external DNS or HTTP requests were made.
                  </p>
                </div>
              </div>

              {/* Cryptographic Export & Integrity Section */}
              <div style={{ marginTop: '18px', borderTop: '1.5px solid #cbd5e1', paddingTop: '14px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontSize: '9.5px', fontWeight: 800 }}>CASE INTEGRITY SHA-256</span>
                  <button
                    type="button"
                    onClick={handleVerifyIntegrity}
                    className="button-secondary"
                    style={{ fontSize: '9px', height: '26px' }}
                  >
                    Verify Hash 🔒
                  </button>
                </div>
                <code
                  style={{
                    display: 'block',
                    background: '#0f172a',
                    color: '#38bdf8',
                    padding: '6px 8px',
                    borderRadius: '4px',
                    fontSize: '9px',
                    wordBreak: 'break-all',
                  }}
                >
                  {activeCase.caseIntegritySha256}
                </code>

                {integrityStatus && (
                  <div
                    style={{
                      marginTop: '6px',
                      fontSize: '9.5px',
                      fontWeight: 800,
                      color: integrityStatus === 'verified' ? '#15803d' : '#b91c1c',
                    }}
                  >
                    {integrityStatus === 'verified'
                      ? '✓ Integrity Verified: JSON payload is mathematically authentic.'
                      : '⚠️ Integrity Check Failed! Payload was altered.'}
                  </div>
                )}

                <div style={{ marginTop: '12px' }}>
                  <button
                    type="button"
                    className="button-primary"
                    style={{ width: '100%', height: '36px', fontSize: '10.5px' }}
                    onClick={handleExportCase}
                  >
                    ⬇ Export Case Report (.JSON)
                  </button>
                </div>
              </div>
            </div>
          )}
        </section>
      </div>
    </section>
  );
};
