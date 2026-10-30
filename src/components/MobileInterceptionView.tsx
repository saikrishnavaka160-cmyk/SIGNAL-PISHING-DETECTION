import React, { useState, useEffect } from 'react';
import { extractUrlsFromText, ExtractionResult, ExtractedUrlInfo } from '../modules/centralLinkExtractor.ts';
import { ANDROID_ACCESSIBILITY_KOTLIN, ANDROID_MANIFEST_XML, ANDROID_SERVICE_CONFIG_XML } from '../modules/androidAccessibilityModule.ts';
import { IOS_SWIFT_INTERCEPTOR, IOS_CONTENT_BLOCKER_JSON } from '../modules/iosContentBlockerModule.ts';
import { auth, googleAuthProvider } from '../lib/firebase.ts';
import { signInWithPopup, signOut, User } from 'firebase/auth';

interface MobileInterceptionViewProps {
  showToast: (msg: string) => void;
}

export const MobileInterceptionView: React.FC<MobileInterceptionViewProps> = ({ showToast }) => {
  const [activeTab, setActiveTab] = useState<'simulator' | 'android' | 'ios' | 'extractor' | 'database'>('simulator');
  const [selectedApp, setSelectedApp] = useState<'com.whatsapp' | 'com.google.android.gm' | 'default_sms'>('com.whatsapp');
  const [messageInput, setMessageInput] = useState('');
  const [extractionResult, setExtractionResult] = useState<ExtractionResult | null>(null);
  const [threatMatches, setThreatMatches] = useState<any[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [showOverlay, setShowOverlay] = useState(false);
  const [resolvingUrl, setResolvingUrl] = useState<string | null>(null);
  const [resolvedInfo, setResolvedInfo] = useState<any | null>(null);

  // Cloud SQL Database Management State
  const [dbDomains, setDbDomains] = useState<any[]>([]);
  const [newDomainInput, setNewDomainInput] = useState('');
  const [newThreatType, setNewThreatType] = useState('phishing');
  const [isLoadingDb, setIsLoadingDb] = useState(false);
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    const unsubscribe = auth.onAuthStateChanged((u) => {
      setUser(u);
    });
    fetchDatabaseDomains();
    return () => unsubscribe();
  }, []);

  const fetchDatabaseDomains = async () => {
    setIsLoadingDb(true);
    try {
      const res = await fetch('/api/malicious-domains');
      const data = await res.json();
      if (data.domains) {
        setDbDomains(data.domains);
      }
    } catch (e) {
      console.error('Failed to load database domains', e);
    } finally {
      setIsLoadingDb(false);
    }
  };

  const handleSignIn = async () => {
    try {
      await signInWithPopup(auth, googleAuthProvider);
      showToast('Signed in with Google successfully.');
    } catch (err: any) {
      showToast('Sign in failed: ' + (err.message || 'Error'));
    }
  };

  const handleSignOut = async () => {
    try {
      await signOut(auth);
      showToast('Signed out.');
    } catch (err: any) {
      showToast('Sign out failed');
    }
  };

  const handleAddDomainToDb = async () => {
    if (!newDomainInput.trim()) {
      showToast('Please enter a domain or hash prefix');
      return;
    }
    try {
      const token = user ? await user.getIdToken() : null;
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      const res = await fetch('/api/malicious-domains', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          domain: newDomainInput.trim(),
          threatType: newThreatType,
        }),
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || 'Failed to add entry. Please sign in.');
      }

      const data = await res.json();
      showToast(`Added to Cloud SQL! Hash prefix: ${data.hashPrefix}`);
      setNewDomainInput('');
      fetchDatabaseDomains();
    } catch (e: any) {
      showToast(e.message || 'Failed to add to database.');
    }
  };

  // Preset communication app test samples
  const SAMPLE_MESSAGES = {
    whatsapp: {
      label: 'WhatsApp Account Phish (Bracketed Defanging)',
      app: 'com.whatsapp' as const,
      text: 'Hey, WhatsApp security alert: Your account has been logged in from another device. Verify immediately to prevent permanent block: hxxp://secure-amazon-support[.]co/verify-login?id=83921 or check backup at http://bit.ly/account-review',
    },
    sms: {
      label: 'SMS Banking Scam (Direct Raw IP)',
      app: 'default_sms' as const,
      text: 'URGENT from CHASE: Your debit card has been restricted due to suspicious activity. Visit http://192.168.1.100/chase-auth to restore access within 2 hours.',
    },
    gmail: {
      label: 'Gmail Apple ID Phish (Embedded Masking)',
      app: 'com.google.android.gm' as const,
      text: 'Apple Security Team: Unrecognized sign-in from Moscow, Russia. If this was not you, unlock your Apple ID now at: http://apple.com@login-appleid-verify.com/security-check',
    },
  };

  const loadSample = (key: keyof typeof SAMPLE_MESSAGES) => {
    const s = SAMPLE_MESSAGES[key];
    setSelectedApp(s.app);
    setMessageInput(s.text);
    triggerScan(s.text);
  };

  const triggerScan = async (textToScan: string) => {
    if (!textToScan.trim()) {
      setExtractionResult(null);
      setThreatMatches([]);
      setShowOverlay(false);
      return;
    }

    setIsScanning(true);
    setResolvedInfo(null);
    try {
      // 1. Local-first Regex extraction & de-obfuscation
      const result = await extractUrlsFromText(textToScan);
      setExtractionResult(result);

      if (result.urls.length > 0) {
        // 2. Query Cloud SQL using 8-byte SHA-256 hash prefixes (k-Anonymity)
        const prefixes = result.urls.map((u) => u.hashPrefix);
        const res = await fetch('/api/check-urls', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ prefixes }),
        });
        const data = await res.json();
        const matches = data.matches || [];
        setThreatMatches(matches);

        if (matches.length > 0) {
          setShowOverlay(true);
          showToast(`⚠️ Malicious link intercepted in ${selectedApp}!`);
        } else {
          setShowOverlay(false);
        }
      } else {
        setThreatMatches([]);
        setShowOverlay(false);
      }
    } catch (err) {
      console.error('Scan error:', err);
    } finally {
      setIsScanning(false);
    }
  };

  const handleResolveUrl = async (url: string) => {
    setResolvingUrl(url);
    // Safety Policy: Zero external network crawl. Replace with labeled local mock.
    setResolvedInfo({
      originalUrl: url,
      finalUrl: 'https://synthetic-destination-payload.local/example',
      finalDomain: 'synthetic-destination-payload.local',
      hashPrefix: 'mock000000000000',
      redirectsCount: 2,
      note: 'LABELED LOCAL MOCK: Live network resolution is disabled by safety policy. The actual destination is unknown without external network access.',
      threat: null,
    });
    showToast('Labeled local mock: actual destination unknown (no-network policy).');
    setResolvingUrl(null);
  };

  return (
    <section className="view" id="mobile-view">
      <div className="subpage-heading">
        <div className="eyebrow">
          <span className="eyebrow-line"></span> ON-DEVICE MOBILE SECURITY
        </div>
        <h1>Mobile Phishing Interceptor.</h1>
        <p>
          Real-time on-device link extraction and Cloud SQL threat verification for SMS, WhatsApp, and Gmail.
        </p>
      </div>

      {/* Sub-nav Tab Bar */}
      <div style={{ display: 'flex', gap: '8px', borderBottom: '1.5px solid #cbd5e1', paddingBottom: '12px', marginBottom: '22px', flexWrap: 'wrap' }}>
        <button
          type="button"
          onClick={() => setActiveTab('simulator')}
          className={`button-secondary ${activeTab === 'simulator' ? 'active-tab' : ''}`}
          style={{
            background: activeTab === 'simulator' ? '#000000' : '#ffffff',
            color: activeTab === 'simulator' ? '#ffffff' : '#000000',
            border: '1.5px solid #000000',
            fontWeight: 800,
          }}
        >
          📱 Live Mobile Simulator
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('android')}
          className={`button-secondary ${activeTab === 'android' ? 'active-tab' : ''}`}
          style={{
            background: activeTab === 'android' ? '#000000' : '#ffffff',
            color: activeTab === 'android' ? '#ffffff' : '#000000',
            border: '1.5px solid #000000',
            fontWeight: 800,
          }}
        >
          🤖 Android AccessibilityService (Kotlin)
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('ios')}
          className={`button-secondary ${activeTab === 'ios' ? 'active-tab' : ''}`}
          style={{
            background: activeTab === 'ios' ? '#000000' : '#ffffff',
            color: activeTab === 'ios' ? '#ffffff' : '#000000',
            border: '1.5px solid #000000',
            fontWeight: 800,
          }}
        >
          🍏 iOS Content Blocker & Universal Link (Swift)
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('extractor')}
          className={`button-secondary ${activeTab === 'extractor' ? 'active-tab' : ''}`}
          style={{
            background: activeTab === 'extractor' ? '#000000' : '#ffffff',
            color: activeTab === 'extractor' ? '#ffffff' : '#000000',
            border: '1.5px solid #000000',
            fontWeight: 800,
          }}
        >
          ⚡ Central Link Extractor
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('database')}
          className={`button-secondary ${activeTab === 'database' ? 'active-tab' : ''}`}
          style={{
            background: activeTab === 'database' ? '#000000' : '#ffffff',
            color: activeTab === 'database' ? '#ffffff' : '#000000',
            border: '1.5px solid #000000',
            fontWeight: 800,
          }}
        >
          🗄️ Cloud SQL Blocklist ({dbDomains.length})
        </button>
      </div>

      {/* 1. SIMULATOR TAB */}
      {activeTab === 'simulator' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: '20px' }}>
          {/* Left: Input & Detection Panel */}
          <section className="panel" style={{ padding: '24px' }}>
            <div className="section-kicker">01 · COMM APP NODE SCANNER</div>
            <h2>Simulate Inbound Message</h2>
            <p className="muted-copy">
              The service inspects message nodes without uploading text. Links are extracted, deobfuscated, and evaluated against Cloud SQL hash prefixes.
            </p>

            {/* App Selector */}
            <div style={{ marginBottom: '16px' }}>
              <label className="field-label">TARGET COMMUNICATION PACKAGE</label>
              <div style={{ display: 'flex', gap: '10px' }}>
                <button
                  type="button"
                  onClick={() => setSelectedApp('com.whatsapp')}
                  style={{
                    flex: 1,
                    padding: '8px',
                    borderRadius: '6px',
                    border: '1.5px solid #000000',
                    background: selectedApp === 'com.whatsapp' ? '#dcfce7' : '#ffffff',
                    fontWeight: 800,
                    cursor: 'pointer',
                  }}
                >
                  WhatsApp <small style={{ display: 'block', fontSize: '9px' }}>com.whatsapp</small>
                </button>
                <button
                  type="button"
                  onClick={() => setSelectedApp('com.google.android.gm')}
                  style={{
                    flex: 1,
                    padding: '8px',
                    borderRadius: '6px',
                    border: '1.5px solid #000000',
                    background: selectedApp === 'com.google.android.gm' ? '#fee2e2' : '#ffffff',
                    fontWeight: 800,
                    cursor: 'pointer',
                  }}
                >
                  Gmail <small style={{ display: 'block', fontSize: '9px' }}>com.google.android.gm</small>
                </button>
                <button
                  type="button"
                  onClick={() => setSelectedApp('default_sms')}
                  style={{
                    flex: 1,
                    padding: '8px',
                    borderRadius: '6px',
                    border: '1.5px solid #000000',
                    background: selectedApp === 'default_sms' ? '#e0edff' : '#ffffff',
                    fontWeight: 800,
                    cursor: 'pointer',
                  }}
                >
                  Default SMS <small style={{ display: 'block', fontSize: '9px' }}>com.google.android.apps.messaging</small>
                </button>
              </div>
            </div>

            {/* Sample Presets */}
            <div style={{ marginBottom: '14px' }}>
              <span style={{ fontSize: '10px', fontWeight: 800, display: 'block', marginBottom: '6px' }}>
                QUICK LOAD ATTACK SCENARIOS:
              </span>
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  onClick={() => loadSample('whatsapp')}
                  className="button-secondary"
                  style={{ fontSize: '10px', height: '30px' }}
                >
                  WhatsApp Phish (hxxp & [.]) ↗
                </button>
                <button
                  type="button"
                  onClick={() => loadSample('sms')}
                  className="button-secondary"
                  style={{ fontSize: '10px', height: '30px' }}
                >
                  SMS Banking Scam (Raw IP) ↗
                </button>
                <button
                  type="button"
                  onClick={() => loadSample('gmail')}
                  className="button-secondary"
                  style={{ fontSize: '10px', height: '30px' }}
                >
                  Gmail Apple ID (@ Spoofing) ↗
                </button>
              </div>
            </div>

            <label className="field-label">RAW MESSAGE NODE TEXT</label>
            <textarea
              className="email-textarea"
              style={{ height: '110px' }}
              value={messageInput}
              onChange={(e) => {
                setMessageInput(e.target.value);
                triggerScan(e.target.value);
              }}
              placeholder="Paste or type raw message text containing links or obfuscated URLs (e.g. hxxp://example[.]com)..."
            />

            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '10px' }}>
              <button
                type="button"
                className="button-primary"
                onClick={() => triggerScan(messageInput)}
                disabled={isScanning}
              >
                {isScanning ? 'Scanning on-device...' : 'Scan Node Text →'}
              </button>
              <button
                type="button"
                className="text-button"
                onClick={() => {
                  setMessageInput('');
                  setExtractionResult(null);
                  setThreatMatches([]);
                  setShowOverlay(false);
                }}
              >
                Clear
              </button>
            </div>

            {/* Extraction Results */}
            {extractionResult && (
              <div style={{ marginTop: '20px', borderTop: '1.5px solid #cbd5e1', paddingTop: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                  <strong style={{ fontSize: '12px' }}>
                    Extracted URLs ({extractionResult.urls.length})
                  </strong>
                  <span style={{ fontSize: '10px', color: '#000000', fontWeight: 700 }}>
                    Scan Time: {extractionResult.scanDurationMs}ms (Local-first)
                  </span>
                </div>

                {extractionResult.urls.length === 0 ? (
                  <div style={{ fontSize: '11px', color: '#000000', background: '#f8fafc', padding: '10px', borderRadius: '6px' }}>
                    No valid or obfuscated links found in this text.
                  </div>
                ) : (
                  <div style={{ display: 'grid', gap: '10px' }}>
                    {extractionResult.urls.map((urlInfo: ExtractedUrlInfo, idx: number) => {
                      const isThreat = threatMatches.some((m: any) => m.hashPrefix === urlInfo.hashPrefix);
                      return (
                        <div
                          key={idx}
                          style={{
                            border: `1.5px solid ${isThreat ? '#dc2626' : '#cbd5e1'}`,
                            background: isThreat ? '#fee2e2' : '#ffffff',
                            borderRadius: '8px',
                            padding: '12px',
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                            <div>
                              <strong style={{ fontSize: '12px', color: '#000000' }}>
                                {urlInfo.domain}
                              </strong>
                              <div style={{ fontSize: '10px', color: '#374151', fontFamily: 'monospace' }}>
                                Raw: {urlInfo.rawMatch}
                              </div>
                            </div>
                            <span
                              style={{
                                fontSize: '9px',
                                fontWeight: 800,
                                padding: '3px 7px',
                                borderRadius: '4px',
                                background: isThreat ? '#b91c1c' : '#15803d',
                                color: '#ffffff',
                              }}
                            >
                              {isThreat ? 'MALICIOUS (Cloud SQL)' : 'CLEAN'}
                            </span>
                          </div>

                          <div style={{ fontSize: '10px', marginTop: '6px', color: '#000000', display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                            <span>
                              SHA-256 Prefix (16-hex): <code style={{ fontWeight: 800 }}>{urlInfo.hashPrefix}</code>
                            </span>
                            {urlInfo.isShortened && (
                              <span style={{ color: '#b45309', fontWeight: 800 }}>
                                🔗 URL Shortener ({urlInfo.domain})
                              </span>
                            )}
                          </div>

                          {urlInfo.obfuscationTechniques.length > 0 && (
                            <div style={{ marginTop: '6px' }}>
                              <span style={{ fontSize: '9px', fontWeight: 800, color: '#dc2626' }}>
                                Obfuscations Detected:
                              </span>
                              <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginTop: '3px' }}>
                                {urlInfo.obfuscationTechniques.map((tech: string, tIdx: number) => (
                                  <span
                                    key={tIdx}
                                    style={{
                                      fontSize: '8.5px',
                                      fontWeight: 700,
                                      background: '#fef3c7',
                                      color: '#92400e',
                                      padding: '2px 5px',
                                      borderRadius: '3px',
                                    }}
                                  >
                                    {tech}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}

                          {urlInfo.isShortened && (
                            <div style={{ marginTop: '8px' }}>
                              <button
                                type="button"
                                className="button-secondary"
                                style={{ fontSize: '10px', height: '28px' }}
                                onClick={() => handleResolveUrl(urlInfo.normalizedUrl)}
                                disabled={resolvingUrl === urlInfo.normalizedUrl}
                              >
                                {resolvingUrl === urlInfo.normalizedUrl ? 'Resolving Redirects...' : 'Unshorten / Follow Redirects ↗'}
                              </button>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}

                {/* Resolved URL Information */}
                {resolvedInfo && (
                  <div style={{ marginTop: '14px', padding: '12px', background: '#f8fafc', border: '1.5px solid #cbd5e1', borderRadius: '8px' }}>
                    <strong style={{ fontSize: '11px', display: 'block', marginBottom: '4px' }}>
                      🔗 Redirect Unshortening Resolution
                    </strong>
                    <div style={{ fontSize: '10px' }}>
                      <div>Original: <code>{resolvedInfo.originalUrl}</code></div>
                      <div>Final Destination: <strong style={{ color: resolvedInfo.threat ? '#b91c1c' : '#15803d' }}>{resolvedInfo.finalUrl}</strong></div>
                      <div>Final Domain: <strong>{resolvedInfo.finalDomain}</strong> (Hash: <code>{resolvedInfo.hashPrefix}</code>)</div>
                      <div>Redirect Hops: {resolvedInfo.redirectsCount}</div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </section>

          {/* Right: Interactive Smartphone Floating Warning Overlay */}
          <section className="panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            <div className="section-kicker">02 · ON-SCREEN SIMULATION</div>
            <h2 style={{ alignSelf: 'flex-start' }}>Android Floating Overlay</h2>
            <p className="muted-copy" style={{ alignSelf: 'flex-start' }}>
              When a malicious hash matches, <code>WindowManager.addView</code> renders a floating warning view over the communication app.
            </p>

            {/* Mobile Device Mockup */}
            <div
              style={{
                width: '280px',
                height: '520px',
                background: '#0f172a',
                borderRadius: '32px',
                border: '6px solid #1e293b',
                boxShadow: '0 20px 40px rgba(0,0,0,0.3)',
                padding: '12px 10px',
                position: 'relative',
                display: 'flex',
                flexDirection: 'column',
                overflow: 'hidden',
              }}
            >
              {/* Speaker & Camera notch */}
              <div
                style={{
                  width: '90px',
                  height: '14px',
                  background: '#1e293b',
                  borderRadius: '10px',
                  alignSelf: 'center',
                  marginBottom: '10px',
                }}
              ></div>

              {/* Simulated App Header */}
              <div
                style={{
                  background: selectedApp === 'com.whatsapp' ? '#075e54' : selectedApp === 'com.google.android.gm' ? '#c5221f' : '#1e40af',
                  padding: '8px 10px',
                  borderRadius: '6px',
                  color: '#ffffff',
                  fontSize: '11px',
                  fontWeight: 800,
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <span>{selectedApp === 'com.whatsapp' ? 'WhatsApp' : selectedApp === 'com.google.android.gm' ? 'Gmail' : 'Messages'}</span>
                <span style={{ fontSize: '9px', opacity: 0.8 }}>Active Node</span>
              </div>

              {/* Message Bubble inside Device */}
              <div style={{ flex: 1, padding: '14px 4px', display: 'flex', flexDirection: 'column', justifyContent: 'flex-start' }}>
                <div
                  style={{
                    background: '#ffffff',
                    padding: '10px 12px',
                    borderRadius: '12px',
                    fontSize: '10px',
                    lineHeight: '1.4',
                    color: '#000000',
                    boxShadow: '0 2px 6px rgba(0,0,0,0.2)',
                    wordBreak: 'break-word',
                  }}
                >
                  {messageInput || 'Waiting for message node text...'}
                </div>
              </div>

              {/* FLOATING OVERLAY VIEW (WindowManager TYPE_APPLICATION_OVERLAY) */}
              {showOverlay && (
                <div
                  style={{
                    position: 'absolute',
                    top: '55px',
                    left: '12px',
                    right: '12px',
                    background: '#dc2626',
                    border: '2px solid #ffffff',
                    borderRadius: '12px',
                    padding: '12px',
                    color: '#ffffff',
                    boxShadow: '0 10px 25px rgba(220, 38, 38, 0.6)',
                    animation: 'fadeIn 0.3s ease-in-out',
                    zIndex: 10,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
                    <span style={{ fontSize: '16px' }}>⚠️</span>
                    <strong style={{ fontSize: '11px', letterSpacing: '0.5px' }}>
                      PHISHING LINK BLOCKED
                    </strong>
                  </div>
                  <div style={{ fontSize: '9.5px', lineHeight: '1.4', background: 'rgba(0,0,0,0.2)', padding: '6px', borderRadius: '6px', marginBottom: '8px' }}>
                    <div><strong>Domain:</strong> {threatMatches[0]?.domain || threatMatches[0]?.hashPrefix}</div>
                    <div><strong>Classification:</strong> {threatMatches[0]?.threatType || 'Phishing Attack'}</div>
                    <div><strong>Threat Hash:</strong> {threatMatches[0]?.hashPrefix}</div>
                  </div>
                  <div style={{ display: 'flex', gap: '6px' }}>
                    <button
                      type="button"
                      onClick={() => setShowOverlay(false)}
                      style={{
                        flex: 1,
                        background: '#ffffff',
                        color: '#000000',
                        border: 'none',
                        borderRadius: '4px',
                        padding: '6px',
                        fontSize: '9px',
                        fontWeight: 800,
                        cursor: 'pointer',
                      }}
                    >
                      Dismiss Overlay
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        showToast('Link blocked. Staying safe in communication app.');
                        setShowOverlay(false);
                      }}
                      style={{
                        flex: 1,
                        background: '#000000',
                        color: '#ffffff',
                        border: '1px solid #ffffff',
                        borderRadius: '4px',
                        padding: '6px',
                        fontSize: '9px',
                        fontWeight: 800,
                        cursor: 'pointer',
                      }}
                    >
                      Safe Stay
                    </button>
                  </div>
                </div>
              )}

              {/* Status indicator bar */}
              <div style={{ textAlign: 'center', fontSize: '9px', color: '#94a3b8', paddingTop: '6px' }}>
                Signal Shield Daemon: {showOverlay ? '🚨 Threat Intercepted' : 'Active & Monitoring'}
              </div>
            </div>
          </section>
        </div>
      )}

      {/* 2. ANDROID CODE & ARCHITECTURE TAB */}
      {activeTab === 'android' && (
        <section className="panel" style={{ padding: '24px' }}>
          <div className="section-kicker">ANDROID 14+ ACCESSIBILITY ENGINE</div>
          <h2>Production-Ready Android AccessibilityService</h2>
          <p className="muted-copy">
            Filters node events in <code>com.whatsapp</code>, <code>com.google.android.gm</code>, and default SMS. Recycles all <code>AccessibilityNodeInfo</code> objects and debounces scans.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px', marginBottom: '16px' }}>
            <div className="metric-box">
              <span>Target Packages</span>
              <strong style={{ fontSize: '13px' }}>4 Apps Monitored</strong>
            </div>
            <div className="metric-box">
              <span>Memory Policy</span>
              <strong style={{ fontSize: '13px' }}>node.recycle()</strong>
            </div>
            <div className="metric-box">
              <span>Event Debounce</span>
              <strong style={{ fontSize: '13px' }}>250ms Delay</strong>
            </div>
            <div className="metric-box">
              <span>Overlay Window</span>
              <strong style={{ fontSize: '13px' }}>TYPE_APP_OVERLAY</strong>
            </div>
          </div>

          <div style={{ marginTop: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <strong>PhishingLinkAccessibilityService.kt</strong>
              <button
                type="button"
                className="button-secondary"
                style={{ height: '28px', fontSize: '10px' }}
                onClick={() => {
                  navigator.clipboard.writeText(ANDROID_ACCESSIBILITY_KOTLIN);
                  showToast('Copied Kotlin source code to clipboard!');
                }}
              >
                Copy Kotlin Code 📋
              </button>
            </div>
            <pre style={{ background: '#0f172a', color: '#f8fafc', padding: '16px', borderRadius: '8px', fontSize: '11px', maxHeight: '420px', overflow: 'auto', lineHeight: '1.5' }}>
              <code>{ANDROID_ACCESSIBILITY_KOTLIN}</code>
            </pre>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginTop: '16px' }}>
            <div>
              <strong>AndroidManifest.xml</strong>
              <pre style={{ background: '#0f172a', color: '#f8fafc', padding: '12px', borderRadius: '8px', fontSize: '10.5px', maxHeight: '200px', overflow: 'auto' }}>
                <code>{ANDROID_MANIFEST_XML}</code>
              </pre>
            </div>
            <div>
              <strong>res/xml/accessibility_service_config.xml</strong>
              <pre style={{ background: '#0f172a', color: '#f8fafc', padding: '12px', borderRadius: '8px', fontSize: '10.5px', maxHeight: '200px', overflow: 'auto' }}>
                <code>{ANDROID_SERVICE_CONFIG_XML}</code>
              </pre>
            </div>
          </div>
        </section>
      )}

      {/* 3. IOS CODE & ARCHITECTURE TAB */}
      {activeTab === 'ios' && (
        <section className="panel" style={{ padding: '24px' }}>
          <div className="section-kicker">IOS 17+ UNIVERSAL LINK & CONTENT BLOCKER</div>
          <h2>iOS Deep Link Interceptor & Safari Content Blocker</h2>
          <p className="muted-copy">
            Intercepts incoming universal links from external apps (Mail, Messages, WhatsApp) in <code>SceneDelegate</code>, verifying safety before presenting <code>SFSafariViewController</code>.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px', marginBottom: '16px' }}>
            <div className="metric-box">
              <span>Universal Link Routing</span>
              <strong style={{ fontSize: '13px' }}>NSUserActivity Hook</strong>
            </div>
            <div className="metric-box">
              <span>Safari Engine</span>
              <strong style={{ fontSize: '13px' }}>SFSafariViewController</strong>
            </div>
            <div className="metric-box">
              <span>WKWebView Security</span>
              <strong style={{ fontSize: '13px' }}>Process Pool Isolation</strong>
            </div>
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <strong>UniversalLinkInterceptor.swift</strong>
              <button
                type="button"
                className="button-secondary"
                style={{ height: '28px', fontSize: '10px' }}
                onClick={() => {
                  navigator.clipboard.writeText(IOS_SWIFT_INTERCEPTOR);
                  showToast('Copied Swift source code to clipboard!');
                }}
              >
                Copy Swift Code 📋
              </button>
            </div>
            <pre style={{ background: '#0f172a', color: '#f8fafc', padding: '16px', borderRadius: '8px', fontSize: '11px', maxHeight: '420px', overflow: 'auto', lineHeight: '1.5' }}>
              <code>{IOS_SWIFT_INTERCEPTOR}</code>
            </pre>
          </div>

          <div style={{ marginTop: '16px' }}>
            <strong>Safari Content Blocker Rules (blockerList.json)</strong>
            <pre style={{ background: '#0f172a', color: '#f8fafc', padding: '12px', borderRadius: '8px', fontSize: '10.5px', maxHeight: '200px', overflow: 'auto' }}>
              <code>{IOS_CONTENT_BLOCKER_JSON}</code>
            </pre>
          </div>
        </section>
      )}

      {/* 4. CENTRAL LINK EXTRACTOR TAB */}
      {activeTab === 'extractor' && (
        <section className="panel" style={{ padding: '24px' }}>
          <div className="section-kicker">LOCAL DE-OBFUSCATION HELPER</div>
          <h2>Central Link Extractor Engine</h2>
          <p className="muted-copy">
            Engineered to extract and normalize evasion attempts used in phishing messages: defanged bracketed dots, hxxp schemes, zero-width spaces, shorteners, and Punycode.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', marginBottom: '16px' }}>
            <div style={{ border: '1.5px solid #cbd5e1', padding: '12px', borderRadius: '8px' }}>
              <strong>Bracketed Dots</strong>
              <p style={{ fontSize: '10px', color: '#374151', margin: '4px 0 0' }}>
                Converts <code>evil[.]com</code> or <code>test(.)org</code> into standard resolvable hostnames.
              </p>
            </div>
            <div style={{ border: '1.5px solid #cbd5e1', padding: '12px', borderRadius: '8px' }}>
              <strong>Zero-Width Stripping</strong>
              <p style={{ fontSize: '10px', color: '#374151', margin: '4px 0 0' }}>
                Removes <code>\u200B</code> and direction overrides used by malware to break regex signatures.
              </p>
            </div>
            <div style={{ border: '1.5px solid #cbd5e1', padding: '12px', borderRadius: '8px' }}>
              <strong>k-Anonymity Hashes</strong>
              <p style={{ fontSize: '10px', color: '#374151', margin: '4px 0 0' }}>
                Truncates SHA-256 to 16 hex characters (8 bytes) so user visited domains are never exposed.
              </p>
            </div>
          </div>
        </section>
      )}

      {/* 5. CLOUD SQL DATABASE MANAGEMENT TAB */}
      {activeTab === 'database' && (
        <section className="panel" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div className="section-kicker">POSTGRESQL ON CLOUD SQL (effective-metric-pwjrd)</div>
              <h2>Malicious Domains Blocklist</h2>
              <p className="muted-copy">
                Indexed with <code>idx_hash_prefix</code> on <code>domain_hash_prefix (VARCHAR 16)</code> for sub-millisecond lookups.
              </p>
            </div>
            <div>
              {user ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '10px', fontWeight: 800 }}>{user.email}</span>
                  <button type="button" onClick={handleSignOut} className="button-secondary" style={{ height: '30px', fontSize: '9.5px' }}>
                    Sign Out
                  </button>
                </div>
              ) : (
                <button type="button" onClick={handleSignIn} className="button-primary" style={{ height: '32px', fontSize: '10px' }}>
                  Sign in with Google
                </button>
              )}
            </div>
          </div>

          {/* Add new entry form */}
          <div style={{ background: '#f8fafc', border: '1.5px solid #cbd5e1', borderRadius: '8px', padding: '16px', margin: '16px 0' }}>
            <strong style={{ fontSize: '11px', display: 'block', marginBottom: '8px' }}>
              Register Malicious Domain or Hash Prefix
            </strong>
            <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr auto', gap: '10px', alignItems: 'flex-end' }}>
              <div>
                <label className="field-label" style={{ margin: '0 0 4px' }}>DOMAIN OR 16-HEX HASH PREFIX</label>
                <input
                  type="text"
                  className="text-input"
                  placeholder="e.g. fake-bank-login.xyz or 15bacd47a3de26e7"
                  value={newDomainInput}
                  onChange={(e) => setNewDomainInput(e.target.value)}
                />
              </div>
              <div>
                <label className="field-label" style={{ margin: '0 0 4px' }}>THREAT CLASSIFICATION</label>
                <input
                  type="text"
                  className="text-input"
                  placeholder="e.g. phishing_credential_harvesting"
                  value={newThreatType}
                  onChange={(e) => setNewThreatType(e.target.value)}
                />
              </div>
              <button
                type="button"
                className="button-primary"
                onClick={handleAddDomainToDb}
                style={{ height: '38px' }}
              >
                + Add to Cloud SQL
              </button>
            </div>
          </div>

          {/* Table of Database Records */}
          <div style={{ marginTop: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <strong>Active Blocklist Entries ({dbDomains.length})</strong>
              <button type="button" onClick={fetchDatabaseDomains} className="text-button">
                ↻ Refresh Table
              </button>
            </div>

            {isLoadingDb ? (
              <div>Loading records from Cloud SQL...</div>
            ) : (
              <table className="indicator-table" style={{ width: '100%', fontSize: '11px' }}>
                <thead>
                  <tr style={{ background: '#f1f5f9', textAlign: 'left' }}>
                    <th style={{ padding: '8px' }}>ID</th>
                    <th style={{ padding: '8px' }}>Domain Hash Prefix (16-hex)</th>
                    <th style={{ padding: '8px' }}>Threat Classification</th>
                    <th style={{ padding: '8px', textAlign: 'right' }}>Created At</th>
                  </tr>
                </thead>
                <tbody>
                  {dbDomains.map((row: any) => (
                    <tr key={row.id}>
                      <td style={{ padding: '8px', fontWeight: 800 }}>#{row.id}</td>
                      <td style={{ padding: '8px' }}>
                        <code style={{ background: '#e2e8f0', padding: '2px 5px', borderRadius: '4px' }}>
                          {row.domainHashPrefix}
                        </code>
                      </td>
                      <td style={{ padding: '8px', color: '#b91c1c', fontWeight: 700 }}>
                        {row.threatType}
                      </td>
                      <td style={{ padding: '8px', textAlign: 'right', color: '#374151' }}>
                        {row.createdAt ? new Date(row.createdAt).toLocaleDateString() : 'Active'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>
      )}
    </section>
  );
};
