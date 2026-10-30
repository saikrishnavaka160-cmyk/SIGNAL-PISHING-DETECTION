import React, { useState, useRef, useEffect } from 'react';
import { AnalysisResult } from '../types';
import { analyzeEmail, parseMail, TITLES } from '../detector';

interface EmailViewProps {
  onOpenGuide: () => void;
  showToast: (msg: string) => void;
}

export const EmailView: React.FC<EmailViewProps> = ({ onOpenGuide, showToast }) => {
  const [sender, setSender] = useState('');
  const [content, setContent] = useState('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [scoreWidth, setScoreWidth] = useState<number>(0);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (result) {
      setScoreWidth(0);
      const timer = setTimeout(() => {
        setScoreWidth(Math.min(100, Math.max(5, (result.score / 12) * 100)));
      }, 35);
      return () => clearTimeout(timer);
    } else {
      setScoreWidth(0);
    }
  }, [result]);

  const handleClear = () => {
    setContent('');
    setSender('');
    setResult(null);
  };

  const handleLoadSample = () => {
    const sampleSender = 'Amazon Account Team <account-alert@secure-amazon-support.co>';
    const sampleContent =
      'From: Amazon Account Team <account-alert@secure-amazon-support.co>\n' +
      'Subject: URGENT: Verify your account immediately\n' +
      'Authentication-Results: mx.example; dkim=fail; spf=softfail\n\n' +
      'Your account will be suspended within 24 hours. Sign in to verify your account and update your payment details: https://bit.ly/account-review\n\n' +
      'Please act immediately to avoid interruption.';

    setSender(sampleSender);
    setContent(sampleContent);
    showToast('Sample loaded. Select Analyze email to see the result.');
  };

  const processFile = (file: File) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const text = String(reader.result || '');
      setContent(text);
      const parsed = parseMail(text);
      if (parsed.from) {
        setSender(parsed.from);
      }
      showToast('Email loaded locally. Review it, then analyze.');
    };
    reader.readAsText(file);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      processFile(e.target.files[0]);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  };

  const handleAnalyze = () => {
    if (!content.trim()) {
      showToast('Paste an email or load a sample to begin.');
      if (textareaRef.current) {
        textareaRef.current.focus();
      }
      return;
    }
    const res = analyzeEmail(content, sender.trim() || null);
    setResult(res);
  };

  const getResultTitle = (risk: 'High' | 'Suspicious' | 'Low') => {
    if (risk === 'Low') return 'No strong signals found';
    if (risk === 'High') return 'Several risk signals found';
    return 'Some signals need a closer look';
  };

  const getScoreFillClass = (risk: 'High' | 'Suspicious' | 'Low') => {
    if (risk === 'High') return 'high';
    if (risk === 'Suspicious') return 'suspicious';
    return '';
  };

  return (
    <section className="view" id="email-view">
      <div className="page-heading">
        <div>
          <div className="eyebrow">
            <span className="eyebrow-line"></span> EMAIL SECURITY, MADE CLEAR
          </div>
          <h1>
            Check an email<br className="mobile-break" /> before you click.
          </h1>
          <p className="heading-copy">
            Spot the signals. Understand the risk. Make your next move with confidence.
          </p>
        </div>
        <div className="heading-illustration" aria-hidden="true">
          <div className="illustration-orbit orbit-one"></div>
          <div className="illustration-orbit orbit-two"></div>
          <div className="illustration-shield">
            <svg viewBox="0 0 78 88" fill="none">
              <path
                d="M39 5 69 16v21.5c0 19-12.7 33.1-30 39.5C21.7 70.6 9 56.5 9 37.5V16L39 5Z"
                fill="#EFF5FF"
                stroke="#2F6BFF"
                strokeWidth="2.5"
              />
              <path
                d="m26 42 9 9 18-19"
                stroke="#2F6BFF"
                strokeWidth="4"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </div>
          <span className="float-dot dot-a"></span>
          <span className="float-dot dot-b"></span>
        </div>
      </div>

      <div className="content-grid">
        <section className="panel input-panel">
          <div className="panel-title-row">
            <div>
              <div className="section-kicker">01 <span>·</span> THE MESSAGE</div>
              <h2>Paste an email to scan</h2>
            </div>
            <button className="text-button" id="clear-email" type="button" onClick={handleClear}>
              Clear
            </button>
          </div>

          <div
            className={`drop-zone ${isDragOver ? 'drag-over' : ''}`}
            id="email-drop-zone"
            onClick={() => fileInputRef.current?.click()}
            onDragEnter={handleDragOver}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
          >
            <input
              id="eml-file"
              ref={fileInputRef}
              type="file"
              accept=".eml,.txt,message/rfc822,text/plain"
              hidden
              onChange={handleFileChange}
            />
            <span className="upload-icon">
              <svg viewBox="0 0 24 24" fill="none">
                <path
                  d="M12 16V4m0 0L7.5 8.5M12 4l4.5 4.5M5 14v4.5A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5V14"
                  stroke="currentColor"
                  strokeWidth="1.7"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            </span>
            <span>
              <strong>Drop an .eml file here</strong>
              <small>
                or{' '}
                <button
                  id="browse-email"
                  className="inline-button"
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    fileInputRef.current?.click();
                  }}
                >
                  browse files
                </button>{' '}
                from your device
              </small>
            </span>
            <span className="file-type">.EML · .TXT</span>
          </div>

          <label className="field-label" htmlFor="sender-input">
            SENDER <span>(OPTIONAL)</span>
          </label>
          <input
            className="text-input"
            id="sender-input"
            type="text"
            placeholder="e.g. Billing Team <help@example.com>"
            autoComplete="off"
            value={sender}
            onChange={(e) => setSender(e.target.value)}
          />

          <label className="field-label message-label" htmlFor="email-input">
            EMAIL CONTENT
          </label>
          <textarea
            className="email-textarea"
            id="email-input"
            ref={textareaRef}
            placeholder="Paste the full email, including headers if available…"
            value={content}
            onChange={(e) => setContent(e.target.value)}
          />

          <div className="input-footer">
            <span>
              <span className="privacy-mini">⌑</span> Your message is analyzed locally and never leaves this page.
            </span>
            <span id="char-count">{content.length.toLocaleString()} characters</span>
          </div>

          <div className="action-row">
            <button className="button-secondary" id="load-sample" type="button" onClick={handleLoadSample}>
              Try a sample <span>↗</span>
            </button>
            <button className="button-primary" id="analyze-email" type="button" onClick={handleAnalyze}>
              <span className="button-spark">✳</span> Analyze email <span className="button-arrow">→</span>
            </button>
          </div>
        </section>

        <section className="panel result-panel" id="email-result-panel">
          {!result ? (
            <div className="empty-state" id="email-empty">
              <div className="empty-art">
                <div className="empty-ring ring-a"></div>
                <div className="empty-ring ring-b"></div>
                <div className="empty-envelope">
                  <svg viewBox="0 0 78 62" fill="none">
                    <rect x="7" y="8" width="64" height="46" rx="8" fill="white" stroke="#CED7E5" strokeWidth="2" />
                    <path
                      d="m10 14 29 22 29-22"
                      stroke="#AAB8CC"
                      strokeWidth="2.5"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                    <path d="M11 50 30 34m37 16L48 34" stroke="#D5DDE8" strokeWidth="2" strokeLinecap="round" />
                  </svg>
                </div>
                <span className="empty-star">✳</span>
              </div>
              <h2>Your results will appear here</h2>
              <p>
                Paste an email and run an analysis<br />to see its risk signals.
              </p>
              <div className="empty-legend">
                <span><i className="legend-dot low"></i>Low</span>
                <span><i className="legend-dot mid"></i>Suspicious</span>
                <span><i className="legend-dot high"></i>High risk</span>
              </div>
            </div>
          ) : (
            <div className="result-content" id="email-result">
              <div className="result-top">
                <div>
                  <div className="result-label">ANALYSIS COMPLETE</div>
                  <h2 className="result-title">{getResultTitle(result.risk)}</h2>
                  <p className="result-subtitle">
                    {result.sender ? `Sender: ${result.sender}` : 'No sender address provided'}
                  </p>
                </div>
                <span className={`risk-pill risk-${result.risk.toLowerCase()}`}>
                  {result.risk.toUpperCase()} RISK
                </span>
              </div>

              <div className="score-card">
                <div className="score-card-head">
                  <span>Rule score</span>
                  <div className="score-value">
                    {result.score} <small>points</small>
                  </div>
                </div>
                <div className="score-track">
                  <div
                    className={`score-fill ${getScoreFillClass(result.risk)}`}
                    style={{ width: `${scoreWidth}%` }}
                  ></div>
                </div>
                <div className="score-scale-small">
                  <span>Low · 0–2</span>
                  <span>Suspicious · 3–6</span>
                  <span>High · 7+</span>
                </div>
              </div>

              <div className="signals-heading">
                <strong>What we noticed</strong>
                <span>
                  {result.signals.length} indicator{result.signals.length === 1 ? '' : 's'}
                </span>
              </div>

              <div className="signal-list">
                {result.signals.length > 0 ? (
                  result.signals.map((s) => (
                    <div
                      key={s.code}
                      className={`signal-item ${s.points >= 3 ? 'critical' : ''}`}
                    >
                      <span className="signal-icon">{s.points >= 3 ? '!' : '↗'}</span>
                      <div>
                        <strong>{TITLES[s.code] || s.code}</strong>
                        <p>{s.description}</p>
                      </div>
                      <span className="points">+{s.points}</span>
                    </div>
                  ))
                ) : (
                  <div className="no-signals">
                    No strong indicators were found by these rules. Stay cautious with unexpected requests.
                  </div>
                )}
              </div>

              <div className="result-meta">
                <div className="meta-label">LINK DOMAINS</div>
                <div className="domain-chips">
                  {result.linkDomains.length > 0 ? (
                    result.linkDomains.map((h) => (
                      <span key={h} className="domain-chip">
                        {h}
                      </span>
                    ))
                  ) : (
                    <span className="domain-chip">No links detected</span>
                  )}
                </div>
              </div>

              {result.attachments.length > 0 && (
                <div className="result-meta">
                  <div className="meta-label">ATTACHMENTS</div>
                  <div className="domain-chips">
                    {result.attachments.map((f) => (
                      <span key={f} className="domain-chip">
                        {f}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <p className="result-disclaimer">
                Treat this heuristic as one input. Verify unexpected requests through a known, trusted channel.
              </p>
            </div>
          )}
        </section>
      </div>

      <div className="disclaimer">
        <span>ⓘ</span>
        <p>
          <strong>Use this as a screening aid.</strong> Interpret low-risk results alongside the message context, and
          verify unexpected requests through a trusted channel.
        </p>
        <button type="button" onClick={onOpenGuide} data-open-guide>
          Learn about the scoring <span>→</span>
        </button>
      </div>
    </section>
  );
};
