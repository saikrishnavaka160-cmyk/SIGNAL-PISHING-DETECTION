import React from 'react';

export const GuideView: React.FC = () => {
  return (
    <section className="view" id="guide-view">
      <div className="subpage-heading">
        <div className="eyebrow">
          <span className="eyebrow-line"></span> TRANSPARENT BY DESIGN
        </div>
        <h1>How the score works.</h1>
        <p>Every result comes from visible rules, with analysis performed on your device.</p>
      </div>

      <div className="guide-grid">
        <article className="panel guide-intro">
          <div className="guide-icon">✳</div>
          <div className="section-kicker">THE SIGNAL SCORE</div>
          <h2>
            Clues add up.<br />Context still matters.
          </h2>
          <p>
            Each indicator adds points. The total groups a message into a risk band so you can decide what to check next.
          </p>
          <div className="score-scale">
            <span className="score-pill low-pill">0–2 <b>Low</b></span>
            <span className="score-pill suspicious-pill">3–6 <b>Suspicious</b></span>
            <span className="score-pill high-pill">7+ <b>High</b></span>
          </div>
        </article>

        <article className="panel guide-rules">
          <div className="section-kicker">WHAT WE LOOK FOR</div>
          <h2>Common warning signs</h2>
          <div className="rule-list">
            <div>
              <span className="rule-symbol amber">↯</span>
              <p>
                <strong>Urgent language</strong>
                <small>Pressure, threats, or a deadline that pushes you to act quickly.</small>
              </p>
              <b>+2</b>
            </div>
            <div>
              <span className="rule-symbol rose">⌑</span>
              <p>
                <strong>Sensitive information</strong>
                <small>Requests for passwords, sign-in codes, or identity details.</small>
              </p>
              <b>+2</b>
            </div>
            <div>
              <span className="rule-symbol amber">＄</span>
              <p>
                <strong>Payment requests</strong>
                <small>Transfers, gift cards, overdue invoices, or payment updates.</small>
              </p>
              <b>+2</b>
            </div>
            <div>
              <span className="rule-symbol blue">↗</span>
              <p>
                <strong>Suspicious links</strong>
                <small>Hidden destinations, URL shorteners, raw IPs, or odd encoding.</small>
              </p>
              <b>+1–3</b>
            </div>
            <div>
              <span className="rule-symbol rose">⊘</span>
              <p>
                <strong>Authentication and sender</strong>
                <small>Reported SPF, DKIM, DMARC failures or brand and sender mismatch.</small>
              </p>
              <b>+2–3</b>
            </div>
            <div>
              <span className="rule-symbol blue">▧</span>
              <p>
                <strong>Risky attachments</strong>
                <small>Executable files and scripts that can run code.</small>
              </p>
              <b>+3</b>
            </div>
          </div>
        </article>
      </div>

      <div className="disclaimer guide-disclaimer">
        <span>ⓘ</span>
        <p>
          <strong>Rules have limits.</strong> Authentication results can be missing or untrusted in forwarded mail,
          and these checks cannot inspect remote websites. Interpret low scores alongside normal security controls.
        </p>
      </div>
    </section>
  );
};
