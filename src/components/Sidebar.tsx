import React from 'react';
import { ViewType } from '../types';

interface SidebarProps {
  currentView: ViewType;
  onSelectView: (view: ViewType) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentView, onSelectView }) => {
  return (
    <aside className="sidebar">
      <a className="brand" href="#" onClick={(e) => { e.preventDefault(); onSelectView('email-view'); }} aria-label="Signal home">
        <span className="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 40 40" fill="none">
            <path d="M20 4.5 33 9v9.4c0 8.2-5.5 14.3-13 17.1-7.5-2.8-13-8.9-13-17.1V9l13-4.5Z" fill="currentColor" opacity=".15" />
            <path d="M20 4.5 33 9v9.4c0 8.2-5.5 14.3-13 17.1-7.5-2.8-13-8.9-13-17.1V9l13-4.5Z" stroke="currentColor" strokeWidth="2" />
            <path d="m14.5 20.5 3.7 3.7 7.6-8" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </span>
        <span className="brand-name">signal<span className="brand-dot">.</span></span>
      </a>

      <div className="workspace-label">WORKSPACE</div>

      <nav className="nav-group" aria-label="Main navigation">
        <button
          className={`nav-link ${currentView === 'email-view' ? 'active' : ''}`}
          onClick={() => onSelectView('email-view')}
          type="button"
        >
          <span className="nav-icon">⌕</span>
          <span>Analyze email</span>
          {currentView === 'email-view' && <span className="nav-arrow">›</span>}
        </button>

        <button
          className={`nav-link ${currentView === 'gmail-view' ? 'active' : ''}`}
          onClick={() => onSelectView('gmail-view')}
          type="button"
        >
          <span className="nav-icon">✉</span>
          <span>Gmail inbox</span>
          {currentView === 'gmail-view' && <span className="nav-arrow">›</span>}
        </button>

        <button
          className={`nav-link ${currentView === 'cases-view' ? 'active' : ''}`}
          onClick={() => onSelectView('cases-view')}
          type="button"
        >
          <span className="nav-icon">📁</span>
          <span>Investigation cases</span>
          {currentView === 'cases-view' && <span className="nav-arrow">›</span>}
        </button>

        <button
          className={`nav-link ${currentView === 'dataset-view' ? 'active' : ''}`}
          onClick={() => onSelectView('dataset-view')}
          type="button"
        >
          <span className="nav-icon">▦</span>
          <span>Dataset review</span>
          {currentView === 'dataset-view' && <span className="nav-arrow">›</span>}
        </button>

        <button
          className={`nav-link ${currentView === 'phishtrace-view' ? 'active' : ''}`}
          onClick={() => onSelectView('phishtrace-view')}
          type="button"
        >
          <span className="nav-icon">🔬</span>
          <span>PhishTrace URL</span>
          {currentView === 'phishtrace-view' && <span className="nav-arrow">›</span>}
        </button>

        <button
          className={`nav-link ${currentView === 'mobile-view' ? 'active' : ''}`}
          onClick={() => onSelectView('mobile-view')}
          type="button"
        >
          <span className="nav-icon">📱</span>
          <span>Mobile interceptor</span>
          {currentView === 'mobile-view' && <span className="nav-arrow">›</span>}
        </button>

        <button
          className={`nav-link ${currentView === 'guide-view' ? 'active' : ''}`}
          onClick={() => onSelectView('guide-view')}
          type="button"
        >
          <span className="nav-icon">◉</span>
          <span>How it works</span>
          {currentView === 'guide-view' && <span className="nav-arrow">›</span>}
        </button>
      </nav>

      <div className="sidebar-bottom">
        <div className="privacy-card">
          <span className="privacy-icon">✳</span>
          <div>
            <strong>Your inbox stays yours.</strong>
            <p>Analysis happens in this browser. Nothing is uploaded.</p>
          </div>
          <span className="privacy-lock">⌑</span>
        </div>
        <div className="sidebar-footer">
          <span className="status-dot"></span>
          Local analysis <span className="footer-version">v1.0</span>
        </div>
      </div>
    </aside>
  );
};
