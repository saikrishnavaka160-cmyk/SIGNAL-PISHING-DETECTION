import React, { useState, useEffect } from 'react';
import { ViewType } from './types';
import { Sidebar } from './components/Sidebar';
import { Topbar } from './components/Topbar';
import { EmailView } from './components/EmailView';
import { GmailInboxView } from './components/GmailInboxView';
import { InvestigationCaseView } from './components/InvestigationCaseView';
import { DatasetView } from './components/DatasetView';
import { MobileInterceptionView } from './components/MobileInterceptionView';
import { PhishTraceView } from './components/PhishTraceView';
import { GuideView } from './components/GuideView';
import { Toast } from './components/Toast';
import { testConnection } from './lib/firebase';

export const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<ViewType>('email-view');
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [pendingTargetUrl, setPendingTargetUrl] = useState<string>('');

  useEffect(() => {
    // Validate connection to Firestore on initial boot per skill requirements
    testConnection();
  }, []);

  useEffect(() => {
    if (!toastMessage) return;
    const timer = setTimeout(() => {
      setToastMessage(null);
    }, 2800);
    return () => clearTimeout(timer);
  }, [toastMessage]);

  const showToast = (msg: string) => {
    setToastMessage(msg);
  };

  const handleSelectView = (view: ViewType) => {
    setCurrentView(view);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleTriageToCase = (url: string) => {
    setPendingTargetUrl(url);
    setCurrentView('cases-view');
    window.scrollTo({ top: 0, behavior: 'smooth' });
    showToast(`Target transferred to Investigation Cases workspace.`);
  };

  const handleInspectUrl = (url: string) => {
    setPendingTargetUrl(url);
    setCurrentView('phishtrace-view');
    window.scrollTo({ top: 0, behavior: 'smooth' });
    showToast(`Transferred URL to PhishTrace Forensics.`);
  };

  return (
    <div className="app-shell">
      <Sidebar currentView={currentView} onSelectView={handleSelectView} />
      <main className="main-content">
        <Topbar currentView={currentView} />

        {currentView === 'email-view' && (
          <EmailView
            onOpenGuide={() => handleSelectView('guide-view')}
            showToast={showToast}
          />
        )}

        {currentView === 'gmail-view' && (
          <GmailInboxView
            onTriageToCase={handleTriageToCase}
            onInspectUrl={handleInspectUrl}
            showToast={showToast}
          />
        )}

        {currentView === 'cases-view' && (
          <InvestigationCaseView
            initialTargetUrl={pendingTargetUrl}
            showToast={showToast}
          />
        )}

        {currentView === 'dataset-view' && (
          <DatasetView showToast={showToast} />
        )}

        {currentView === 'phishtrace-view' && (
          <PhishTraceView showToast={showToast} />
        )}

        {currentView === 'mobile-view' && (
          <MobileInterceptionView showToast={showToast} />
        )}

        {currentView === 'guide-view' && <GuideView />}

        <footer className="page-footer">
          <span>
            Signal <b>·</b> Local-first email &amp; URL defensive screening
          </span>
          <span>
            Zero-network AST heuristics <i>✳</i>
          </span>
        </footer>
      </main>

      <Toast message={toastMessage} />
    </div>
  );
};

export default App;
