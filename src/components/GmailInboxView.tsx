import React, { useState, useEffect } from 'react';
import {
  fetchInboxMessages,
  ParsedGmailEmail,
  applyPhishingLabel,
  archiveGmailMessage,
  trashGmailMessage,
} from '../services/gmail';
import {
  signInWithGoogle,
  signOutGoogle,
  getGoogleAccessToken,
  subscribeToAuth,
} from '../services/googleAuth';
import { User } from 'firebase/auth';

interface GmailInboxViewProps {
  onTriageToCase?: (url: string, emailContext: string) => void;
  onInspectUrl?: (url: string) => void;
  showToast: (msg: string) => void;
}

export const GmailInboxView: React.FC<GmailInboxViewProps> = ({
  onTriageToCase,
  onInspectUrl,
  showToast,
}) => {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(getGoogleAccessToken());
  const [emails, setEmails] = useState<ParsedGmailEmail[]>([]);
  const [selectedEmail, setSelectedEmail] = useState<ParsedGmailEmail | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('in:inbox');
  const [error, setError] = useState<string | null>(null);

  // Destructive action confirmation modal
  const [confirmModal, setConfirmModal] = useState<{
    action: 'label' | 'archive' | 'trash';
    messageId: string;
    subject: string;
  } | null>(null);

  useEffect(() => {
    const unsub = subscribeToAuth((user, token) => {
      setCurrentUser(user);
      setAccessToken(token);
      if (token) {
        loadInbox(token, searchQuery);
      } else {
        setEmails([]);
        setSelectedEmail(null);
      }
    });
    return () => unsub();
  }, []);

  const loadInbox = async (token: string, query: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const msgs = await fetchInboxMessages(token, { maxResults: 15, query });
      setEmails(msgs);
      if (msgs.length > 0 && !selectedEmail) {
        setSelectedEmail(msgs[0]);
      }
    } catch (err) {
      console.error('Failed to load Gmail messages:', err);
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsLoading(false);
    }
  };

  const handleSignIn = async () => {
    try {
      setIsLoading(true);
      const { accessToken: token } = await signInWithGoogle();
      if (token) {
        await loadInbox(token, searchQuery);
        showToast('Connected to Gmail with zero-network link safety screening.');
      } else {
        showToast('Signed in. Please ensure Gmail permissions were granted.');
      }
    } catch (e) {
      console.error('Sign-in error:', e);
      showToast('Authentication error: ' + (e instanceof Error ? e.message : String(e)));
    } finally {
      setIsLoading(false);
    }
  };

  const handleSignOut = async () => {
    try {
      await signOutGoogle();
      showToast('Signed out of Gmail.');
    } catch (e) {
      console.error('Sign-out error:', e);
    }
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (!accessToken) return;
    loadInbox(accessToken, searchQuery);
  };

  const executeConfirmedAction = async () => {
    if (!confirmModal || !accessToken) return;
    const { action, messageId, subject } = confirmModal;
    setConfirmModal(null);
    setIsLoading(true);

    try {
      if (action === 'label') {
        await applyPhishingLabel(accessToken, messageId);
        showToast(`Applied "Signal-Suspicious" label to "${subject}"`);
      } else if (action === 'archive') {
        await archiveGmailMessage(accessToken, messageId);
        showToast(`Archived "${subject}" from Inbox`);
        setEmails(emails.filter((m) => m.id !== messageId));
        if (selectedEmail?.id === messageId) setSelectedEmail(null);
      } else if (action === 'trash') {
        await trashGmailMessage(accessToken, messageId);
        showToast(`Moved "${subject}" to Trash`);
        setEmails(emails.filter((m) => m.id !== messageId));
        if (selectedEmail?.id === messageId) setSelectedEmail(null);
      }
    } catch (e) {
      console.error('Action failed:', e);
      showToast('Action failed: ' + (e instanceof Error ? e.message : String(e)));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="gmail-workspace">
      {/* Top Header */}
      <div className="page-heading">
        <div>
          <div className="eyebrow">
            <span className="eyebrow-line"></span> GOOGLE WORKSPACE SECURITY
          </div>
          <h1 style={{ color: '#000000', fontWeight: 800 }}>
            Gmail Inbox Triage &amp; Link Screening
          </h1>
          <p className="heading-copy" style={{ color: '#1e293b' }}>
            Inspect incoming messages in real-time, audit SPF/DKIM authentication records, and triage extracted URLs without touching live destinations.
          </p>
        </div>

        <div>
          {!currentUser || !accessToken ? (
            <button
              onClick={handleSignIn}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '12px',
                padding: '11px 20px',
                background: '#ffffff',
                border: '1px solid #d1d5db',
                borderRadius: '8px',
                color: '#1e293b',
                fontWeight: 600,
                fontSize: '14px',
                cursor: 'pointer',
                boxShadow: '0 1px 3px rgba(0,0,0,0.08)',
              }}
            >
              <svg width="20" height="20" viewBox="0 0 24 24">
                <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" />
                <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" />
              </svg>
              Sign in with Google
            </button>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: '13px', fontWeight: 700, color: '#000000' }}>
                  {currentUser.displayName || 'Authorized Investigator'}
                </div>
                <div style={{ fontSize: '11px', color: '#64748b' }}>
                  {currentUser.email}
                </div>
              </div>
              <button
                onClick={handleSignOut}
                style={{
                  padding: '8px 14px',
                  background: '#f3f4f6',
                  border: '1px solid #d1d5db',
                  borderRadius: '6px',
                  fontSize: '12px',
                  fontWeight: 600,
                  color: '#1e293b',
                  cursor: 'pointer',
                }}
              >
                Sign out
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Main Content Area */}
      {!accessToken ? (
        <div style={{ background: '#ffffff', border: '1px solid #d1d5db', borderRadius: '12px', padding: '60px 20px', textAlign: 'center', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.05)' }}>
          <div style={{ width: '56px', height: '56px', margin: '0 auto 16px', background: '#eff6ff', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#2563eb', fontSize: '24px' }}>
            ✉
          </div>
          <h2 style={{ fontSize: '20px', fontWeight: 800, color: '#000000', margin: '0 0 10px 0' }}>
            Connect Your Gmail Workspace
          </h2>
          <p style={{ maxWidth: '480px', margin: '0 auto 24px', fontSize: '14px', color: '#1e293b', lineHeight: 1.6 }}>
            Screen your inbox against phishing and credential lures directly in your browser. All URL and heuristic analysis runs locally with zero network requests to target destinations.
          </p>
          <button
            onClick={handleSignIn}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '12px',
              padding: '12px 24px',
              background: '#ffffff',
              border: '1px solid #d1d5db',
              borderRadius: '8px',
              color: '#1e293b',
              fontWeight: 700,
              fontSize: '14px',
              cursor: 'pointer',
              boxShadow: '0 2px 4px rgba(0,0,0,0.06)',
            }}
          >
            <svg width="20" height="20" viewBox="0 0 24 24">
              <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
              <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
              <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" />
              <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" />
            </svg>
            Sign in with Google
          </button>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '400px 1fr', gap: '20px', alignItems: 'start' }}>
          {/* Email List Left Panel */}
          <div style={{ background: '#ffffff', border: '1px solid #d1d5db', borderRadius: '12px', padding: '16px', minHeight: '600px' }}>
            {/* Search filter form */}
            <form onSubmit={handleSearch} style={{ display: 'flex', gap: '8px', marginBottom: '14px' }}>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search mail (e.g. in:inbox, is:unread)"
                style={{ flex: 1, padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: '6px', fontSize: '13px', color: '#000000' }}
              />
              <button
                type="submit"
                disabled={isLoading}
                style={{ padding: '8px 14px', background: '#2563eb', color: '#ffffff', border: 'none', borderRadius: '6px', fontSize: '13px', fontWeight: 600, cursor: 'pointer' }}
              >
                Filter
              </button>
            </form>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px', paddingBottom: '6px', borderBottom: '1px solid #f1f5f9' }}>
              <span style={{ fontSize: '11px', fontWeight: 800, color: '#475569', textTransform: 'uppercase' }}>
                INBOX MESSAGES ({emails.length})
              </span>
              <button
                onClick={() => loadInbox(accessToken, searchQuery)}
                disabled={isLoading}
                style={{ background: 'transparent', border: 'none', color: '#2563eb', fontSize: '12px', fontWeight: 600, cursor: 'pointer' }}
              >
                {isLoading ? 'Scanning...' : '↻ Refresh'}
              </button>
            </div>

            {error && (
              <div style={{ padding: '10px', background: '#fef2f2', border: '1px solid #fecaca', borderRadius: '6px', color: '#991b1b', fontSize: '12px', marginBottom: '10px' }}>
                {error}
              </div>
            )}

            {emails.length === 0 && !isLoading ? (
              <div style={{ textAlign: 'center', padding: '40px 10px', color: '#64748b', fontSize: '13px' }}>
                No messages found matching "{searchQuery}".
              </div>
            ) : (
              <div style={{ display: 'grid', gap: '8px', maxHeight: '700px', overflowY: 'auto' }}>
                {emails.map((m) => {
                  const isSelected = selectedEmail?.id === m.id;
                  const isHighRisk = m.analysis.risk === 'High';
                  const isSuspicious = m.analysis.risk === 'Suspicious';
                  const badgeColor = isHighRisk ? '#b91c1c' : isSuspicious ? '#b45309' : '#15803d';
                  const badgeBg = isHighRisk ? '#fee2e2' : isSuspicious ? '#fef3c7' : '#dcfce7';

                  return (
                    <div
                      key={m.id}
                      onClick={() => setSelectedEmail(m)}
                      style={{
                        padding: '12px',
                        border: isSelected ? '2px solid #2563eb' : '1px solid #e2e8f0',
                        borderRadius: '8px',
                        cursor: 'pointer',
                        background: isSelected ? '#eff6ff' : '#ffffff',
                        transition: 'all 0.15s ease',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                        <span style={{ fontSize: '12px', fontWeight: 700, color: '#000000', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '220px' }}>
                          {m.from.replace(/<.*>/, '').trim() || m.from}
                        </span>
                        <span style={{ fontSize: '10px', fontWeight: 800, padding: '2px 6px', borderRadius: '4px', background: badgeBg, color: badgeColor, textTransform: 'uppercase' }}>
                          {m.analysis.risk}
                        </span>
                      </div>
                      <div style={{ fontSize: '13px', fontWeight: 600, color: '#000000', marginBottom: '4px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {m.subject}
                      </div>
                      <div style={{ fontSize: '11px', color: '#64748b', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginBottom: '6px' }}>
                        {m.snippet}
                      </div>
                      <div style={{ display: 'flex', gap: '6px', alignItems: 'center', fontSize: '10px', color: '#475569' }}>
                        <span style={{ background: '#f1f5f9', padding: '2px 5px', borderRadius: '3px' }}>
                          SPF: {m.spfStatus.toUpperCase()}
                        </span>
                        <span style={{ background: '#f1f5f9', padding: '2px 5px', borderRadius: '3px' }}>
                          DKIM: {m.dkimStatus.toUpperCase()}
                        </span>
                        {m.extractedUrls.length > 0 && (
                          <span style={{ background: '#eff6ff', color: '#2563eb', padding: '2px 5px', borderRadius: '3px', fontWeight: 700 }}>
                            🔗 {m.extractedUrls.length} links
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Email Inspection Right Detail Panel */}
          {selectedEmail ? (
            <div style={{ background: '#ffffff', border: '1px solid #d1d5db', borderRadius: '12px', padding: '20px' }}>
              {/* Header details */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid #f1f5f9', paddingBottom: '16px', marginBottom: '16px' }}>
                <div>
                  <h2 style={{ margin: '0 0 6px 0', fontSize: '18px', fontWeight: 800, color: '#000000' }}>
                    {selectedEmail.subject}
                  </h2>
                  <div style={{ fontSize: '13px', color: '#1e293b', marginBottom: '4px' }}>
                    <strong>From:</strong> {selectedEmail.from}
                  </div>
                  <div style={{ fontSize: '12px', color: '#64748b' }}>
                    <strong>Date:</strong> {selectedEmail.date}
                  </div>
                </div>

                {/* Workspace Action Buttons */}
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    onClick={() => setConfirmModal({ action: 'label', messageId: selectedEmail.id, subject: selectedEmail.subject })}
                    style={{ padding: '6px 12px', background: '#fef3c7', color: '#92400e', border: '1px solid #fde68a', borderRadius: '6px', fontSize: '12px', fontWeight: 600, cursor: 'pointer' }}
                  >
                    🏷 Apply Phishing Label
                  </button>
                  <button
                    onClick={() => setConfirmModal({ action: 'archive', messageId: selectedEmail.id, subject: selectedEmail.subject })}
                    style={{ padding: '6px 12px', background: '#f3f4f6', color: '#374151', border: '1px solid #d1d5db', borderRadius: '6px', fontSize: '12px', fontWeight: 600, cursor: 'pointer' }}
                  >
                    Archive
                  </button>
                  <button
                    onClick={() => setConfirmModal({ action: 'trash', messageId: selectedEmail.id, subject: selectedEmail.subject })}
                    style={{ padding: '6px 12px', background: '#fee2e2', color: '#991b1b', border: '1px solid #fecaca', borderRadius: '6px', fontSize: '12px', fontWeight: 600, cursor: 'pointer' }}
                  >
                    Move to Trash
                  </button>
                </div>
              </div>

              {/* Security Triage Summary Card */}
              <div style={{ background: selectedEmail.analysis.risk === 'High' ? '#fff5f5' : selectedEmail.analysis.risk === 'Suspicious' ? '#fffbeb' : '#f0fdf4', border: `1px solid ${selectedEmail.analysis.risk === 'High' ? '#fecaca' : selectedEmail.analysis.risk === 'Suspicious' ? '#fde68a' : '#bbf7d0'}`, borderRadius: '8px', padding: '16px', marginBottom: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontWeight: 800, fontSize: '15px', color: selectedEmail.analysis.risk === 'High' ? '#991b1b' : selectedEmail.analysis.risk === 'Suspicious' ? '#92400e' : '#166534' }}>
                      Security Rating: {selectedEmail.analysis.risk.toUpperCase()} RISK
                    </span>
                    <span style={{ fontSize: '12px', color: '#475569' }}>
                      (Score: {selectedEmail.analysis.score}/100)
                    </span>
                  </div>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <span style={{ fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '4px', background: selectedEmail.spfStatus === 'pass' ? '#dcfce7' : '#fee2e2', color: selectedEmail.spfStatus === 'pass' ? '#15803d' : '#991b1b' }}>
                      SPF: {selectedEmail.spfStatus.toUpperCase()}
                    </span>
                    <span style={{ fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '4px', background: selectedEmail.dkimStatus === 'pass' ? '#dcfce7' : '#fee2e2', color: selectedEmail.dkimStatus === 'pass' ? '#15803d' : '#991b1b' }}>
                      DKIM: {selectedEmail.dkimStatus.toUpperCase()}
                    </span>
                  </div>
                </div>

                {/* Signals trigger list */}
                {selectedEmail.analysis.signals.length > 0 ? (
                  <div style={{ display: 'grid', gap: '6px', marginTop: '10px' }}>
                    {selectedEmail.analysis.signals.map((sig) => (
                      <div key={sig.code} style={{ fontSize: '12px', color: '#1e293b', display: 'flex', gap: '6px', alignItems: 'center' }}>
                        <span style={{ color: '#b91c1c', fontWeight: 800 }}>•</span>
                        <strong>{sig.description}</strong>
                        <span style={{ color: '#64748b', fontSize: '11px' }}>({sig.points} pts)</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize: '12px', color: '#166534' }}>
                    ✓ No malicious urgency, credential requests, or spoofing heuristics detected.
                  </div>
                )}
              </div>

              {/* Extracted URLs Table with Deep Inspection */}
              {selectedEmail.extractedUrls.length > 0 && (
                <div style={{ marginBottom: '20px' }}>
                  <h4 style={{ margin: '0 0 10px 0', fontSize: '14px', fontWeight: 800, color: '#000000' }}>
                    Extracted URLs ({selectedEmail.extractedUrls.length}) — Zero-Network Inspection
                  </h4>
                  <div style={{ display: 'grid', gap: '8px' }}>
                    {selectedEmail.extractedUrls.map((u, idx) => (
                      <div
                        key={idx}
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          padding: '10px 14px',
                          border: '1px solid #e2e8f0',
                          borderRadius: '8px',
                          background: '#f8fafc',
                        }}
                      >
                        <code style={{ fontSize: '12px', color: '#000000', wordBreak: 'break-all', fontFamily: 'monospace' }}>
                          {u}
                        </code>
                        <div style={{ display: 'flex', gap: '8px', minWidth: '220px', justifyContent: 'flex-end' }}>
                          {onInspectUrl && (
                            <button
                              onClick={() => onInspectUrl(u)}
                              style={{ padding: '5px 10px', background: '#eff6ff', color: '#2563eb', border: '1px solid #bfdbfe', borderRadius: '4px', fontSize: '11px', fontWeight: 600, cursor: 'pointer' }}
                            >
                              🔬 Forensics
                            </button>
                          )}
                          {onTriageToCase && (
                            <button
                              onClick={() => onTriageToCase(u, `Email from ${selectedEmail.from}: ${selectedEmail.subject}`)}
                              style={{ padding: '5px 10px', background: '#2563eb', color: '#ffffff', border: 'none', borderRadius: '4px', fontSize: '11px', fontWeight: 600, cursor: 'pointer' }}
                            >
                              + Open Case
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Body Content Safe Preview */}
              <div>
                <h4 style={{ margin: '0 0 10px 0', fontSize: '14px', fontWeight: 800, color: '#000000' }}>
                  Safe Message Content Preview
                </h4>
                <div
                  style={{
                    background: '#f8fafc',
                    border: '1px solid #e2e8f0',
                    borderRadius: '8px',
                    padding: '16px',
                    fontSize: '13px',
                    color: '#000000',
                    lineHeight: 1.6,
                    whiteSpace: 'pre-wrap',
                    maxHeight: '350px',
                    overflowY: 'auto',
                    fontFamily: 'system-ui, -apple-system, sans-serif',
                  }}
                >
                  {selectedEmail.bodyText || selectedEmail.snippet || '(No body content available)'}
                </div>
              </div>
            </div>
          ) : (
            <div style={{ background: '#ffffff', border: '1px solid #d1d5db', borderRadius: '12px', padding: '40px', textAlign: 'center' }}>
              <p style={{ margin: 0, color: '#64748b' }}>Select an email from the left column to screen headers, analyze heuristics, and inspect extracted links.</p>
            </div>
          )}
        </div>
      )}

      {/* Confirmation Modal for Modifying/Destructive Workspace Actions */}
      {confirmModal && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '20px' }}>
          <div style={{ background: '#ffffff', borderRadius: '12px', width: '100%', maxWidth: '480px', padding: '24px', boxShadow: '0 20px 25px -5px rgba(0,0,0,0.2)' }}>
            <h3 style={{ margin: '0 0 12px 0', fontSize: '16px', fontWeight: 800, color: '#000000' }}>
              Confirm Gmail Action
            </h3>
            <p style={{ fontSize: '13px', color: '#1e293b', lineHeight: 1.6, margin: '0 0 16px 0' }}>
              {confirmModal.action === 'trash' && (
                <>Are you sure you want to move <strong>"{confirmModal.subject}"</strong> to the Gmail Trash? This action can be undone from your Gmail Trash folder.</>
              )}
              {confirmModal.action === 'archive' && (
                <>Are you sure you want to archive <strong>"{confirmModal.subject}"</strong>? This will remove the INBOX label and keep it accessible in All Mail.</>
              )}
              {confirmModal.action === 'label' && (
                <>Are you sure you want to apply the <strong>Signal-Suspicious</strong> label to <strong>"{confirmModal.subject}"</strong> in your Gmail account?</>
              )}
            </p>
            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setConfirmModal(null)}
                style={{ padding: '8px 16px', background: '#f3f4f6', border: '1px solid #d1d5db', borderRadius: '6px', fontWeight: 600, fontSize: '13px', cursor: 'pointer', color: '#1e293b' }}
              >
                Cancel
              </button>
              <button
                onClick={executeConfirmedAction}
                style={{
                  padding: '8px 18px',
                  background: confirmModal.action === 'trash' ? '#b91c1c' : '#2563eb',
                  border: 'none',
                  borderRadius: '6px',
                  fontWeight: 600,
                  fontSize: '13px',
                  cursor: 'pointer',
                  color: '#ffffff',
                }}
              >
                Confirm Action
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
