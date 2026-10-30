# Signal — Email Security Screening & Incident Forensics Platform

Signal is a defensive cybersecurity email screening platform and explainable URL-forensics workspace designed for authorized defensive triage, threat analysis, and security incident management.

## Workspaces & Core Features

- **Analyze Email**: Local MIME message parsing, heuristic scoring, attachment auditing, and domain extraction without server transmission.
- **Gmail Inbox Screening (`src/components/GmailInboxView.tsx`)**:
  - Live Gmail API integration over in-memory OAuth Bearer tokens (never stored in `localStorage` or `sessionStorage`).
  - Real-time inbox triage auditing sender headers, SPF/DKIM authentication records, urgency lures, and extracted URLs.
  - Workspace actions (Apply "Signal-Suspicious" label, Archive, Move to Trash) protected by mandatory user confirmation modal dialogues.
  - 1-click triage transfer of suspect URLs and messages into tracked Investigation Cases.
- **Investigation Cases & Evidence Vault (`src/components/InvestigationCaseView.tsx`)**:
  - **Case Lifecycle**: Create, track, prioritize, reopen, and close cases, persisted in Cloud Firestore (`effective-metric-pwjrd`).
  - **URL Analysis**: Real-time parsing of hostnames, paths, query parameters, punycode, and Shannon entropy.
  - **Explainable Risk Scoring**: Itemized breakdown of all triggered heuristic rules, exact point deltas (+1 to +5), and analytical explanations.
  - **Attack-Path Explorer**: Visual topological graph distinguishing **Observed** (verified static attributes), **Inferred** (heuristically deduced threat mechanics), and **Simulated** (synthetic redirect models).
  - **Evidence Vault**: Client-side cryptographic SHA-256 file hashing (`crypto.subtle`) for EMLs, logs, and screenshots with tamper-detection integrity verification.
  - **Case History**: Append-only chronological audit trail recording investigator actions, timestamps, and findings.
  - **Report Export**: Exportable tamper-evident JSON case packages with SHA-256 digests and formatted printable forensics reports.
  - **Automated Security Testing**: Integrated assertion runner testing malformed URLs, unsafe schemes (`javascript:`, `data:`), RFC-1918 private IP exposure, and malicious payloads.
- **PhishTrace URL Forensics (`src/components/PhishTraceView.tsx` & `src/phishTrace.ts`)**:
  - Pure static string forensics: Never connects to, crawls, or fetches submitted links.
  - Explainable heuristic scoring: Decomposes protocol, apex domains, subdomains, credential keywords, high-abuse TLDs, and entropy.
  - Synthetic redirect modeling: Models redirect chains as labeled pedagogical examples.
- **Dataset Review**: In-browser batch CSV scanning with automatic column detection, score threshold adjustment, and confusion matrix evaluation.
- **Mobile Link Interception Reference Modules**: Educational reference architectures for Android `AccessibilityService` (with `node.recycle()`, 250ms debouncing, and `TYPE_APPLICATION_OVERLAY`) and iOS `UniversalLinkInterceptor` (with `NSUserActivity` deep link routing and process-isolated `WKWebView`).

---

## Mandatory Safety & Privacy Guarantees

- **No Remote Crawling**: The URL resolution endpoint is removed. Target URLs are never visited or resolved.
- **Client-Side OAuth Only**: Google Workspace access tokens are stored in memory only and cleared automatically upon sign-out.
- **Cloud Firestore RBAC & ABAC**: Hardened security rules (`firestore.rules`) enforce strict schema validation, owner isolation, immutability of creation timestamps and owner IDs, and append-only audit histories.
- **Privacy Preservation ($k$-Anonymity)**: Only 16-hex character SHA-256 prefixes are checked against the Cloud SQL database (`effective-metric-pwjrd`). Raw URLs are strictly rejected. Note: 16-hex prefixes are pseudonymous rather than anonymous.
- **Strict Input Bounds**: URLs are bounded to 2,048 characters. Only `http:` and `https:` schemes are allowed. Embedded credentials and private RFC-1918 addresses are automatically flagged.
- **Safe Output Rendering**: User inputs are rendered exclusively as plain text, never raw HTML.
- **No Absolute Safety Claims**: A low score indicates the absence of specific heuristic indicators—never a guarantee of safety.

---

## Commands

```bash
# Start development server (Full-stack Express + Vite on port 3000)
npm run dev

# Run automated unit test suite (Node built-in test runner via tsx)
npx --yes tsx --test src/phishTrace.test.ts

# Type-check codebase
npm run lint

# Production build
npm run build

# Start production server
npm start
```

---

## Storage & Database

- **Cloud Firestore** (`effective-metric-pwjrd` / `ai-studio-phishtrace-77d9076e-fa27-4017-9c61-e2cadb0d1205`):
  - `/cases/{caseId}`: Investigation case records with status, priority, risk scores, and integrity hashes.
  - `/cases/{caseId}/evidence/{evidenceId}`: Cryptographically hashed digital evidence artifacts.
  - `/cases/{caseId}/history/{historyId}`: Chronological audit trail for case accountability.
- **Cloud SQL PostgreSQL**:
  - `malicious_domains`: `domain_hash_prefix (VARCHAR 16 UNIQUE)`, `threat_type`, `created_at`, indexed via `idx_hash_prefix`.
- **Local Browser Cache**:
  - `signal_phishtrace_history`: Quick investigation history in `localStorage`.

---

## Limitations

1. **Static Analysis Scope**: PhishTrace evaluates URL text syntax and known heuristic patterns. It does not inspect remote server headers or page contents over the network.
2. **Mobile Code Status**: The Android and iOS code snippets are educational reference prototypes and must undergo independent security, memory, and battery auditing before production deployment.
