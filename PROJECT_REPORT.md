# Signal / PhishTrace Project Report & Security Architecture

## 1. Project Overview & Mission

Signal / PhishTrace is an explainable, responsive URL and email forensics workspace engineered for defensive triage, threat analysis, incident response, and authorized security education. The application analyzes only URL and message text without making unauthorized external network requests, clearly displaying the heuristic signals behind every score, maintaining persistent investigation cases in Cloud Firestore, and producing integrity-verifiable JSON case files cryptographically sealed with SHA-256 hashes.

---

## 2. Completed Feature Checklist

- [x] **Investigation cases**: Create, save, reopen, and close cases in Cloud Firestore (`effective-metric-pwjrd`).
- [x] **URL analysis**: Parse hostnames, schemes, paths, query parameters, punycode, and suspicious patterns under zero-network constraints.
- [x] **Explainable risk scoring**: Show individual heuristic indicators, point deltas (+1 to +5), severity bands, and explicit rationale for every score.
- [x] **Attack-path explorer**: Interactive topological diagram clearly distinguishing:
  - **Observed Nodes** (solid border: verified static attributes, headers, and parameters)
  - **Inferred Nodes** (dashed border: heuristically deduced threat mechanics, credential lures)
  - **Simulated Nodes** (dotted border: synthetic redirect models without network transmission)
- [x] **Evidence vault**: Client-side cryptographic SHA-256 file hashing (`crypto.subtle`) for EMLs, logs, and screenshots, complete with tamper-detection integrity verification.
- [x] **Case history**: Append-only chronological audit trail recording investigator actions, timestamps, evidence sources, and observations.
- [x] **Report export**: Generates structured, tamper-evident case reports with findings, limitations, and recommendations in exportable JSON and printable summary format.
- [x] **Security testing**: Built-in automated assertion suite testing malformed URLs, unsafe schemes (`javascript:`, `data:`), RFC-1918 private IP exposure, and malicious uploads.
- [x] **Gmail Integration**: Real-time inbox screening via in-memory OAuth Bearer tokens, SPF/DKIM authentication header auditing, zero-network link extraction, and safe workspace actions (label, archive, trash) protected by explicit user confirmation modals.

---

## 3. Mandatory Safety & Privacy Guarantees

1. **Zero-Network URL Analysis**:
   - Submitted URLs are never visited, resolved, crawled, previewed, or fetched.
   - The server URL resolution endpoint is completely removed. Features involving redirect pathways utilize explicitly labeled local synthetic models.
   - No browser automation, `fetch`, `XMLHttpRequest`, or raw sockets are permitted to touch target URLs.

2. **Client-Side OAuth Token Isolation**:
   - Google Workspace access tokens are retained strictly in memory (`inMemoryAccessToken`) and never persisted in `localStorage` or `sessionStorage`.
   - On sign-out or session change, tokens are immediately cleared.

3. **Cloud Firestore ABAC & RBAC Security Rules**:
   - Hardened `firestore.rules` deployed to project `effective-metric-pwjrd`.
   - All single-document operations validate document ID bounds with `isValidId()`.
   - Owner isolation: `resource.data.ownerId == request.auth.uid`.
   - Immutability of ownership and creation timestamps enforced via differential schema rules.
   - Subcollection audit logs (`history`) are strictly append-only (deletions rejected).

4. **$k$-Anonymity Hash Prefix Lookup**:
   - The backend reputation provider rejects raw URLs.
   - Only validated 16-hex character SHA-256 hash prefixes (the first 8 bytes of the domain hash) are transmitted to the PostgreSQL database.
   - 16-hex prefixes provide pseudonymous rather than absolute anonymity; user communication text never leaves the client device.

5. **Input Bounds & Rejection Policies**:
   - URL length is strictly capped at `2,048` characters to eliminate buffer overruns and ReDoS vectors.
   - Protocols are strictly limited to `http:` and `https:`. Non-web schemes (`javascript:`, `data:`, `file:`) are rejected.
   - Embedded credentials (e.g. `user:pass@host`) are detected, flagged as high-risk authority masking, and isolated.
   - Reserved, loopback (`127.0.0.1`), RFC 1918 private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and cloud metadata (`169.254.169.254`) ranges are strictly flagged with an exception only for authorized demo fixtures.

6. **Transparent, Defensive Semantics**:
   - Clean scores (low risk) indicate that known heuristic indicators were not triggered; they never assert that a destination is verified "safe".
   - Rule scores represent heuristic indicator weights, not mathematical probability distributions.
   - All synthetic redirect paths are clearly marked as educational simulations.
   - All user inputs are rendered as plain text strings—never via raw HTML.

---

## 4. Storage Architecture

| Layer | Technology | Purpose | Privacy Characteristics |
|---|---|---|---|
| **Cloud Firestore** | Firebase Firestore (`effective-metric-pwjrd`) | Persistent investigation cases (`/cases`), evidence records (`/cases/{id}/evidence`), and audit history (`/cases/{id}/history`). | Secured by Attribute-Based Access Control rules. Authenticated owner-isolated access only. |
| **Relational Database** | PostgreSQL on Google Cloud SQL (`effective-metric-pwjrd`) | Stores known malicious domain hash prefixes (`malicious_domains`) and authenticated users (`users`). | Contains only 16-hex hash prefixes (`domain_hash_prefix`), threat classifications, and timestamps. No user browsing history is retained. |
| **Local Triage History** | Browser `localStorage` (`signal_phishtrace_history`) | Stores the 15 most recent URL investigations locally. | Fully local to the user's browser. Cleared on demand. |
| **Case Artifacts** | Client-side File Blob / Downloadable JSON | Exports tamper-evident case reports with `caseIntegritySha256`. | Kept under investigator custody. Integrity is verifiable via SHA-256 hash re-calculation. |

---

## 5. Run & Deployment Commands

```bash
# Install dependencies
npm install

# Start development server (Express full-stack backend + Vite middleware)
npm run dev

# Run unit test suite (Node built-in test runner via tsx)
npx --yes tsx --test src/phishTrace.test.ts

# Type-check codebase
npm run lint

# Production build
npm run build

# Start production server
npm start
```

---

## 6. Test Suite Verification

The automated test suite (`src/phishTrace.test.ts`) verifies:
- `URL Bounds`: Rejection of strings exceeding 2,048 characters.
- `Protocol Validation`: Rejection of `javascript:`, `data:`, `file:`.
- `Defanged Notation`: Correct normalization of `hxxp` and `[.]`.
- `Embedded Credentials`: Detection of `@` symbol authority masking.
- `Reserved IP Addresses`: Detection of `127.0.0.1`, `192.168.1.1`, `10.0.0.5`, `169.254.169.254`.
- `Brand in Subdomain`: Detection of brand tokens nested in third-party apex domains.
- `Synthetic Redirect Modeling`: Validation that simulated hops are labeled as simulations.
- `Cryptographic Case Integrity`: Verification of SHA-256 hash calculations on untampered vs tampered cases.
- `Shannon Entropy Calculation`: Validation of randomness measurements.
- `validateUrlInput Helper`: Validation of schemes, bounds, and user credentials.

---

## 7. Mobile Interceptor Status Notice

The Android AccessibilityService and iOS Content Blocker implementations located in `src/modules/androidAccessibilityModule.ts` and `src/modules/iosContentBlockerModule.ts` are provided as **educational reference architectures and security prototypes**. They demonstrate production-grade architectural patterns (such as `node.recycle()`, 250ms debouncing, `LruCache` deduplication, and isolated `WKProcessPool`), but must not be labeled as production-ready without independent security review, platform testing, and memory/battery profiling.
