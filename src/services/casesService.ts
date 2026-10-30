import {
  collection,
  doc,
  getDocs,
  getDoc,
  setDoc,
  updateDoc,
  query,
  where,
} from 'firebase/firestore';
import { db, handleFirestoreError, OperationType } from '../lib/firebase';

export interface CaseRecord {
  caseId: string;
  title: string;
  status: 'open' | 'investigating' | 'closed';
  priority: 'low' | 'medium' | 'high' | 'critical';
  targetUrl?: string;
  targetDomain?: string;
  riskLevel: 'Benign' | 'Suspicious' | 'High Risk';
  riskScore: number;
  findings?: string;
  recommendations?: string;
  limitations?: string;
  integrityHash?: string;
  ownerId: string;
  ownerEmail?: string;
  createdAt: string;
  updatedAt?: string;
}

export interface EvidenceRecord {
  id: string;
  filename: string;
  mimeType?: string;
  sha256: string;
  sizeBytes: number;
  source?: string;
  verifiedAt?: string;
  notes?: string;
  ownerId: string;
  createdAt: string;
}

export interface AuditLogRecord {
  id: string;
  timestamp: string;
  action: string;
  investigator?: string;
  detail: string;
  ownerId: string;
  createdAt: string;
}

// Client-side SHA-256 for integrity verification
export async function computeSha256Hex(data: string | ArrayBuffer): Promise<string> {
  const buffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function computeFileSha256(file: File): Promise<string> {
  const arrayBuffer = await file.arrayBuffer();
  return computeSha256Hex(arrayBuffer);
}

// Generate unique identifier
export function generateCaseId(): string {
  const now = new Date();
  const year = now.getFullYear();
  const rand = Math.random().toString(36).substring(2, 8).toUpperCase();
  return `CASE-${year}-${rand}`;
}

export async function fetchUserCases(userId: string): Promise<CaseRecord[]> {
  const path = 'cases';
  try {
    const q = query(
      collection(db, path),
      where('ownerId', '==', userId)
    );
    const snapshot = await getDocs(q);
    const results: CaseRecord[] = [];
    snapshot.forEach((d) => {
      results.push(d.data() as CaseRecord);
    });
    // Sort descending by createdAt
    return results.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, path);
  }
}

export async function createInvestigationCase(
  caseData: Omit<CaseRecord, 'integrityHash'>
): Promise<CaseRecord> {
  const path = `cases/${caseData.caseId}`;
  try {
    // Generate integrity hash of the critical case definition
    const digestPayload = JSON.stringify({
      id: caseData.caseId,
      title: caseData.title,
      targetUrl: caseData.targetUrl || '',
      riskScore: caseData.riskScore,
      ownerId: caseData.ownerId,
      createdAt: caseData.createdAt,
    });
    const integrityHash = await computeSha256Hex(digestPayload);

    const record: CaseRecord = {
      ...caseData,
      integrityHash,
    };

    await setDoc(doc(db, 'cases', caseData.caseId), record);

    // Add initial audit history
    await addCaseHistory(caseData.caseId, {
      id: `HIST-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      action: 'CASE_CREATED',
      investigator: caseData.ownerEmail || 'Investigator',
      detail: `Investigation case opened for target: ${caseData.targetUrl || caseData.title}. Assigned initial risk: ${caseData.riskLevel} (${caseData.riskScore}/100).`,
      ownerId: caseData.ownerId,
      createdAt: new Date().toISOString(),
    });

    return record;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function updateInvestigationCase(
  caseId: string,
  updates: Partial<CaseRecord>,
  investigatorEmail?: string
): Promise<void> {
  const path = `cases/${caseId}`;
  try {
    const docRef = doc(db, 'cases', caseId);
    const existingSnap = await getDoc(docRef);
    if (!existingSnap.exists()) {
      throw new Error(`Case ${caseId} does not exist`);
    }
    const current = existingSnap.data() as CaseRecord;

    const updatedRecord = {
      ...updates,
      updatedAt: new Date().toISOString(),
    };

    await updateDoc(docRef, updatedRecord);

    if (updates.status && updates.status !== current.status) {
      await addCaseHistory(caseId, {
        id: `HIST-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
        timestamp: new Date().toISOString(),
        action: updates.status === 'closed' ? 'CASE_CLOSED' : 'CASE_REOPENED',
        investigator: investigatorEmail || 'Investigator',
        detail: `Status changed from ${current.status} to ${updates.status}.`,
        ownerId: current.ownerId,
        createdAt: new Date().toISOString(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

export async function addCaseEvidence(
  caseId: string,
  evidence: EvidenceRecord
): Promise<void> {
  const path = `cases/${caseId}/evidence/${evidence.id}`;
  try {
    await setDoc(doc(db, 'cases', caseId, 'evidence', evidence.id), evidence);

    // Audit log
    await addCaseHistory(caseId, {
      id: `HIST-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      action: 'EVIDENCE_ADDED',
      investigator: evidence.ownerId,
      detail: `Attached evidence artifact "${evidence.filename}" (${evidence.sizeBytes} bytes). SHA-256: ${evidence.sha256.substring(0, 16)}...`,
      ownerId: evidence.ownerId,
      createdAt: new Date().toISOString(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function fetchCaseEvidence(caseId: string): Promise<EvidenceRecord[]> {
  const path = `cases/${caseId}/evidence`;
  try {
    const snapshot = await getDocs(collection(db, 'cases', caseId, 'evidence'));
    const items: EvidenceRecord[] = [];
    snapshot.forEach((d) => items.push(d.data() as EvidenceRecord));
    return items.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, path);
  }
}

export async function addCaseHistory(
  caseId: string,
  history: AuditLogRecord
): Promise<void> {
  const path = `cases/${caseId}/history/${history.id}`;
  try {
    await setDoc(doc(db, 'cases', caseId, 'history', history.id), history);
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function fetchCaseHistory(caseId: string): Promise<AuditLogRecord[]> {
  const path = `cases/${caseId}/history`;
  try {
    const snapshot = await getDocs(collection(db, 'cases', caseId, 'history'));
    const logs: AuditLogRecord[] = [];
    snapshot.forEach((d) => logs.push(d.data() as AuditLogRecord));
    return logs.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, path);
  }
}
