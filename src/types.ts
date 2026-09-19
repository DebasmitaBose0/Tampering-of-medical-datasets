export interface PatientRecord {
  id: string;
  name: string;
  age: number;
  bloodType: string;
  diagnosis: string;
  medication: string;
  dosage: string;
  status: 'Stable' | 'Critical' | 'Recovering';
  lastUpdated: string;
  updatedBy: string;
  hash: string;
  prevHash: string;
  signature: string;
  isFrozen?: boolean;
  frozenSignature?: string;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  action: 'CREATE' | 'READ' | 'UPDATE' | 'TAMPER' | 'VERIFY_SUCCESS' | 'VERIFY_FAIL' | 'DEFENSE_TRIGGERED';
  recordId?: string;
  patientName?: string;
  details: string;
  performedBy: string;
  severity: 'info' | 'warning' | 'error' | 'success';
}

export interface SecurityStrategy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  type: 'CRYPTOGRAPHIC_CHAIN' | 'HMAC_VERIFICATION' | 'MULTI_SIGNATURE' | 'IMMUTABLE_LOGS' | 'ACTIVE_PREVENTION';
}

export interface AttackVector {
  id: string;
  name: string;
  threatLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
  impact: string;
  mitigation: string;
  actionLabel: string;
}

export interface TamperAttempt {
  id: string;
  timestamp: string; // YYYY-MM-DD HH:MM:SS or HH:MM:SS format
  timeLabel: string; // e.g., "12:00"
  attackType: 'Direct SQL Write' | 'Chain Recalculation' | 'MITM Transmission' | 'Insider Privilege Exploit' | 'Sandbox Override' | string;
  targetPatient: string;
  targetPatientId?: string;
  status: 'Detected & Blocked' | 'Undetected (Succeeded)';
  details: string;
  defensesEnabledCount: number;
  threatLevel?: 'Low' | 'Medium' | 'High' | 'Critical';
  attackerProfile?: string;
  originalData?: {
    diagnosis?: string;
    medication?: string;
    dosage?: string;
    status?: string;
    hash?: string;
    prevHash?: string;
    signature?: string;
    updatedBy?: string;
  };
  tamperedData?: {
    diagnosis?: string;
    medication?: string;
    dosage?: string;
    status?: string;
    hash?: string;
    prevHash?: string;
    signature?: string;
    updatedBy?: string;
  };
  detectionMechanism?: string;
  remediation?: string;
}

export interface RegisteredUser {
  id: string;
  username: string;
  name: string;
  role: 'Clinical Auditor' | 'Lead Doctor' | 'Compliance Officer' | 'Database Admin';
  organization: string;
  password?: string;
}


