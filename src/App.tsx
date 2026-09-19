import React, { useState, useEffect, Fragment, useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  ResponsiveContainer, 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  Cell, 
  PieChart, 
  Pie 
} from 'recharts';
import { 
  Database, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Activity, 
  Clock, 
  Terminal, 
  RefreshCw, 
  X, 
  Lock, 
  User,
  ShieldCheck,
  Zap,
  Edit2,
  Trash2,
  ShieldAlert,
  LockOpen,
  HeartPulse,
  Download,
  ChevronDown,
  ChevronUp,
  ArrowRight,
  ArrowLeft,
  ArrowUpDown,
  FileText,
  FileSpreadsheet,
  Plus,
  Cpu,
  Fingerprint,
  History,
  FileJson
} from 'lucide-react';
import { jsPDF } from 'jspdf';
import { INITIALIZED_PATIENTS, INITIAL_LOGS, INITIAL_TAMPER_ATTEMPTS, calculateRecordHash, generateHMACSignature } from './data';
import { PatientRecord, AuditLogEntry, SecurityStrategy, TamperAttempt, RegisteredUser } from './types';
import { SecurityAgentHub } from './components/SecurityAgentHub';
import { LedgerRiskScoreCard } from './components/LedgerRiskScoreCard';
import { TamperHistoryPage } from './components/TamperHistoryPage';
import { TableScanOverlay, BlockScanStatus } from './components/TableScanOverlay';

export default function App() {
  // --- Core States ---
  const [currentPage, setCurrentPage] = useState<'clinical' | 'security_agent' | 'auditor' | 'tamper_history'>('clinical');
  const [patients, setPatients] = useState<PatientRecord[]>(() => {
    // Re-verify initial chain on start just to be solid
    let prev = "00000000000000000000000000000000";
    return INITIALIZED_PATIENTS.map(p => {
      const copy = { ...p, prevHash: prev };
      copy.hash = calculateRecordHash(copy);
      copy.signature = generateHMACSignature(copy.hash, "SUPER_SECRET_KEY_123");
      prev = copy.hash;
      return copy;
    });
  });

  // Track the golden authoritative state for self-healing
  const [authorizedPatients, setAuthorizedPatients] = useState<PatientRecord[]>(() => {
    let prev = "00000000000000000000000000000000";
    return INITIALIZED_PATIENTS.map(p => {
      const copy = { ...p, prevHash: prev };
      copy.hash = calculateRecordHash(copy);
      copy.signature = generateHMACSignature(copy.hash, "SUPER_SECRET_KEY_123");
      prev = copy.hash;
      return copy;
    });
  });

  const [logs, setLogs] = useState<AuditLogEntry[]>(INITIAL_LOGS);
  const [tamperAttempts, setTamperAttempts] = useState<TamperAttempt[]>(INITIAL_TAMPER_ATTEMPTS);
  
  // Custom states
  const [secretKey, setSecretKey] = useState('SUPER_SECRET_KEY_123');
  const [selectedPatient, setSelectedPatient] = useState<PatientRecord | null>(null);
  const [actionType, setActionType] = useState<'doctor' | 'tamper' | null>(null);
  
  // Log filter and search state
  const [logFilter, setLogFilter] = useState<'ALL' | 'THREATS' | 'UPDATES' | 'SYSTEM'>('ALL');
  const [logSearch, setLogSearch] = useState('');
  
  // Database visual sorting states
  const [sortBy, setSortBy] = useState<'index' | 'name' | 'age' | 'status'>('index');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');

  // Interactive sandbox mode for direct inline tampering
  const [sandboxMode, setSandboxMode] = useState(false);
  const [expandedBlockIndex, setExpandedBlockIndex] = useState<number | null>(null);
  const [healerAlert, setHealerAlert] = useState<{
    show: boolean;
    patientName: string;
    field: string;
    attemptedValue: string;
  } | null>(null);

  // Security Intrusion Alarm and Notifications
  const [tamperAlarms, setTamperAlarms] = useState<{
    id: string;
    patientName: string;
    detail: string;
    timestamp: string;
  }[]>([]);

  // Input values for editing/tampering
  const [newName, setNewName] = useState('');
  const [newMedication, setNewMedication] = useState('');
  const [newDosage, setNewDosage] = useState('');
  const [newDiagnosis, setNewDiagnosis] = useState('');
  const [newStatus, setNewStatus] = useState<'Stable' | 'Critical' | 'Recovering'>('Stable');

  // Manual Register Patient Block state variables
  const [showAddPatientModal, setShowAddPatientModal] = useState(false);
  const [addPatientName, setAddPatientName] = useState('');
  const [addPatientAge, setAddPatientAge] = useState<number | ''>('');
  const [addPatientBloodType, setAddPatientBloodType] = useState('O+');
  const [addPatientDiagnosis, setAddPatientDiagnosis] = useState('');
  const [addPatientMedication, setAddPatientMedication] = useState('');
  const [addPatientDosage, setAddPatientDosage] = useState('');
  const [addPatientStatus, setAddPatientStatus] = useState<'Stable' | 'Critical' | 'Recovering'>('Stable');

  // Memoized, dynamically sorted patients list to prevent abrupt layout jumps and preserve sequential cryptography back-links
  const sortedPatients = useMemo(() => {
    const list = patients.map((p, index) => ({ p, originalIndex: index }));
    list.sort((a, b) => {
      let comparison = 0;
      if (sortBy === 'index') {
        comparison = a.originalIndex - b.originalIndex;
      } else if (sortBy === 'name') {
        comparison = a.p.name.localeCompare(b.p.name);
      } else if (sortBy === 'age') {
        comparison = a.p.age - b.p.age;
      } else if (sortBy === 'status') {
        comparison = a.p.status.localeCompare(b.p.status);
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });
    return list;
  }, [patients, sortBy, sortOrder]);

  // --- Threat Simulation States ---
  const [activeScenarioId, setActiveScenarioId] = useState('sql_injection');
  const [simulationTargetId, setSimulationTargetId] = useState('PAT-001');
  const [simulationActive, setSimulationActive] = useState(false);
  const [simulationProgress, setSimulationProgress] = useState(0);
  const [simulationResult, setSimulationResult] = useState<{
    scenarioId: string;
    outcome: 'FOILED' | 'MITIGATED' | 'BREACHED';
    statusText: string;
    explanation: string;
    remediation: string;
    targetName: string;
  } | null>(null);
  const [simulationLogs, setSimulationLogs] = useState<string[]>([]);

  // --- Auth States ---
  const [registeredUsers, setRegisteredUsers] = useState<RegisteredUser[]>(() => {
    const stored = localStorage.getItem('medtrust_users');
    if (stored) {
      try { return JSON.parse(stored); } catch (e) {}
    }
    return [
      {
        id: 'user-default-1',
        username: 'auditor_jones',
        name: 'Dr. Evelyn Jones',
        role: 'Clinical Auditor',
        organization: 'MedTrust Labs Compliance',
        password: 'password123'
      },
      {
        id: 'user-default-2',
        username: 'doctor_vance',
        name: 'Dr. Eleanor Vance',
        role: 'Lead Doctor',
        organization: 'MedTrust Central Clinic',
        password: 'password123'
      }
    ];
  });

  const [currentUser, setCurrentUser] = useState<RegisteredUser | null>(() => {
    const stored = localStorage.getItem('medtrust_current_user');
    if (stored) {
      try { return JSON.parse(stored); } catch (e) {}
    }
    return null;
  });

  // Keep localStorage updated
  useEffect(() => {
    localStorage.setItem('medtrust_users', JSON.stringify(registeredUsers));
  }, [registeredUsers]);

  useEffect(() => {
    localStorage.setItem('medtrust_current_user', JSON.stringify(currentUser));
  }, [currentUser]);

  const [showAuthModal, setShowAuthModal] = useState(false);
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  
  // Login fields
  const [loginUsername, setLoginUsername] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginError, setLoginError] = useState('');

  // Register fields
  const [regUsername, setRegUsername] = useState('');
  const [regName, setRegName] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regRole, setRegRole] = useState<'Clinical Auditor' | 'Lead Doctor' | 'Compliance Officer' | 'Database Admin'>('Clinical Auditor');
  const [regOrg, setRegOrg] = useState('MedTrust Central Clinic');
  const [regError, setRegError] = useState('');

  // Active Defense Strategies
  const [strategies, setStrategies] = useState<SecurityStrategy[]>([
    {
      id: 'crypt_chain',
      name: 'Blockchain Hash Chaining',
      description: 'Links records sequentially. Tampering breaks the forward integrity chain.',
      enabled: true,
      type: 'CRYPTOGRAPHIC_CHAIN'
    },
    {
      id: 'hmac_sig',
      name: 'HMAC Private Key Signature',
      description: 'Signs hashes with a secret key. Bypasses forgery attempts.',
      enabled: true,
      type: 'HMAC_VERIFICATION'
    },
    {
      id: 'immutable_logs',
      name: 'WORM Immutable Audit Trail',
      description: 'Secures clinical events. Intrusions trigger un-eraseable alerts.',
      enabled: true,
      type: 'IMMUTABLE_LOGS'
    },
    {
      id: 'active_lock',
      name: 'IPS Real-time Self-Healer',
      description: 'Active Intrusion Prevention. Detects manual cell overrides, blocks them, and auto-restores the record baseline.',
      enabled: false,
      type: 'ACTIVE_PREVENTION'
    }
  ]);

  // Verification Scanner Results
  const [scanStatus, setScanStatus] = useState<{
    scanned: boolean;
    valid: boolean;
    brokenIndex: number | null;
    brokenFields: string[];
    signatureMismatch: boolean;
  } | null>(null);

  const [isScanning, setIsScanning] = useState(false);
  const [scanningBlockIndex, setScanningBlockIndex] = useState<number | null>(null);
  const [scanningProgress, setScanningProgress] = useState(0);
  const [scannedBlocksMap, setScannedBlocksMap] = useState<Record<number, BlockScanStatus>>({});

  // --- Logger Helper ---
  const addLog = (
    action: AuditLogEntry['action'],
    details: string,
    severity: AuditLogEntry['severity'],
    patientId?: string,
    patientName?: string,
    actorOverride?: string
  ) => {
    let operator = 'System Secure Daemon';
    if (action === 'TAMPER') {
      operator = 'External Malicious Actor';
    } else if (actorOverride) {
      operator = actorOverride;
    } else if (currentUser) {
      operator = `${currentUser.name} (${currentUser.role})`;
    }

    const newLog: AuditLogEntry = {
      id: `LOG-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
      timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19),
      action,
      details,
      performedBy: operator,
      severity,
      recordId: patientId,
      patientName
    };
    setLogs(prev => [newLog, ...prev]);
  };

  // --- Security Intrusion Audio-Visual Alarm ---
  const playAlarmSound = () => {
    try {
      const AudioContextClass = window.AudioContext || (window as any).webkitAudioContext;
      if (!AudioContextClass) return;
      const ctx = new AudioContextClass();
      const now = ctx.currentTime;
      
      // Dual-tone high intensity police/medical siren simulation (Web Audio API synthesis)
      const osc1 = ctx.createOscillator();
      const osc2 = ctx.createOscillator();
      const gainNode = ctx.createGain();
      
      osc1.type = 'sawtooth';
      osc1.frequency.setValueAtTime(950, now);
      osc1.frequency.linearRampToValueAtTime(750, now + 0.35);
      osc1.frequency.linearRampToValueAtTime(950, now + 0.7);
      osc1.frequency.linearRampToValueAtTime(750, now + 1.05);
      osc1.frequency.linearRampToValueAtTime(950, now + 1.4);
      
      osc2.type = 'sine';
      osc2.frequency.setValueAtTime(1150, now);
      osc2.frequency.linearRampToValueAtTime(850, now + 0.35);
      osc2.frequency.linearRampToValueAtTime(1150, now + 0.7);
      osc2.frequency.linearRampToValueAtTime(850, now + 1.05);
      osc2.frequency.linearRampToValueAtTime(1150, now + 1.4);
      
      gainNode.gain.setValueAtTime(0.08, now);
      gainNode.gain.linearRampToValueAtTime(0.08, now + 1.2);
      gainNode.gain.exponentialRampToValueAtTime(0.001, now + 1.45);
      
      osc1.connect(gainNode);
      osc2.connect(gainNode);
      gainNode.connect(ctx.destination);
      
      osc1.start(now);
      osc2.start(now);
      
      osc1.stop(now + 1.45);
      osc2.stop(now + 1.45);
    } catch (e) {
      console.warn("AudioContext playback blocked or failed:", e);
    }
  };

  const triggerTamperAlarm = (patientName: string, detail: string) => {
    playAlarmSound();
    
    const timestampStr = new Date().toLocaleTimeString();
    const newAlarm = {
      id: `ALARM-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      patientName,
      detail,
      timestamp: timestampStr
    };
    
    setTamperAlarms(prev => [newAlarm, ...prev]);
  };

  // --- Auth Handlers ---
  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError('');
    
    if (!loginUsername.trim() || !loginPassword.trim()) {
      setLoginError('Please enter both username and password.');
      return;
    }

    const found = registeredUsers.find(
      u => u.username.toLowerCase() === loginUsername.trim().toLowerCase() && u.password === loginPassword
    );

    if (found) {
      setCurrentUser(found);
      setShowAuthModal(false);
      setLoginUsername('');
      setLoginPassword('');
      
      addLog(
        'VERIFY_SUCCESS',
        `User ${found.name} logged in successfully as a verified ${found.role}.`,
        'success',
        undefined,
        undefined,
        `${found.name} (${found.role})`
      );
    } else {
      setLoginError('Invalid username or password. Try user "auditor_jones" with password "password123".');
    }
  };

  const handleRegister = (e: React.FormEvent) => {
    e.preventDefault();
    setRegError('');

    if (!regUsername.trim() || !regName.trim() || !regPassword.trim() || !regOrg.trim()) {
      setRegError('Please fill in all the registration fields.');
      return;
    }

    const exists = registeredUsers.some(
      u => u.username.toLowerCase() === regUsername.trim().toLowerCase()
    );

    if (exists) {
      setRegError('This username is already taken.');
      return;
    }

    const newUser: RegisteredUser = {
      id: `user-${Date.now()}`,
      username: regUsername.trim(),
      name: regName.trim(),
      role: regRole,
      organization: regOrg.trim(),
      password: regPassword
    };

    setRegisteredUsers(prev => [...prev, newUser]);
    setCurrentUser(newUser);
    setShowAuthModal(false);
    
    setRegUsername('');
    setRegName('');
    setRegPassword('');
    setRegRole('Clinical Auditor');
    setRegOrg('MedTrust Central Clinic');

    addLog(
      'VERIFY_SUCCESS',
      `New user ${newUser.name} registered and logged in as a verified ${newUser.role}.`,
      'success',
      undefined,
      undefined,
      `${newUser.name} (${newUser.role})`
    );
  };

  const handleLogout = () => {
    if (currentUser) {
      const oldUser = currentUser;
      setCurrentUser(null);
      addLog(
        'VERIFY_SUCCESS',
        `User ${oldUser.name} logged out from the Auditor Console.`,
        'info',
        undefined,
        undefined,
        `${oldUser.name} (${oldUser.role})`
      );
    }
  };

  // --- Export Single Patient Block to PDF ---
  const exportSinglePatientToPDF = (p: PatientRecord, idx: number, isOriginal: boolean) => {
    const doc = new jsPDF({
      orientation: 'p',
      unit: 'mm',
      format: 'a4'
    });

    const timestampStr = new Date().toLocaleString();
    const pageHeight = doc.internal.pageSize.getHeight();
    const pageWidth = doc.internal.pageSize.getWidth();

    // Draw Header Banner
    doc.setFillColor(15, 23, 42); // Slate 900
    doc.rect(0, 0, pageWidth, 35, 'F');

    // Title Text
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(18);
    doc.text('MEDTRUST CENTRAL', 15, 14);
    
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9.5);
    doc.setTextColor(148, 163, 184); // Slate 400
    doc.text('Single Clinical Record Integrity & Security Report', 15, 21);

    // Indicator status pill (Secure vs Compromised state)
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setFillColor(30, 41, 59); // Slate 800
    doc.rect(pageWidth - 65, 10, 50, 7, 'F');
    doc.setTextColor(255, 255, 255);
    doc.text(isOriginal ? 'SECURE BASELINE DATA' : 'CURRENT SYSTEM STATE', pageWidth - 17, 14.5, { align: 'right' });

    // Divider
    doc.setFillColor(16, 185, 129); // Emerald 500 line
    doc.rect(0, 35, pageWidth, 1.2, 'F');

    // Report details
    doc.setTextColor(71, 85, 105); // Slate 600
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.text(`Exported On: ${timestampStr}`, 15, 45);
    doc.text(`Target Record: Patient Block #0${idx + 1} (${p.id})`, 15, 50);

    // Verify individual block
    let individualValid = true;
    const isChainEnabled = strategies.find(s => s.id === 'crypt_chain')?.enabled;
    const isHmacEnabled = strategies.find(s => s.id === 'hmac_sig')?.enabled;

    const sourceList = isOriginal ? authorizedPatients : patients;
    const isFirst = idx === 0;
    const individualPrev = isFirst ? "00000000000000000000000000000000" : sourceList[idx - 1]?.hash || "00000000000000000000000000000000";
    const calculatedLocal = calculateRecordHash({ 
      ...p, 
      prevHash: p.prevHash 
    });
    
    if (p.hash !== calculatedLocal) individualValid = false;
    if (isChainEnabled && p.prevHash !== individualPrev) individualValid = false;
    if (isHmacEnabled) {
      const sig = generateHMACSignature(p.hash, secretKey);
      if (p.signature !== sig) {
        individualValid = false;
      }
    }

    // Overruled if isOriginal is forced
    if (isOriginal) {
      individualValid = true;
    }

    // Draw Health Stamp
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    if (individualValid) {
      doc.setFillColor(240, 253, 244); // Green 50
      doc.setDrawColor(74, 222, 128); // Green 400
      doc.rect(pageWidth - 75, 41, 60, 11, 'FD');
      doc.setTextColor(22, 101, 52); // Green 800
      doc.text('BLOCK STATE: VERIFIED', pageWidth - 45, 48, { align: 'center' });
    } else {
      doc.setFillColor(254, 242, 242); // Red 50
      doc.setDrawColor(248, 113, 113); // Red 400
      doc.rect(pageWidth - 75, 41, 60, 11, 'FD');
      doc.setTextColor(153, 27, 27); // Red 800
      doc.text('BLOCK STATE: TAMPERED', pageWidth - 45, 48, { align: 'center' });
    }

    const yPos = 58;

    // Draw Block Panel Box with modern card aesthetics
    if (individualValid) {
      doc.setDrawColor(226, 232, 240); // Slate 200
      doc.setFillColor(248, 250, 252); // Slate 50
    } else {
      doc.setDrawColor(254, 202, 202); // Red 200
      doc.setFillColor(254, 242, 242); // Red 50
    }
    doc.rect(14, yPos, pageWidth - 28, 50, 'FD');

    // Left Vertical Indicator Bar
    if (individualValid) {
      doc.setFillColor(16, 185, 129); // Emerald 500
    } else {
      doc.setFillColor(239, 68, 68); // Red 500
    }
    doc.rect(14, yPos, 2.5, 50, 'F');

    // 1. Block Header text row
    doc.setTextColor(71, 85, 105); // Slate 600
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.text(`RECORD BLOCK #0${idx + 1}  [ID: ${p.id}]`, 20, yPos + 7);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    if (individualValid) {
      doc.setTextColor(16, 185, 129); // Emerald
      doc.text('VERIFIED CLINICAL INTEGRITY', pageWidth - 20, yPos + 7, { align: 'right' });
    } else {
      doc.setTextColor(239, 68, 68); // Red
      doc.text('CRYPTOGRAPHIC TAMPER DETECTED', pageWidth - 20, yPos + 7, { align: 'right' });
    }

    // Horizontal separator line 1
    doc.setDrawColor(241, 245, 249);
    doc.line(20, yPos + 11, pageWidth - 20, yPos + 11);

    // 2. Patient info details
    doc.setTextColor(15, 23, 42); // Slate 900
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.text(`Patient Name: ${p.name}`, 20, yPos + 18);
    
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9.5);
    doc.setTextColor(100, 116, 139); // Slate 500
    doc.text(`Demographics: Age ${p.age}   |   Blood Group ${p.bloodType}   |   System Tag ${p.status}`, 20, yPos + 24);

    // 3. Medical Diagnosis and Medication details
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text(`Diagnosis:`, 20, yPos + 32);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(51, 65, 85);
    doc.text(`${p.diagnosis}`, 42, yPos + 32);

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text(`Medication:`, 20, yPos + 38);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(51, 65, 85);
    doc.text(`${p.medication} (${p.dosage})`, 44, yPos + 38);

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(100, 116, 139);
    doc.text(`Audit Trail:`, 20, yPos + 44);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(51, 65, 85);
    doc.text(`Last updated by "${p.updatedBy}" at ${p.lastUpdated}`, 44, yPos + 44);

    // Footer
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(148, 163, 184);
    doc.text('MedTrust Central Clinical Single Record Report • Highly Secure Ledger Proof of Integrity.', 15, pageHeight - 10);
    doc.text('Page 1 of 1', pageWidth - 30, pageHeight - 10);

    const reportName = `medtrust-block-0${idx + 1}-${isOriginal ? 'original' : 'current'}.pdf`;
    doc.save(reportName);

    addLog(
      'VERIFY_SUCCESS',
      `Downloaded single clinical block PDF for ${p.name} (${isOriginal ? 'Baseline' : 'Current System State'})`,
      'success',
      p.id,
      p.name
    );
  };

  // --- Dynamic Live Audit / Self-Healer Daemon ---
  // Calculates live if records currently match expected cryptographic standards
  const getRecordVerificationDetails = (record: PatientRecord, index: number, prevRecord: PatientRecord | null) => {
    const isChainEnabled = strategies.find(s => s.id === 'crypt_chain')?.enabled;
    const isHmacEnabled = strategies.find(s => s.id === 'hmac_sig')?.enabled;

    // 1. Check local hash match: verifies if THIS record's clinical fields were modified without recalculating hash
    const localHash = calculateRecordHash({
      id: record.id,
      name: record.name,
      age: record.age,
      bloodType: record.bloodType,
      diagnosis: record.diagnosis,
      medication: record.medication,
      dosage: record.dosage,
      status: record.status,
      lastUpdated: record.lastUpdated,
      updatedBy: record.updatedBy,
      prevHash: record.prevHash
    });

    const isHashValid = record.hash === localHash;
    
    // 2. Check chain integrity: verifies if this block's prevHash matches previous block's hash
    const expectedPrevHash = prevRecord ? prevRecord.hash : "00000000000000000000000000000000";
    const isChainValid = !isChainEnabled || record.prevHash === expectedPrevHash;

    // 3. Check HMAC signature correctness: verifies if block hash is signed with valid HMAC secret key
    const expectedSignature = generateHMACSignature(record.hash, secretKey);
    const isSignatureValid = !isHmacEnabled || record.signature === expectedSignature;

    // A patient is tampered ONLY if its own data fields were altered (hash mismatch) or signature forged:
    const isRecordTampered = !isHashValid || !isSignatureValid;
    const overallValid = isHashValid && isSignatureValid;

    return {
      isHashValid,
      isChainValid,
      isSignatureValid,
      isRecordTampered,
      overallValid
    };
  };

  // --- Integrity Verification Process ---
  const handleRunVerification = async () => {
    setIsScanning(true);
    setScanStatus(null);
    setScanningProgress(0);
    
    // Initialize all blocks as pending
    const initialMap: Record<number, BlockScanStatus> = {};
    for (let j = 0; j < patients.length; j++) {
      initialMap[j] = { status: 'pending' };
    }
    setScannedBlocksMap(initialMap);
    
    addLog(
      'DEFENSE_TRIGGERED',
      `Initializing security scan. Verifying cryptographically chained clinical ledger of ${patients.length} records...`,
      'info'
    );

    let brokenIndex: number | null = null;
    let signatureMismatch = false;
    let brokenFields: string[] = [];

    const isChainEnabled = strategies.find(s => s.id === 'crypt_chain')?.enabled;
    const isHmacEnabled = strategies.find(s => s.id === 'hmac_sig')?.enabled;

    let previousHash = "00000000000000000000000000000000";

    // Sequentially scan each block with simulated latency delay representing cryptographic complexity
    for (let i = 0; i < patients.length; i++) {
      setScanningBlockIndex(i);
      setScanningProgress(Math.round(((i + 0.35) / patients.length) * 100));
      setScannedBlocksMap(prev => ({
        ...prev,
        [i]: { status: 'scanning' }
      }));
      
      // Artificial delay (450ms per record) to represent SHA-256 and HMAC cryptographic work
      await new Promise(resolve => setTimeout(resolve, 450));

      const p = patients[i];
      
      // Expected hash of this record
      const calculatedLocal = calculateRecordHash({
        id: p.id,
        name: p.name,
        age: p.age,
        bloodType: p.bloodType,
        diagnosis: p.diagnosis,
        medication: p.medication,
        dosage: p.dosage,
        status: p.status,
        lastUpdated: p.lastUpdated,
        updatedBy: p.updatedBy,
        prevHash: p.prevHash
      });

      const isHashValid = p.hash === calculatedLocal;
      const isChainValid = !isChainEnabled || p.prevHash === previousHash;
      let isHmacValid = true;
      if (isHmacEnabled) {
        const expectedSig = generateHMACSignature(p.hash, secretKey);
        isHmacValid = p.signature === expectedSig;
      }

      if (!isHashValid || !isChainValid || !isHmacValid) {
        brokenIndex = i;
        const currentBlockBroken: string[] = [];
        if (!isHashValid) currentBlockBroken.push("Block Hash Mismatch");
        if (!isChainValid) currentBlockBroken.push("Blockchain Link Breakage");
        if (!isHmacValid) {
          signatureMismatch = true;
          currentBlockBroken.push("HMAC Signature Authenticity Failure");
        }
        brokenFields = currentBlockBroken;

        setScannedBlocksMap(prev => {
          const next = { ...prev };
          next[i] = {
            status: 'invalid',
            brokenFields: currentBlockBroken,
            isHashValid,
            isChainValid,
            isHmacValid,
            timestamp: Date.now()
          };
          for (let k = i + 1; k < patients.length; k++) {
            next[k] = { status: 'aborted' };
          }
          return next;
        });
        break;
      } else {
        // Block verified valid!
        setScannedBlocksMap(prev => ({
          ...prev,
          [i]: {
            status: 'valid',
            isHashValid: true,
            isChainValid: true,
            isHmacValid: true,
            timestamp: Date.now()
          }
        }));
        previousHash = p.hash;
        setScanningProgress(Math.round(((i + 1) / patients.length) * 100));
      }
    }

    setScanningProgress(100);
    // Slight pause at 100% to let the user admire the complete progress
    await new Promise(resolve => setTimeout(resolve, 300));
    setScanningBlockIndex(null);

    const isValid = brokenIndex === null;
    setScanStatus({
      scanned: true,
      valid: isValid,
      brokenIndex,
      brokenFields,
      signatureMismatch
    });
    setIsScanning(false);

    if (isValid) {
      addLog(
        'VERIFY_SUCCESS',
        'Database scan complete. All patient nodes, cryptographic link hashes, and digital signatures confirmed intact.',
        'success'
      );
    } else {
      const targetPatient = patients[brokenIndex!];
      addLog(
        'VERIFY_FAIL',
        `Intrusion ALERT! ${brokenFields.join(' & ')} detected at Block 0${brokenIndex! + 1} (${targetPatient.name}). Chain verification aborted early.`,
        'error',
        targetPatient.id,
        targetPatient.name
      );
    }
  };

  // --- Doctor Authorized Edit ---
  const executeDoctorUpdate = () => {
    if (!selectedPatient) return;

    if (selectedPatient.isFrozen) {
      addLog(
        'VERIFY_FAIL',
        `[LOCK PREVENTION] Authorized update rejected! Block ${selectedPatient.id} (${selectedPatient.name}) is cryptographically frozen.`,
        'error',
        selectedPatient.id,
        selectedPatient.name
      );
      setSelectedPatient(null);
      setActionType(null);
      return;
    }

    const isChainEnabled = strategies.find(s => s.id === 'crypt_chain')?.enabled;
    const isHmacEnabled = strategies.find(s => s.id === 'hmac_sig')?.enabled;

    const updatedWithHashes = (() => {
      const updated = patients.map(p => {
        if (p.id === selectedPatient.id) {
          return {
            ...p,
            name: newName.trim() || p.name,
            medication: newMedication.trim() || p.medication,
            dosage: newDosage.trim() || p.dosage,
            diagnosis: newDiagnosis.trim() || p.diagnosis,
            status: newStatus || p.status,
            lastUpdated: new Date().toISOString().replace('T', ' ').slice(0, 19),
            updatedBy: currentUser ? `${currentUser.name} (${currentUser.role})` : "Dr. Robert Chen (Secure Portal)"
          };
        }
        return p;
      });

      // Securely recalculate cascading blocks & signatures
      let previousHash = "00000000000000000000000000000000";
      return updated.map(p => {
        const recomputed = {
          ...p,
          prevHash: isChainEnabled ? previousHash : p.prevHash
        };
        recomputed.hash = calculateRecordHash(recomputed);
        recomputed.signature = generateHMACSignature(recomputed.hash, secretKey);
        previousHash = recomputed.hash;
        return recomputed;
      });
    })();

    setPatients(updatedWithHashes);
    setAuthorizedPatients(updatedWithHashes);

    addLog(
      'UPDATE',
      `Authorized clinical sign-off completed securely for ${newName.trim() || selectedPatient.name}. Cryptographic SHA-256 and HMAC keys re-computed.`,
      'success',
      selectedPatient.id,
      newName.trim() || selectedPatient.name
    );

    // Reset controls
    setSelectedPatient(null);
    setActionType(null);
    setScanStatus(null);
  };

  // --- Manual Register New Patient Block ---
  const executeAddPatient = () => {
    if (!addPatientName.trim()) return;

    const nextIdx = patients.length + 1;
    const nextId = `PAT-${String(nextIdx).padStart(3, '0')}`;
    const timestampStr = new Date().toISOString().replace('T', ' ').slice(0, 19);

    const newRecord: PatientRecord = {
      id: nextId,
      name: addPatientName.trim(),
      age: Number(addPatientAge) || 30,
      bloodType: addPatientBloodType,
      diagnosis: addPatientDiagnosis.trim() || 'General Wellness Examination',
      medication: addPatientMedication.trim() || 'N/A',
      dosage: addPatientDosage.trim() || 'N/A',
      status: addPatientStatus,
      lastUpdated: timestampStr,
      updatedBy: currentUser ? `${currentUser.name} (${currentUser.role})` : "Dr. Robert Chen (Secure Portal)",
      prevHash: "",
      hash: "",
      signature: ""
    };

    const isChainEnabled = strategies.find(s => s.id === 'crypt_chain')?.enabled;

    // 1. Recalculate working patient list with new record appended
    const updatedPatientsList = [...patients, newRecord];
    let previousWorkingHash = "00000000000000000000000000000000";
    const finalWorkingList = updatedPatientsList.map(p => {
      const copy = {
        ...p,
        prevHash: isChainEnabled ? previousWorkingHash : p.prevHash
      };
      copy.hash = calculateRecordHash(copy);
      copy.signature = generateHMACSignature(copy.hash, secretKey);
      previousWorkingHash = copy.hash;
      return copy;
    });

    // 2. Recalculate authorized golden state list with new record appended
    const updatedAuthList = [...authorizedPatients, { ...newRecord }];
    let previousAuthHash = "00000000000000000000000000000000";
    const finalAuthList = updatedAuthList.map(p => {
      const copy = {
        ...p,
        prevHash: isChainEnabled ? previousAuthHash : p.prevHash
      };
      copy.hash = calculateRecordHash(copy);
      copy.signature = generateHMACSignature(copy.hash, secretKey);
      previousAuthHash = copy.hash;
      return copy;
    });

    setPatients(finalWorkingList);
    setAuthorizedPatients(finalAuthList);
    setScanStatus(null);

    addLog(
      'VERIFY_SUCCESS',
      `Manual Patient Registration complete. Node Block ${nextId} (${newRecord.name}) securely linked and signed.`,
      'success',
      nextId,
      newRecord.name
    );

    // Reset fields & close modal
    setAddPatientName('');
    setAddPatientAge('');
    setAddPatientBloodType('O+');
    setAddPatientDiagnosis('');
    setAddPatientMedication('');
    setAddPatientDosage('');
    setAddPatientStatus('Stable');
    setShowAddPatientModal(false);
  };

  // --- Cryptographically Freeze Block ---
  const freezeBlock = (id: string) => {
    const target = patients.find(p => p.id === id);
    if (!target) return;

    const timestampStr = new Date().toISOString().replace('T', ' ').slice(0, 19);
    const freezePayload = `${target.hash}|FROZEN|${timestampStr}`;
    const signatureLock = generateHMACSignature(freezePayload, secretKey);

    setPatients(prev => prev.map(p => {
      if (p.id === id) {
        return {
          ...p,
          isFrozen: true,
          frozenSignature: signatureLock
        };
      }
      return p;
    }));

    setAuthorizedPatients(prev => prev.map(p => {
      if (p.id === id) {
        return {
          ...p,
          isFrozen: true,
          frozenSignature: signatureLock
        };
      }
      return p;
    }));

    addLog(
      'VERIFY_SUCCESS',
      `[FREEZE ACTION] Block locked! Patient Block ${id} is cryptographically frozen with signature: ${signatureLock.slice(0, 20)}... All future edits barred.`,
      'success',
      target.id,
      target.name
    );
  };

  // --- Manual Inline Tampering ---
  const handleInlineTamper = (id: string, field: keyof PatientRecord, value: any) => {
    const target = patients.find(p => p.id === id);
    if (!target) return;

    if (target.isFrozen) {
      addLog(
        'TAMPER',
        `[LOCK PREVENTION] Manual override blocked! Attempted edit on cryptographically frozen Block ${id} (${target.name}) rejected.`,
        'error',
        target.id,
        target.name
      );
      return;
    }

    // Check if IPS Real-time Self-Healer is enabled
    const isIpsEnabled = strategies.find(s => s.id === 'active_lock')?.enabled;
    if (isIpsEnabled) {
      // Trigger a beautiful visual alert popup
      setHealerAlert({
        show: true,
        patientName: target.name,
        field: field.toString(),
        attemptedValue: value.toString()
      });

      // Auto-hide alert after 3.5 seconds
      setTimeout(() => setHealerAlert(null), 3500);

      addLog(
        'VERIFY_FAIL',
        `[IPS BLOCK] Authorized state protected! Intercepted manual edit on ${target.name}'s '${field.toString()}' to '${value.toString()}'. Value auto-healed to baseline.`,
        'error',
        target.id,
        target.name
      );
      return;
    }

    // Apply the unauthorized edit directly without updating any signatures or cascading hashes
    setPatients(prev => prev.map(p => {
      if (p.id === id) {
        return {
          ...p,
          [field]: value,
          lastUpdated: new Date().toISOString().replace('T', ' ').slice(0, 19).slice(11, 19),
          updatedBy: "MANUAL_TAMPER_USER"
        };
      }
      return p;
    }));

    const countEnabled = strategies.filter(s => s.enabled).length;
    const timestampStr = new Date().toISOString().replace('T', ' ').slice(0, 19);
    const updatedPatient = { ...target, [field]: value };
    const forgedHash = calculateRecordHash(updatedPatient);

    const sandboxAttempt: TamperAttempt = {
      id: `TMP-${Date.now().toString().slice(-6)}`,
      timestamp: timestampStr,
      timeLabel: timestampStr.slice(11, 19),
      attackType: 'Sandbox Direct Override',
      targetPatient: target.name,
      targetPatientId: target.id,
      status: 'Undetected (Succeeded)',
      threatLevel: 'High',
      attackerProfile: 'Clinical Sandbox Manual Override',
      details: `Field '${String(field)}' changed from '${String((target as any)[field])}' to '${String(value)}'. Ledger chain integrity compromised.`,
      defensesEnabledCount: countEnabled,
      originalData: {
        medication: target.medication,
        dosage: target.dosage,
        diagnosis: target.diagnosis,
        status: target.status,
        hash: target.hash,
        prevHash: target.prevHash,
        signature: target.signature,
        updatedBy: target.updatedBy
      },
      tamperedData: {
        medication: field === 'medication' ? String(value) : target.medication,
        dosage: field === 'dosage' ? String(value) : target.dosage,
        diagnosis: field === 'diagnosis' ? String(value) : target.diagnosis,
        status: field === 'status' ? (String(value) as any) : target.status,
        hash: forgedHash,
        prevHash: target.prevHash,
        signature: target.signature,
        updatedBy: 'MANUAL_TAMPER_USER'
      },
      detectionMechanism: 'Direct cell override without cryptographic signature recalculation. Stored hash now diverges from live state.',
      remediation: 'Restore block to golden baseline or trigger automated IPS integrity scan.'
    };
    setTamperAttempts(prev => [sandboxAttempt, ...prev]);

    addLog(
      'TAMPER',
      `Manual Tamper: Direct database override on ${target.name}'s '${field.toString()}' to '${value.toString()}'. Ledger chain integrity compromised!`,
      'warning',
      target.id,
      target.name
    );

    triggerTamperAlarm(target.name, `Manual direct override of clinical field '${field.toString()}' inside Sandbox mode.`);

    // Clear verification scan status
    setScanStatus(null);
  };

  // --- Backdoor Tampering Simulation ---
  const executeDirectTampering = (recalculateChain: boolean) => {
    if (!selectedPatient) return;

    if (selectedPatient.isFrozen) {
      addLog(
        'TAMPER',
        `[LOCK PREVENTION] Simulation blocked! Attempted backdoor hack on cryptographically frozen Block ${selectedPatient.id} (${selectedPatient.name}) was automatically repelled.`,
        'error',
        selectedPatient.id,
        selectedPatient.name
      );
      setHealerAlert({
        show: true,
        patientName: selectedPatient.name,
        field: 'FROZEN LOCK SHIELD',
        attemptedValue: recalculateChain ? 'Forged Hash Cascade Rejected' : 'Unauthorized Medication Edit Rejected'
      });
      setTimeout(() => setHealerAlert(null), 3500);
      return;
    }

    const targetPatientName = newName.trim() || selectedPatient.name;
    const isChainEnabled = strategies.find(s => s.id === 'crypt_chain')?.enabled;
    const isHmacEnabled = strategies.find(s => s.id === 'hmac_sig')?.enabled;
    const isIpsEnabled = strategies.find(s => s.id === 'active_lock')?.enabled;

    // INTERCEPT IF IPS IS ACTIVE
    if (isIpsEnabled) {
      setHealerAlert({
        show: true,
        patientName: targetPatientName,
        field: recalculateChain ? 'Chain Hash recalculation' : 'SQL Database Table Write',
        attemptedValue: recalculateChain ? 'Forged Hash Cascade' : `${newMedication || selectedPatient.medication} ${newDosage || selectedPatient.dosage}`
      });
      setTimeout(() => setHealerAlert(null), 3500);

      const countEnabled = strategies.filter(s => s.enabled).length;
      const timestampStr = new Date().toISOString().replace('T', ' ').slice(0, 19);

      const blockedAttempt: TamperAttempt = {
        id: `TMP-${Date.now().toString().slice(-6)}`,
        timestamp: timestampStr,
        timeLabel: timestampStr.slice(11, 19),
        attackType: recalculateChain ? 'Chain Recalculation' : 'Direct SQL Write',
        targetPatient: targetPatientName,
        targetPatientId: selectedPatient.id,
        status: 'Detected & Blocked',
        threatLevel: recalculateChain ? 'High' : 'Critical',
        attackerProfile: recalculateChain ? 'Adversary (Cascade Chain Forger)' : 'Direct SQL Database Injector',
        details: `Manual tamper attack on ${targetPatientName} intercepted and blocked by the Real-time IPS Self-Healer Shield. All records protected.`,
        defensesEnabledCount: countEnabled,
        originalData: {
          medication: selectedPatient.medication,
          dosage: selectedPatient.dosage,
          diagnosis: selectedPatient.diagnosis,
          status: selectedPatient.status,
          hash: selectedPatient.hash,
          prevHash: selectedPatient.prevHash,
          signature: selectedPatient.signature,
          updatedBy: selectedPatient.updatedBy
        },
        tamperedData: {
          medication: newMedication.trim() || selectedPatient.medication,
          dosage: newDosage.trim() || selectedPatient.dosage,
          diagnosis: newDiagnosis.trim() || selectedPatient.diagnosis,
          status: newStatus || selectedPatient.status,
          hash: recalculateChain ? 'FORGED_CASCADE_HASH' : 'MISMATCHED_LIVE_HASH',
          prevHash: selectedPatient.prevHash,
          signature: 'UNAUTHORIZED_FORGED_SIG',
          updatedBy: 'MANUAL_TAMPER_OVERRIDE'
        },
        detectionMechanism: 'Real-time IPS Self-Healer Shield detected unauthorized mutation and rolled back block to golden baseline.',
        remediation: 'No further action required — ledger integrity maintained.'
      };
      setTamperAttempts(prev => [blockedAttempt, ...prev]);

      addLog(
        'VERIFY_FAIL',
        `[IPS ACTIVE SHIELD] Intercepted and blocked manual tamper on ${targetPatientName}. Patient record protected.`,
        'error',
        selectedPatient.id,
        targetPatientName
      );

      setSelectedPatient(null);
      setActionType(null);
      setScanStatus(null);
      return;
    }
    
    // Determine outcomes for statistics
    // 1. Direct tampering is detected if we don't recalculate the chain and standard hash validation is on
    // 2. Chain recalculation attack is detected if HMAC key validation is on
    let isDetected = false;
    if (!recalculateChain) {
      isDetected = true; // Easily spotted because block hash won't match its modified fields
    } else {
      isDetected = isHmacEnabled || false; // Spied only if HMAC key validates, because standard hashes were recalculated by attacker!
    }

    const countEnabled = strategies.filter(s => s.enabled).length;
    const timestampStr = new Date().toISOString().replace('T', ' ').slice(0, 19);

    const newAttempt: TamperAttempt = {
      id: `TMP-${Date.now().toString().slice(-6)}`,
      timestamp: timestampStr,
      timeLabel: timestampStr.slice(11, 19),
      attackType: recalculateChain ? 'Chain Recalculation' : 'Direct SQL Write',
      targetPatient: targetPatientName,
      targetPatientId: selectedPatient.id,
      status: isDetected ? 'Detected & Blocked' : 'Undetected (Succeeded)',
      threatLevel: recalculateChain ? 'High' : 'Critical',
      attackerProfile: recalculateChain ? 'Adversary (Cascade Chain Forger)' : 'Direct SQL Database Injector',
      details: isDetected 
        ? `Manual database tampering injected into Block ${selectedPatient.id} (${targetPatientName}). Cryptographic hash mismatch triggered immediate audit alert.`
        : `Maliciously injected database values into Block ${selectedPatient.id}. Integrity checks bypassed because relevant defenses were disabled.`,
      defensesEnabledCount: countEnabled,
      originalData: {
        medication: selectedPatient.medication,
        dosage: selectedPatient.dosage,
        diagnosis: selectedPatient.diagnosis,
        status: selectedPatient.status,
        hash: selectedPatient.hash,
        prevHash: selectedPatient.prevHash,
        signature: selectedPatient.signature,
        updatedBy: selectedPatient.updatedBy
      },
      tamperedData: {
        medication: newMedication.trim() || selectedPatient.medication,
        dosage: newDosage.trim() || selectedPatient.dosage,
        diagnosis: newDiagnosis.trim() || selectedPatient.diagnosis,
        status: newStatus || selectedPatient.status,
        hash: recalculateChain ? 'FORGED_CASCADE_HASH_99' : 'MISMATCHED_LIVE_HASH_00',
        prevHash: selectedPatient.prevHash,
        signature: recalculateChain ? 'hmac_sig_FORGED_KEY' : selectedPatient.signature,
        updatedBy: 'MANUAL_TAMPER_OVERRIDE'
      },
      detectionMechanism: isDetected
        ? (recalculateChain ? 'HMAC Private Key Verification Failed: Key signature cannot be computed by adversary.' : 'SHA-256 Record Hash Inconsistency: Live computed hash diverges from block header.')
        : 'Integrity checks disabled during manual injection.',
      remediation: 'Restore record from golden baseline or toggle on Blockchain Hash Chaining and HMAC Private Key signing.'
    };

    setTamperAttempts(prev => [newAttempt, ...prev]);

    // Apply the attack directly ONLY to the selected target patient record
    setPatients(prev => {
      return prev.map(p => {
        if (p.id === selectedPatient.id) {
          return {
            ...p,
            name: newName.trim() || p.name,
            medication: newMedication.trim() || p.medication,
            dosage: newDosage.trim() || p.dosage,
            diagnosis: newDiagnosis.trim() || p.diagnosis,
            status: newStatus || p.status,
            lastUpdated: timestampStr,
            updatedBy: "MANUAL_TAMPER_OVERRIDE"
          };
        }
        return p;
      });
    });

    addLog(
      'TAMPER',
      `Manual Tamper Injected: Direct database override on ${targetPatientName} (Block ${selectedPatient.id}). Cryptographic hash is now mismatched!`,
      isDetected ? 'warning' : 'error',
      selectedPatient.id,
      targetPatientName
    );

    triggerTamperAlarm(targetPatientName, recalculateChain ? "Backdoor exploit with forged hash cascade recalculation" : `Direct unauthorized database tampering`);

    setSelectedPatient(null);
    setActionType(null);
    setScanStatus(null);
  };

  // --- Threat Scenarios Constant Library ---
  const THREAT_SCENARIOS = [
    {
      id: 'sql_injection',
      name: 'SQL Injection / Direct DB Overwrite',
      category: 'Database Manipulation',
      threatLevel: 'Critical' as const,
      objective: 'Bypass API routers to write custom payloads directly into the patient database records.',
      method: 'Inject harmful query commands through input vectors, compromising the medical diagnosis or medication values.',
      requiredDefenses: [
        { id: 'crypt_chain', name: 'Blockchain Hash Chaining' },
        { id: 'active_lock', name: 'IPS Real-time Self-Healer' }
      ],
      evaluate: (activeStrategies: SecurityStrategy[]) => {
        const ips = activeStrategies.find(s => s.id === 'active_lock')?.enabled;
        const chain = activeStrategies.find(s => s.id === 'crypt_chain')?.enabled;
        
        if (ips) {
          return {
            outcome: 'FOILED' as const,
            statusText: 'Foiled & Prevented',
            explanation: 'The Active IPS Self-Healer detected the direct write attempt, intercepted the execution, blocked the commit, and auto-healed the patient state.',
            remediation: 'No action required. Your active prevention shield is securing this vector.',
            isDetected: true,
            recalculate: false
          };
        } else if (chain) {
          return {
            outcome: 'MITIGATED' as const,
            statusText: 'Mitigated (Detected on Scan)',
            explanation: 'The write succeeded, but because Blockchain Hash Chaining is enabled, the integrity chain is broken. The upcoming integrity scan will detect this tamper immediately.',
            remediation: 'Enable IPS Real-time Self-Healer to prevent these writes from completing in real-time rather than just detecting them post-hoc.',
            isDetected: true,
            recalculate: false
          };
        } else {
          return {
            outcome: 'BREACHED' as const,
            statusText: 'Successful Breach',
            explanation: 'The database record was modified. Because both hashing chains and active IPS shields are disabled, the compromise is undetected and patient safety is severely compromised.',
            remediation: 'Immediately enable Blockchain Hash Chaining and IPS Real-time Self-Healer to secure database records.',
            isDetected: false,
            recalculate: false
          };
        }
      }
    },
    {
      id: 'chain_recalc',
      name: 'Cascading Hash Chain Recalculation',
      category: 'Advanced Persistent Threat (APT)',
      threatLevel: 'High' as const,
      objective: 'Modify patient history and programmatically recalculate all subsequent hashes in the chain.',
      method: 'Attackers edit a block, then loop through all subsequent nodes, updating the prevHash links to forge a valid chaining verification.',
      requiredDefenses: [
        { id: 'hmac_sig', name: 'HMAC Private Key Signature' },
        { id: 'active_lock', name: 'IPS Real-time Self-Healer' }
      ],
      evaluate: (activeStrategies: SecurityStrategy[]) => {
        const ips = activeStrategies.find(s => s.id === 'active_lock')?.enabled;
        const hmac = activeStrategies.find(s => s.id === 'hmac_sig')?.enabled;
        
        if (ips) {
          return {
            outcome: 'FOILED' as const,
            statusText: 'Foiled & Blocked',
            explanation: 'Active prevention shield immediately blocked the cascading recalculation attempt before any hashes could be modified.',
            remediation: 'No action required. IPS self-healing is neutralizing the intrusion.',
            isDetected: true,
            recalculate: true
          };
        } else if (hmac) {
          return {
            outcome: 'FOILED' as const,
            statusText: 'Foiled & Spotted',
            explanation: 'Although the attacker successfully recalculated all the parent hash chain links, they do not possess the HSM secret key. The HMAC validation failed due to invalid signature verification.',
            remediation: 'Consider enabling IPS Real-time Self-Healer to actively shield against recalculation loops.',
            isDetected: true,
            recalculate: true
          };
        } else {
          return {
            outcome: 'BREACHED' as const,
            statusText: 'Successful Breach',
            explanation: 'Hashes were forged and linked successfully. Since HMAC signature validation is disabled, the system accepts the tampered chain as genuine.',
            remediation: 'Enable HMAC Private Key Signature immediately. Having hashes alone is insufficient if attackers can recalculate them.',
            isDetected: false,
            recalculate: true
          };
        }
      }
    },
    {
      id: 'mitm_transmission',
      name: 'Man-in-the-Middle (MitM) Payload Modification',
      category: 'Network Interception',
      threatLevel: 'High' as const,
      objective: 'Intercept medical data in transit and inject malicious values prior to saving.',
      method: 'Alter the clinical values inside the transmission packets, forcing the database node to save tampered values as a legitimate original entry.',
      requiredDefenses: [
        { id: 'hmac_sig', name: 'HMAC Private Key Signature' }
      ],
      evaluate: (activeStrategies: SecurityStrategy[]) => {
        const hmac = activeStrategies.find(s => s.id === 'hmac_sig')?.enabled;
        
        if (hmac) {
          return {
            outcome: 'FOILED' as const,
            statusText: 'Foiled & Rejected',
            explanation: 'The intercepted packet lacked a valid signature matching the server key. The ledger rejected the commit due to signature verification failure.',
            remediation: 'Keep HMAC signatures enabled on all ingestion interfaces.',
            isDetected: true,
            recalculate: false
          };
        } else {
          return {
            outcome: 'BREACHED' as const,
            statusText: 'Successful Breach',
            explanation: 'The modified payload was saved. The server accepted the payload and calculated standard hashes for it, storing the forged medication natively.',
            remediation: 'Enable HMAC Private Key Signature to verify that all inbound clinical logs originate from authorized clients.',
            isDetected: false,
            recalculate: false
          };
        }
      }
    },
    {
      id: 'brute_force',
      name: 'HMAC Key Brute Force Exhaustion',
      category: 'Cryptographic Attack',
      threatLevel: 'Medium' as const,
      objective: 'Exhaustively search for the HMAC secret key to forge arbitrary administrative signatures.',
      method: 'Spin up offline brute-force clusters to crack the secret password used to sign patient hashes.',
      requiredDefenses: [
        { id: 'hmac_sig', name: 'HMAC Private Key Signature' }
      ],
      evaluate: (activeStrategies: SecurityStrategy[]) => {
        const hmac = activeStrategies.find(s => s.id === 'hmac_sig')?.enabled;
        
        if (hmac) {
          return {
            outcome: 'FOILED' as const,
            statusText: 'Foiled & Thwarted',
            explanation: 'The system uses 256-bit entropy bounds. A complete search space of 2^256 keys is mathematically impossible to exhaust in trillions of years with modern hardware.',
            remediation: 'Maintain complex 256-bit cryptographically random key rotations.',
            isDetected: true,
            recalculate: false
          };
        } else {
          return {
            outcome: 'MITIGATED' as const,
            statusText: 'Not Applicable (Mitigated)',
            explanation: 'Since HMAC signatures are disabled, the attacker does not need to brute force any key to forge entries, but the ledger remains vulnerable to simple hash shifting.',
            remediation: 'Enable HMAC Private Key Signature to enforce cryptographic safety.',
            isDetected: true,
            recalculate: false
          };
        }
      }
    },
    {
      id: 'insider_threat',
      name: 'Credential Theft / Disgruntled Insider',
      category: 'Session Exploitation',
      threatLevel: 'High' as const,
      objective: 'Perform unauthorized clinical modifications under a stolen clinical auditor session.',
      method: 'Exfiltrate session tokens or credentials to modify critical dosages, then attempt to clear audit trail logs.',
      requiredDefenses: [
        { id: 'immutable_logs', name: 'WORM Immutable Audit Trail' }
      ],
      evaluate: (activeStrategies: SecurityStrategy[]) => {
        const worm = activeStrategies.find(s => s.id === 'immutable_logs')?.enabled;
        
        if (worm) {
          return {
            outcome: 'MITIGATED' as const,
            statusText: 'Traced & Non-Repudiated',
            explanation: 'The attacker edited values, but because the Write-Once-Read-Many (WORM) ledger is active, all log entries are secured offsite. All actions are logged permanently, establishing full forensic accountability.',
            remediation: 'Enforce multi-factor verification on auditor portal entries and active roles.',
            isDetected: true,
            recalculate: false
          };
        } else {
          return {
            outcome: 'BREACHED' as const,
            statusText: 'Successful Breach & Wipe',
            explanation: 'The attacker modified records and successfully purged or falsified the system console logs to cover up their trail.',
            remediation: 'Enable WORM Immutable Audit Trail immediately to prevent log tampering.',
            isDetected: false,
            recalculate: false
          };
        }
      }
    }
  ];

  const runThreatSimulation = () => {
    if (simulationActive) return;
    
    const targetPatient = patients.find(p => p.id === simulationTargetId) || patients[0];
    const targetPatientName = targetPatient.name;
    const scenario = THREAT_SCENARIOS.find(s => s.id === activeScenarioId)!;
    
    setSimulationActive(true);
    setSimulationProgress(0);
    setSimulationResult(null);
    setSimulationLogs(['[INFO] Preparing attack vector framework...', '[INFO] Enumerating clinical ingestion endpoints...']);
    
    let step = 0;
    const interval = setInterval(() => {
      step += 20;
      setSimulationProgress(step);
      
      if (step === 20) {
        setSimulationLogs(prev => [...prev, `[TARGET] Locked on record node ID: ${targetPatient.id} (${targetPatientName})`]);
      } else if (step === 40) {
        setSimulationLogs(prev => [...prev, `[EXPLOIT] Injecting customized malicious payload: "${scenario.name}"`]);
      } else if (step === 60) {
        setSimulationLogs(prev => [...prev, `[NETWORK] Payload delivered to node. Probing server memory layer...`]);
      } else if (step === 80) {
        setSimulationLogs(prev => [...prev, `[AUDIT] Analyzing active defensive countermeasures...`]);
      } else if (step === 100) {
        clearInterval(interval);
        
        // Evaluate outcome
        const evalResult = scenario.evaluate(strategies);
        const timestampStr = new Date().toISOString().replace('T', ' ').slice(0, 19);
        const countEnabled = strategies.filter(s => s.enabled).length;
        
        setSimulationActive(false);
        setSimulationResult({
          scenarioId: scenario.id,
          outcome: evalResult.outcome,
          statusText: evalResult.statusText,
          explanation: evalResult.explanation,
          remediation: evalResult.remediation,
          targetName: targetPatientName
        });
        
        // Construct TamperAttempt history entry
        const isDetected = evalResult.isDetected;
        const newAttempt: TamperAttempt = {
          id: `TMP-${Date.now().toString().slice(-6)}`,
          timestamp: timestampStr,
          timeLabel: timestampStr.slice(11, 19),
          attackType: (scenario.id === 'chain_recalc' || evalResult.recalculate) ? 'Chain Recalculation' : (scenario.id === 'mitm_transmission' ? 'MITM Transmission' : (scenario.id === 'insider_threat' ? 'Insider Privilege Exploit' : 'Direct SQL Write')),
          targetPatient: targetPatientName,
          targetPatientId: targetPatient.id,
          status: isDetected ? 'Detected & Blocked' : 'Undetected (Succeeded)',
          threatLevel: scenario.threatLevel,
          attackerProfile: scenario.name,
          details: `${scenario.name} threat vector: ${evalResult.statusText}. ${evalResult.explanation}`,
          defensesEnabledCount: countEnabled,
          originalData: {
            medication: targetPatient.medication,
            dosage: targetPatient.dosage,
            diagnosis: targetPatient.diagnosis,
            status: targetPatient.status,
            hash: targetPatient.hash,
            prevHash: targetPatient.prevHash,
            signature: targetPatient.signature,
            updatedBy: targetPatient.updatedBy
          },
          tamperedData: {
            medication: scenario.id === 'sql_injection' ? "MALICIOUS PLACEBO (Compromised)" : (scenario.id === 'chain_recalc' ? "EXPLOITED CASCADE DRUG" : (scenario.id === 'mitm_transmission' ? "INJECTED MITM TRANSMISSION" : "DISGRUNTLED MEDICINE")),
            dosage: scenario.id === 'sql_injection' ? "REDACTED" : (scenario.id === 'chain_recalc' ? "0mg COMPROMISED" : (scenario.id === 'mitm_transmission' ? "999mg TOXIC" : targetPatient.dosage)),
            diagnosis: `COMPROMISED VIA ${scenario.name.toUpperCase()}`,
            status: 'Critical',
            hash: (scenario.id === 'chain_recalc' || evalResult.recalculate) ? 'sha256_forged_cascade_recalc' : 'sha256_mismatched_payload',
            prevHash: targetPatient.prevHash,
            signature: (scenario.id === 'chain_recalc') ? 'hmac_sig_FORGED_KEY' : targetPatient.signature,
            updatedBy: `ATTACKER_${scenario.id.toUpperCase()}`
          },
          detectionMechanism: evalResult.explanation,
          remediation: evalResult.remediation
        };
        
        setTamperAttempts(prev => [newAttempt, ...prev]);
        
        // Update live database if breached or mitigated (meaning write completed or chain shifted)
        if (evalResult.outcome === 'BREACHED' || evalResult.outcome === 'MITIGATED') {
          setPatients(prev => {
            if (scenario.id === 'sql_injection') {
              return prev.map(p => {
                if (p.id === targetPatient.id) {
                  return {
                    ...p,
                    medication: "MALICIOUS PLACEBO (Compromised)",
                    dosage: "REDACTED",
                    diagnosis: "WARNING: SECURITY INTEGRITY BREACHED",
                    lastUpdated: timestampStr,
                    updatedBy: "MALICIOUS_SQL_INJECTOR"
                  };
                }
                return p;
              });
            } else if (scenario.id === 'chain_recalc') {
              return prev.map(p => {
                if (p.id === targetPatient.id) {
                  const copy = {
                    ...p,
                    medication: "EXPLOITED CASCADE DRUG",
                    dosage: "0mg COMPROMISED",
                    diagnosis: "WARNING: CHAIN COLLUSION EXPLOIT",
                    lastUpdated: timestampStr,
                    updatedBy: "CHAIN_RECALC_EXPLOIT"
                  };
                  copy.hash = calculateRecordHash(copy);
                  copy.signature = generateHMACSignature(copy.hash, "BAD_KEY_666"); // attacker's forged signature
                  return copy;
                }
                return p;
              });
            } else if (scenario.id === 'mitm_transmission') {
              return prev.map(p => {
                if (p.id === targetPatient.id) {
                  return {
                    ...p,
                    medication: "INJECTED MITM TRANSMISSION",
                    dosage: "999mg TOXIC",
                    diagnosis: "WARNING: INTERCEPTED IN TRANSIT",
                    lastUpdated: timestampStr,
                    updatedBy: "MITM_ATTACKER"
                  };
                }
                return p;
              });
            } else if (scenario.id === 'insider_threat') {
              return prev.map(p => {
                if (p.id === targetPatient.id) {
                  return {
                    ...p,
                    medication: "DISGRUNTLED MEDICINE",
                    diagnosis: "COMPROMISED BY INSIDER ACCESS",
                    lastUpdated: timestampStr,
                    updatedBy: "STOLEN_AUDITOR_CREDS"
                  };
                }
                return p;
              });
            }
            return prev;
          });
        }
        
        // Log to MedTrust Secure Auditor Console
        if (evalResult.outcome === 'FOILED') {
          addLog(
            'VERIFY_FAIL',
            `[SECURITY SHIELD] ${scenario.name} threat vector neutralized. Attack targeted patient ${targetPatientName}.`,
            'success',
            targetPatient.id,
            targetPatientName
          );
        } else if (evalResult.outcome === 'MITIGATED') {
          addLog(
            'TAMPER',
            `[BREACH DETECTED DOWNSTREAM] ${scenario.name} modified patient ${targetPatientName} data, but changes broke hash linkages. Run Integrity Scan to flag block.`,
            'warning',
            targetPatient.id,
            targetPatientName
          );
          triggerTamperAlarm(targetPatientName, `Breach Simulation: ${scenario.name} (Broke sequence hash linkages)`);
        } else {
          addLog(
            'TAMPER',
            `[CRITICAL BREACH SUCCESSFUL] ${scenario.name} bypassed all defenses! Modified clinical data on patient ${targetPatientName} without detection.`,
            'error',
            targetPatient.id,
            targetPatientName
          );
          triggerTamperAlarm(targetPatientName, `Breach Simulation: ${scenario.name} (Bypassed all active defenses!)`);
        }
        
        // If IPS self-healer blocks it, show the healer alert modal
        if (evalResult.outcome === 'FOILED' && strategies.find(s => s.id === 'active_lock')?.enabled) {
          setHealerAlert({
            show: true,
            patientName: targetPatientName,
            field: scenario.category,
            attemptedValue: 'Malicious Payload Injected'
          });
          setTimeout(() => setHealerAlert(null), 3500);
        }
      }
    }, 300);
  };

  // --- Reset Database Baseline ---
  const handleResetSystem = () => {
    let prev = "00000000000000000000000000000000";
    const baseline = INITIALIZED_PATIENTS.map(p => {
      const copy = { ...p, prevHash: prev };
      copy.hash = calculateRecordHash(copy);
      copy.signature = generateHMACSignature(copy.hash, secretKey);
      prev = copy.hash;
      return copy;
    });

    setPatients(baseline);
    setAuthorizedPatients(baseline);
    setScanStatus(null);
    setScannedBlocksMap({});
    setTamperAlarms([]);
    addLog('VERIFY_SUCCESS', 'Database restored to trusted clinical baseline.', 'success');
  };

  // --- Toggle Strategy ---
  const toggleStrategy = (id: string) => {
    setStrategies(prev => prev.map(s => {
      if (s.id === id) {
        const nextState = !s.enabled;
        addLog(
          'DEFENSE_TRIGGERED',
          `Security defense mode '${s.name}' was manually ${nextState ? 'ENABLED' : 'DISABLED'}.`,
          nextState ? 'info' : 'warning'
        );

        // If enabling IPS real-time self-healer, instantly trigger database repair!
        if (id === 'active_lock' && nextState) {
          setTimeout(() => {
            let tamperedCount = 0;
            patients.forEach((p, idx) => {
              const authP = authorizedPatients[idx];
              if (p.diagnosis !== authP.diagnosis || 
                  p.medication !== authP.medication || 
                  p.dosage !== authP.dosage || 
                  p.status !== authP.status ||
                  p.name !== authP.name) {
                tamperedCount++;
              }
            });

            if (tamperedCount > 0) {
              setPatients(authorizedPatients);
              addLog(
                'VERIFY_SUCCESS',
                `[IPS ACTION] Active self-healing triggered! ${tamperedCount} compromised clinical fields repaired and restored to secure cryptographic baseline.`,
                'success'
              );
            } else {
              addLog(
                'VERIFY_SUCCESS',
                `[IPS MONITOR] System healthy. Real-time shield is actively protecting database integrity.`,
                'success'
              );
            }
          }, 100);
        }

        return { ...s, enabled: nextState };
      }
      return s;
    }));
    setScanStatus(null);
  };

  // --- Self Healing Action for Security Agent ---
  const handleTriggerSelfHealing = () => {
    setPatients(authorizedPatients);
    setScanStatus(null);
    setTamperAlarms([]);
    addLog(
      'VERIFY_SUCCESS',
      `[SECURITY AGENT ACTION] Autonomous Self-Healing IPS restored entire patient database to golden cryptographic baseline.`,
      'success'
    );
  };

  // --- Restore Single Patient Block to Golden Authoritative Baseline ---
  const handleRestoreSinglePatient = (patientId: string) => {
    const golden = authorizedPatients.find(p => p.id === patientId);
    if (!golden) return;
    setPatients(prev => prev.map(p => p.id === patientId ? { ...golden } : p));
    setTamperAlarms(prev => prev.filter(a => a.patientName !== golden.name));
    setScanStatus(null);
    addLog(
      'VERIFY_SUCCESS',
      `Restored patient block ${patientId} (${golden.name}) to authoritative cryptographic baseline.`,
      'success',
      patientId,
      golden.name
    );
  };

  // --- Navigate to Specific Patient in Clinical Operations ---
  const handleNavigateToPatient = (patientId: string) => {
    setCurrentPage('clinical');
    const index = patients.findIndex(p => p.id === patientId);
    if (index !== -1) {
      setExpandedBlockIndex(index);
      setTimeout(() => {
        const element = document.getElementById(`patient-row-${patientId}`);
        if (element) {
          element.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      }, 150);
    }
  };

  // --- Setup inputs for patient updates ---
  const startAction = (patient: PatientRecord, type: 'doctor' | 'tamper') => {
    setSelectedPatient(patient);
    setActionType(type);
    setNewName(patient.name);
    setNewMedication(patient.medication);
    setNewDosage(patient.dosage);
    setNewDiagnosis(patient.diagnosis);
    setNewStatus(patient.status);
  };

  // --- Export Data as CSV ---
  const exportToCSV = (data: PatientRecord[], filename: string) => {
    const headers = [
      'Block Index', 
      'Patient ID', 
      'Name', 
      'Age', 
      'Blood Type', 
      'Status', 
      'Diagnosis', 
      'Medication', 
      'Dosage', 
      'Previous Hash', 
      'Hash', 
      'Signature', 
      'Last Updated', 
      'Updated By'
    ];
    
    const rows = data.map((p, idx) => [
      `0${idx + 1}`,
      p.id,
      p.name,
      p.age,
      p.bloodType,
      p.status,
      p.diagnosis,
      p.medication,
      p.dosage,
      p.prevHash,
      p.hash,
      p.signature,
      p.lastUpdated,
      p.updatedBy
    ]);
    
    const csvString = [
      headers.join(','), 
      ...rows.map(row => row.map(val => `"${String(val).replace(/"/g, '""')}"`).join(','))
    ].join('\n');
    
    const blob = new Blob([csvString], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    addLog(
      'VERIFY_SUCCESS',
      `Successfully generated and downloaded CSV report: ${filename}`,
      'info'
    );
  };

  // --- Export Data as PDF ---
  const exportToPDF = (data: PatientRecord[], isOriginal: boolean) => {
    const doc = new jsPDF({
      orientation: 'p',
      unit: 'mm',
      format: 'a4'
    });

    const timestampStr = new Date().toLocaleString();
    const pageHeight = doc.internal.pageSize.getHeight();
    const pageWidth = doc.internal.pageSize.getWidth();

    // Draw Header Banner (Slate 900 Theme for a high-assurance trusted feel)
    doc.setFillColor(15, 23, 42); 
    doc.rect(0, 0, pageWidth, 35, 'F');

    // Title Text
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(18);
    doc.text('MEDTRUST CENTRAL', 15, 14);
    
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9.5);
    doc.setTextColor(148, 163, 184); // Slate 400
    doc.text('Clinical Record Ledger Audit & Security Report', 15, 21);

    // Indicator status pill (Secure vs Compromised state)
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setFillColor(30, 41, 59); // Slate 800
    doc.rect(pageWidth - 65, 10, 50, 7, 'F');
    doc.setTextColor(255, 255, 255);
    doc.text(isOriginal ? 'SECURE BASELINE DATA' : 'CURRENT SYSTEM STATE', pageWidth - 17, 14.5, { align: 'right' });

    // Divider
    doc.setFillColor(16, 185, 129); // Emerald 500 line
    doc.rect(0, 35, pageWidth, 1.2, 'F');

    // Report details
    doc.setTextColor(71, 85, 105); // Slate 600
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.text(`Exported On: ${timestampStr}`, 15, 45);
    doc.text(`Total Ledger Records: ${data.length} Clinical Blocks`, 15, 50);

    // Check overall integrity of data
    let isLedgerHealthy = true;
    let prevHash = "00000000000000000000000000000000";
    const isChainEnabled = strategies.find(s => s.id === 'crypt_chain')?.enabled;
    const isHmacEnabled = strategies.find(s => s.id === 'hmac_sig')?.enabled;

    for (let i = 0; i < data.length; i++) {
      const p = data[i];
      const calc = calculateRecordHash({ ...p, prevHash: p.prevHash });
      if (p.hash !== calc) isLedgerHealthy = false;
      if (isChainEnabled && p.prevHash !== prevHash) isLedgerHealthy = false;
      if (isHmacEnabled) {
        const sig = generateHMACSignature(p.hash, secretKey);
        if (p.signature !== sig) isLedgerHealthy = false;
      }
      prevHash = p.hash;
    }

    // Draw Health Stamp
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    if (isOriginal || isLedgerHealthy) {
      doc.setFillColor(240, 253, 244); // Green 50
      doc.setDrawColor(74, 222, 128); // Green 400
      doc.rect(pageWidth - 75, 41, 60, 11, 'FD');
      doc.setTextColor(22, 101, 52); // Green 800
      doc.text('LEDGER STATE: SECURE', pageWidth - 45, 48, { align: 'center' });
    } else {
      doc.setFillColor(254, 242, 242); // Red 50
      doc.setDrawColor(248, 113, 113); // Red 400
      doc.rect(pageWidth - 75, 41, 60, 11, 'FD');
      doc.setTextColor(153, 27, 27); // Red 800
      doc.text('LEDGER STATE: TAMPERED', pageWidth - 45, 48, { align: 'center' });
    }

    let yPos = 58;

    data.forEach((p, idx) => {
      // If close to page bottom, add a page
      if (yPos > pageHeight - 48) {
        doc.addPage();
        
        // Draw small page header
        doc.setFillColor(15, 23, 42); // Slate 900
        doc.rect(0, 0, pageWidth, 11, 'F');
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8);
        doc.setTextColor(255, 255, 255);
        doc.text('MEDTRUST CENTRAL SECURE AUDITOR LEDGER REPORT', 15, 7.5);
        doc.setFont('helvetica', 'normal');
        doc.text(`Page ${doc.internal.pages.length - 1}`, pageWidth - 25, 7.5);
        
        doc.setFillColor(16, 185, 129); // Accent line
        doc.rect(0, 11, pageWidth, 0.5, 'F');

        yPos = 20;
      }

      // Verify individual block
      let individualValid = true;
      const isFirst = idx === 0;
      const individualPrev = isFirst ? "00000000000000000000000000000000" : data[idx - 1].hash;
      const calculatedLocal = calculateRecordHash({ 
         ...p, 
        prevHash: p.prevHash 
      });
      
      if (p.hash !== calculatedLocal) individualValid = false;
      if (isChainEnabled && p.prevHash !== individualPrev) individualValid = false;
      if (isHmacEnabled) {
        const sig = generateHMACSignature(p.hash, secretKey);
        if (p.signature !== sig) individualValid = false;
      }

      // Draw Block Panel Box with modern card aesthetics
      if (individualValid) {
        doc.setDrawColor(226, 232, 240); // Slate 200
        doc.setFillColor(248, 250, 252); // Slate 50
      } else {
        doc.setDrawColor(254, 202, 202); // Red 200
        doc.setFillColor(254, 242, 242); // Red 50
      }
      doc.rect(14, yPos, pageWidth - 28, 32, 'FD');

      // Left Vertical Indicator Bar (Color indicator accent)
      if (individualValid) {
        doc.setFillColor(16, 185, 129); // Emerald 500
      } else {
        doc.setFillColor(239, 68, 68); // Red 500
      }
      doc.rect(14, yPos, 2.5, 32, 'F');

      // 1. Block Header text row
      doc.setTextColor(71, 85, 105); // Slate 600
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.5);
      doc.text(`RECORD BLOCK #0${idx + 1}  [ID: ${p.id}]`, 20, yPos + 5.5);

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      if (individualValid) {
        doc.setTextColor(16, 185, 129); // Emerald
        doc.text('VERIFIED CLINICAL INTEGRITY', pageWidth - 20, yPos + 5.5, { align: 'right' });
      } else {
        doc.setTextColor(239, 68, 68); // Red
        doc.text('CRYPTOGRAPHIC TAMPER DETECTED', pageWidth - 20, yPos + 5.5, { align: 'right' });
      }

      // Horizontal separator line 1
      doc.setDrawColor(241, 245, 249);
      doc.line(20, yPos + 8, pageWidth - 20, yPos + 8);

      // 2. Patient info details
      doc.setTextColor(15, 23, 42); // Slate 900
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10);
      doc.text(`Patient Name: ${p.name}`, 20, yPos + 13.5);
      
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8.5);
      doc.setTextColor(100, 116, 139); // Slate 500
      doc.text(`Demographics: Age ${p.age}   |   Blood Group ${p.bloodType}   |   System Tag ${p.status}`, 20, yPos + 18);

      // 3. Medical Diagnosis and Medication details
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(15, 23, 42);
      doc.text(`Diagnosis:`, 20, yPos + 23.5);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(51, 65, 85);
      doc.text(`${p.diagnosis}`, 38, yPos + 23.5);

      doc.setFont('helvetica', 'bold');
      doc.setTextColor(15, 23, 42);
      doc.text(`Medication:`, 20, yPos + 28);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(51, 65, 85);
      doc.text(`${p.medication} (${p.dosage})`, 40, yPos + 28);

      yPos += 36;
    });

    // Footer on all pages
    const totalPages = doc.internal.pages.length - 1;
    for (let i = 1; i <= totalPages; i++) {
      doc.setPage(i);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(148, 163, 184); // slate-400
      doc.text('MedTrust Central Clinical Ledger • This report contains cryptographically signed clinical metadata for compliance.', 15, pageHeight - 10);
      doc.text(`Page ${i} of ${totalPages}`, pageWidth - 30, pageHeight - 10);
    }

    const reportName = isOriginal ? 'medtrust-original-baseline.pdf' : 'medtrust-current-compromised-ledger.pdf';
    doc.save(reportName);
    
    addLog(
      'VERIFY_SUCCESS',
      `Successfully generated and downloaded PDF report: ${reportName}`,
      'info'
    );
  };

  // Stats
  const activeDefensesCount = strategies.filter(s => s.enabled).length;

  // Filter and search auditor logs
  const filteredLogs = logs.filter(log => {
    const matchesSearch = logSearch.trim() === '' || 
      log.details.toLowerCase().includes(logSearch.toLowerCase()) || 
      log.performedBy.toLowerCase().includes(logSearch.toLowerCase()) ||
      log.action.toLowerCase().includes(logSearch.toLowerCase()) ||
      (log.patientName && log.patientName.toLowerCase().includes(logSearch.toLowerCase())) ||
      (log.recordId && log.recordId.toLowerCase().includes(logSearch.toLowerCase()));

    if (!matchesSearch) return false;

    if (logFilter === 'ALL') return true;
    if (logFilter === 'THREATS') {
      return log.action === 'TAMPER' || log.action === 'VERIFY_FAIL' || log.severity === 'danger' || log.severity === 'warning';
    }
    if (logFilter === 'UPDATES') {
      return log.action === 'UPDATE' || log.action === 'CREATE';
    }
    if (logFilter === 'SYSTEM') {
      return log.action === 'VERIFY_SUCCESS' || log.action === 'DEFENSE_TRIGGERED' || log.performedBy === 'System Auditor';
    }
    return true;
  });

  if (!currentUser) {
    return (
      <div className="min-h-screen wavy-bg font-sans text-slate-700 flex flex-col justify-center items-center p-4 md:p-8">
        <div className="w-full max-w-lg">
          {/* Logo / Brand Header */}
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-tr from-teal-600 to-teal-600 text-white shadow-premium-lg mb-4">
              <ShieldCheck className="w-8 h-8" />
            </div>
            <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight">
              MEDTRUST CENTRAL
            </h1>
            <p className="text-xs text-slate-500 font-medium mt-1">
              Cryptographic Clinical Ledger & Integrity Auditor Portal
            </p>
          </div>

          {/* Auth Card */}
          <div className="bg-white border border-slate-200/80 rounded-2xl overflow-hidden shadow-premium-lg text-slate-800">
            {/* Switcher Tab */}
            <div className="flex border-b border-slate-100 bg-slate-50/30">
              <button
                type="button"
                onClick={() => { setAuthMode('login'); setLoginError(''); setRegError(''); }}
                className={`flex-1 py-3.5 text-center text-xs font-extrabold transition border-b-2 ${
                  authMode === 'login' 
                    ? 'border-teal-600 text-teal-700 bg-white font-black' 
                    : 'border-transparent text-slate-500 hover:text-slate-800'
                }`}
              >
                Sign In to Auditor Portal
              </button>
              <button
                type="button"
                onClick={() => { setAuthMode('register'); setLoginError(''); setRegError(''); }}
                className={`flex-1 py-3.5 text-center text-xs font-extrabold transition border-b-2 ${
                  authMode === 'register' 
                    ? 'border-teal-600 text-teal-700 bg-white font-black' 
                    : 'border-transparent text-slate-500 hover:text-slate-800'
                }`}
              >
                Register Auditor Account
              </button>
            </div>

            {/* Form Body */}
            <form 
              onSubmit={authMode === 'login' ? handleLogin : handleRegister} 
              className="p-6 md:p-8 space-y-4"
            >
              {authMode === 'login' ? (
                // SIGN IN FORM
                <div className="space-y-4">
                  {loginError && (
                    <div className="p-3 bg-rose-50 border border-rose-150 rounded-lg text-xs text-rose-700 font-semibold leading-relaxed flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
                      <span>{loginError}</span>
                    </div>
                  )}
                  <div>
                    <label className="text-[10px] text-slate-500 uppercase font-mono tracking-wider block mb-1.5">Username</label>
                    <input 
                      type="text" 
                      value={loginUsername}
                      onChange={e => setLoginUsername(e.target.value)}
                      placeholder="e.g. auditor_jones"
                      className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded-lg px-3.5 py-2.5 text-slate-900 font-semibold text-xs transition"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] text-slate-500 uppercase font-mono tracking-wider block mb-1.5">Password</label>
                    <input 
                      type="password" 
                      value={loginPassword}
                      onChange={e => setLoginPassword(e.target.value)}
                      placeholder="••••••••"
                      className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded-lg px-3.5 py-2.5 text-slate-900 font-semibold text-xs transition"
                    />
                  </div>
                  <div className="text-[11px] text-slate-500 leading-normal mt-3 bg-slate-50 p-3 rounded-lg border border-slate-100">
                    💡 <strong>Demo Access Credentials:</strong><br />
                    • Username: <strong className="text-slate-700">auditor_jones</strong><br />
                    • Password: <strong className="text-slate-700">password123</strong><br />
                    <span className="text-[10px] text-slate-400 block mt-1">Or register a custom credential above to play with individual organizational auditor roles!</span>
                  </div>
                </div>
              ) : (
                // REGISTER FORM
                <div className="space-y-3.5">
                  {regError && (
                    <div className="p-3 bg-rose-50 border border-rose-150 rounded-lg text-xs text-rose-700 font-semibold leading-relaxed flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
                      <span>{regError}</span>
                    </div>
                  )}
                  <div className="grid grid-cols-2 gap-3.5">
                    <div>
                      <label className="text-[10px] text-slate-500 uppercase font-mono tracking-wider block mb-1.5">Username</label>
                      <input 
                        type="text" 
                        value={regUsername}
                        onChange={e => setRegUsername(e.target.value)}
                        placeholder="e.g. auditor_jones"
                        className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded-lg px-3.5 py-2.5 text-slate-900 font-semibold text-xs transition"
                      />
                    </div>
                    <div>
                      <label className="text-[10px] text-slate-500 uppercase font-mono tracking-wider block mb-1.5">Password</label>
                      <input 
                        type="password" 
                        value={regPassword}
                        onChange={e => setRegPassword(e.target.value)}
                        placeholder="password123"
                        className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded-lg px-3.5 py-2.5 text-slate-900 font-semibold text-xs transition"
                      />
                    </div>
                  </div>
                  <div>
                    <label className="text-[10px] text-slate-500 uppercase font-mono tracking-wider block mb-1.5">Auditor Full Name</label>
                    <input 
                      type="text" 
                      value={regName}
                      onChange={e => setRegName(e.target.value)}
                      placeholder="e.g. Dr. Robert Chen"
                      className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded-lg px-3.5 py-2.5 text-slate-900 font-bold text-xs transition"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] text-slate-500 uppercase font-mono tracking-wider block mb-1.5">Assigned Auditor Role</label>
                    <select 
                      value={regRole}
                      onChange={e => setRegRole(e.target.value as any)}
                      className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded-lg px-3.5 py-2.5 text-slate-900 font-bold text-xs cursor-pointer transition"
                    >
                      <option value="Clinical Auditor">Clinical Auditor</option>
                      <option value="Lead Doctor">Lead Doctor</option>
                      <option value="Compliance Officer">Compliance Officer</option>
                      <option value="Database Admin">Database Admin</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] text-slate-500 uppercase font-mono tracking-wider block mb-1.5">Organization / Clinic</label>
                    <input 
                      type="text" 
                      value={regOrg}
                      onChange={e => setRegOrg(e.target.value)}
                      placeholder="e.g. MedTrust Labs Central"
                      className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded-lg px-3.5 py-2.5 text-slate-900 font-semibold text-xs transition"
                    />
                  </div>
                </div>
              )}

              {/* Submit Button */}
              <div className="pt-4 border-t border-slate-100 flex justify-end">
                <button 
                  type="submit"
                  className="w-full py-3 bg-teal-600 hover:bg-teal-500 text-white font-extrabold text-xs rounded-xl transition shadow-premium cursor-pointer flex items-center justify-center gap-1.5"
                >
                  <ShieldCheck className="w-4 h-4" />
                  {authMode === 'login' ? 'Authenticate & Enter' : 'Create Account & Enter'}
                </button>
              </div>
            </form>
          </div>
          
          <div className="text-center mt-6">
            <span className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">
              🔒 Fully Encrypted Cryptographic Integrity Audit Node
            </span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen wavy-bg font-sans text-slate-700">
      
      {/* 1. Header Area */}
      <header className="border-b border-slate-200/80 bg-white/95 backdrop-blur-md sticky top-0 z-30 shadow-xs">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-2.5">
          <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-3">
            
            {/* Top Row / Left: Brand & System Badge */}
            <div className="flex items-center justify-between gap-3 shrink-0">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-teal-50 border border-teal-200/80 text-teal-600 shadow-xs shrink-0">
                  <HeartPulse className="w-5 h-5 text-rose-500 animate-pulse" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h1 className="text-base sm:text-lg font-black tracking-tight text-slate-900 leading-none">
                      MedTrust Central
                    </h1>
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-mono font-bold bg-teal-50 text-teal-700 border border-teal-200">
                      <span className="w-1.5 h-1.5 rounded-full bg-teal-500 animate-pulse"></span>
                      HSM Chained
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500 font-medium leading-tight mt-0.5">Clinical Ledger & Cryptographic Auditor Console</p>
                </div>
              </div>
            </div>

            {/* Navigation Tabs (Centered on wide viewports, dedicated clean strip on smaller) */}
            <nav aria-label="Main Navigation" className="flex items-center gap-1 p-1 bg-slate-100/90 rounded-xl border border-slate-200/80 overflow-x-auto scrollbar-none shrink-0 self-start xl:self-center w-full xl:w-auto">
              <button
                onClick={() => setCurrentPage('clinical')}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
                  currentPage === 'clinical'
                    ? 'bg-white text-slate-900 shadow-xs font-extrabold ring-1 ring-slate-200/80'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-white/60'
                }`}
              >
                <Database className="w-3.5 h-3.5 text-teal-600" />
                <span>Clinical Operations</span>
              </button>

              <button
                onClick={() => setCurrentPage('security_agent')}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
                  currentPage === 'security_agent'
                    ? 'bg-teal-600 text-white shadow-xs font-extrabold'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-white/60'
                }`}
              >
                <ShieldCheck className="w-3.5 h-3.5 text-teal-300" />
                <span>Security Agent</span>
              </button>

              <button
                onClick={() => setCurrentPage('auditor')}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
                  currentPage === 'auditor'
                    ? 'bg-slate-900 text-white shadow-xs font-extrabold'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-white/60'
                }`}
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>Auditor Console</span>
              </button>

              <button
                onClick={() => setCurrentPage('tamper_history')}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 whitespace-nowrap cursor-pointer relative ${
                  currentPage === 'tamper_history'
                    ? 'bg-rose-700 text-white shadow-xs font-extrabold'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-white/60'
                }`}
              >
                <Fingerprint className="w-3.5 h-3.5 text-rose-400" />
                <span>Tamper History</span>
                {tamperAttempts.length > 0 && (
                  <span className={`text-[10px] px-1.5 py-0.2 rounded-full font-mono font-bold ${
                    currentPage === 'tamper_history' 
                      ? 'bg-rose-900 text-rose-100' 
                      : 'bg-rose-100 text-rose-700 border border-rose-200'
                  }`}>
                    {tamperAttempts.length}
                  </span>
                )}
              </button>
            </nav>

            {/* Right Controls: User Profile & Actions (Neatly packed without awkward multi-line break) */}
            <div className="flex items-center gap-2 justify-end shrink-0 self-end xl:self-center">
              {currentUser ? (
                <div className="flex items-center gap-2 bg-slate-50/90 border border-slate-200/90 rounded-xl py-1 px-2.5 shadow-xs shrink-0">
                  <div className="w-6 h-6 bg-teal-100 text-teal-800 rounded-lg flex items-center justify-center font-black text-[10px] select-none shrink-0 border border-teal-200">
                    {currentUser.name.split(' ').map(n => n[0]).slice(0, 2).join('').toUpperCase() || 'DA'}
                  </div>
                  <div className="text-left hidden sm:block">
                    <div className="text-[11px] font-extrabold text-slate-800 leading-tight">
                      {currentUser.name}
                    </div>
                    <div className="text-[9px] text-slate-500 font-extrabold leading-tight uppercase tracking-wider">
                      {currentUser.role}
                    </div>
                  </div>
                  <button 
                    onClick={handleLogout}
                    className="text-[10px] text-slate-400 hover:text-rose-600 hover:bg-rose-50 font-bold px-1.5 py-0.5 rounded transition-colors cursor-pointer"
                    title="Sign out"
                  >
                    Logout
                  </button>
                </div>
              ) : (
                <button 
                  onClick={() => { setAuthMode('login'); setShowAuthModal(true); }}
                  className="px-3 py-1.5 bg-slate-50 hover:bg-slate-100 text-slate-700 text-xs font-bold rounded-xl border border-slate-200 transition flex items-center gap-1.5 cursor-pointer shadow-xs shrink-0 whitespace-nowrap"
                >
                  <User className="w-3.5 h-3.5 text-slate-500" />
                  <span>Sign In</span>
                </button>
              )}

              <button 
                onClick={handleResetSystem}
                className="px-3 py-1.5 bg-white hover:bg-slate-50 text-slate-700 text-xs font-bold rounded-xl border border-slate-200/90 transition shadow-xs hover:shadow-sm flex items-center gap-1.5 cursor-pointer shrink-0 whitespace-nowrap"
                title="Reset database to baseline"
              >
                <RefreshCw className="w-3.5 h-3.5 text-slate-500" />
                <span className="hidden sm:inline">Reset Baseline</span>
                <span className="sm:hidden">Reset</span>
              </button>

              <button 
                onClick={handleRunVerification}
                disabled={isScanning}
                className={`px-3.5 py-1.5 rounded-xl text-xs font-extrabold text-white shadow-xs transition flex items-center gap-1.5 cursor-pointer shrink-0 whitespace-nowrap ${
                  isScanning 
                    ? 'bg-teal-700/80 cursor-not-allowed animate-pulse' 
                    : 'bg-teal-600 hover:bg-teal-500 shadow-[0_2px_8px_rgba(13,148,136,0.25)]'
                }`}
              >
                <Activity className={`w-3.5 h-3.5 text-white ${isScanning ? 'animate-spin' : ''}`} />
                <span>
                  {isScanning 
                    ? `Scanning (${scanningProgress}%)` 
                    : 'Run Integrity Scan'
                  }
                </span>
              </button>
            </div>

          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-4 md:px-6 py-6 space-y-6">

        {/* 🚨 Dynamic Security Intrusion Alarm Overlay 🚨 */}
        <AnimatePresence>
          {tamperAlarms.length > 0 && (
            <motion.div
              initial={{ opacity: 0, y: -20, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -20, scale: 0.95 }}
              className="bg-rose-600 text-white rounded-xl p-5 shadow-2xl border-4 border-rose-700 relative overflow-hidden animate-pulse flex flex-col md:flex-row gap-5 items-start md:items-center justify-between"
              style={{
                boxShadow: "0 0 25px rgba(225, 29, 72, 0.65)",
                backgroundImage: "repeating-linear-gradient(45deg, rgba(255,255,255,0.05) 0px, rgba(255,255,255,0.05) 10px, transparent 10px, transparent 20px)"
              }}
            >
              <div className="flex items-start gap-4 flex-1">
                <div className="p-3.5 bg-rose-800 rounded-xl text-rose-100 shrink-0 border border-rose-500 animate-bounce">
                  <ShieldAlert className="w-8 h-8 text-rose-300" />
                </div>
                <div className="flex-1 min-w-0">
                  <h3 className="text-base font-black uppercase tracking-wider flex items-center gap-2 flex-wrap">
                    <span className="bg-rose-100 text-rose-800 text-[10px] font-extrabold px-2 py-0.5 rounded-full animate-pulse">ACTIVE ALARM</span>
                    Intrusion Detection System: Compromised Block detected!
                  </h3>
                  <p className="text-xs text-rose-100 mt-1.5 leading-relaxed font-medium">
                    Critical Error: Cryptographic linkage or data authenticity was bypassed by direct table modification. 
                    Unsanitized clinical ledger data detected! Database has been compromised.
                  </p>
                  
                  {/* List of active intrusion incidents */}
                  <div className="mt-3.5 space-y-2 max-h-[140px] overflow-y-auto pr-2">
                    {tamperAlarms.map((alarm) => (
                      <div key={alarm.id} className="bg-rose-900/60 border border-rose-500/40 rounded px-3 py-2 text-[11px] font-mono flex items-center justify-between gap-3 text-rose-50">
                        <div className="truncate">
                          <strong className="text-white">Block Target:</strong> {alarm.patientName} &bull; <span className="opacity-90">{alarm.detail}</span>
                        </div>
                        <span className="text-[10px] bg-rose-800 text-rose-200 px-1.5 py-0.5 rounded font-bold shrink-0">{alarm.timestamp}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
              
              <div className="flex flex-row md:flex-col gap-2 shrink-0 w-full md:w-auto">
                <button
                  onClick={playAlarmSound}
                  className="flex-1 md:w-44 py-2 px-3 bg-rose-800 hover:bg-rose-900 text-white font-bold text-xs rounded border border-rose-500 transition flex items-center justify-center gap-1.5 cursor-pointer shadow-inner uppercase tracking-wider font-sans"
                >
                  🔊 Test Sound
                </button>
                <button
                  onClick={handleResetSystem}
                  className="flex-1 md:w-44 py-2 px-3 bg-white hover:bg-slate-100 text-rose-800 font-extrabold text-xs rounded border border-slate-200 transition flex items-center justify-center gap-1.5 cursor-pointer shadow-md uppercase tracking-wider font-sans"
                >
                  Repair Database
                </button>
                <button
                  onClick={() => setTamperAlarms([])}
                  className="flex-1 md:w-44 py-2 px-3 bg-rose-700 hover:bg-rose-800 text-rose-100 font-bold text-xs rounded border border-rose-600 transition flex items-center justify-center gap-1.5 cursor-pointer shadow-inner uppercase tracking-wider font-sans"
                >
                  Dismiss Alarm
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Real-time IPS Interceptor Warning Alert */}
        <AnimatePresence>
          {healerAlert && (
            <motion.div
              initial={{ opacity: 0, y: -10, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -10, scale: 0.95 }}
              className="bg-rose-50 border-2 border-rose-200 rounded-xl p-4 shadow-lg text-rose-900 flex items-start gap-4"
            >
              <div className="p-2 bg-rose-100 rounded-lg text-rose-600 shrink-0 animate-bounce">
                <ShieldAlert className="w-6 h-6" />
              </div>
              <div className="flex-1">
                <h4 className="font-extrabold text-sm flex items-center gap-2">
                  <span className="bg-rose-600 text-white text-[9px] uppercase px-1.5 py-0.5 rounded-full font-black animate-pulse">IPS BLOCKED & HEALED</span>
                  Intrusion Prevention System Active: Write Prevented
                </h4>
                <p className="text-xs text-rose-700 mt-1 leading-relaxed">
                  The active cryptographic shield intercepted an unauthorized edit on <strong className="text-rose-950 font-bold">{healerAlert.patientName}</strong>'s <strong className="font-mono bg-rose-150/50 px-1.5 py-0.5 rounded text-rose-900">{healerAlert.field}</strong> to <strong className="font-mono bg-rose-150/50 px-1.5 py-0.5 rounded text-rose-900">"{healerAlert.attemptedValue}"</strong>. The direct modification was discarded, and the record's clinical state was immediately auto-healed back to its certified clinical baseline.
                </p>
              </div>
              <button
                onClick={() => setHealerAlert(null)}
                className="text-rose-400 hover:text-rose-600 font-bold text-xs cursor-pointer p-1"
              >
                Dismiss
              </button>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Full Chaining Scan Latency Progress HUD & Interactive Table Overlay */}
        <TableScanOverlay
          isScanning={isScanning}
          scanningProgress={scanningProgress}
          scanningBlockIndex={scanningBlockIndex}
          scannedBlocksMap={scannedBlocksMap}
          patients={patients}
          scanStatus={scanStatus}
          onRunScan={handleRunVerification}
          onClearScanResults={() => {
            setScanStatus(null);
            setScannedBlocksMap({});
          }}
          onResetSystem={handleResetSystem}
        />

        {currentPage === 'auditor' && (
          <div className="space-y-6">
            {/* Back to Clinical Operations Bar */}
            <div className="bg-white border border-slate-200/60 rounded-xl p-4 flex flex-col sm:flex-row justify-between items-center gap-4 shadow-sm">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-teal-100 text-teal-700 flex items-center justify-center font-bold">
                  <ShieldCheck className="w-5 h-5" />
                </div>
                <div className="text-left">
                  <h4 className="text-xs font-black text-slate-900 uppercase tracking-wider">
                    Secured Audit Mode Active
                  </h4>
                  <p className="text-[11px] text-slate-500 font-medium">
                    Manage cryptographic defenses, run full database security scans, and download clinical compliance audit reports.
                  </p>
                </div>
              </div>
              <button 
                onClick={() => setCurrentPage('clinical')}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-extrabold rounded-lg transition border border-slate-200 cursor-pointer flex items-center gap-1.5"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Return to Clinical Operations</span>
              </button>
            </div>

            {/* Dynamic Ledger Risk Score Card (Auditor Console Header) */}
            <LedgerRiskScoreCard
              patients={patients}
              strategies={strategies}
              secretKey={secretKey}
              onRunIntegrityScan={handleRunVerification}
              onResetSystem={handleResetSystem}
              isScanning={isScanning}
            />

            {/* Top Control Grid: Defenses and Live Charts */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          
          {/* Defenses Controls Column */}
          <div className="lg:col-span-4 bg-white border border-slate-200/60 rounded-xl p-5 flex flex-col justify-between shadow-premium">
            <div>
              <div className="flex items-center justify-between mb-3 pb-3 border-b border-slate-100">
                <h3 className="font-extrabold text-xs text-slate-500 uppercase tracking-wider flex items-center gap-2">
                  <Shield className="w-4 h-4 text-slate-400" />
                  Security Engine Toggles
                </h3>
                <span className="text-[10px] bg-slate-50 border border-slate-200 font-mono text-slate-600 px-2.5 py-0.5 rounded font-bold">
                  {activeDefensesCount}/4 Active
                </span>
              </div>
              <p className="text-[11px] text-slate-600 mb-4 leading-relaxed font-medium">
                Configure your defense baseline. Disable security strategies to observe simulated backdoors bypassing validation or being neutralized.
              </p>

              {/* Defenses Toggles */}
              <div className="space-y-3">
                {strategies.map(s => (
                  <div 
                    key={s.id}
                    onClick={() => toggleStrategy(s.id)}
                    className={`p-3 rounded-lg border transition cursor-pointer flex items-center justify-between ${
                      s.enabled 
                        ? 'bg-teal-50/60 border-teal-100/80 shadow-sm' 
                        : 'bg-slate-50/50 border-slate-100 opacity-60 hover:opacity-100'
                    }`}
                  >
                    <div className="flex-1 pr-3">
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${s.enabled ? 'bg-emerald-500' : 'bg-slate-300'}`}></span>
                        <h4 className="text-xs font-bold text-slate-800">{s.name}</h4>
                      </div>
                      <p className="text-[10px] text-slate-500 mt-1 leading-snug">{s.description}</p>
                    </div>
                    <div className="relative">
                      <input 
                        type="checkbox" 
                        checked={s.enabled}
                        onChange={() => {}} // Controlled via parent click
                        className="sr-only" 
                      />
                      <div className={`w-8 h-4 rounded-full transition ${s.enabled ? 'bg-teal-500' : 'bg-slate-200'}`}></div>
                      <div className={`absolute left-0.5 top-0.5 w-3 h-3 rounded-full bg-white transition-transform ${s.enabled ? 'translate-x-4' : ''}`}></div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="mt-5 pt-3 border-t border-slate-100 text-[10px] text-slate-500 flex items-center gap-2 bg-slate-50 p-2.5 rounded">
              <Zap className="w-3.5 h-3.5 text-slate-400" />
              <span><strong>HMAC Salt Key:</strong> <code className="font-mono bg-white px-1 py-0.5 border border-slate-200 rounded text-teal-600 font-bold">{secretKey}</code></span>
            </div>
          </div>

          {/* Quick Analytics Dashboard */}
          <div className="lg:col-span-8 bg-white border border-slate-200/60 rounded-xl p-5 shadow-premium flex flex-col justify-between">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="font-extrabold text-xs text-slate-500 uppercase tracking-wider flex items-center gap-2">
                  <Activity className="w-4 h-4 text-slate-400" />
                  Tamper Neutralization & Telemetry
                </h3>
                <p className="text-[10px] text-slate-400">Chronological history of security breach simulations</p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setCurrentPage('tamper_history')}
                  className="text-[10px] text-rose-700 bg-rose-50 hover:bg-rose-100 font-bold border border-rose-200 px-2.5 py-1 rounded transition cursor-pointer flex items-center gap-1.5"
                >
                  <Fingerprint className="w-3 h-3 text-rose-600" />
                  <span>Full Forensic History ({tamperAttempts.length})</span>
                </button>
                <button 
                  onClick={() => setTamperAttempts([])}
                  className="text-[10px] text-slate-500 hover:text-slate-800 hover:bg-slate-50 font-bold border border-slate-200 px-2.5 py-1 rounded transition cursor-pointer"
                >
                  Clear History
                </button>
              </div>
            </div>

            {/* Recharts Layout */}
            <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
              
              <div className="md:col-span-8 h-44 w-full">
                {tamperAttempts.length === 0 ? (
                  <div className="h-full flex items-center justify-center text-xs text-slate-400 italic bg-slate-50/50 rounded border border-dashed border-slate-200">
                    No simulated attack telemetry registered yet.
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart
                      data={tamperAttempts.map((attempt, index) => ({
                        name: `T-${index + 1}`,
                        defenses: attempt.defensesEnabledCount,
                        outcome: attempt.status === 'Detected & Blocked' ? 1.0 : 0.0,
                        patient: attempt.targetPatient,
                        vector: attempt.attackType
                      }))}
                      margin={{ top: 5, right: 5, left: -25, bottom: 0 }}
                    >
                      <defs>
                        <linearGradient id="chartDef" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#7c3aed" stopOpacity={0.15}/>
                          <stop offset="95%" stopColor="#7c3aed" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                      <XAxis dataKey="name" stroke="#a78bfa" fontSize={9} />
                      <YAxis stroke="#a78bfa" fontSize={9} domain={[0, 3]} />
                      <Tooltip 
                        content={({ active, payload }) => {
                          if (active && payload && payload.length) {
                            const data = payload[0].payload;
                            return (
                              <div className="bg-white border border-slate-200 p-2.5 rounded text-[11px] shadow-lg max-w-xs text-slate-800">
                                <div className="font-bold text-slate-900">{data.vector}</div>
                                <div className="text-slate-500 text-[10px]">Target: {data.patient}</div>
                                <div className={`font-semibold ${data.outcome === 1 ? 'text-emerald-600' : 'text-rose-600'}`}>
                                  {data.outcome === 1 ? 'Foiled / Blocked' : 'Successful Breach'}
                                </div>
                              </div>
                            );
                          }
                          return null;
                        }}
                      />
                      <Area type="monotone" name="Running Defenses" dataKey="defenses" stroke="#7c3aed" fillOpacity={1} fill="url(#chartDef)" strokeWidth={1.5} />
                    </AreaChart>
                  </ResponsiveContainer>
                )}
              </div>

              {/* Pie Summary Rate */}
              <div className="md:col-span-4 bg-slate-50/60 p-3 rounded-lg border border-slate-200/70 flex flex-col justify-between">
                <div>
                  <span className="text-[9px] text-slate-400 font-mono uppercase block">Active Neutralization Rate</span>
                  <div className="flex items-baseline gap-1.5 mt-1">
                    <span className="text-xl font-extrabold text-slate-900">
                      {tamperAttempts.length > 0 
                        ? Math.round((tamperAttempts.filter(a => a.status === 'Detected & Blocked').length / tamperAttempts.length) * 100) 
                        : 100}%
                    </span>
                    <span className="text-[9px] text-slate-500 font-medium">foiled</span>
                  </div>
                </div>

                <div className="text-[10px] space-y-1.5 border-t border-slate-100 pt-2 mt-2">
                  <div className="flex justify-between items-center">
                    <span className="text-slate-500">Total Encounters</span>
                    <span className="font-mono text-slate-800 font-bold">{tamperAttempts.length}</span>
                  </div>
                  <div className="flex justify-between items-center text-emerald-600 font-medium">
                    <span>Foiled & Blocked</span>
                    <span className="font-mono font-bold">{tamperAttempts.filter(a => a.status === 'Detected & Blocked').length}</span>
                  </div>
                  <div className="flex justify-between items-center text-rose-600 font-medium">
                    <span>Bypassed Attacks</span>
                    <span className="font-mono font-bold">{tamperAttempts.filter(a => a.status === 'Undetected (Succeeded)').length}</span>
                  </div>
                </div>
              </div>

            </div>
          </div>
        </div>
          </div>
        )}

        {/* Security Agent Hub (Threat Detection & Mitigation Policies) */}
        {currentPage === 'security_agent' && (
          <SecurityAgentHub
            patients={patients}
            authorizedPatients={authorizedPatients}
            strategies={strategies}
            toggleStrategy={toggleStrategy}
            secretKey={secretKey}
            logs={logs}
            onTriggerSelfHealing={handleTriggerSelfHealing}
            onRunIntegrityScan={handleRunVerification}
            isScanning={isScanning}
          />
        )}

        {/* Tampered Data Forensic History Page */}
        {currentPage === 'tamper_history' && (
          <TamperHistoryPage
            tamperAttempts={tamperAttempts}
            setTamperAttempts={setTamperAttempts}
            patients={patients}
            authorizedPatients={authorizedPatients}
            onRestorePatient={handleRestoreSinglePatient}
            onRestoreAll={handleTriggerSelfHealing}
            onNavigateToPatient={handleNavigateToPatient}
            onNavigatePage={(page) => setCurrentPage(page)}
            currentUser={currentUser}
            addLog={addLog}
          />
        )}

        {currentPage === 'clinical' && (
          <div className="space-y-6">
            {/* Quick Access Navigation Bar to Security Agent & Tamper History */}
            <div className="bg-gradient-to-r from-slate-900 via-teal-950 to-slate-900 text-white rounded-xl p-5 shadow-sm border border-slate-800 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-[9px] font-mono font-bold bg-teal-500/20 text-teal-300 border border-teal-500/30 px-2 py-0.5 rounded uppercase">
                    Security Agent Active
                  </span>
                  <Cpu className="w-4 h-4 text-teal-400" />
                </div>
                <h3 className="text-sm font-extrabold text-white">
                  Security Agent & Tamper Prevention Shield
                </h3>
                <p className="text-xs text-slate-300 max-w-2xl leading-relaxed">
                  Explore the 5-stage cryptographic verification pipeline, real-time autonomous IPS self-healing policies, and inspect recorded forensic breach history.
                </p>
              </div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <button
                  onClick={() => setCurrentPage('tamper_history')}
                  className="px-3.5 py-2 bg-rose-950/80 hover:bg-rose-900 text-rose-200 border border-rose-800/60 font-bold text-xs rounded-lg transition flex items-center justify-center gap-1.5 cursor-pointer shadow-sm shrink-0"
                >
                  <Fingerprint className="w-3.5 h-3.5 text-rose-400" />
                  <span>Tamper History ({tamperAttempts.length})</span>
                </button>
                <button
                  onClick={() => setCurrentPage('security_agent')}
                  className="px-4 py-2 bg-teal-600 hover:bg-teal-500 text-white font-bold text-xs rounded-lg transition flex items-center justify-center gap-2 cursor-pointer shadow-sm shrink-0"
                >
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>Open Security Hub</span>
                </button>
              </div>
            </div>

            {/* Promotional Callout Card to the Auditor Console */}
            <div className="bg-gradient-to-r from-teal-50 to-emerald-50 text-slate-800 rounded-xl p-6 shadow-sm border border-teal-100 flex flex-col md:flex-row justify-between items-center gap-6">
              <div className="space-y-1.5 text-left">
                <div className="flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-teal-600 animate-pulse" />
                  <span className="bg-teal-600 text-white text-[9px] px-2 py-0.5 rounded font-black tracking-wider uppercase">
                    SECURE AUDIT PORTAL
                  </span>
                </div>
                <h3 className="text-base font-extrabold tracking-tight text-slate-900">
                  MedTrust Central Secure Auditor Console
                </h3>
                <p className="text-slate-600 text-xs max-w-2xl leading-relaxed font-medium">
                  Access the isolated secure auditing dashboard to toggle real-time defense layers, evaluate database threat statistics, and view comprehensive SHA-256 integrity logs.
                </p>
              </div>
              <button 
                onClick={() => setCurrentPage('auditor')}
                className="px-5 py-3 bg-teal-600 hover:bg-teal-700 text-white text-xs font-extrabold rounded-xl transition shadow-sm cursor-pointer flex items-center gap-2 group shrink-0"
              >
                <span>Enter Secure Auditor Console</span>
                <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
              </button>
            </div>

            {/* Threat Scenarios Section */}
            <div id="threat-scenarios-section" className="mb-8">
          <div className="bg-white rounded-xl border border-slate-200/80 shadow-sm p-5 md:p-6">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-100 pb-4 mb-5">
              <div>
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5 text-red-500 animate-pulse" />
                  <h2 className="text-sm font-extrabold uppercase text-slate-800 tracking-wider">
                    Simulation Lab: Pre-defined Threat Scenarios
                  </h2>
                </div>
                <p className="text-xs text-slate-500 font-medium mt-1">
                  Test and observe how the system's current cryptographic defenses react dynamically in real-time to different threat vectors.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-bold text-slate-400 bg-slate-100 px-2 py-1 rounded uppercase font-mono">
                  Environment: Sandbox Mode
                </span>
              </div>
            </div>

            {/* List of Scenarios Tabs */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 mb-6">
              {THREAT_SCENARIOS.map(sc => {
                const isActive = activeScenarioId === sc.id;
                const evalResult = sc.evaluate(strategies);
                
                let levelColor = 'bg-slate-100 text-slate-600';
                if (sc.threatLevel === 'Critical') levelColor = 'bg-rose-50 text-rose-700 border border-rose-100';
                if (sc.threatLevel === 'High') levelColor = 'bg-amber-50 text-amber-700 border border-amber-100';
                if (sc.threatLevel === 'Medium') levelColor = 'bg-sky-50 text-sky-700 border border-sky-100';

                return (
                  <button
                    key={sc.id}
                    id={`scenario-tab-${sc.id}`}
                    onClick={() => {
                      setActiveScenarioId(sc.id);
                      setSimulationResult(null);
                    }}
                    className={`text-left p-3.5 rounded-lg transition-all duration-200 border flex flex-col justify-between h-full relative overflow-hidden ${
                      isActive 
                        ? 'bg-teal-600 border-teal-600 text-white shadow-md shadow-teal-600/15' 
                        : 'bg-white hover:bg-slate-50 border-slate-200 text-slate-700'
                    }`}
                  >
                    <div>
                      <div className="flex justify-between items-center gap-1 mb-2">
                        <span className={`text-[9px] font-bold font-mono uppercase px-1.5 py-0.5 rounded ${levelColor}`}>
                          {sc.threatLevel}
                        </span>
                        <span className={`text-[10px] font-mono font-semibold ${
                          isActive ? 'text-slate-400' : 'text-slate-400'
                        }`}>
                          {sc.id === 'sql_injection' ? 'DB-01' : sc.id === 'chain_recalc' ? 'CRYP-02' : sc.id === 'mitm_transmission' ? 'NET-03' : sc.id === 'brute_force' ? 'CRYP-04' : 'SESS-05'}
                        </span>
                      </div>
                      <h3 className="text-xs font-bold leading-tight line-clamp-2 mb-1">
                        {sc.name}
                      </h3>
                      <p className={`text-[10px] line-clamp-2 leading-relaxed ${isActive ? 'text-slate-300' : 'text-slate-500'}`}>
                        {sc.objective}
                      </p>
                    </div>

                    <div className="mt-3 pt-2 border-t border-slate-100/10 flex justify-between items-center">
                      <span className="text-[9px] font-semibold opacity-75">Outcome:</span>
                      <span className={`text-[9px] font-bold font-mono px-1.5 py-0.5 rounded uppercase ${
                        evalResult.outcome === 'FOILED' 
                          ? 'bg-emerald-500/10 text-emerald-400' 
                          : evalResult.outcome === 'MITIGATED'
                            ? 'bg-amber-500/10 text-amber-400'
                            : 'bg-rose-500/10 text-rose-400'
                      }`}>
                        {evalResult.outcome}
                      </span>
                    </div>

                    {isActive && (
                      <div className="absolute right-0 bottom-0 w-1.5 h-full bg-teal-500" />
                    )}
                  </button>
                );
              })}
            </div>

            {/* Selected Scenario Details & Live Simulation Panel */}
            {(() => {
              const activeSc = THREAT_SCENARIOS.find(s => s.id === activeScenarioId)!;
              const evalResult = activeSc.evaluate(strategies);
              
              let outcomeBg = 'bg-rose-50 border-rose-200 text-rose-800';
              let outcomeTitleColor = 'text-rose-900';
              let outcomeBadge = 'bg-rose-600 text-white';
              
              if (evalResult.outcome === 'FOILED') {
                outcomeBg = 'bg-emerald-50 border-emerald-200 text-emerald-800';
                outcomeTitleColor = 'text-emerald-900';
                outcomeBadge = 'bg-emerald-600 text-white';
              } else if (evalResult.outcome === 'MITIGATED') {
                outcomeBg = 'bg-amber-50 border-amber-200 text-amber-800';
                outcomeTitleColor = 'text-amber-900';
                outcomeBadge = 'bg-amber-600 text-white';
              }

              return (
                <div id="active-scenario-panel" className="grid grid-cols-1 lg:grid-cols-12 gap-6 bg-slate-50/40 p-4 sm:p-5 rounded-xl border border-slate-200/60">
                  {/* Left Column: Attack Vector Configuration */}
                  <div className="lg:col-span-6 space-y-4">
                    <div>
                      <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider block">
                        Selected Attack Vector
                      </span>
                      <h4 className="text-base font-extrabold text-slate-800 mt-1">
                        {activeSc.name}
                      </h4>
                      <p className="text-xs text-slate-500 font-semibold mt-0.5">
                        Category: {activeSc.category}
                      </p>
                    </div>

                    <div className="bg-white rounded-lg border border-slate-200/50 p-3.5 space-y-3 shadow-sm">
                      <div>
                        <span className="text-[10px] font-mono font-bold text-slate-400 uppercase block">
                          Attacker Objective
                        </span>
                        <p className="text-xs text-slate-700 leading-relaxed mt-0.5">
                          {activeSc.objective}
                        </p>
                      </div>

                      <div className="border-t border-slate-100 pt-2.5">
                        <span className="text-[10px] font-mono font-bold text-slate-400 uppercase block">
                          Attack Mechanism
                        </span>
                        <p className="text-xs text-slate-700 leading-relaxed mt-0.5">
                          {activeSc.method}
                        </p>
                      </div>

                      {/* Dropdown to pick Target Patient Node */}
                      <div className="border-t border-slate-100 pt-2.5">
                        <label htmlFor="sim-target-patient" className="text-[10px] font-mono font-bold text-slate-400 uppercase block mb-1">
                          Select Target Patient Node
                        </label>
                        <select
                          id="sim-target-patient"
                          value={simulationTargetId}
                          onChange={(e) => setSimulationTargetId(e.target.value)}
                          disabled={simulationActive}
                          className="text-xs w-full bg-slate-50 hover:bg-slate-100 border border-slate-200 text-slate-800 font-medium px-3 py-2 rounded-lg transition-all duration-200 outline-none focus:border-slate-400 disabled:opacity-50"
                        >
                          {patients.map(p => (
                            <option key={p.id} value={p.id}>
                              {p.id} — {p.name} ({p.status})
                            </option>
                          ))}
                        </select>
                        <span className="text-[9px] text-slate-400 mt-1 block">
                          The simulated threat vector will directly attack this patient node inside the database layer.
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Right Column: Countermeasure Assessment & Simulation Trigger */}
                  <div className="lg:col-span-6 flex flex-col justify-between space-y-4">
                    <div className="space-y-3.5">
                      <div>
                        <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider block">
                          Defense Analysis Matrix
                        </span>
                      </div>

                      {/* Required defenses list with current live status */}
                      <div className="space-y-2">
                        {activeSc.requiredDefenses.map(def => {
                          const liveStrategy = strategies.find(s => s.id === def.id);
                          const isEnabled = liveStrategy?.enabled;
                          
                          return (
                            <div 
                              key={def.id} 
                              className={`flex items-center justify-between p-2.5 rounded-lg border text-xs transition-all duration-200 ${
                                isEnabled 
                                  ? 'bg-emerald-50/50 border-emerald-100 text-emerald-800 font-medium' 
                                  : 'bg-rose-50/50 border-rose-100 text-rose-800 font-medium'
                              }`}
                            >
                              <div className="flex items-center gap-2">
                                {isEnabled ? (
                                  <ShieldCheck className="w-4 h-4 text-emerald-500" />
                                ) : (
                                  <LockOpen className="w-4 h-4 text-rose-500 animate-pulse" />
                                )}
                                <span>{def.name}</span>
                              </div>
                              <span className={`text-[9px] font-bold font-mono uppercase px-2 py-0.5 rounded ${
                                isEnabled 
                                  ? 'bg-emerald-200/50 text-emerald-800' 
                                  : 'bg-rose-200/50 text-rose-800'
                              }`}>
                                {isEnabled ? 'Active Defense' : 'Offline / Vulnerable'}
                              </span>
                            </div>
                          );
                        })}
                      </div>

                      {/* Live Outcome Badge based on evaluation */}
                      <div className={`p-4 rounded-xl border ${outcomeBg}`}>
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] font-bold uppercase tracking-wider font-mono opacity-80">
                            Defense Assessment
                          </span>
                          <span className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded uppercase ${outcomeBadge}`}>
                            {evalResult.outcome}
                          </span>
                        </div>
                        <h5 className={`text-sm font-extrabold mt-1.5 ${outcomeTitleColor}`}>
                          {evalResult.statusText}
                        </h5>
                        <p className="text-xs opacity-90 leading-relaxed mt-1">
                          {evalResult.explanation}
                        </p>
                      </div>
                    </div>

                    {/* Simulation Console Terminal & Trigger Button */}
                    <div className="space-y-3">
                      {/* Active Terminal Screen */}
                      {simulationActive && (
                        <div id="simulation-terminal" className="bg-slate-900 border border-slate-800 rounded-lg p-3 font-mono text-[10px] text-emerald-400 space-y-1.5 shadow-inner">
                          <div className="flex justify-between items-center text-slate-500 text-[9px] border-b border-slate-800 pb-1.5 mb-1.5">
                            <span>MEDTRUST_EXPLOIT_LAB.SH</span>
                            <span className="animate-pulse">● LIVE RUN</span>
                          </div>
                          
                          <div className="h-24 overflow-y-auto space-y-1 custom-scrollbar">
                            {simulationLogs.map((logLine, idx) => (
                              <div key={idx} className="leading-relaxed">
                                {logLine}
                              </div>
                            ))}
                            <div className="flex items-center gap-1">
                              <span className="animate-pulse">_</span>
                            </div>
                          </div>

                          {/* Progress bar */}
                          <div className="space-y-1 pt-1.5 border-t border-slate-800">
                            <div className="flex justify-between items-center text-[8px] text-slate-500">
                              <span>EXPLOIT PAYLOAD DISPATCH</span>
                              <span>{simulationProgress}%</span>
                            </div>
                            <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                              <div 
                                className="bg-emerald-400 h-full transition-all duration-300"
                                style={{ width: `${simulationProgress}%` }}
                              />
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Simulation Result Card */}
                      {simulationResult && !simulationActive && (
                        <div id="simulation-verdict" className="bg-slate-50 border border-slate-200 rounded-lg p-3.5 shadow-md">
                          <div className="flex items-center gap-1.5 text-xs font-bold mb-2">
                            {simulationResult.outcome === 'FOILED' ? (
                              <>
                                <CheckCircle className="w-4 h-4 text-emerald-600" />
                                <span className="text-emerald-700">Neutralization Successful</span>
                              </>
                            ) : (
                              <>
                                <AlertTriangle className="w-4 h-4 text-rose-600" />
                                <span className="text-rose-700">Simulation Target Compromised</span>
                              </>
                            )}
                          </div>
                          
                          <p className="text-[11px] text-slate-600 leading-relaxed font-medium">
                            Malicious payload targeted at <span className="text-slate-900 font-extrabold">{simulationResult.targetName}</span>'s record block. 
                            The attack was <span className={`font-bold ${simulationResult.outcome === 'FOILED' ? 'text-emerald-600' : 'text-rose-600'}`}>{simulationResult.statusText.toLowerCase()}</span>.
                          </p>

                          <div className="bg-white rounded border border-slate-200 p-2.5 mt-2.5 space-y-1.5">
                            <span className="text-[9px] font-mono text-slate-400 uppercase block font-bold">
                              Mitigation & Actionable Remediation:
                            </span>
                            <p className="text-[10px] text-slate-700 leading-relaxed font-mono font-bold">
                              {simulationResult.reremedy || simulationResult.remediation}
                            </p>
                          </div>
                        </div>
                      )}

                      <button
                        id="run-simulation-btn"
                        onClick={runThreatSimulation}
                        disabled={simulationActive}
                        className={`w-full py-3 px-4 rounded-lg font-bold text-xs uppercase tracking-wider transition-all duration-200 flex items-center justify-center gap-2 shadow-sm ${
                          simulationActive 
                            ? 'bg-slate-100 text-slate-450 cursor-not-allowed' 
                            : 'bg-teal-600 hover:bg-teal-700 text-white hover:shadow-teal-600/15 cursor-pointer active:scale-[0.98]'
                        }`}
                      >
                        <Zap className={`w-4 h-4 ${simulationActive ? 'animate-bounce text-slate-600' : 'text-teal-200'}`} />
                        {simulationActive ? 'Running Interactive Simulation...' : 'Execute Live Attack Simulation'}
                      </button>
                    </div>
                  </div>
                </div>
              );
            })()}
          </div>
        </div>

        {/* 2. Patient Ledger Database Grid (Simplified & Unclumsy) */}
        <div>
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-3 mb-4">
            <div>
              <h2 className="text-sm font-extrabold uppercase text-slate-500 tracking-wider flex items-center gap-2">
                <Database className="w-4 h-4 text-slate-400" />
                Patient Cryptographic Ledger Blocks
              </h2>
              <p className="text-xs text-slate-500 font-medium">Interactive patient nodes linking sequentially to form a cryptographically secured chain.</p>
            </div>
            
            <div className="flex items-center gap-3 flex-wrap">
              {/* Interactive Sandbox Toggle Switch */}
              <div className="flex items-center gap-2.5 bg-amber-50/70 border border-amber-200/50 rounded-lg px-3 py-1.5 shadow-sm shrink-0">
                <span className="relative flex h-2 w-2">
                  <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${sandboxMode ? 'bg-amber-400' : 'bg-slate-300'}`}></span>
                  <span className={`relative inline-flex rounded-full h-2 w-2 ${sandboxMode ? 'bg-amber-500' : 'bg-slate-400'}`}></span>
                </span>
                <span className="text-[10px] font-extrabold text-amber-800 uppercase tracking-wider">Manual Tamper (Sandbox)</span>
                <button
                  onClick={() => {
                    setSandboxMode(!sandboxMode);
                    addLog(
                      'DEFENSE_TRIGGERED',
                      `Manual Cell Editing (Sandbox Mode) was manually ${!sandboxMode ? 'ENABLED' : 'DISABLED'}.`,
                      !sandboxMode ? 'warning' : 'info'
                    );
                  }}
                  className={`w-9 h-5 rounded-full relative transition-colors duration-200 ease-in-out cursor-pointer outline-none ${
                    sandboxMode ? 'bg-amber-500' : 'bg-slate-200'
                  }`}
                >
                  <span className={`w-3.5 h-3.5 bg-white rounded-full absolute top-0.5 left-0.5 transition-transform duration-200 ease-in-out shadow-sm ${
                    sandboxMode ? 'translate-x-4' : 'translate-x-0'
                  }`} />
                </button>
              </div>

              {/* Advanced Reports & Exporters Group */}
              <div className="flex items-center gap-2 bg-slate-100/80 border border-slate-200 rounded-lg p-1 shadow-sm shrink-0">
                <span className="text-[9px] font-extrabold text-slate-500 uppercase tracking-wider px-2">Export Ledger:</span>
                
                {/* Original Baseline downloads */}
                <div className="relative group">
                  <button 
                    className="px-2.5 py-1 text-[10px] font-bold bg-white hover:bg-emerald-50 text-emerald-700 border border-emerald-200 rounded transition flex items-center gap-1 cursor-pointer"
                    title="Export secure original baseline state"
                  >
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                    <span>Baseline</span>
                    <ChevronDown className="w-2.5 h-2.5 text-emerald-500" />
                  </button>
                  <div className="absolute right-0 mt-1 w-36 bg-white border border-slate-250 rounded-lg shadow-xl py-1 hidden group-hover:block z-20">
                    <button 
                      onClick={() => exportToPDF(authorizedPatients, true)}
                      className="w-full text-left px-3 py-1.5 text-[10px] font-semibold hover:bg-slate-50 text-slate-700 flex items-center gap-1.5"
                    >
                      <FileText className="w-3.5 h-3.5 text-rose-500" />
                      <span>Download PDF</span>
                    </button>
                    <button 
                      onClick={() => exportToCSV(authorizedPatients, 'healthsecure-original-baseline.csv')}
                      className="w-full text-left px-3 py-1.5 text-[10px] font-semibold hover:bg-slate-50 text-slate-700 flex items-center gap-1.5"
                    >
                      <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-600" />
                      <span>Download CSV</span>
                    </button>
                  </div>
                </div>

                {/* Live / Tampered State downloads */}
                <div className="relative group">
                  <button 
                    className="px-2.5 py-1 text-[10px] font-bold bg-white hover:bg-teal-50 text-teal-700 border border-teal-200 rounded transition flex items-center gap-1 cursor-pointer"
                    title="Export current state of the database"
                  >
                    <Activity className="w-3.5 h-3.5 text-teal-600 animate-pulse" />
                    <span>Live State</span>
                    <ChevronDown className="w-2.5 h-2.5 text-teal-500" />
                  </button>
                  <div className="absolute right-0 mt-1 w-36 bg-white border border-slate-250 rounded-lg shadow-xl py-1 hidden group-hover:block z-20">
                    <button 
                      onClick={() => exportToPDF(patients, false)}
                      className="w-full text-left px-3 py-1.5 text-[10px] font-semibold hover:bg-slate-50 text-slate-700 flex items-center gap-1.5"
                    >
                      <FileText className="w-3.5 h-3.5 text-rose-500" />
                      <span>Download PDF</span>
                    </button>
                    <button 
                      onClick={() => exportToCSV(patients, 'healthsecure-current-compromised-ledger.csv')}
                      className="w-full text-left px-3 py-1.5 text-[10px] font-semibold hover:bg-slate-50 text-slate-700 flex items-center gap-1.5"
                    >
                      <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-600" />
                      <span>Download CSV</span>
                    </button>
                  </div>
                </div>
              </div>

              {/* Database Sorting Widget */}
              <div className="flex items-center gap-1.5 bg-slate-100/80 border border-slate-200 rounded-lg p-1 shadow-sm shrink-0">
                <span className="text-[9px] font-extrabold text-slate-500 uppercase tracking-wider px-2">Sort By:</span>
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value as any)}
                  className="bg-white border border-slate-200 rounded px-2 py-1 text-[10px] font-bold text-slate-700 outline-none cursor-pointer focus:ring-1 focus:ring-teal-500"
                >
                  <option value="index">Block Index</option>
                  <option value="name">Patient Name</option>
                  <option value="age">Patient Age</option>
                  <option value="status">Health Status</option>
                </select>
                <button
                  onClick={() => setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')}
                  className="p-1 bg-white hover:bg-slate-50 border border-slate-200 rounded transition text-slate-700 cursor-pointer"
                  title={`Toggle sort order (Current: ${sortOrder === 'asc' ? 'Ascending' : 'Descending'})`}
                >
                  <ArrowUpDown className="w-3.5 h-3.5 text-slate-600" />
                </button>
              </div>

              <button
                onClick={() => setShowAddPatientModal(true)}
                className="px-3.5 py-1.5 bg-teal-600 hover:bg-teal-500 text-white text-xs font-bold rounded-lg transition-all shadow-sm cursor-pointer flex items-center gap-1.5 shrink-0"
              >
                <Plus className="w-3.5 h-3.5 text-white" />
                <span>Register New Patient Block</span>
              </button>

              <div className="text-xs font-mono bg-white border border-slate-200 px-3 py-1.5 rounded-lg text-slate-600 shadow-sm font-bold">
                Database Nodes: <strong>{patients.length} Blocks</strong>
              </div>
            </div>
          </div>

          <div className={`bg-white rounded-xl overflow-hidden shadow-premium transition-all duration-300 relative ${
            isScanning 
              ? 'border-2 border-teal-400/80 ring-4 ring-teal-400/20 shadow-[0_0_30px_rgba(20,184,166,0.15)]' 
              : 'border border-slate-200/80'
          }`}>
            {isScanning && (
              <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-teal-500 via-emerald-400 to-teal-500 animate-pulse z-20" />
            )}
            {sandboxMode && (
              <div className="bg-amber-500/10 border-b border-amber-300/60 px-4 py-2 text-xs text-amber-900 font-semibold flex items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
                  <span>
                    <strong>In-Table Direct Tamper Sandbox Active:</strong> You can edit medication, dosage, or diagnosis fields directly within table cells below. Each cell edit immediately corrupts the SHA-256 block hash without updating signatures, flagging the row as <strong>Tampered</strong>!
                  </span>
                </div>
                <button
                  onClick={() => setSandboxMode(false)}
                  className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 bg-amber-200 hover:bg-amber-300 text-amber-900 rounded cursor-pointer shrink-0"
                >
                  Exit Sandbox
                </button>
              </div>
            )}
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50/50 text-[10px] font-mono uppercase tracking-wider text-slate-500">
                    <th className="py-2.5 px-3.5 text-center w-16">Block</th>
                    <th className="py-2.5 px-3.5">Patient Details</th>
                    <th className="py-2.5 px-3.5">Clinical Data</th>
                    <th className="py-2.5 px-3.5">Cryptographic Trace</th>
                    <th className="py-2.5 px-3.5 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  <AnimatePresence initial={false}>
                    {sortedPatients.map(({ p, originalIndex }) => {
                      const index = originalIndex;
                      const previousPatient = index > 0 ? patients[index - 1] : null;
                      const securityDetails = getRecordVerificationDetails(p, index, previousPatient);
                      const scanBlock = scannedBlocksMap[index];
                      const isBeingScanned = index === scanningBlockIndex;
                      const isScannedValid = scanBlock?.status === 'valid';
                      const isScannedInvalid = scanBlock?.status === 'invalid';
                      const isScannedAborted = scanBlock?.status === 'aborted';
                      const isRowTampered = isScannedInvalid || (!scanBlock && !securityDetails.overallValid);
                      
                      return (
                        <Fragment key={p.id}>
                          <motion.tr 
                            layout
                            initial={{ opacity: 0, y: 15 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -15 }}
                            transition={{ 
                              type: "spring", 
                              stiffness: 260, 
                              damping: 26,
                              layout: { duration: 0.35 }
                            }}
                            className={`transition-all duration-500 relative ${
                              isBeingScanned
                                ? 'bg-teal-50/95 border-y-2 border-teal-500 shadow-[0_0_20px_rgba(20,184,166,0.35)] ring-2 ring-teal-400/50 z-10'
                                : isScannedValid
                                  ? 'bg-emerald-50/40 border-y border-emerald-300 shadow-[0_0_16px_rgba(16,185,129,0.22)] ring-1 ring-emerald-400/30'
                                  : isRowTampered
                                    ? 'bg-rose-50/75 border-y border-rose-400 shadow-[0_0_22px_rgba(244,63,94,0.35)] ring-1 ring-rose-500/50 animate-red-glow tampered-pattern-bg'
                                    : isScannedAborted
                                      ? 'bg-slate-100/60 opacity-65 border-y border-slate-200'
                                      : expandedBlockIndex === index
                                        ? 'bg-slate-50/80 border-b-0'
                                        : 'hover:bg-slate-50/50'
                            }`}
                        >
                          {/* Block Index & ID */}
                          <td className="py-3 px-3.5 text-center border-r border-slate-100 relative">
                            {isBeingScanned && (
                              <div className="absolute inset-0 pointer-events-none bg-gradient-to-r from-transparent via-teal-400/20 to-transparent animate-scan-laser" />
                            )}
                            <div className="flex items-center justify-center gap-1 font-mono text-xs font-bold text-slate-900">
                              {p.isFrozen && (
                                <Lock 
                                  className="w-3 h-3 text-amber-500 animate-pulse shrink-0" 
                                  title="Block Cryptographically Frozen & Locked" 
                                />
                              )}
                              {isBeingScanned ? (
                                <span className="px-1.5 py-0.5 rounded bg-teal-500 text-slate-950 font-black shadow-[0_0_8px_rgba(20,184,166,0.6)] animate-pulse">
                                  {String(index + 1).padStart(2, '0')}
                                </span>
                              ) : isScannedValid ? (
                                <span className="px-1.5 py-0.5 rounded bg-emerald-600 text-white font-bold shadow-[0_0_8px_rgba(16,185,129,0.5)]">
                                  {String(index + 1).padStart(2, '0')}
                                </span>
                              ) : isRowTampered ? (
                                <span className="px-1.5 py-0.5 rounded bg-rose-600 text-white font-bold shadow-[0_0_10px_rgba(244,63,94,0.6)] animate-pulse">
                                  {String(index + 1).padStart(2, '0')}
                                </span>
                              ) : (
                                <span>{String(index + 1).padStart(2, '0')}</span>
                              )}
                            </div>
                            <div className="text-[9px] font-mono text-slate-400 mt-0.5">{p.id}</div>
                          </td>
                          
                           {/* Patient details */}
                          <td className="py-3 px-3.5">
                            {sandboxMode ? (
                              <div className="flex flex-col gap-1">
                                <div className="flex items-center gap-1">
                                  <User className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                                  <input
                                    type="text"
                                    value={p.name}
                                    onChange={(e) => handleInlineTamper(p.id, 'name', e.target.value)}
                                    className="font-bold text-slate-900 text-xs bg-amber-50 border border-amber-200 rounded px-1.5 py-0.5 focus:outline-none focus:ring-1 focus:ring-amber-500 max-w-[130px] font-mono"
                                  />
                                </div>
                                <div className="flex items-center gap-1.5 text-[10px] text-slate-500">
                                  <span>Age:</span>
                                  <input
                                    type="number"
                                    value={p.age}
                                    onChange={(e) => handleInlineTamper(p.id, 'age', parseInt(e.target.value) || p.age)}
                                    className="bg-amber-50 border border-amber-200 rounded px-1 py-0.2 focus:outline-none w-10 text-center font-bold text-slate-700"
                                  />
                                  <span>• Blood:</span>
                                  <span className="font-bold">{p.bloodType}</span>
                                </div>
                                <div className="flex items-center mt-1">
                                  <select
                                    value={p.status}
                                    onChange={(e) => handleInlineTamper(p.id, 'status', e.target.value)}
                                    className="bg-amber-50 border border-amber-200 rounded px-1.5 py-0.5 text-[9px] font-bold text-slate-700 outline-none"
                                  >
                                    <option value="Stable">Stable</option>
                                    <option value="Critical">Critical</option>
                                    <option value="Recovering">Recovering</option>
                                  </select>
                                </div>
                              </div>
                            ) : (
                              <>
                                <div className="font-bold text-slate-900 text-xs flex items-center gap-1">
                                  <User className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                                  {p.name}
                                </div>
                                <div className="text-[10px] text-slate-500 mt-0.5 font-medium">
                                  Age {p.age} • Blood {p.bloodType} • <span className={`font-semibold ${
                                    p.status === 'Stable' ? 'text-slate-500' :
                                    p.status === 'Critical' ? 'text-rose-600' : 'text-emerald-600'
                                  }`}>{p.status}</span>
                                </div>
                              </>
                            )}
                          </td>
                          
                          {/* Clinical diagnosis/meds */}
                          <td className="py-3 px-3.5">
                            {sandboxMode ? (
                              <div className="space-y-1.5">
                                <div className="flex items-center gap-1">
                                  <span className="text-[10px] text-slate-500 font-mono">Diag:</span>
                                  <input
                                    type="text"
                                    value={p.diagnosis}
                                    onChange={(e) => handleInlineTamper(p.id, 'diagnosis', e.target.value)}
                                    className="bg-amber-50 border border-amber-200 text-slate-900 font-bold text-xs rounded px-1.5 py-0.5 focus:outline-none focus:ring-1 focus:ring-amber-500 w-full max-w-[200px]"
                                  />
                                </div>
                                <div className="flex items-center gap-1.5 flex-wrap">
                                  <input
                                    type="text"
                                    value={p.medication}
                                    onChange={(e) => handleInlineTamper(p.id, 'medication', e.target.value)}
                                    className="font-mono text-slate-800 font-bold bg-amber-50 border border-amber-200 text-[9px] rounded px-1.5 py-0.5 focus:outline-none focus:ring-1 focus:ring-amber-500 max-w-[110px]"
                                    placeholder="Medication"
                                  />
                                  <input
                                    type="text"
                                    value={p.dosage}
                                    onChange={(e) => handleInlineTamper(p.id, 'dosage', e.target.value)}
                                    className="font-mono text-teal-700 font-bold bg-amber-50 border border-amber-200 text-[9px] rounded px-1.5 py-0.5 focus:outline-none focus:ring-1 focus:ring-amber-500 max-w-[65px]"
                                    placeholder="Dosage"
                                  />
                                </div>
                              </div>
                            ) : (
                              <>
                                <div className="text-xs">
                                  <span className="text-slate-500 font-medium">Diag: </span>
                                  <span className="text-slate-900 font-semibold">{p.diagnosis}</span>
                                </div>
                                <div className="text-[10px] text-slate-500 mt-1 flex items-center gap-1.5 flex-wrap">
                                  <span className="font-mono text-slate-800 font-bold bg-slate-100 border border-slate-200 px-1.5 py-0.5 rounded text-[9px]">{p.medication}</span>
                                  <span className="px-1.5 py-0.5 bg-teal-50 text-teal-700 border border-teal-100 font-bold font-mono text-[9px] rounded">{p.dosage}</span>
                                </div>
                              </>
                            )}
                          </td>
                          
                          {/* Cryptography details & Status */}
                          <td className="py-3 px-3.5">
                            <div className="flex items-center gap-3">
                              {isBeingScanned ? (
                                <span className="px-2.5 py-1 rounded text-[9px] font-black bg-teal-500 text-slate-950 shadow-[0_0_10px_rgba(20,184,166,0.5)] flex items-center gap-1 shrink-0 animate-pulse font-mono">
                                  <RefreshCw className="w-2.5 h-2.5 animate-spin text-slate-950" />
                                  AUDITING BLOCK
                                </span>
                              ) : isScannedValid ? (
                                <span className="px-2.5 py-0.5 rounded text-[9px] font-extrabold bg-emerald-100 text-emerald-800 border border-emerald-300 shadow-[0_0_8px_rgba(16,185,129,0.25)] flex items-center gap-1 shrink-0">
                                  <CheckCircle className="w-3 h-3 text-emerald-600" />
                                  Verified Intact ✓
                                </span>
                              ) : isScannedAborted ? (
                                <span className="px-2 py-0.5 rounded text-[9px] font-mono text-slate-500 bg-slate-200 border border-slate-300 flex items-center gap-1 shrink-0">
                                  Chain Broken Upstream
                                </span>
                              ) : isRowTampered ? (
                                <span className="px-2.5 py-0.5 rounded text-[9px] font-bold bg-rose-100 text-rose-800 border border-rose-300 shadow-[0_0_10px_rgba(244,63,94,0.25)] flex items-center gap-1 shrink-0 animate-pulse">
                                  <AlertTriangle className="w-3 h-3 text-rose-600" />
                                  Tampered
                                </span>
                              ) : (
                                <span className="px-2.5 py-0.5 rounded text-[9px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1 shrink-0">
                                  <CheckCircle className="w-2.5 h-2.5" />
                                  Valid
                                </span>
                              )}
                              
                              <div className="hidden sm:block text-[9px] font-mono text-slate-400 space-y-0.5">
                                <div className="truncate max-w-[130px]" title={`Prev Link: ${p.prevHash}`}>Prev: <span className="text-slate-600">{p.prevHash.slice(0, 10)}...</span></div>
                                <div className="truncate max-w-[130px]" title={`Block Hash: ${p.hash}`}>Hash: <span className="text-slate-600">{p.hash.slice(0, 10)}...</span></div>
                              </div>
                            </div>
                          </td>

                          {/* Patient actions */}
                          <td className="py-3 px-3.5 text-right">
                            <div className="flex items-center justify-end gap-1.5 flex-wrap">
                              <button 
                                onClick={() => setExpandedBlockIndex(expandedBlockIndex === index ? null : index)}
                                className={`p-1 px-2.5 border text-[10px] font-bold rounded shadow-sm transition flex items-center gap-1 cursor-pointer shrink-0 ${
                                  expandedBlockIndex === index 
                                    ? 'bg-teal-600 hover:bg-teal-700 text-white border-teal-600'
                                    : 'bg-white hover:bg-slate-50 border-slate-200 text-slate-700'
                                }`}
                                title="Toggle Cryptographic Block Inspector"
                              >
                                {expandedBlockIndex === index ? (
                                  <>
                                    <ChevronUp className="w-3 h-3" />
                                    <span>Hide proof</span>
                                  </>
                                ) : (
                                  <>
                                    <ChevronDown className="w-3 h-3 text-teal-500" />
                                    <span>Inspect Proof</span>
                                  </>
                                )}
                              </button>

                              {/* Individual Block Export Dropdown */}
                              <div className="relative group/export inline-block text-left">
                                <button 
                                  className="p-1 px-2.5 bg-emerald-50 hover:bg-emerald-100 border border-emerald-200 text-emerald-800 text-[10px] font-bold rounded shadow-sm transition flex items-center gap-1 cursor-pointer shrink-0"
                                  title="Export individual block PDF reports"
                                >
                                  <Download className="w-3 h-3 text-emerald-600" />
                                  <span>Export PDF</span>
                                  <ChevronDown className="w-2.5 h-2.5 text-emerald-500" />
                                </button>
                                <div className="absolute right-0 mt-1 w-44 bg-white border border-slate-200 rounded-lg shadow-xl py-1 hidden group-hover/export:block z-30">
                                  <button 
                                    onClick={() => exportSinglePatientToPDF(authorizedPatients[index], index, true)}
                                    className="w-full text-left px-3 py-1.5 text-[10px] font-bold hover:bg-emerald-50 text-emerald-800 flex items-center gap-2 cursor-pointer"
                                  >
                                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                                    <span>Download Baseline PDF</span>
                                  </button>
                                  <button 
                                    onClick={() => exportSinglePatientToPDF(p, index, false)}
                                    className="w-full text-left px-3 py-1.5 text-[10px] font-bold hover:bg-teal-50 text-teal-800 flex items-center gap-2 border-t border-slate-100 cursor-pointer"
                                  >
                                    <Activity className="w-3.5 h-3.5 text-teal-600" />
                                    <span>Download Current PDF</span>
                                  </button>
                                </div>
                              </div>

                              {p.isFrozen ? (
                                <div className="p-1 px-2 bg-amber-50 border border-amber-200 text-amber-800 text-[10px] font-bold rounded shadow-sm flex items-center gap-1 select-none shrink-0 animate-pulse" title="Cryptographically frozen & locked">
                                  <Lock className="w-3 h-3 text-amber-600" />
                                  <span>Locked</span>
                                </div>
                              ) : (
                                <>
                                  <button 
                                    onClick={() => startAction(p, 'doctor')}
                                    className="p-1 px-2.5 bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-[10px] font-bold rounded shadow-sm transition flex items-center gap-1 cursor-pointer shrink-0"
                                    title="Authorized Doctor Edit"
                                  >
                                    <Edit2 className="w-3 h-3 text-slate-500" />
                                    <span>Edit</span>
                                  </button>
                                  <button 
                                    onClick={() => startAction(p, 'tamper')}
                                    className="p-1 px-2.5 bg-rose-50 hover:bg-rose-100 border border-rose-200 text-rose-700 text-[10px] font-bold rounded shadow-sm transition flex items-center gap-1 cursor-pointer shrink-0"
                                    title="Inject Backdoor Tampering"
                                  >
                                    <Trash2 className="w-3 h-3 text-rose-600" />
                                    <span>Tamper</span>
                                  </button>
                                  <button 
                                    onClick={() => freezeBlock(p.id)}
                                    className="p-1 px-2.5 bg-slate-900 hover:bg-slate-800 text-white border border-slate-950 text-[10px] font-bold rounded shadow-sm transition flex items-center gap-1.5 cursor-pointer shrink-0"
                                    title="Cryptographically Freeze Block Record"
                                  >
                                    <Lock className="w-3 h-3 text-amber-400" />
                                    <span>Freeze</span>
                                  </button>
                                </>
                              )}
                            </div>
                          </td>
                        </motion.tr>

                        {expandedBlockIndex === index && (
                          <tr className="bg-slate-50 border-x border-slate-200 text-slate-800 select-none">
                            <td colSpan={5} className="p-5">
                              <motion.div
                                initial={{ opacity: 0, y: -10 }}
                                animate={{ opacity: 1, y: 0 }}
                                className="space-y-4 font-mono text-xs"
                              >
                                {/* Header / Protocol Badge */}
                                <div className="flex items-center justify-between border-b border-slate-200/60 pb-3 flex-wrap gap-2">
                                  <div className="flex items-center gap-2">
                                    <Terminal className="w-4 h-4 text-teal-600 animate-pulse" />
                                    <span className="font-extrabold text-xs text-slate-700 tracking-tight">
                                      BLOCK #{String(index + 1).padStart(2, '0')} CRYPTOGRAPHIC CONSTRAINTS DAEMON
                                    </span>
                                  </div>
                                  <div className="flex items-center gap-2">
                                    <span className="bg-teal-50 border border-teal-100 text-teal-700 font-bold px-2 py-0.5 rounded text-[9px] uppercase tracking-wider">
                                      Protocol: SHA-256 + HMAC-SHA256
                                    </span>
                                    <span className="bg-slate-200 border border-slate-300 text-slate-700 font-bold px-2 py-0.5 rounded text-[9px] uppercase tracking-wider">
                                      State: {securityDetails.overallValid ? 'VERIFIED_SECURE' : 'COMPROMISED'}
                                    </span>
                                  </div>
                                </div>

                                {/* Step 1 & Step 2 Layout */}
                                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                                  {/* Step 1: Preimage Payload */}
                                  <div className="bg-white border border-slate-200 rounded-lg p-3.5 space-y-2.5">
                                    <div className="flex items-center gap-2 text-slate-800 font-extrabold text-[11px] uppercase tracking-wider">
                                      <span className="text-teal-700 font-mono font-bold bg-teal-50 border border-teal-150 px-1.5 py-0.5 rounded">01.</span> Preimage Payload Concatenation
                                    </div>
                                    <p className="text-[10px] text-slate-500 leading-normal font-sans">
                                      The block is compiled by serializing patient identifiers, medical measurements, clinical audit state, last updater tag, and parent node reference into a deterministic pipe-separated string.
                                    </p>
                                    <div className="bg-slate-50 border border-slate-200 p-2.5 rounded font-mono text-[9px] text-slate-700 select-all overflow-x-auto whitespace-pre-wrap max-h-24 leading-relaxed">
                                      {`${p.id}|${p.name}|${p.age}|${p.bloodType}|${p.diagnosis}|${p.medication}|${p.dosage}|${p.status}|${p.lastUpdated}|${p.updatedBy}|${p.prevHash}`}
                                    </div>
                                  </div>

                                  {/* Step 2: Hashing Proof */}
                                  <div className="bg-white border border-slate-200 rounded-lg p-3.5 space-y-2.5">
                                    <div className="flex items-center gap-2 text-slate-800 font-extrabold text-[11px] uppercase tracking-wider">
                                      <span className="text-teal-700 font-mono font-bold bg-teal-50 border border-teal-150 px-1.5 py-0.5 rounded">02.</span> SHA-256 Hashing Verification
                                    </div>
                                    
                                    <div className="space-y-2 text-[10px]">
                                      <div>
                                        <div className="flex justify-between items-center text-slate-500 mb-1">
                                          <span>Expected Block Hash (Computed):</span>
                                          <span className={`font-bold ${securityDetails.isHashValid ? 'text-emerald-600' : 'text-rose-600 animate-pulse'}`}>
                                            {securityDetails.isHashValid ? '● Valid Match' : '▲ Hash Mismatch Detected!'}
                                          </span>
                                        </div>
                                        <div className="bg-slate-50 border border-slate-200 p-2 rounded font-mono text-[9px] text-slate-700 truncate font-semibold" title={calculateRecordHash(p)}>
                                          {calculateRecordHash({
                                            ...p,
                                            prevHash: p.prevHash
                                          })}
                                        </div>
                                      </div>
                                      
                                      <div>
                                        <div className="flex justify-between items-center text-slate-500 mb-1">
                                          <span>Stored Database Hash Field:</span>
                                          <span className={securityDetails.isHashValid ? 'text-emerald-600 font-bold' : 'text-rose-600 font-bold'}>
                                            {securityDetails.isHashValid ? 'Matched (Intact)' : 'Tampered / Mismatched'}
                                          </span>
                                        </div>
                                        <div className="bg-slate-50 border border-slate-200 p-2 rounded font-mono text-[9px] text-slate-700 truncate" title={p.hash}>
                                          {p.hash}
                                        </div>
                                      </div>
                                    </div>
                                  </div>
                                </div>

                                {/* Step 3 & Step 4 Layout */}
                                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                                  {/* Chain Link Verification */}
                                  <div className="bg-white border border-slate-200 rounded-lg p-3.5 space-y-2.5">
                                    <div className="flex items-center gap-2 text-slate-800 font-extrabold text-[11px] uppercase tracking-wider">
                                      <span className="text-teal-700 font-mono font-bold bg-teal-50 border border-teal-150 px-1.5 py-0.5 rounded">03.</span> Block Linkage (Sequence Continuity)
                                    </div>
                                    <p className="text-[10px] text-slate-500 leading-normal font-sans">
                                      Verifies the current block contains the matching cryptographic parent hash. If the predecessor is manipulated, downstream integrity is instantly severed.
                                    </p>
                                    
                                    <div className="space-y-1.5 text-[9px] bg-slate-50 p-2.5 rounded border border-slate-200">
                                      <div className="flex justify-between">
                                        <span className="text-slate-500">Preceding Block Hash (Block 0{index}):</span>
                                        <span className="text-slate-700 font-bold">
                                          {previousPatient ? previousPatient.hash.slice(0, 16) + '...' : '0000000000000000 (Genesis Parent)'}
                                        </span>
                                      </div>
                                      <div className="flex justify-between mt-1 items-center">
                                        <span className="text-slate-500">Stored Parent Hash Pointer:</span>
                                        <span className={`font-bold ${securityDetails.isChainValid ? 'text-emerald-600' : 'text-rose-600 font-semibold'}`}>
                                          {p.prevHash.slice(0, 16)}... ({securityDetails.isChainValid ? 'Aligned' : 'Broken sequence!'})
                                        </span>
                                      </div>
                                      
                                      <div className="mt-2 flex items-center gap-1.5 justify-center py-1 bg-white border border-slate-200 rounded">
                                        <span className="text-slate-500 font-extrabold">CHAIN INTEGRITY:</span>
                                        {securityDetails.isChainValid ? (
                                          <span className="text-emerald-600 font-bold flex items-center gap-1 text-[10px]">
                                            <CheckCircle className="w-3 h-3 text-emerald-600 animate-pulse" /> FORWARD SECURE LINK
                                          </span>
                                        ) : (
                                          <span className="text-rose-600 font-bold flex items-center gap-1 text-[10px] animate-pulse">
                                            <AlertTriangle className="w-3 h-3 text-rose-600" /> LINK BREACH DETECTED
                                          </span>
                                        )}
                                      </div>
                                    </div>
                                  </div>

                                  {/* HMAC digital signature details */}
                                  <div className="bg-white border border-slate-200 rounded-lg p-3.5 space-y-2.5">
                                    <div className="flex items-center gap-2 text-slate-800 font-extrabold text-[11px] uppercase tracking-wider">
                                      <span className="text-teal-700 font-mono font-bold bg-teal-50 border border-teal-150 px-1.5 py-0.5 rounded">04.</span> HSM Private Key signature verification
                                    </div>
                                    
                                    <div className="space-y-2 text-[10px]">
                                      <div>
                                        <div className="flex justify-between text-slate-500 mb-1">
                                          <span>Expected HMAC-SHA256 Sign-off:</span>
                                          <span className={securityDetails.isSignatureValid ? 'text-emerald-600 font-bold' : 'text-rose-600 font-bold animate-pulse'}>
                                            {securityDetails.isSignatureValid ? '● Signed Authentic' : '▲ Signature Key Corrupted!'}
                                          </span>
                                        </div>
                                        <div className="bg-slate-50 border border-slate-200 p-2 rounded font-mono text-[9px] text-slate-700 truncate" title={generateHMACSignature(p.hash, secretKey)}>
                                          {generateHMACSignature(p.hash, secretKey)}
                                        </div>
                                      </div>

                                      <div>
                                        <div className="flex justify-between text-slate-500 mb-1">
                                          <span>Stored signature proof:</span>
                                          <span className={p.signature === generateHMACSignature(p.hash, secretKey) ? 'text-emerald-600 font-bold' : 'text-rose-600 font-bold'}>
                                            {p.signature === generateHMACSignature(p.hash, secretKey) ? 'Authentic Sign-off' : 'Forged / Missing Key'}
                                          </span>
                                        </div>
                                        <div className="bg-slate-50 border border-slate-200 p-2 rounded font-mono text-[9px] text-slate-700 truncate" title={p.signature}>
                                          {p.signature || 'No signature token registered'}
                                        </div>
                                      </div>

                                      {/* Freeze Block lock status and button action */}
                                      <div className="pt-2 border-t border-slate-100 flex flex-col gap-2">
                                        <div className="flex items-center justify-between">
                                          <span className="text-[9px] text-slate-500 font-bold uppercase tracking-wider">Lock Status:</span>
                                          {p.isFrozen ? (
                                            <span className="bg-amber-100 border border-amber-200 text-amber-800 text-[8px] font-extrabold px-1.5 py-0.5 rounded flex items-center gap-1">
                                              <Lock className="w-2.5 h-2.5 text-amber-700" /> FROZEN LOCK ACTIVE
                                            </span>
                                          ) : (
                                            <span className="bg-emerald-50 border border-emerald-100 text-emerald-700 text-[8px] font-bold px-1.5 py-0.5 rounded flex items-center gap-1">
                                              <LockOpen className="w-2.5 h-2.5 text-emerald-600" /> ACTIVE & UNLOCKED
                                            </span>
                                          )}
                                        </div>

                                        {p.isFrozen ? (
                                          <div className="bg-amber-50/50 border border-amber-100 rounded p-2 text-[9px] text-amber-800 leading-normal font-sans space-y-1">
                                            <div><strong>Lock Hash-Signature:</strong></div>
                                            <div className="font-mono text-[8px] truncate bg-white border border-amber-200/50 p-1 rounded select-all text-slate-700" title={p.frozenSignature}>
                                              {p.frozenSignature}
                                            </div>
                                            <div className="text-[8px] text-amber-600 font-medium leading-tight">
                                              This ledger block has been sealed with a cryptographic signature and is permanently immutable.
                                            </div>
                                          </div>
                                        ) : (
                                          <button
                                            type="button"
                                            onClick={() => freezeBlock(p.id)}
                                            className="w-full py-1.5 px-3 bg-slate-900 hover:bg-slate-800 text-white font-bold text-[10px] rounded border border-slate-950 transition flex items-center justify-center gap-1.5 cursor-pointer shadow-sm mt-1"
                                          >
                                            <Lock className="w-3 h-3 text-amber-400" />
                                            <span>Freeze Block #{String(index + 1).padStart(2, '0')} Record</span>
                                          </button>
                                        )}
                                      </div>
                                    </div>
                                  </div>
                                </div>

                                {/* Cryptographic Metadata Summary Row */}
                                <div className="bg-white border border-slate-200 rounded-xl p-3.5 flex flex-col md:flex-row gap-3 items-start md:items-center justify-between text-xs text-slate-700 shadow-inner">
                                  <div className="flex items-center gap-2">
                                    <ShieldAlert className="w-4 h-4 text-teal-600 shrink-0" />
                                    <div>
                                      <span className="font-bold text-slate-800 block md:inline tracking-wide uppercase text-[10px]">Cryptographic Node Parameters Summary</span>
                                      <span className="text-[9px] text-slate-400 font-medium block md:inline md:ml-1.5">SHA-256 Ledger Node Ledger Specifications</span>
                                    </div>
                                  </div>
                                  <div className="flex flex-wrap items-center gap-y-2 gap-x-4 md:gap-x-6 text-[10px] font-mono w-full md:w-auto">
                                    <div className="flex items-center gap-2 bg-slate-50 border border-slate-200 rounded px-2 py-1 flex-1 md:flex-initial justify-between md:justify-start">
                                      <span className="text-slate-400 text-[9px] font-medium uppercase font-sans">Hash Algorithm</span>
                                      <span className="font-extrabold text-teal-700">SHA-256</span>
                                    </div>
                                    <div className="flex items-center gap-2 bg-slate-50 border border-slate-200 rounded px-2 py-1 flex-1 md:flex-initial justify-between md:justify-start">
                                      <span className="text-slate-400 text-[9px] font-medium uppercase font-sans">Hash Length</span>
                                      <span className="font-extrabold text-teal-700">{p.hash ? p.hash.length : 64} hex characters</span>
                                    </div>
                                    <div className="flex items-center gap-2 bg-slate-50 border border-slate-200 rounded px-2 py-1 flex-1 md:flex-initial justify-between md:justify-start">
                                      <span className="text-slate-400 text-[9px] font-medium uppercase font-sans">Signature</span>
                                      <span className="font-extrabold text-emerald-700">HMAC-SHA256</span>
                                    </div>
                                    <div className="flex items-center gap-2 bg-slate-50 border border-slate-200 rounded px-2 py-1 flex-1 md:flex-initial justify-between md:justify-start">
                                      <span className="text-slate-400 text-[9px] font-medium uppercase font-sans">Entropy Bounds</span>
                                      <span className="font-extrabold text-emerald-700">256-bit Key</span>
                                    </div>
                                  </div>
                                </div>

                                {/* Active Protection Remediation Note */}
                                {!securityDetails.overallValid && (
                                  <div className="bg-rose-950/40 border border-rose-900/50 p-3 rounded-lg text-[10px] text-rose-300 leading-normal font-sans">
                                    🚨 <strong>DATABASE TAMPER EXPLOIT ACTIVE:</strong> This block has failed one or more cryptographic assertion audits. This mismatch represents a clear security bypass (such as a direct unauthorized database edit or file modification). Activate the <strong>IPS Real-time Self-Healer</strong> in the Control Panel or trigger a <strong>Repair with Backup</strong> to automatically recover clinical data integrity.
                                  </div>
                                )}
                              </motion.div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </AnimatePresence>
              </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Mini Log Console Widget */}
        <div className="bg-slate-50 border border-slate-200 rounded-xl p-5 shadow-sm">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 mb-4 pb-2.5 border-b border-slate-200">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-teal-600 animate-pulse" />
              <h3 className="font-extrabold text-xs text-slate-700 uppercase tracking-wider">
                Live Real-Time Security Auditor Log Stream
              </h3>
            </div>
            <button 
              onClick={() => setCurrentPage('auditor')}
              className="text-[10px] text-teal-600 hover:text-teal-700 font-bold flex items-center gap-1 transition cursor-pointer"
            >
              <span>View Full Auditor Console & Analytics</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
          <div className="space-y-1.5 font-mono text-[10px] text-slate-600 max-h-24 overflow-y-auto">
            {logs.slice(0, 3).map(log => (
              <div key={log.id} className="flex items-start gap-2.5 truncate text-slate-700 hover:bg-slate-100/50 p-0.5 rounded transition">
                <span className="text-slate-400 shrink-0">[{log.timestamp.slice(11, 19)}]</span>
                <span className={`px-1.5 py-0.2 rounded text-[8px] font-bold uppercase tracking-wider shrink-0 select-none ${
                  log.action === 'TAMPER' ? 'bg-rose-50 text-rose-600 border border-rose-100' :
                  log.action === 'VERIFY_FAIL' ? 'bg-rose-100 text-rose-700 border border-rose-200 animate-pulse' :
                  log.action === 'VERIFY_SUCCESS' ? 'bg-emerald-50 text-emerald-700 border border-emerald-100' :
                  'bg-slate-100 text-slate-500 border border-slate-200'
                }`}>{log.action}</span>
                <span className="text-slate-500 shrink-0 font-bold">({log.performedBy}):</span>
                <span className="text-slate-800 truncate">{log.details}</span>
              </div>
            ))}
            {logs.length === 0 && (
              <div className="text-slate-400 italic text-center py-2">Console empty. Active operations secure.</div>
            )}
          </div>
        </div>
      </div>
    )}

        {/* 3. Authoring Dialogue Panel (Dr secure Edit or Hack Tamper Tool) */}
        <AnimatePresence>
          {selectedPatient && actionType && (
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 bg-black/40 z-40 flex items-center justify-center p-4 backdrop-blur-sm"
            >
              <motion.div 
                initial={{ scale: 0.95 }}
                animate={{ scale: 1 }}
                exit={{ scale: 0.95 }}
                className="bg-white border border-slate-100 rounded-xl w-full max-w-lg overflow-hidden shadow-premium-lg text-slate-800"
              >
                {/* Banner Header */}
                <div className={`px-5 py-4 border-b flex justify-between items-center ${
                  actionType === 'doctor' ? 'bg-teal-50/50 border-teal-100' : 'bg-rose-50/50 border-rose-100'
                }`}>
                  <div className="flex items-center gap-2">
                    {actionType === 'doctor' ? (
                      <ShieldCheck className="w-5 h-5 text-teal-600 shrink-0" />
                    ) : (
                      <AlertTriangle className="w-5 h-5 text-rose-500 animate-pulse shrink-0" />
                    )}
                    <div>
                      <h3 className="text-sm font-extrabold text-slate-900">
                        {actionType === 'doctor' ? 'Authorized Doctor Portal: Record Sign-off' : 'Manual Database Tampering & Injection Tool'}
                      </h3>
                      <p className="text-[10px] text-slate-500">
                        Target Block: <strong className="text-slate-800 font-mono">{selectedPatient.id}</strong> • Patient: <strong className="text-slate-800">{selectedPatient.name}</strong>
                      </p>
                    </div>
                  </div>
                  <button 
                    onClick={() => { setSelectedPatient(null); setActionType(null); }}
                    className="p-1 text-slate-400 hover:text-slate-600 transition cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>

                {/* Mode Switcher Tabs */}
                <div className="bg-slate-100/80 p-2 border-b border-slate-200 flex items-center gap-2 text-xs">
                  <span className="text-[9px] font-mono font-bold text-slate-500 uppercase tracking-wider pl-1 shrink-0">Action Mode:</span>
                  <button
                    onClick={() => setActionType('doctor')}
                    className={`flex-1 py-1.5 px-2.5 rounded-lg font-bold transition flex items-center justify-center gap-1.5 cursor-pointer text-xs ${
                      actionType === 'doctor' 
                        ? 'bg-teal-600 text-white shadow-sm' 
                        : 'bg-white text-slate-700 hover:bg-slate-50 border border-slate-200'
                    }`}
                  >
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>Authorized Update (Valid)</span>
                  </button>
                  <button
                    onClick={() => setActionType('tamper')}
                    className={`flex-1 py-1.5 px-2.5 rounded-lg font-bold transition flex items-center justify-center gap-1.5 cursor-pointer text-xs ${
                      actionType === 'tamper' 
                        ? 'bg-rose-600 text-white shadow-sm' 
                        : 'bg-white text-rose-700 hover:bg-rose-50 border border-rose-200'
                    }`}
                  >
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Manual Tamper (Corrupts Hash)</span>
                  </button>
                </div>

                {/* Form fields */}
                <div className="p-5 space-y-4 text-xs">
                  {actionType === 'tamper' ? (
                    <div className="p-3 bg-rose-50 border border-rose-200 rounded-lg text-[11px] text-rose-900 font-medium leading-relaxed flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                      <div>
                        <strong>Manual Tamper Mode Active:</strong> Saving changes will directly overwrite database values <em>without</em> updating the cryptographic SHA-256 hash. The ledger will immediately flag this record as <strong className="text-rose-700">Tampered (Compromised)</strong> and trigger real-time integrity intrusion alarms!
                      </div>
                    </div>
                  ) : (
                    <div className="p-3 bg-teal-50 border border-teal-200 rounded-lg text-[11px] text-teal-900 font-medium leading-relaxed flex items-start gap-2">
                      <ShieldCheck className="w-4 h-4 text-teal-600 shrink-0 mt-0.5" />
                      <div>
                        <strong>Authorized Doctor Sign-off Active:</strong> Saving changes will legally re-compute the SHA-256 block hash and HMAC signature with the master key. The record will remain <strong className="text-teal-700">Valid & Verified</strong>.
                      </div>
                    </div>
                  )}

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-[10px] text-slate-500 uppercase font-mono block mb-1 font-bold">Patient Name</label>
                      <input 
                        type="text" 
                        value={newName} 
                        onChange={e => setNewName(e.target.value)}
                        className={`w-full border rounded px-2.5 py-1.5 font-semibold text-xs focus:outline-none focus:ring-1 ${
                          actionType === 'tamper' ? 'bg-rose-50/50 border-rose-200 focus:ring-rose-500 text-rose-950' : 'bg-white border-slate-200 focus:ring-teal-500 text-slate-900'
                        }`}
                      />
                    </div>
                    <div>
                      <label className="text-[10px] text-slate-400 uppercase font-mono block mb-1 font-bold">Block Index / ID</label>
                      <input 
                        type="text" 
                        disabled 
                        value={selectedPatient.id} 
                        className="w-full bg-slate-100 border border-slate-200 rounded px-2.5 py-1.5 text-slate-500 cursor-not-allowed font-mono text-xs"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-[10px] text-slate-500 uppercase font-mono block mb-1 font-bold">Clinical Diagnosis</label>
                      <input 
                        type="text" 
                        value={newDiagnosis}
                        onChange={e => setNewDiagnosis(e.target.value)}
                        className={`w-full border rounded px-3 py-2 font-semibold text-xs focus:outline-none focus:ring-1 ${
                          actionType === 'tamper' ? 'bg-rose-50/50 border-rose-200 focus:ring-rose-500 text-rose-950' : 'bg-white border-slate-200 focus:ring-teal-500 text-slate-900'
                        }`}
                        placeholder="e.g. Severe Hypertension"
                      />
                    </div>
                    <div>
                      <label className="text-[10px] text-slate-500 uppercase font-mono block mb-1 font-bold">Health Status</label>
                      <select
                        value={newStatus}
                        onChange={e => setNewStatus(e.target.value as any)}
                        className={`w-full border rounded px-2.5 py-2 font-semibold text-xs focus:outline-none focus:ring-1 ${
                          actionType === 'tamper' ? 'bg-rose-50/50 border-rose-200 focus:ring-rose-500 text-rose-950' : 'bg-white border-slate-200 focus:ring-teal-500 text-slate-900'
                        }`}
                      >
                        <option value="Stable">Stable</option>
                        <option value="Critical">Critical</option>
                        <option value="Recovering">Recovering</option>
                      </select>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-[10px] text-slate-500 uppercase font-mono block mb-1 font-bold">Prescribed Medication</label>
                      <input 
                        type="text" 
                        value={newMedication}
                        onChange={e => setNewMedication(e.target.value)}
                        className={`w-full border rounded px-3 py-2 font-mono font-bold text-xs focus:outline-none focus:ring-1 ${
                          actionType === 'tamper' ? 'bg-rose-50/50 border-rose-200 focus:ring-rose-500 text-rose-950' : 'bg-white border-slate-200 focus:ring-teal-500 text-slate-900'
                        }`}
                        placeholder="e.g. Metoprolol"
                      />
                    </div>
                    <div>
                      <label className="text-[10px] text-slate-500 uppercase font-mono block mb-1 font-bold">Dosage Prescription</label>
                      <input 
                        type="text" 
                        value={newDosage}
                        onChange={e => setNewDosage(e.target.value)}
                        className={`w-full border rounded px-3 py-2 font-mono font-bold text-xs focus:outline-none focus:ring-1 ${
                          actionType === 'tamper' ? 'bg-rose-50/50 border-rose-200 focus:ring-rose-500 text-rose-950' : 'bg-white border-slate-200 focus:ring-teal-500 text-teal-700'
                        }`}
                        placeholder="e.g. 50mg QD"
                      />
                    </div>
                  </div>
                </div>

                {/* Form CTA Buttons */}
                <div className="px-5 py-4 bg-slate-50 border-t border-slate-100 flex items-center justify-between gap-2 flex-wrap">
                  <button 
                    onClick={() => { setSelectedPatient(null); setActionType(null); }}
                    className="px-3.5 py-2 bg-white hover:bg-slate-50 text-slate-600 font-bold text-xs rounded-lg transition border border-slate-200 cursor-pointer"
                  >
                    Cancel
                  </button>

                  <div className="flex items-center gap-2 flex-wrap">
                    {actionType === 'tamper' ? (
                      <button 
                        onClick={() => executeDirectTampering(false)}
                        className="px-4 py-2 bg-rose-600 hover:bg-rose-700 text-white font-bold text-xs rounded-lg transition cursor-pointer shadow-sm flex items-center gap-1.5 animate-pulse"
                      >
                        <AlertTriangle className="w-3.5 h-3.5" />
                        <span>Inject Manual Tamper (Corrupts Hash)</span>
                      </button>
                    ) : (
                      <button 
                        onClick={executeDoctorUpdate}
                        className="px-4 py-2 bg-teal-600 hover:bg-teal-500 text-white font-bold text-xs rounded-lg transition shadow-premium cursor-pointer flex items-center gap-1.5"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>Authorize Sign & Re-Hash Record</span>
                      </button>
                    )}
                  </div>
                </div>

              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* User Authentication Modal (Sign In & Register) */}
        <AnimatePresence>
          {showAuthModal && (
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 bg-black/40 z-40 flex items-center justify-center p-4 backdrop-blur-sm"
            >
              <motion.div 
                initial={{ scale: 0.95 }}
                animate={{ scale: 1 }}
                exit={{ scale: 0.95 }}
                className="bg-white border border-slate-100 rounded-xl w-full max-w-md overflow-hidden shadow-premium-lg text-slate-800"
              >
                {/* Header */}
                <div className="px-5 py-4 border-b flex justify-between items-center bg-slate-50/60 border-slate-150">
                  <div className="flex items-center gap-2">
                    <User className="w-5 h-5 text-teal-600" />
                    <div>
                      <h3 className="text-sm font-extrabold text-slate-900">
                        {authMode === 'login' ? 'Verified Sign In Portal' : 'Register Auditor Credential'}
                      </h3>
                      <p className="text-[10px] text-slate-500">Access and audit the cryptographic clinical ledger</p>
                    </div>
                  </div>
                  <button 
                    onClick={() => { setShowAuthModal(false); setLoginError(''); setRegError(''); }}
                    className="p-1 text-slate-400 hover:text-slate-600 transition cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>

                {/* Switcher Tab */}
                <div className="flex border-b border-slate-100 bg-slate-50/30">
                  <button
                    onClick={() => { setAuthMode('login'); setLoginError(''); setRegError(''); }}
                    className={`flex-1 py-2.5 text-center text-xs font-bold transition border-b-2 ${
                      authMode === 'login' 
                        ? 'border-teal-600 text-teal-700 bg-white' 
                        : 'border-transparent text-slate-500 hover:text-slate-800'
                    }`}
                  >
                    Sign In
                  </button>
                  <button
                    onClick={() => { setAuthMode('register'); setLoginError(''); setRegError(''); }}
                    className={`flex-1 py-2.5 text-center text-xs font-bold transition border-b-2 ${
                      authMode === 'register' 
                        ? 'border-teal-600 text-teal-700 bg-white' 
                        : 'border-transparent text-slate-500 hover:text-slate-800'
                    }`}
                  >
                    Register Account
                  </button>
                </div>

                {/* Form Body */}
                <form 
                  onSubmit={authMode === 'login' ? handleLogin : handleRegister} 
                  className="p-5 space-y-4"
                >
                  {authMode === 'login' ? (
                    // SIGN IN FORM
                    <div className="space-y-3">
                      {loginError && (
                        <div className="p-2.5 bg-rose-50 border border-rose-150 rounded text-[10px] text-rose-700 font-semibold leading-relaxed flex items-center gap-1.5">
                          <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-rose-600" />
                          <span>{loginError}</span>
                        </div>
                      )}
                      <div>
                        <label className="text-[10px] text-slate-500 uppercase font-mono block mb-1">Username</label>
                        <input 
                          type="text" 
                          value={loginUsername}
                          onChange={e => setLoginUsername(e.target.value)}
                          placeholder="e.g. auditor_jones"
                          className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded px-3 py-2 text-slate-900 font-medium text-xs"
                        />
                      </div>
                      <div>
                        <label className="text-[10px] text-slate-500 uppercase font-mono block mb-1">Password</label>
                        <input 
                          type="password" 
                          value={loginPassword}
                          onChange={e => setLoginPassword(e.target.value)}
                          placeholder="••••••••"
                          className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded px-3 py-2 text-slate-900 font-medium text-xs"
                        />
                      </div>
                      <div className="text-[9px] text-slate-400 leading-normal mt-2.5 bg-slate-50 p-2 rounded">
                        ℹ️ <strong>Quick testing helper:</strong> Sign in with username <strong className="text-slate-700">auditor_jones</strong> and password <strong className="text-slate-700">password123</strong>, or register your own credential!
                      </div>
                    </div>
                  ) : (
                    // REGISTER FORM
                    <div className="space-y-3">
                      {regError && (
                        <div className="p-2.5 bg-rose-50 border border-rose-150 rounded text-[10px] text-rose-700 font-semibold leading-relaxed flex items-center gap-1.5">
                          <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-rose-600" />
                          <span>{regError}</span>
                        </div>
                      )}
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="text-[10px] text-slate-500 uppercase font-mono block mb-1">Username</label>
                          <input 
                            type="text" 
                            value={regUsername}
                            onChange={e => setRegUsername(e.target.value)}
                            placeholder="e.g. auditor_jones"
                            className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded px-3 py-1.5 text-slate-900 font-medium text-xs"
                          />
                        </div>
                        <div>
                          <label className="text-[10px] text-slate-500 uppercase font-mono block mb-1">Password</label>
                          <input 
                            type="password" 
                            value={regPassword}
                            onChange={e => setRegPassword(e.target.value)}
                            placeholder="password123"
                            className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded px-3 py-1.5 text-slate-900 font-medium text-xs"
                          />
                        </div>
                      </div>
                      <div>
                        <label className="text-[10px] text-slate-500 uppercase font-mono block mb-1">Auditor Full Name</label>
                        <input 
                          type="text" 
                          value={regName}
                          onChange={e => setRegName(e.target.value)}
                          placeholder="e.g. Dr. Robert Chen"
                          className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded px-3 py-1.5 text-slate-900 font-medium text-xs font-semibold"
                        />
                      </div>
                      <div>
                        <label className="text-[10px] text-slate-500 uppercase font-mono block mb-1">Assigned Auditor Role</label>
                        <select 
                          value={regRole}
                          onChange={e => setRegRole(e.target.value as any)}
                          className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded px-3 py-1.5 text-slate-900 font-medium text-xs font-semibold"
                        >
                          <option value="Clinical Auditor">Clinical Auditor</option>
                          <option value="Lead Doctor">Lead Doctor</option>
                          <option value="Compliance Officer">Compliance Officer</option>
                          <option value="Database Admin">Database Admin</option>
                        </select>
                      </div>
                      <div>
                        <label className="text-[10px] text-slate-500 uppercase font-mono block mb-1">Organization / Clinic</label>
                        <input 
                          type="text" 
                          value={regOrg}
                          onChange={e => setRegOrg(e.target.value)}
                          placeholder="e.g. MedTrust Labs Central"
                          className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded px-3 py-1.5 text-slate-900 font-medium text-xs"
                        />
                      </div>
                    </div>
                  )}

                  {/* Submit buttons */}
                  <div className="pt-3 border-t border-slate-100 flex justify-end gap-2">
                    <button 
                      type="button"
                      onClick={() => { setShowAuthModal(false); setLoginError(''); setRegError(''); }}
                      className="px-4 py-2 bg-white hover:bg-slate-50 text-slate-600 font-bold text-xs rounded-lg transition border border-slate-200 cursor-pointer"
                    >
                      Cancel
                    </button>
                    <button 
                      type="submit"
                      className="px-5 py-2 bg-teal-600 hover:bg-teal-500 text-white font-bold text-xs rounded-lg transition shadow-premium cursor-pointer"
                    >
                      {authMode === 'login' ? 'Sign In as Auditor' : 'Register & Log In'}
                    </button>
                  </div>
                </form>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Manual Register New Patient Block Modal */}
        <AnimatePresence>
          {showAddPatientModal && (
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 bg-black/40 z-40 flex items-center justify-center p-4 backdrop-blur-sm"
            >
              <motion.div 
                initial={{ scale: 0.95 }}
                animate={{ scale: 1 }}
                exit={{ scale: 0.95 }}
                className="bg-white border border-slate-100 rounded-xl w-full max-w-lg overflow-hidden shadow-premium-lg text-slate-800"
              >
                {/* Header Banner */}
                <div className="px-5 py-4 border-b flex justify-between items-center bg-teal-50/50 border-teal-100">
                  <div className="flex items-center gap-2">
                    <Database className="w-5 h-5 text-teal-600 animate-pulse" />
                    <div>
                      <h3 className="text-sm font-extrabold text-slate-900">
                        Cryptographic Registry: Register New Patient Block
                      </h3>
                      <p className="text-[10px] text-slate-500">
                        Enrolling a new ledger block sequentially with SHA-256 forward hash chaining
                      </p>
                    </div>
                  </div>
                  <button 
                    onClick={() => setShowAddPatientModal(false)}
                    className="p-1 text-slate-400 hover:text-slate-600 transition cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>

                {/* Form fields */}
                <div className="p-5 space-y-4 text-xs">
                  <div className="p-3 bg-teal-50/50 border border-teal-100 rounded-lg text-[11px] text-teal-800 font-medium leading-relaxed">
                    📝 <strong>Sequential Integrity Enforced:</strong> This patient will be appended as **Block #{String(patients.length + 1).padStart(2, '0')}** (`PAT-${String(patients.length + 1).padStart(3, '0')}`). Its back-link (`prevHash`) will lock onto the current last block's hash.
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-12 gap-4">
                    <div className="sm:col-span-8">
                      <label className="text-[10px] text-slate-500 uppercase font-mono block mb-1 font-bold">Patient Full Name</label>
                      <input 
                        type="text" 
                        value={addPatientName}
                        onChange={e => setAddPatientName(e.target.value)}
                        placeholder="Benny Harrison"
                        className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded px-3 py-2 text-slate-900 font-semibold"
                      />
                    </div>
                    <div className="sm:col-span-4">
                      <label className="text-[10px] text-slate-500 uppercase font-mono block mb-1 font-bold">Age</label>
                      <input 
                        type="number" 
                        value={addPatientAge}
                        onChange={e => setAddPatientAge(e.target.value === '' ? '' : Number(e.target.value))}
                        placeholder="45"
                        className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded px-3 py-2 text-slate-900 font-semibold"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-12 gap-4">
                    <div className="sm:col-span-6">
                      <label className="text-[10px] text-slate-500 uppercase font-mono block mb-1 font-bold">Blood Group</label>
                      <select 
                        value={addPatientBloodType}
                        onChange={e => setAddPatientBloodType(e.target.value)}
                        className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded px-3 py-2 text-slate-900 font-semibold"
                      >
                        <option value="A+">A+</option>
                        <option value="A-">A-</option>
                        <option value="B+">B+</option>
                        <option value="B-">B-</option>
                        <option value="O+">O+</option>
                        <option value="O-">O-</option>
                        <option value="AB+">AB+</option>
                        <option value="AB-">AB-</option>
                      </select>
                    </div>
                    <div className="sm:col-span-6">
                      <label className="text-[10px] text-slate-500 uppercase font-mono block mb-1 font-bold">Clinical Status</label>
                      <select 
                        value={addPatientStatus}
                        onChange={e => setAddPatientStatus(e.target.value as any)}
                        className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded px-3 py-2 text-slate-900 font-semibold"
                      >
                        <option value="Stable">Stable</option>
                        <option value="Recovering">Recovering</option>
                        <option value="Critical">Critical</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="text-[10px] text-slate-500 uppercase font-mono block mb-1 font-bold">Medical Diagnosis</label>
                    <input 
                      type="text" 
                      value={addPatientDiagnosis}
                      onChange={e => setAddPatientDiagnosis(e.target.value)}
                      placeholder="e.g. Acute Mitral Valve Regurgitation Post-op"
                      className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded px-3 py-2 text-slate-900 font-semibold"
                    />
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-12 gap-4">
                    <div className="sm:col-span-7">
                      <label className="text-[10px] text-slate-500 uppercase font-mono block mb-1 font-bold">Prescribed Medication</label>
                      <input 
                        type="text" 
                        value={addPatientMedication}
                        onChange={e => setAddPatientMedication(e.target.value)}
                        placeholder="e.g. Lisinopril Oral"
                        className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded px-3 py-2 text-slate-900 font-mono font-bold"
                      />
                    </div>
                    <div className="sm:col-span-5">
                      <label className="text-[10px] text-slate-500 uppercase font-mono block mb-1 font-bold">Dosage</label>
                      <input 
                        type="text" 
                        value={addPatientDosage}
                        onChange={e => setAddPatientDosage(e.target.value)}
                        placeholder="e.g. 10mg QD"
                        className="w-full bg-white border border-slate-200 focus:border-teal-400 focus:ring-1 focus:ring-teal-400 focus:outline-none rounded px-3 py-2 text-slate-900 font-mono font-bold"
                      />
                    </div>
                  </div>
                </div>

                {/* Form CTA Buttons */}
                <div className="px-5 py-4 bg-slate-50 border-t border-slate-100 flex justify-end gap-2">
                  <button 
                    onClick={() => setShowAddPatientModal(false)}
                    className="px-4 py-2 bg-white hover:bg-slate-50 text-slate-600 font-bold text-xs rounded-lg transition border border-slate-200 cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button 
                    onClick={executeAddPatient}
                    disabled={!addPatientName.trim()}
                    className="px-5 py-2 bg-teal-600 hover:bg-teal-500 disabled:opacity-50 text-white font-bold text-xs rounded-lg transition shadow-premium cursor-pointer"
                  >
                    Sign, Hash & Append Block
                  </button>
                </div>

              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* 4. Live Real-time Security Auditor Trail (Console Log Feed) */}
        {currentPage === 'auditor' && (
          <div className="bg-white border border-slate-200/60 rounded-xl p-5 shadow-premium">
          <div className="flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between mb-4 border-b border-slate-100 pb-3">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-slate-400 animate-pulse" />
              <h3 className="font-extrabold text-xs text-slate-500 uppercase tracking-wider">
                MedTrust Central Secure Auditor Console
              </h3>
            </div>
            
            {/* Filter buttons & Search */}
            <div className="flex flex-wrap items-center gap-2">
              {/* Log Search */}
              <input
                type="text"
                placeholder="Search auditor logs..."
                value={logSearch}
                onChange={(e) => setLogSearch(e.target.value)}
                className="px-2.5 py-1 bg-slate-50 border border-slate-200 rounded-md focus:outline-none focus:ring-1 focus:ring-teal-500 text-[11px] w-48 font-sans font-medium"
              />

              {/* Filter Pills */}
              <div className="flex items-center border border-slate-200 rounded-md p-0.5 bg-slate-50">
                {(['ALL', 'THREATS', 'UPDATES', 'SYSTEM'] as const).map(f => (
                  <button
                    key={f}
                    onClick={() => setLogFilter(f)}
                    className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase transition cursor-pointer ${
                      logFilter === f
                        ? 'bg-teal-600 text-white shadow-sm'
                        : 'text-slate-500 hover:text-slate-800'
                    }`}
                  >
                    {f}
                  </button>
                ))}
              </div>

              <button 
                onClick={() => setLogs([])}
                className="px-2.5 py-1 text-slate-400 hover:text-rose-600 font-bold border border-transparent hover:border-slate-200 hover:bg-slate-50 rounded transition duration-150 text-[10px] cursor-pointer"
                title="Clear Auditor Logs"
              >
                Clear
              </button>
            </div>
          </div>

          <div className="h-44 overflow-y-auto font-mono text-[11px] space-y-2 bg-slate-50 p-4 rounded-lg border border-slate-200 shadow-inner">
            {filteredLogs.length === 0 ? (
              <div className="text-slate-400 text-center py-10 italic">
                {logs.length === 0 
                  ? 'Secure Auditor Console initialized. Ready to observe operations.'
                  : 'No logs match the current search or filter query.'}
              </div>
            ) : (
              filteredLogs.map(log => (
                <div key={log.id} className="flex items-start gap-2.5 leading-relaxed text-slate-600 hover:bg-slate-100/50 p-1 rounded transition">
                  <span className="text-slate-400 shrink-0 text-[10px] select-none">[{log.timestamp}]</span>
                  
                  <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold uppercase tracking-wider shrink-0 select-none ${
                    log.action === 'TAMPER' ? 'bg-rose-50 text-rose-600 border border-rose-100' :
                    log.action === 'VERIFY_FAIL' ? 'bg-rose-100 text-rose-700 border border-rose-200 font-black animate-pulse' :
                    log.action === 'VERIFY_SUCCESS' ? 'bg-emerald-50 text-emerald-700 border border-emerald-100' :
                    log.action === 'UPDATE' ? 'bg-teal-50 text-teal-700 border border-teal-100' : 'bg-slate-100 text-slate-500 border border-slate-200'
                  }`}>
                    {log.action}
                  </span>

                  <span className="text-slate-500 font-semibold shrink-0">({log.performedBy}):</span>
                  
                  <span className="text-slate-800 flex-1">{log.details}</span>
                </div>
              ))
            )}
          </div>
        </div>
        )}

      </main>

      {/* Decorative Wave Footer */}
      <footer className="mt-12 py-8 border-t border-slate-200/65 text-center text-xs text-slate-400 font-medium">
        <p>© 2026 MedTrust Security Operations. All rights reserved.</p>
        <p className="mt-1 text-[10px] font-mono text-slate-400">Secure Cryptographic Chaining Demonstration Workspace</p>
      </footer>

    </div>
  );
}
