import React, { useState, useMemo } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  History, 
  AlertTriangle, 
  FileWarning, 
  ArrowLeft, 
  Download, 
  Trash2, 
  Search, 
  CheckCircle2, 
  XCircle, 
  Lock, 
  Unlock, 
  RefreshCw, 
  FileJson, 
  FileSpreadsheet, 
  Copy, 
  Check, 
  ExternalLink, 
  Activity, 
  Database, 
  Key, 
  Zap, 
  ChevronDown, 
  ChevronUp, 
  Fingerprint, 
  Clock, 
  User, 
  Pill, 
  HeartPulse, 
  Terminal,
  Layers,
  ArrowRight,
  Info
} from 'lucide-react';
import { TamperAttempt, PatientRecord, AuditLogEntry, RegisteredUser } from '../types';
import { calculateRecordHash } from '../data';

interface TamperHistoryPageProps {
  tamperAttempts: TamperAttempt[];
  setTamperAttempts: React.Dispatch<React.SetStateAction<TamperAttempt[]>>;
  patients: PatientRecord[];
  authorizedPatients: PatientRecord[];
  onRestorePatient: (patientId: string) => void;
  onRestoreAll: () => void;
  onNavigateToPatient: (patientId: string) => void;
  onNavigatePage: (page: 'clinical' | 'security_agent' | 'auditor' | 'tamper_history') => void;
  currentUser: RegisteredUser | null;
  addLog: (action: AuditLogEntry['action'], details: string, severity?: AuditLogEntry['severity'], recordId?: string, patientName?: string) => void;
}

export const TamperHistoryPage: React.FC<TamperHistoryPageProps> = ({
  tamperAttempts,
  setTamperAttempts,
  patients,
  authorizedPatients,
  onRestorePatient,
  onRestoreAll,
  onNavigateToPatient,
  onNavigatePage,
  currentUser,
  addLog
}) => {
  // --- Filter & Search States ---
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'BLOCKED' | 'BREACHED'>('ALL');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [threatFilter, setThreatFilter] = useState<string>('ALL');
  const [sortBy, setSortBy] = useState<'newest' | 'oldest' | 'threat' | 'patient'>('newest');
  
  // Expanded card state
  const [expandedIncidentIds, setExpandedIncidentIds] = useState<Record<string, boolean>>(() => {
    // Expand the first 3 by default
    const initial: Record<string, boolean> = {};
    tamperAttempts.slice(0, 3).forEach(t => { initial[t.id] = true; });
    return initial;
  });

  const [copiedIncidentId, setCopiedIncidentId] = useState<string | null>(null);
  const [showClearConfirm, setShowClearConfirm] = useState(false);

  const toggleExpand = (id: string) => {
    setExpandedIncidentIds(prev => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  const expandAll = () => {
    const all: Record<string, boolean> = {};
    tamperAttempts.forEach(t => { all[t.id] = true; });
    setExpandedIncidentIds(all);
  };

  const collapseAll = () => {
    setExpandedIncidentIds({});
  };

  // --- Check Active Compromised Blocks in Live Memory ---
  const compromisedBlocks = useMemo(() => {
    return patients.filter((p, index) => {
      const auth = authorizedPatients.find(a => a.id === p.id);
      const computedHash = calculateRecordHash({
        ...p,
        prevHash: p.prevHash
      });
      const hashMismatch = p.hash !== computedHash;
      const dataAltered = auth && (
        auth.medication !== p.medication ||
        auth.dosage !== p.dosage ||
        auth.diagnosis !== p.diagnosis ||
        auth.status !== p.status ||
        auth.name !== p.name
      );
      return hashMismatch || dataAltered;
    });
  }, [patients, authorizedPatients]);

  // --- Compute Attack Types from Data ---
  const availableAttackTypes = useMemo(() => {
    const types = new Set<string>();
    tamperAttempts.forEach(t => {
      if (t.attackType) types.add(t.attackType);
    });
    return Array.from(types);
  }, [tamperAttempts]);

  // --- Filtered and Sorted Tamper Attempts ---
  const filteredAttempts = useMemo(() => {
    return tamperAttempts.filter(attempt => {
      // Search
      const q = searchQuery.toLowerCase().trim();
      const matchesSearch = !q || (
        attempt.id.toLowerCase().includes(q) ||
        attempt.targetPatient.toLowerCase().includes(q) ||
        (attempt.targetPatientId && attempt.targetPatientId.toLowerCase().includes(q)) ||
        attempt.details.toLowerCase().includes(q) ||
        attempt.attackType.toLowerCase().includes(q) ||
        (attempt.attackerProfile && attempt.attackerProfile.toLowerCase().includes(q)) ||
        (attempt.originalData?.medication && attempt.originalData.medication.toLowerCase().includes(q)) ||
        (attempt.tamperedData?.medication && attempt.tamperedData.medication.toLowerCase().includes(q))
      );

      // Status Filter
      const matchesStatus = 
        statusFilter === 'ALL' ||
        (statusFilter === 'BLOCKED' && attempt.status === 'Detected & Blocked') ||
        (statusFilter === 'BREACHED' && attempt.status === 'Undetected (Succeeded)');

      // Attack Type Filter
      const matchesType = typeFilter === 'ALL' || attempt.attackType === typeFilter;

      // Threat Level Filter
      const matchesThreat = threatFilter === 'ALL' || attempt.threatLevel === threatFilter;

      return matchesSearch && matchesStatus && matchesType && matchesThreat;
    }).sort((a, b) => {
      if (sortBy === 'newest') {
        return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime() || b.id.localeCompare(a.id);
      }
      if (sortBy === 'oldest') {
        return new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime() || a.id.localeCompare(b.id);
      }
      if (sortBy === 'threat') {
        const order: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 };
        const aVal = order[a.threatLevel || 'Medium'] || 0;
        const bVal = order[b.threatLevel || 'Medium'] || 0;
        return bVal - aVal;
      }
      if (sortBy === 'patient') {
        return a.targetPatient.localeCompare(b.targetPatient);
      }
      return 0;
    });
  }, [tamperAttempts, searchQuery, statusFilter, typeFilter, threatFilter, sortBy]);

  // --- Statistics ---
  const stats = useMemo(() => {
    const total = tamperAttempts.length;
    const blocked = tamperAttempts.filter(t => t.status === 'Detected & Blocked').length;
    const breached = tamperAttempts.filter(t => t.status === 'Undetected (Succeeded)').length;
    const blockRate = total > 0 ? Math.round((blocked / total) * 100) : 100;

    // Most targeted patient
    const counts: Record<string, number> = {};
    tamperAttempts.forEach(t => {
      counts[t.targetPatient] = (counts[t.targetPatient] || 0) + 1;
    });
    let mostTargeted = 'None';
    let maxTargetCount = 0;
    Object.entries(counts).forEach(([name, count]) => {
      if (count > maxTargetCount) {
        maxTargetCount = count;
        mostTargeted = `${name} (${count}x)`;
      }
    });

    // Primary attack vector
    const vectorCounts: Record<string, number> = {};
    tamperAttempts.forEach(t => {
      vectorCounts[t.attackType] = (vectorCounts[t.attackType] || 0) + 1;
    });
    let topVector = 'None';
    let maxVectorCount = 0;
    Object.entries(vectorCounts).forEach(([vec, count]) => {
      if (count > maxVectorCount) {
        maxVectorCount = count;
        topVector = vec;
      }
    });

    return { total, blocked, breached, blockRate, mostTargeted, topVector };
  }, [tamperAttempts]);

  // --- Export Full Signed Forensic JSON Dossier ---
  const handleExportJSON = () => {
    const exportData = {
      exportType: "MedTrust-Tamper-Forensics-Dossier",
      version: "3.2.0-SECURE",
      generatedAt: new Date().toISOString(),
      generatedBy: currentUser ? `${currentUser.name} (${currentUser.role})` : 'Clinical Auditor',
      summary: {
        totalIncidents: tamperAttempts.length,
        interceptedCount: stats.blocked,
        breachedCount: stats.breached,
        interceptionRate: `${stats.blockRate}%`,
        activeLiveCompromisedBlocks: compromisedBlocks.length
      },
      liveLedgerIntegrity: {
        totalDatabaseNodes: patients.length,
        compromisedNodes: compromisedBlocks.map(b => ({
          id: b.id,
          name: b.name,
          currentHash: b.hash,
          diagnosis: b.diagnosis,
          medication: b.medication
        }))
      },
      tamperIncidents: tamperAttempts
    };

    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportData, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `medtrust_tamper_forensics_history_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();

    addLog(
      'READ',
      `Exported signed forensic JSON dossier containing ${tamperAttempts.length} tamper incidents.`,
      'info'
    );
  };

  // --- Export CSV Report ---
  const handleExportCSV = () => {
    const headers = [
      'Incident ID',
      'Timestamp',
      'Attack Vector',
      'Target Patient',
      'Target ID',
      'Threat Level',
      'Status',
      'Defenses Active',
      'Original Medication',
      'Tampered Medication',
      'Original Dosage',
      'Tampered Dosage',
      'Original Hash',
      'Tampered Hash',
      'Details',
      'Detection Mechanism'
    ];

    const rows = tamperAttempts.map(t => [
      t.id,
      t.timestamp,
      `"${t.attackType.replace(/"/g, '""')}"`,
      `"${t.targetPatient.replace(/"/g, '""')}"`,
      t.targetPatientId || 'N/A',
      t.threatLevel || 'Medium',
      t.status,
      t.defensesEnabledCount,
      `"${(t.originalData?.medication || '').replace(/"/g, '""')}"`,
      `"${(t.tamperedData?.medication || '').replace(/"/g, '""')}"`,
      `"${(t.originalData?.dosage || '').replace(/"/g, '""')}"`,
      `"${(t.tamperedData?.dosage || '').replace(/"/g, '""')}"`,
      t.originalData?.hash || 'N/A',
      t.tamperedData?.hash || 'N/A',
      `"${t.details.replace(/"/g, '""')}"`,
      `"${(t.detectionMechanism || '').replace(/"/g, '""')}"`
    ]);

    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `medtrust_tampered_data_history_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();

    addLog(
      'READ',
      `Exported CSV audit spreadsheet for ${tamperAttempts.length} tamper incidents.`,
      'info'
    );
  };

  // --- Copy Incident Diff ---
  const handleCopyDiff = (attempt: TamperAttempt) => {
    const payload = JSON.stringify({
      incidentId: attempt.id,
      targetPatient: attempt.targetPatient,
      attackType: attempt.attackType,
      status: attempt.status,
      originalGoldenState: attempt.originalData,
      maliciousTamperedState: attempt.tamperedData,
      detectionTrace: attempt.detectionMechanism
    }, null, 2);

    navigator.clipboard.writeText(payload);
    setCopiedIncidentId(attempt.id);
    setTimeout(() => setCopiedIncidentId(null), 2500);
  };

  // --- Single Incident JSON Export ---
  const handleExportSingleIncident = (attempt: TamperAttempt) => {
    const singleData = {
      reportType: "MedTrust-Single-Incident-Forensic-Artifact",
      incident: attempt,
      exportedAt: new Date().toISOString(),
      verifiedBy: currentUser?.name || 'Clinical Auditor'
    };

    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(singleData, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `forensic_incident_${attempt.id}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // --- Clear History ---
  const handleClearHistory = () => {
    setTamperAttempts([]);
    setShowClearConfirm(false);
    addLog('UPDATE', 'Cleared all recorded tamper history from auditor session memory.', 'warning');
  };

  return (
    <div className="space-y-6 pb-12">
      {/* ========================================================================= */}
      {/* TOP HEADER & FORENSIC BREADCRUMBS */}
      {/* ========================================================================= */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 text-white shadow-xl relative overflow-hidden">
        {/* Background ambient gradient */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-rose-600/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20"></div>
        <div className="absolute bottom-0 left-1/3 w-64 h-64 bg-teal-600/10 rounded-full blur-2xl pointer-events-none"></div>

        <div className="relative z-10">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="space-y-2">
              <div className="flex items-center gap-2.5 flex-wrap">
                <button
                  onClick={() => onNavigatePage('clinical')}
                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded-lg text-xs font-bold transition flex items-center gap-1.5 border border-slate-700 cursor-pointer"
                >
                  <ArrowLeft className="w-3.5 h-3.5" />
                  <span>Clinical Ledger</span>
                </button>
                <span className="text-slate-600 text-sm">/</span>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-extrabold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                  <Fingerprint className="w-3 h-3 text-rose-400" />
                  Forensic Security Intelligence
                </span>
                <span className="text-xs font-mono text-slate-400">
                  Session Records: {tamperAttempts.length} Incidents
                </span>
              </div>

              <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white flex items-center gap-3">
                <ShieldAlert className="w-8 h-8 text-rose-400 shrink-0" />
                <span>Tampered Data & Cryptographic Breach History</span>
              </h1>
              <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
                Comprehensive cryptographic forensic ledger documenting all unauthorized data modifications, 
                direct SQL injections, forged hash cascades, and intercepted threat vectors across patient blocks.
              </p>
            </div>

            {/* Header Action Buttons */}
            <div className="flex items-center gap-2 flex-wrap shrink-0">
              <button
                onClick={handleExportJSON}
                className="px-3.5 py-2 bg-teal-600 hover:bg-teal-500 text-white text-xs font-bold rounded-xl transition flex items-center gap-2 shadow-sm cursor-pointer"
                title="Download complete signed JSON audit artifact for offline forensic tools"
              >
                <FileJson className="w-4 h-4" />
                <span>Export Signed JSON Dossier</span>
              </button>

              <button
                onClick={handleExportCSV}
                className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white text-xs font-bold rounded-xl border border-slate-700 transition flex items-center gap-2 cursor-pointer"
                title="Download CSV spreadsheet report"
              >
                <FileSpreadsheet className="w-4 h-4 text-emerald-400" />
                <span>Export CSV</span>
              </button>

              <button
                onClick={() => onNavigatePage('auditor')}
                className="px-3.5 py-2 bg-indigo-600/80 hover:bg-indigo-600 text-white text-xs font-bold rounded-xl transition flex items-center gap-2 cursor-pointer shadow-sm"
                title="Open Auditor Console to simulate threat vectors"
              >
                <Terminal className="w-4 h-4" />
                <span>Threat Simulator</span>
              </button>

              {tamperAttempts.length > 0 && (
                <button
                  onClick={() => setShowClearConfirm(true)}
                  className="p-2 bg-slate-800/80 hover:bg-rose-900/60 text-slate-400 hover:text-rose-300 rounded-xl border border-slate-700 transition cursor-pointer"
                  title="Clear history"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* CLEAR HISTORY CONFIRMATION MODAL */}
      {/* ========================================================================= */}
      {showClearConfirm && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-in fade-in duration-200">
          <div className="bg-white rounded-2xl p-6 max-w-md w-full shadow-2xl border border-slate-200 space-y-4">
            <div className="flex items-center gap-3 text-rose-600">
              <AlertTriangle className="w-6 h-6" />
              <h3 className="text-lg font-bold text-slate-900">Clear Tamper History?</h3>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              This will remove all <strong className="text-slate-900">{tamperAttempts.length}</strong> recorded 
              forensic tamper events from this session. Active patient database records will remain unchanged.
            </p>
            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setShowClearConfirm(false)}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl text-xs font-bold transition cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleClearHistory}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-700 text-white rounded-xl text-xs font-bold transition flex items-center gap-1.5 cursor-pointer shadow-sm"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Yes, Clear History</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* LIVE COMPROMISED DATABASE BLOCKS ALERT BANNER */}
      {/* ========================================================================= */}
      {compromisedBlocks.length > 0 ? (
        <div className="bg-gradient-to-r from-rose-900/90 via-red-900/90 to-amber-900/90 border-2 border-rose-500/80 rounded-2xl p-5 text-white shadow-lg animate-in fade-in">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-start gap-3.5">
              <div className="p-2.5 bg-rose-600 text-white rounded-xl shrink-0 animate-pulse">
                <AlertTriangle className="w-6 h-6" />
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <h3 className="font-extrabold text-base tracking-tight text-white">
                    Active Cryptographic Breach Detected in Live Database!
                  </h3>
                  <span className="px-2 py-0.5 bg-rose-500 text-white text-[11px] font-black rounded-full uppercase tracking-wider">
                    {compromisedBlocks.length} {compromisedBlocks.length === 1 ? 'Block' : 'Blocks'} Altered
                  </span>
                </div>
                <p className="text-xs text-rose-100/90 leading-relaxed max-w-2xl">
                  The following patient record(s) currently diverge from their authoritative golden baseline or calculated SHA-256 hash:{' '}
                  <strong className="text-white">
                    {compromisedBlocks.map(b => `${b.name} (${b.id})`).join(', ')}
                  </strong>.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={onRestoreAll}
                className="px-4 py-2.5 bg-white hover:bg-rose-50 text-rose-900 font-extrabold text-xs rounded-xl shadow-md transition flex items-center gap-2 cursor-pointer"
              >
                <RefreshCw className="w-4 h-4 text-rose-600" />
                <span>Heal & Restore All to Golden Baseline</span>
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-emerald-50 border border-emerald-200 rounded-2xl p-4 text-emerald-900 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-emerald-100 text-emerald-700 rounded-xl">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="text-xs font-extrabold text-emerald-900 flex items-center gap-2">
                <span>Live Database Status: Pristine & Cryptographically Synchronized</span>
                <span className="px-2 py-0.5 bg-emerald-200/70 text-emerald-800 rounded text-[10px] font-mono font-bold">
                  All {patients.length} Blocks Verified
                </span>
              </div>
              <p className="text-[11px] text-emerald-700 mt-0.5">
                Zero active memory divergences detected. Stored hashes strictly match live SHA-256 recalculations and golden baselines.
              </p>
            </div>
          </div>
          <button
            onClick={() => onNavigatePage('clinical')}
            className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold rounded-lg transition shrink-0 cursor-pointer"
          >
            Inspect Ledger
          </button>
        </div>
      )}

      {/* ========================================================================= */}
      {/* FORENSIC KPI METRICS OVERVIEW */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Total Incidents */}
        <div className="bg-white border border-slate-200/80 rounded-2xl p-4.5 shadow-sm space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Total Recorded Incidents</span>
            <div className="p-1.5 bg-slate-100 text-slate-700 rounded-lg">
              <History className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-black text-slate-900 font-mono">{stats.total}</span>
            <span className="text-xs text-slate-500 font-medium">attempted breaches</span>
          </div>
          <div className="text-[11px] text-slate-500 pt-1 border-t border-slate-100 flex items-center gap-1">
            <Activity className="w-3 h-3 text-teal-600" />
            <span>Forensic log stream active</span>
          </div>
        </div>

        {/* Card 2: Neutralized & Blocked Rate */}
        <div className="bg-white border border-slate-200/80 rounded-2xl p-4.5 shadow-sm space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Interception Rate</span>
            <div className="p-1.5 bg-emerald-100 text-emerald-700 rounded-lg">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-black text-emerald-600 font-mono">{stats.blockRate}%</span>
            <span className="text-xs text-slate-500 font-medium">({stats.blocked} blocked)</span>
          </div>
          <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
            <div 
              className="bg-emerald-500 h-full rounded-full transition-all duration-500"
              style={{ width: `${stats.blockRate}%` }}
            />
          </div>
        </div>

        {/* Card 3: Unchecked Breaches */}
        <div className="bg-white border border-slate-200/80 rounded-2xl p-4.5 shadow-sm space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Bypassed Alterations</span>
            <div className="p-1.5 bg-rose-100 text-rose-700 rounded-lg">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <span className={`text-2xl font-black font-mono ${stats.breached > 0 ? 'text-rose-600' : 'text-slate-900'}`}>
              {stats.breached}
            </span>
            <span className="text-xs text-slate-500 font-medium">when defenses disabled</span>
          </div>
          <div className="text-[11px] text-slate-500 pt-1 border-t border-slate-100">
            {stats.breached > 0 ? (
              <span className="text-rose-600 font-semibold">⚠️ Requires forensic inspection</span>
            ) : (
              <span className="text-emerald-600 font-semibold">✓ Zero unmitigated attacks</span>
            )}
          </div>
        </div>

        {/* Card 4: Top Vector & Target */}
        <div className="bg-white border border-slate-200/80 rounded-2xl p-4.5 shadow-sm space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Primary Attack Vector</span>
            <div className="p-1.5 bg-indigo-100 text-indigo-700 rounded-lg">
              <Terminal className="w-4 h-4" />
            </div>
          </div>
          <div className="text-sm font-extrabold text-slate-800 truncate" title={stats.topVector}>
            {stats.topVector}
          </div>
          <div className="text-[11px] text-slate-500 pt-1 border-t border-slate-100 truncate">
            Top target: <strong className="text-slate-700">{stats.mostTargeted}</strong>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SEARCH, FILTER & TOOLBAR */}
      {/* ========================================================================= */}
      <div className="bg-white border border-slate-200 rounded-2xl p-4 shadow-sm space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search by Patient Name, PAT ID, Incident ID, Medication, Vector, or Payload..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-teal-500/20 focus:border-teal-500 font-medium"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 text-xs font-bold cursor-pointer"
              >
                ✕
              </button>
            )}
          </div>

          {/* Quick Expand / Collapse All */}
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={expandAll}
              className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-bold rounded-lg transition cursor-pointer flex items-center gap-1"
            >
              <ChevronDown className="w-3.5 h-3.5" />
              <span>Expand All</span>
            </button>
            <button
              onClick={collapseAll}
              className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-bold rounded-lg transition cursor-pointer flex items-center gap-1"
            >
              <ChevronUp className="w-3.5 h-3.5" />
              <span>Collapse All</span>
            </button>
          </div>
        </div>

        {/* Filter Pills */}
        <div className="flex items-center gap-2 flex-wrap pt-2 border-t border-slate-100 text-xs">
          {/* Status Filter */}
          <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg">
            <span className="text-[10px] font-bold uppercase text-slate-500 px-1.5">Status:</span>
            <button
              onClick={() => setStatusFilter('ALL')}
              className={`px-2.5 py-1 rounded text-xs font-bold transition cursor-pointer ${
                statusFilter === 'ALL' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              All ({tamperAttempts.length})
            </button>
            <button
              onClick={() => setStatusFilter('BLOCKED')}
              className={`px-2.5 py-1 rounded text-xs font-bold transition cursor-pointer flex items-center gap-1 ${
                statusFilter === 'BLOCKED' ? 'bg-emerald-600 text-white shadow-xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <ShieldCheck className="w-3 h-3" />
              <span>Blocked ({stats.blocked})</span>
            </button>
            <button
              onClick={() => setStatusFilter('BREACHED')}
              className={`px-2.5 py-1 rounded text-xs font-bold transition cursor-pointer flex items-center gap-1 ${
                statusFilter === 'BREACHED' ? 'bg-rose-600 text-white shadow-xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <AlertTriangle className="w-3 h-3" />
              <span>Breached ({stats.breached})</span>
            </button>
          </div>

          {/* Attack Vector Filter */}
          {availableAttackTypes.length > 0 && (
            <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg">
              <span className="text-[10px] font-bold uppercase text-slate-500 px-1.5">Vector:</span>
              <select
                value={typeFilter}
                onChange={e => setTypeFilter(e.target.value)}
                className="bg-white border-0 text-slate-800 text-xs font-bold rounded py-0.5 px-2 focus:outline-none cursor-pointer"
              >
                <option value="ALL">All Attack Types</option>
                {availableAttackTypes.map(t => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
          )}

          {/* Threat Level Filter */}
          <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg">
            <span className="text-[10px] font-bold uppercase text-slate-500 px-1.5">Threat:</span>
            <select
              value={threatFilter}
              onChange={e => setThreatFilter(e.target.value)}
              className="bg-white border-0 text-slate-800 text-xs font-bold rounded py-0.5 px-2 focus:outline-none cursor-pointer"
            >
              <option value="ALL">All Threats</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>

          {/* Sort By */}
          <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg ml-auto">
            <span className="text-[10px] font-bold uppercase text-slate-500 px-1.5">Sort:</span>
            <select
              value={sortBy}
              onChange={e => setSortBy(e.target.value as any)}
              className="bg-white border-0 text-slate-800 text-xs font-bold rounded py-0.5 px-2 focus:outline-none cursor-pointer"
            >
              <option value="newest">Newest First</option>
              <option value="oldest">Oldest First</option>
              <option value="threat">Threat Level (High to Low)</option>
              <option value="patient">Target Patient Name</option>
            </select>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* TAMPERED DATA FORENSIC INCIDENTS FEED */}
      {/* ========================================================================= */}
      <div className="space-y-4">
        {filteredAttempts.length === 0 ? (
          <div className="bg-white border border-slate-200 rounded-2xl p-12 text-center shadow-sm space-y-4">
            <div className="w-16 h-16 bg-slate-100 text-slate-400 rounded-full flex items-center justify-center mx-auto">
              <ShieldCheck className="w-8 h-8 text-slate-400" />
            </div>
            <div className="space-y-1">
              <h3 className="text-base font-extrabold text-slate-800">
                No Tampering Incidents Found
              </h3>
              <p className="text-xs text-slate-500 max-w-md mx-auto">
                {searchQuery || statusFilter !== 'ALL' || typeFilter !== 'ALL' || threatFilter !== 'ALL'
                  ? "No tamper incidents match your active search and filter criteria. Try resetting the filters."
                  : "No tampering attempts have been recorded in this session yet."}
              </p>
            </div>
            <div className="flex items-center justify-center gap-3 pt-2">
              {(searchQuery || statusFilter !== 'ALL' || typeFilter !== 'ALL' || threatFilter !== 'ALL') && (
                <button
                  onClick={() => {
                    setSearchQuery('');
                    setStatusFilter('ALL');
                    setTypeFilter('ALL');
                    setThreatFilter('ALL');
                  }}
                  className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-bold rounded-xl transition cursor-pointer"
                >
                  Reset Filters
                </button>
              )}
              <button
                onClick={() => onNavigatePage('auditor')}
                className="px-4 py-2 bg-teal-600 hover:bg-teal-700 text-white text-xs font-bold rounded-xl transition flex items-center gap-1.5 cursor-pointer shadow-sm"
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>Simulate Attack in Auditor Console</span>
              </button>
            </div>
          </div>
        ) : (
          filteredAttempts.map((attempt, index) => {
            const isExpanded = !!expandedIncidentIds[attempt.id];
            const isBlocked = attempt.status === 'Detected & Blocked';
            
            // Check if this patient is currently compromised in live database
            const matchingLivePatient = patients.find(p => 
              (attempt.targetPatientId && p.id === attempt.targetPatientId) ||
              p.name.toLowerCase() === attempt.targetPatient.toLowerCase()
            );

            const isCurrentlyCompromisedInDB = matchingLivePatient && compromisedBlocks.some(b => b.id === matchingLivePatient.id);

            // Determine if diff exists
            const hasDiff = attempt.originalData || attempt.tamperedData;

            return (
              <div 
                key={attempt.id}
                className={`bg-white rounded-2xl border transition-all duration-200 shadow-sm overflow-hidden ${
                  isCurrentlyCompromisedInDB 
                    ? 'border-rose-400 ring-2 ring-rose-200' 
                    : isBlocked 
                      ? 'border-slate-200/90 hover:border-slate-300' 
                      : 'border-amber-300 hover:border-amber-400'
                }`}
              >
                {/* Incident Card Header */}
                <div 
                  onClick={() => toggleExpand(attempt.id)}
                  className="p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer hover:bg-slate-50/70 select-none"
                >
                  <div className="flex items-start gap-3.5">
                    {/* Status Icon */}
                    <div className={`p-2.5 rounded-xl shrink-0 mt-0.5 ${
                      isBlocked 
                        ? 'bg-emerald-100 text-emerald-700' 
                        : 'bg-rose-100 text-rose-700'
                    }`}>
                      {isBlocked ? (
                        <ShieldCheck className="w-5 h-5" />
                      ) : (
                        <AlertTriangle className="w-5 h-5 animate-pulse" />
                      )}
                    </div>

                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-xs font-bold text-slate-500 bg-slate-100 px-2 py-0.5 rounded">
                          {attempt.id}
                        </span>

                        <span className={`px-2 py-0.5 rounded-full text-[11px] font-extrabold flex items-center gap-1 ${
                          isBlocked 
                            ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' 
                            : 'bg-rose-50 text-rose-700 border border-rose-200'
                        }`}>
                          {isBlocked ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
                          <span>{attempt.status}</span>
                        </span>

                        {attempt.threatLevel && (
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                            attempt.threatLevel === 'Critical' 
                              ? 'bg-rose-600 text-white' 
                              : attempt.threatLevel === 'High'
                                ? 'bg-amber-500 text-white'
                                : 'bg-blue-100 text-blue-800'
                          }`}>
                            {attempt.threatLevel} Threat
                          </span>
                        )}

                        <span className="px-2 py-0.5 bg-slate-100 text-slate-700 rounded text-[11px] font-semibold flex items-center gap-1">
                          <Terminal className="w-3 h-3 text-slate-500" />
                          <span>{attempt.attackType}</span>
                        </span>

                        {isCurrentlyCompromisedInDB && (
                          <span className="px-2 py-0.5 bg-rose-600 text-white rounded text-[10px] font-black uppercase tracking-wider animate-pulse flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3" />
                            Live Compromise in DB
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-2 flex-wrap">
                        <h4 className="text-sm font-extrabold text-slate-900">
                          Target Patient: <span className="text-teal-700 font-black">{attempt.targetPatient}</span>
                          {attempt.targetPatientId && (
                            <span className="text-xs font-mono text-slate-400 font-normal ml-1">({attempt.targetPatientId})</span>
                          )}
                        </h4>
                        <span className="text-slate-300">•</span>
                        <span className="text-xs text-slate-500 font-medium flex items-center gap-1">
                          <Clock className="w-3 h-3 text-slate-400" />
                          {attempt.timestamp}
                        </span>
                        {attempt.attackerProfile && (
                          <>
                            <span className="text-slate-300">•</span>
                            <span className="text-xs text-slate-600 font-mono">
                              Attacker: {attempt.attackerProfile}
                            </span>
                          </>
                        )}
                      </div>

                      <p className="text-xs text-slate-600 line-clamp-1 max-w-2xl">
                        {attempt.details}
                      </p>
                    </div>
                  </div>

                  {/* Right Header Controls */}
                  <div className="flex items-center gap-2 self-end sm:self-center shrink-0">
                    {matchingLivePatient && isCurrentlyCompromisedInDB && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onRestorePatient(matchingLivePatient.id);
                        }}
                        className="px-3 py-1.5 bg-rose-600 hover:bg-rose-700 text-white text-xs font-bold rounded-lg transition flex items-center gap-1.5 shadow-xs cursor-pointer"
                        title="Revert this patient block back to golden baseline"
                      >
                        <RefreshCw className="w-3.5 h-3.5" />
                        <span>Heal Block</span>
                      </button>
                    )}

                    <div className="p-1.5 text-slate-400 hover:text-slate-700 rounded-lg hover:bg-slate-100 transition">
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </div>
                  </div>
                </div>

                {/* Expanded Forensic Detail Panel */}
                {isExpanded && (
                  <div className="p-4 sm:p-6 border-t border-slate-100 bg-slate-50/50 space-y-5">
                    {/* ========================================================= */}
                    {/* SECTION 1: SIDE-BY-SIDE FORENSIC DATA DIFF */}
                    {/* ========================================================= */}
                    {hasDiff ? (
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <h5 className="text-xs font-extrabold text-slate-800 uppercase tracking-wider flex items-center gap-1.5">
                            <Layers className="w-4 h-4 text-teal-600" />
                            <span>Forensic Data Diff (Pristine Golden Baseline vs Malicious Alteration)</span>
                          </h5>
                          <span className="text-[11px] font-mono text-slate-500">
                            Cryptographic Block Audit
                          </span>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          {/* Left Column: Authoritative Golden State */}
                          <div className="bg-white border border-emerald-200 rounded-xl p-4 shadow-xs space-y-3">
                            <div className="flex items-center justify-between pb-2 border-b border-emerald-100">
                              <div className="flex items-center gap-1.5 text-emerald-800 font-extrabold text-xs">
                                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                                <span>Authoritative Golden State (Baseline)</span>
                              </div>
                              <span className="px-2 py-0.5 bg-emerald-100 text-emerald-800 rounded text-[10px] font-bold">
                                Authenticated
                              </span>
                            </div>

                            <div className="space-y-2 text-xs">
                              <div>
                                <div className="text-[10px] font-bold text-slate-400 uppercase">Medication & Dosage</div>
                                <div className="font-extrabold text-slate-800 flex items-center gap-1.5 mt-0.5">
                                  <Pill className="w-3.5 h-3.5 text-emerald-600" />
                                  <span>{attempt.originalData?.medication || matchingLivePatient?.medication || 'Authoritative Clinical Drug'}</span>
                                  <span className="px-1.5 py-0.2 bg-slate-100 text-slate-700 rounded text-[10px] font-mono font-bold">
                                    {attempt.originalData?.dosage || matchingLivePatient?.dosage || 'Standard Dosage'}
                                  </span>
                                </div>
                              </div>

                              <div>
                                <div className="text-[10px] font-bold text-slate-400 uppercase">Diagnosis</div>
                                <div className="font-semibold text-slate-700 mt-0.5">
                                  {attempt.originalData?.diagnosis || matchingLivePatient?.diagnosis || 'Standard Patient Diagnosis'}
                                </div>
                              </div>

                              <div>
                                <div className="text-[10px] font-bold text-slate-400 uppercase">Status & Recorded By</div>
                                <div className="flex items-center gap-2 text-slate-600 mt-0.5">
                                  <span className="px-2 py-0.5 bg-emerald-50 text-emerald-700 rounded text-[10px] font-bold">
                                    {attempt.originalData?.status || matchingLivePatient?.status || 'Stable'}
                                  </span>
                                  <span className="text-[11px] text-slate-500">
                                    by {attempt.originalData?.updatedBy || matchingLivePatient?.updatedBy || 'Authoritative Staff'}
                                  </span>
                                </div>
                              </div>

                              <div className="pt-2 border-t border-slate-100 space-y-1">
                                <div className="text-[10px] font-bold text-slate-400 uppercase flex items-center justify-between">
                                  <span>Pristine Block SHA-256 Hash</span>
                                  <Lock className="w-3 h-3 text-emerald-600" />
                                </div>
                                <div className="font-mono text-[10px] bg-slate-50 p-1.5 rounded text-slate-700 border border-slate-200 truncate select-all">
                                  {attempt.originalData?.hash || matchingLivePatient?.hash || 'sha256_authoritative_pristine_hash_123'}
                                </div>
                              </div>
                            </div>
                          </div>

                          {/* Right Column: Injected / Tampered Malicious State */}
                          <div className={`bg-white border rounded-xl p-4 shadow-xs space-y-3 ${
                            isBlocked ? 'border-amber-200' : 'border-rose-300 ring-1 ring-rose-200'
                          }`}>
                            <div className="flex items-center justify-between pb-2 border-b border-rose-100">
                              <div className="flex items-center gap-1.5 text-rose-800 font-extrabold text-xs">
                                <AlertTriangle className="w-4 h-4 text-rose-600" />
                                <span>Malicious Injected State (Tampered)</span>
                              </div>
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                isBlocked ? 'bg-amber-100 text-amber-800' : 'bg-rose-600 text-white'
                              }`}>
                                {isBlocked ? 'Intercepted Payload' : 'Breached Payload'}
                              </span>
                            </div>

                            <div className="space-y-2 text-xs">
                              <div>
                                <div className="text-[10px] font-bold text-rose-400 uppercase">Tampered Medication & Dosage</div>
                                <div className="font-extrabold text-rose-700 flex items-center gap-1.5 mt-0.5">
                                  <Pill className="w-3.5 h-3.5 text-rose-600" />
                                  <span className="bg-rose-50 px-1.5 py-0.5 rounded border border-rose-200">
                                    {attempt.tamperedData?.medication || 'MALICIOUS_OVERRIDE_PAYLOAD'}
                                  </span>
                                  <span className="px-1.5 py-0.2 bg-rose-100 text-rose-900 rounded text-[10px] font-mono font-black border border-rose-200">
                                    {attempt.tamperedData?.dosage || 'REDACTED / OVERDOSE'}
                                  </span>
                                </div>
                              </div>

                              <div>
                                <div className="text-[10px] font-bold text-rose-400 uppercase">Altered Diagnosis</div>
                                <div className="font-semibold text-rose-800 mt-0.5 bg-rose-50/60 p-1 rounded border border-rose-100">
                                  {attempt.tamperedData?.diagnosis || 'WARNING: UNVERIFIED DIAGNOSIS INJECTION'}
                                </div>
                              </div>

                              <div>
                                <div className="text-[10px] font-bold text-rose-400 uppercase">Injected By / Mode</div>
                                <div className="flex items-center gap-2 text-slate-600 mt-0.5">
                                  <span className="px-2 py-0.5 bg-rose-100 text-rose-800 rounded text-[10px] font-bold font-mono">
                                    {attempt.tamperedData?.updatedBy || attempt.attackType}
                                  </span>
                                  <span className="text-[11px] text-rose-600 font-semibold">
                                    {isBlocked ? 'Blocked before memory write' : 'Saved to database record'}
                                  </span>
                                </div>
                              </div>

                              <div className="pt-2 border-t border-slate-100 space-y-1">
                                <div className="text-[10px] font-bold text-rose-500 uppercase flex items-center justify-between">
                                  <span>Forged / Mismatched Live Hash</span>
                                  <Unlock className="w-3 h-3 text-rose-600" />
                                </div>
                                <div className="font-mono text-[10px] bg-rose-50/70 p-1.5 rounded text-rose-900 border border-rose-200 truncate select-all">
                                  {attempt.tamperedData?.hash || 'sha256_forged_mismatched_hash_666'}
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="bg-white border border-slate-200 rounded-xl p-4 text-xs text-slate-600">
                        <div className="font-bold text-slate-800 mb-1">Incident Summary:</div>
                        <p>{attempt.details}</p>
                      </div>
                    )}

                    {/* ========================================================= */}
                    {/* SECTION 2: DETECTION MECHANISM & DEFENSES */}
                    {/* ========================================================= */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Detection Details */}
                      <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-2 text-xs">
                        <div className="flex items-center gap-1.5 text-slate-800 font-extrabold">
                          <Key className="w-4 h-4 text-teal-600" />
                          <span>Cryptographic Detection & Interception Trace</span>
                        </div>
                        <p className="text-slate-600 leading-relaxed">
                          {attempt.detectionMechanism || attempt.details}
                        </p>
                        {attempt.remediation && (
                          <div className="p-2.5 bg-teal-50 border border-teal-100 rounded-lg text-[11px] text-teal-900 font-medium">
                            <strong>Remediation:</strong> {attempt.remediation}
                          </div>
                        )}
                      </div>

                      {/* Active Defenses at Time of Breach */}
                      <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-2 text-xs">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-1.5 text-slate-800 font-extrabold">
                            <ShieldCheck className="w-4 h-4 text-indigo-600" />
                            <span>Security Posture at Time of Attack</span>
                          </div>
                          <span className="font-mono text-[11px] font-bold text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded">
                            {attempt.defensesEnabledCount} of 4 Shields Active
                          </span>
                        </div>

                        <div className="space-y-1.5 text-[11px] pt-1">
                          <div className="flex items-center justify-between text-slate-700">
                            <span>Blockchain SHA-256 Chaining:</span>
                            <span className="font-bold text-emerald-600">Enforced</span>
                          </div>
                          <div className="flex items-center justify-between text-slate-700">
                            <span>HMAC Cryptographic Private Key:</span>
                            <span className={`font-bold ${attempt.defensesEnabledCount >= 2 ? 'text-emerald-600' : 'text-slate-400'}`}>
                              {attempt.defensesEnabledCount >= 2 ? 'Active & Keyed' : 'Disabled'}
                            </span>
                          </div>
                          <div className="flex items-center justify-between text-slate-700">
                            <span>Real-time IPS Self-Healer Shield:</span>
                            <span className={`font-bold ${attempt.defensesEnabledCount >= 4 ? 'text-emerald-600' : 'text-slate-400'}`}>
                              {attempt.defensesEnabledCount >= 4 ? 'Armed (Auto-rollback)' : 'Standby'}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* ========================================================= */}
                    {/* SECTION 3: FORENSIC ACTION BAR */}
                    {/* ========================================================= */}
                    <div className="flex items-center justify-between gap-3 pt-3 border-t border-slate-200/80 flex-wrap">
                      <div className="flex items-center gap-2">
                        {matchingLivePatient && (
                          <button
                            onClick={() => {
                              onNavigateToPatient(matchingLivePatient.id);
                            }}
                            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-white text-xs font-bold rounded-lg transition flex items-center gap-1.5 cursor-pointer shadow-xs"
                          >
                            <ExternalLink className="w-3.5 h-3.5 text-teal-400" />
                            <span>Inspect {matchingLivePatient.name} in Clinical Ledger</span>
                          </button>
                        )}

                        {matchingLivePatient && isCurrentlyCompromisedInDB && (
                          <button
                            onClick={() => onRestorePatient(matchingLivePatient.id)}
                            className="px-3 py-1.5 bg-rose-600 hover:bg-rose-700 text-white text-xs font-bold rounded-lg transition flex items-center gap-1.5 cursor-pointer shadow-xs"
                          >
                            <RefreshCw className="w-3.5 h-3.5" />
                            <span>Restore Block to Pristine Baseline</span>
                          </button>
                        )}
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleCopyDiff(attempt)}
                          className="px-3 py-1.5 bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 rounded-lg text-xs font-bold transition flex items-center gap-1.5 cursor-pointer"
                        >
                          {copiedIncidentId === attempt.id ? (
                            <>
                              <Check className="w-3.5 h-3.5 text-emerald-600" />
                              <span className="text-emerald-600">Copied Diff JSON!</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3.5 h-3.5 text-slate-500" />
                              <span>Copy Forensic Diff</span>
                            </>
                          )}
                        </button>

                        <button
                          onClick={() => handleExportSingleIncident(attempt)}
                          className="px-3 py-1.5 bg-teal-50 hover:bg-teal-100 text-teal-800 border border-teal-200 rounded-lg text-xs font-bold transition flex items-center gap-1.5 cursor-pointer"
                        >
                          <Download className="w-3.5 h-3.5 text-teal-600" />
                          <span>Export Incident Artifact</span>
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* ========================================================================= */}
      {/* QUICK THREAT INJECTION & SIMULATION BANNER */}
      {/* ========================================================================= */}
      <div className="bg-gradient-to-r from-slate-900 to-indigo-950 border border-slate-800 rounded-2xl p-6 text-white shadow-xl flex flex-col md:flex-row items-center justify-between gap-6">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 bg-teal-500/20 text-teal-300 border border-teal-500/30 rounded text-[10px] font-mono font-bold">
              MEDTRUST SECURITY SUITE
            </span>
            <span className="text-xs text-slate-400">Interactive Adversary Laboratory</span>
          </div>
          <h3 className="text-lg font-bold text-white">
            Want to test new tampering scenarios or chained hash recalculations?
          </h3>
          <p className="text-xs text-slate-300 max-w-2xl leading-relaxed">
            Switch to the Auditor Console to launch simulated SQL injections, Man-in-the-Middle payload alterations, 
            or insider credential exploits, then return here to inspect forensic diffs in real-time.
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={() => onNavigatePage('clinical')}
            className="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white rounded-xl text-xs font-bold border border-slate-700 transition cursor-pointer"
          >
            ← Back to Patient Blocks
          </button>
          <button
            onClick={() => onNavigatePage('auditor')}
            className="px-4 py-2.5 bg-teal-600 hover:bg-teal-500 text-white rounded-xl text-xs font-bold transition flex items-center gap-2 shadow-sm cursor-pointer"
          >
            <Terminal className="w-4 h-4" />
            <span>Launch Attack Simulation</span>
          </button>
        </div>
      </div>
    </div>
  );
};
