import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Shield, 
  ShieldCheck, 
  ShieldAlert, 
  Lock, 
  LockOpen, 
  AlertTriangle, 
  CheckCircle, 
  Activity, 
  Terminal, 
  RefreshCw, 
  Sliders, 
  Eye, 
  ArrowRight, 
  Cpu, 
  Key, 
  FileCode, 
  Zap, 
  HeartPulse, 
  RotateCcw,
  Check,
  Search,
  Database
} from 'lucide-react';
import { PatientRecord, SecurityStrategy, AuditLogEntry } from '../types';
import { calculateRecordHash, generateHMACSignature } from '../data';

interface SecurityAgentHubProps {
  patients: PatientRecord[];
  authorizedPatients: PatientRecord[];
  strategies: SecurityStrategy[];
  toggleStrategy: (id: string) => void;
  secretKey: string;
  logs: AuditLogEntry[];
  onTriggerSelfHealing: () => void;
  onRunIntegrityScan: () => void;
  isScanning: boolean;
}

export function SecurityAgentHub({
  patients,
  authorizedPatients,
  strategies,
  toggleStrategy,
  secretKey,
  logs,
  onTriggerSelfHealing,
  onRunIntegrityScan,
  isScanning
}: SecurityAgentHubProps) {
  const [activeTab, setActiveTab] = useState<'detection' | 'policies' | 'diagnostic' | 'playbooks'>('detection');
  const [selectedInspectPatientId, setSelectedInspectPatientId] = useState<string>(patients[0]?.id || 'PAT-001');
  const [activePlaybook, setActivePlaybook] = useState<string>('direct_db_tamper');
  const [playbookStep, setPlaybookStep] = useState<number>(0);
  const [isRunningPlaybook, setIsRunningPlaybook] = useState<boolean>(false);

  // Active Defense Status
  const activeDefensesCount = strategies.filter(s => s.enabled).length;
  const ipsEnabled = strategies.find(s => s.id === 'active_lock')?.enabled;
  const chainEnabled = strategies.find(s => s.id === 'crypt_chain')?.enabled;
  const hmacEnabled = strategies.find(s => s.id === 'hmac_sig')?.enabled;
  const wormEnabled = strategies.find(s => s.id === 'immutable_logs')?.enabled;

  // Selected Patient for Live Diagnostic
  const selectedPatient = patients.find(p => p.id === selectedInspectPatientId) || patients[0];
  const selectedIndex = patients.findIndex(p => p.id === selectedInspectPatientId);
  const previousPatient = selectedIndex > 0 ? patients[selectedIndex - 1] : null;

  // Real-time recomputation for selected patient
  const computedHash = selectedPatient ? calculateRecordHash(selectedPatient) : '';
  const isHashValid = selectedPatient ? computedHash === selectedPatient.hash : false;
  
  const isChainValid = selectedIndex === 0 
    ? selectedPatient?.prevHash === "00000000000000000000000000000000"
    : previousPatient ? selectedPatient?.prevHash === previousPatient.hash : false;

  const expectedSignature = selectedPatient ? generateHMACSignature(computedHash, secretKey) : '';
  const isSignatureValid = selectedPatient ? selectedPatient.signature === expectedSignature : false;
  const isOverallSecure = isHashValid && isChainValid && isSignatureValid;

  // Playbook execution simulation
  const handleRunPlaybook = (playbookId: string) => {
    setActivePlaybook(playbookId);
    setPlaybookStep(1);
    setIsRunningPlaybook(true);

    const interval = setInterval(() => {
      setPlaybookStep(prev => {
        if (prev >= 4) {
          clearInterval(interval);
          setIsRunningPlaybook(false);
          return 4;
        }
        return prev + 1;
      });
    }, 1200);
  };

  return (
    <div className="space-y-6">
      {/* 1. Security Agent Command Center HUD */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-850 to-teal-950 text-white rounded-2xl p-6 shadow-xl border border-slate-800 relative overflow-hidden">
        {/* Background Grid Accent */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b15_1px,transparent_1px),linear-gradient(to_bottom,#1e293b15_1px,transparent_1px)] bg-[size:24px_24px] pointer-events-none opacity-40"></div>
        
        <div className="relative z-10 flex flex-col lg:flex-row justify-between items-start lg:items-center gap-6">
          <div className="space-y-2">
            <div className="flex items-center gap-2.5">
              <div className="w-10 h-10 rounded-xl bg-teal-500/20 border border-teal-400/40 text-teal-400 flex items-center justify-center shadow-inner">
                <Cpu className="w-5 h-5 animate-pulse text-teal-300" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="bg-teal-500/20 border border-teal-400/30 text-teal-300 text-[10px] font-mono font-bold px-2 py-0.5 rounded-full uppercase tracking-wider">
                    Autonomous Agent Active
                  </span>
                  <span className="flex h-2 w-2 relative">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                  </span>
                </div>
                <h2 className="text-xl font-black tracking-tight text-white mt-1">
                  MedTrust Autonomous Security Agent
                </h2>
              </div>
            </div>
            <p className="text-slate-300 text-xs max-w-2xl leading-relaxed font-normal">
              Continuous monitoring engine enforcing multi-tier cryptographic integrity, real-time threat detection algorithms, and autonomous self-healing mitigation policies across all clinical ledger blocks.
            </p>
          </div>

          {/* Quick HUD Metrics */}
          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <div className="bg-slate-800/80 border border-slate-700/60 rounded-xl p-3 text-center min-w-[110px]">
              <span className="text-[10px] font-mono text-slate-400 uppercase block">Active Policies</span>
              <span className="text-lg font-black text-teal-400">{activeDefensesCount} / {strategies.length}</span>
            </div>
            <div className="bg-slate-800/80 border border-slate-700/60 rounded-xl p-3 text-center min-w-[110px]">
              <span className="text-[10px] font-mono text-slate-400 uppercase block">Self-Healing</span>
              <span className={`text-xs font-bold font-mono px-2 py-0.5 rounded inline-block mt-1 ${ipsEnabled ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'}`}>
                {ipsEnabled ? 'ACTIVE (IPS)' : 'OFFLINE'}
              </span>
            </div>
            <div className="bg-slate-800/80 border border-slate-700/60 rounded-xl p-3 text-center min-w-[110px]">
              <span className="text-[10px] font-mono text-slate-400 uppercase block">Monitored Blocks</span>
              <span className="text-lg font-black text-white">{patients.length}</span>
            </div>
          </div>
        </div>

        {/* Quick Action Navigation Buttons */}
        <div className="mt-6 pt-4 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveTab('detection')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'detection'
                  ? 'bg-teal-500 text-slate-950 font-extrabold shadow-sm'
                  : 'bg-slate-800/80 text-slate-300 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Eye className="w-3.5 h-3.5" />
              <span>How Threats Are Detected</span>
            </button>
            <button
              onClick={() => setActiveTab('policies')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'policies'
                  ? 'bg-teal-500 text-slate-950 font-extrabold shadow-sm'
                  : 'bg-slate-800/80 text-slate-300 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Sliders className="w-3.5 h-3.5" />
              <span>Mitigation Policies</span>
            </button>
            <button
              onClick={() => setActiveTab('diagnostic')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'diagnostic'
                  ? 'bg-teal-500 text-slate-950 font-extrabold shadow-sm'
                  : 'bg-slate-800/80 text-slate-300 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Live Diagnostic Inspector</span>
            </button>
            <button
              onClick={() => setActiveTab('playbooks')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'playbooks'
                  ? 'bg-teal-500 text-slate-950 font-extrabold shadow-sm'
                  : 'bg-slate-800/80 text-slate-300 hover:text-white hover:bg-slate-800'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>Incident Playbooks</span>
            </button>
          </div>
        </div>
      </div>

      {/* 2. TAB 1: HOW THREATS ARE DETECTED (Deep Step-by-Step Cryptographic Detection Pipeline) */}
      {activeTab === 'detection' && (
        <div className="space-y-6">
          <div className="bg-white rounded-2xl border border-slate-200/80 p-6 shadow-sm">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 pb-4 border-b border-slate-100">
              <div>
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-teal-600" />
                  <h3 className="text-base font-extrabold text-slate-900 uppercase tracking-wider">
                    How Threats Are Detected: The 5-Stage Verification Pipeline
                  </h3>
                </div>
                <p className="text-xs text-slate-500 font-medium mt-1">
                  Step-by-step algorithmic breakdown showing how the Security Agent intercepts, recalculates, and mathematically validates every record.
                </p>
              </div>
              <button
                onClick={onRunIntegrityScan}
                disabled={isScanning}
                className="px-4 py-2 bg-teal-600 hover:bg-teal-500 text-white text-xs font-bold rounded-lg transition shadow-sm flex items-center gap-2 cursor-pointer disabled:opacity-50"
              >
                <Activity className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
                <span>{isScanning ? 'Running Live Verification Scan...' : 'Trigger Live Database Scan'}</span>
              </button>
            </div>

            {/* 5-Stage Visual Workflow Cards */}
            <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mt-6">
              {/* Stage 1 */}
              <div className="bg-slate-50 border border-slate-200/80 rounded-xl p-4 flex flex-col justify-between relative">
                <div className="absolute -top-3 left-4 bg-teal-600 text-white text-[10px] font-black px-2 py-0.5 rounded-full font-mono">
                  STAGE 01
                </div>
                <div className="pt-2">
                  <h4 className="text-xs font-extrabold text-slate-900 flex items-center gap-1.5">
                    <Database className="w-3.5 h-3.5 text-teal-600" />
                    Payload Canonicalization
                  </h4>
                  <p className="text-[11px] text-slate-600 mt-2 leading-relaxed font-normal">
                    Extracts raw clinical parameters <code className="font-mono text-[10px] bg-slate-200 px-1 py-0.5 rounded text-slate-800 font-bold">&#123;id, diagnosis, medication, dosage, status&#125;</code> and normalizes them into a deterministic byte string.
                  </p>
                </div>
                <div className="mt-4 pt-2 border-t border-slate-200/60 text-[10px] font-mono text-slate-500">
                  <strong>Output:</strong> Normalized Payload Buffer
                </div>
              </div>

              {/* Stage 2 */}
              <div className="bg-slate-50 border border-slate-200/80 rounded-xl p-4 flex flex-col justify-between relative">
                <div className="absolute -top-3 left-4 bg-teal-600 text-white text-[10px] font-black px-2 py-0.5 rounded-full font-mono">
                  STAGE 02
                </div>
                <div className="pt-2">
                  <h4 className="text-xs font-extrabold text-slate-900 flex items-center gap-1.5">
                    <Cpu className="w-3.5 h-3.5 text-teal-600" />
                    In-Memory Hash Computation
                  </h4>
                  <p className="text-[11px] text-slate-600 mt-2 leading-relaxed font-normal">
                    Recomputes live 256-bit cryptographic digest:
                    <br />
                    <code className="font-mono text-[9px] bg-slate-200/90 text-teal-800 px-1 py-0.5 rounded font-bold block mt-1.5">
                      H_live = SHA256(Data || PrevHash)
                    </code>
                    Independent of stored values.
                  </p>
                </div>
                <div className="mt-4 pt-2 border-t border-slate-200/60 text-[10px] font-mono text-slate-500">
                  <strong>Check:</strong> Cryptographic Entropy
                </div>
              </div>

              {/* Stage 3 */}
              <div className="bg-slate-50 border border-slate-200/80 rounded-xl p-4 flex flex-col justify-between relative">
                <div className="absolute -top-3 left-4 bg-teal-600 text-white text-[10px] font-black px-2 py-0.5 rounded-full font-mono">
                  STAGE 03
                </div>
                <div className="pt-2">
                  <h4 className="text-xs font-extrabold text-slate-900 flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-rose-500" />
                    Local Invariant Check
                  </h4>
                  <p className="text-[11px] text-slate-600 mt-2 leading-relaxed font-normal">
                    Compares computed hash against stored hash:
                    <br />
                    <code className="font-mono text-[9px] bg-slate-200/90 text-slate-800 px-1 py-0.5 rounded font-bold block mt-1.5">
                      H_live === Block.hash
                    </code>
                    If false &rarr; <span className="text-rose-600 font-bold">Direct SQL Alteration Detected!</span>
                  </p>
                </div>
                <div className="mt-4 pt-2 border-t border-slate-200/60 text-[10px] font-mono text-slate-500">
                  <strong>Catches:</strong> Direct Database Overrides
                </div>
              </div>

              {/* Stage 4 */}
              <div className="bg-slate-50 border border-slate-200/80 rounded-xl p-4 flex flex-col justify-between relative">
                <div className="absolute -top-3 left-4 bg-teal-600 text-white text-[10px] font-black px-2 py-0.5 rounded-full font-mono">
                  STAGE 04
                </div>
                <div className="pt-2">
                  <h4 className="text-xs font-extrabold text-slate-900 flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-teal-600" />
                    Forward Link Continuity
                  </h4>
                  <p className="text-[11px] text-slate-600 mt-2 leading-relaxed font-normal">
                    Verifies cryptographic chain continuity:
                    <br />
                    <code className="font-mono text-[9px] bg-slate-200/90 text-slate-800 px-1 py-0.5 rounded font-bold block mt-1.5">
                      Block_N.prevHash === Block_&#123;N-1&#125;.hash
                    </code>
                    If false &rarr; <span className="text-rose-600 font-bold">Broken Chain Linkage!</span>
                  </p>
                </div>
                <div className="mt-4 pt-2 border-t border-slate-200/60 text-[10px] font-mono text-slate-500">
                  <strong>Catches:</strong> Splice & Delete Attacks
                </div>
              </div>

              {/* Stage 5 */}
              <div className="bg-slate-50 border border-slate-200/80 rounded-xl p-4 flex flex-col justify-between relative">
                <div className="absolute -top-3 left-4 bg-teal-600 text-white text-[10px] font-black px-2 py-0.5 rounded-full font-mono">
                  STAGE 05
                </div>
                <div className="pt-2">
                  <h4 className="text-xs font-extrabold text-slate-900 flex items-center gap-1.5">
                    <Key className="w-3.5 h-3.5 text-amber-500" />
                    Digital Signature Proof
                  </h4>
                  <p className="text-[11px] text-slate-600 mt-2 leading-relaxed font-normal">
                    Verifies asymmetric digital signature:
                    <br />
                    <code className="font-mono text-[9px] bg-slate-200/90 text-slate-800 px-1 py-0.5 rounded font-bold block mt-1.5">
                      HMAC(H_live, K_secret) === Block.sig
                    </code>
                    If false &rarr; <span className="text-rose-600 font-bold">Key Forgery Detected!</span>
                  </p>
                </div>
                <div className="mt-4 pt-2 border-t border-slate-200/60 text-[10px] font-mono text-slate-500">
                  <strong>Catches:</strong> Chain-Shift Recalculation
                </div>
              </div>
            </div>
          </div>

          {/* Deep Algorithmic Matrix & How Security Agent Neutralizes Attacks */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-7 bg-white rounded-2xl border border-slate-200/80 p-6 shadow-sm space-y-4">
              <div className="flex items-center gap-2 pb-3 border-b border-slate-100">
                <Terminal className="w-4 h-4 text-teal-600" />
                <h4 className="text-xs font-extrabold text-slate-900 uppercase tracking-wider">
                  Detection vs. Attack Vector Matrix
                </h4>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 text-slate-400 font-mono text-[10px] uppercase">
                      <th className="py-2 px-2 font-bold">Threat Vector</th>
                      <th className="py-2 px-2 font-bold">Attacker Vector</th>
                      <th className="py-2 px-2 font-bold">Detection Checkpoint</th>
                      <th className="py-2 px-2 font-bold text-right">Detection Rate</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 text-[11px]">
                    <tr className="hover:bg-slate-50/60">
                      <td className="py-2.5 px-2 font-bold text-slate-800">Direct SQL Injection</td>
                      <td className="py-2.5 px-2 text-slate-500">Manual UPDATE query on clinical cells</td>
                      <td className="py-2.5 px-2 font-mono text-teal-700 font-bold">Stage 3: Hash Invariant Mismatch</td>
                      <td className="py-2.5 px-2 text-right"><span className="bg-emerald-100 text-emerald-800 text-[10px] font-mono font-bold px-1.5 py-0.5 rounded">100% Deterministic</span></td>
                    </tr>
                    <tr className="hover:bg-slate-50/60">
                      <td className="py-2.5 px-2 font-bold text-slate-800">Cascading Hash Recalc</td>
                      <td className="py-2.5 px-2 text-slate-500">Scripted loop re-computing prevHash values</td>
                      <td className="py-2.5 px-2 font-mono text-teal-700 font-bold">Stage 5: HMAC Signature Invalidation</td>
                      <td className="py-2.5 px-2 text-right"><span className="bg-emerald-100 text-emerald-800 text-[10px] font-mono font-bold px-1.5 py-0.5 rounded">100% (2^256 key space)</span></td>
                    </tr>
                    <tr className="hover:bg-slate-50/60">
                      <td className="py-2.5 px-2 font-bold text-slate-800">MitM Flight Mutation</td>
                      <td className="py-2.5 px-2 text-slate-500">Altering network packet payload in flight</td>
                      <td className="py-2.5 px-2 font-mono text-teal-700 font-bold">Stage 1 & 5: Ingestion Signature Check</td>
                      <td className="py-2.5 px-2 text-right"><span className="bg-emerald-100 text-emerald-800 text-[10px] font-mono font-bold px-1.5 py-0.5 rounded">Instant Rejection</span></td>
                    </tr>
                    <tr className="hover:bg-slate-50/60">
                      <td className="py-2.5 px-2 font-bold text-slate-800">Audit History Erasure</td>
                      <td className="py-2.5 px-2 text-slate-500">Purging SQL audit rows or dropping tables</td>
                      <td className="py-2.5 px-2 font-mono text-teal-700 font-bold">WORM Sequential Index Audit</td>
                      <td className="py-2.5 px-2 text-right"><span className="bg-emerald-100 text-emerald-800 text-[10px] font-mono font-bold px-1.5 py-0.5 rounded">Non-Repudiated</span></td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            {/* Right Column: Security Agent Automated Response Loop */}
            <div className="lg:col-span-5 bg-gradient-to-br from-slate-50 to-teal-50/40 rounded-2xl border border-teal-100 p-6 shadow-sm flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center gap-2 pb-2 border-b border-teal-100">
                  <Zap className="w-4 h-4 text-teal-600" />
                  <h4 className="text-xs font-extrabold text-slate-900 uppercase tracking-wider">
                    Autonomous Response Loop
                  </h4>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed font-normal">
                  When a threat is detected across any checkpoint, the Security Agent executes an immediate 3-step mitigation playbook:
                </p>
                <div className="space-y-2 text-xs">
                  <div className="p-2.5 bg-white rounded-lg border border-teal-100/80 shadow-xs flex items-start gap-2">
                    <span className="w-5 h-5 rounded-full bg-teal-100 text-teal-800 font-bold text-[10px] flex items-center justify-center shrink-0">1</span>
                    <div>
                      <strong className="text-slate-900">Quarantine & Alarm Dispatch:</strong>
                      <p className="text-[11px] text-slate-500 mt-0.5">Locks corrupted block node from clinical dispensing and fires audible siren overlay.</p>
                    </div>
                  </div>
                  <div className="p-2.5 bg-white rounded-lg border border-teal-100/80 shadow-xs flex items-start gap-2">
                    <span className="w-5 h-5 rounded-full bg-teal-100 text-teal-800 font-bold text-[10px] flex items-center justify-center shrink-0">2</span>
                    <div>
                      <strong className="text-slate-900">Autonomous Self-Healing (IPS):</strong>
                      <p className="text-[11px] text-slate-500 mt-0.5">Reverts memory cell to authoritative golden baseline and recalculates pristine hashes.</p>
                    </div>
                  </div>
                  <div className="p-2.5 bg-white rounded-lg border border-teal-100/80 shadow-xs flex items-start gap-2">
                    <span className="w-5 h-5 rounded-full bg-teal-100 text-teal-800 font-bold text-[10px] flex items-center justify-center shrink-0">3</span>
                    <div>
                      <strong className="text-slate-900">Forensic WORM Logging:</strong>
                      <p className="text-[11px] text-slate-500 mt-0.5">Records immutable audit log with cryptographic evidence for compliance verification.</p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-teal-100 flex items-center justify-between">
                <button
                  onClick={onTriggerSelfHealing}
                  className="w-full py-2 bg-teal-600 hover:bg-teal-700 text-white font-bold text-xs rounded-lg transition shadow-sm flex items-center justify-center gap-2 cursor-pointer"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Execute Database Self-Healing Baseline Reset</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 3. TAB 2: MITIGATION POLICIES (Configurable Defense Policies Engine) */}
      {activeTab === 'policies' && (
        <div className="space-y-6">
          <div className="bg-white rounded-2xl border border-slate-200/80 p-6 shadow-sm">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 pb-4 border-b border-slate-100">
              <div>
                <div className="flex items-center gap-2">
                  <Sliders className="w-5 h-5 text-teal-600" />
                  <h3 className="text-base font-extrabold text-slate-900 uppercase tracking-wider">
                    Security Agent Mitigation Policy Engine
                  </h3>
                </div>
                <p className="text-xs text-slate-500 font-medium mt-1">
                  Active policy directives enforced by the Security Agent to prevent unauthorized clinical mutations and data corruption.
                </p>
              </div>
              <span className="text-xs font-mono font-bold bg-slate-100 text-slate-700 px-3 py-1.5 rounded-lg border border-slate-200">
                Active Directives: {activeDefensesCount} of {strategies.length} Enabled
              </span>
            </div>

            {/* Policy Cards Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
              {/* Policy 1 */}
              <div className="bg-slate-50 border border-slate-200/90 rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-teal-100 text-teal-800">
                      POLICY-01
                    </span>
                    <h4 className="text-xs font-extrabold text-slate-900">
                      Real-time Autonomous Self-Healing (IPS)
                    </h4>
                  </div>
                  <button
                    onClick={() => toggleStrategy('active_lock')}
                    className={`w-10 h-5 rounded-full relative transition-colors duration-200 cursor-pointer ${
                      ipsEnabled ? 'bg-teal-600' : 'bg-slate-300'
                    }`}
                  >
                    <span className={`w-3.5 h-3.5 bg-white rounded-full absolute top-0.5 left-0.5 transition-transform duration-200 shadow-sm ${
                      ipsEnabled ? 'translate-x-5' : 'translate-x-0'
                    }`} />
                  </button>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed">
                  <strong>Enforcement:</strong> When an unauthorized direct cell override or SQL mutation is executed, the Security Agent intercepts the request, blocks commit, triggers an audible intrusion siren, and restores the record from the trusted baseline.
                </p>
                <div className="text-[10px] font-mono text-slate-500 bg-white p-2 rounded border border-slate-200/80">
                  <strong>Rule:</strong> <code className="text-teal-700 font-bold">ON cell_mutate() &rarr; IF NOT is_authorized() &rarr; ROLLBACK & ALERT</code>
                </div>
              </div>

              {/* Policy 2 */}
              <div className="bg-slate-50 border border-slate-200/90 rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-teal-100 text-teal-800">
                      POLICY-02
                    </span>
                    <h4 className="text-xs font-extrabold text-slate-900">
                      Cryptographic Forward Hash Chaining
                    </h4>
                  </div>
                  <button
                    onClick={() => toggleStrategy('crypt_chain')}
                    className={`w-10 h-5 rounded-full relative transition-colors duration-200 cursor-pointer ${
                      chainEnabled ? 'bg-teal-600' : 'bg-slate-300'
                    }`}
                  >
                    <span className={`w-3.5 h-3.5 bg-white rounded-full absolute top-0.5 left-0.5 transition-transform duration-200 shadow-sm ${
                      chainEnabled ? 'translate-x-5' : 'translate-x-0'
                    }`} />
                  </button>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed">
                  <strong>Enforcement:</strong> Enforces sequential linking where block $N$ incorporates the cryptographic hash of block $N-1$. Tampering with any historical block cascades an unrecoverable hash mismatch through all forward records.
                </p>
                <div className="text-[10px] font-mono text-slate-500 bg-white p-2 rounded border border-slate-200/80">
                  <strong>Rule:</strong> <code className="text-teal-700 font-bold">ASSERT Block[N].prevHash === Block[N-1].hash ELSE QUARANTINE</code>
                </div>
              </div>

              {/* Policy 3 */}
              <div className="bg-slate-50 border border-slate-200/90 rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-teal-100 text-teal-800">
                      POLICY-03
                    </span>
                    <h4 className="text-xs font-extrabold text-slate-900">
                      HMAC Private Key Signature Enforcement
                    </h4>
                  </div>
                  <button
                    onClick={() => toggleStrategy('hmac_sig')}
                    className={`w-10 h-5 rounded-full relative transition-colors duration-200 cursor-pointer ${
                      hmacEnabled ? 'bg-teal-600' : 'bg-slate-300'
                    }`}
                  >
                    <span className={`w-3.5 h-3.5 bg-white rounded-full absolute top-0.5 left-0.5 transition-transform duration-200 shadow-sm ${
                      hmacEnabled ? 'translate-x-5' : 'translate-x-0'
                    }`} />
                  </button>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed">
                  <strong>Enforcement:</strong> Signs every hash with an isolated secret key stored in the security enclave. Defeats advanced recalculation attacks because an attacker cannot forge signatures without the master cryptographic key.
                </p>
                <div className="text-[10px] font-mono text-slate-500 bg-white p-2 rounded border border-slate-200/80">
                  <strong>Rule:</strong> <code className="text-teal-700 font-bold">VERIFY HMAC_SHA256(Block.hash, HSM_SECRET_KEY) === Block.signature</code>
                </div>
              </div>

              {/* Policy 4 */}
              <div className="bg-slate-50 border border-slate-200/90 rounded-xl p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-teal-100 text-teal-800">
                      POLICY-04
                    </span>
                    <h4 className="text-xs font-extrabold text-slate-900">
                      WORM Immutable Audit Trail
                    </h4>
                  </div>
                  <button
                    onClick={() => toggleStrategy('immutable_logs')}
                    className={`w-10 h-5 rounded-full relative transition-colors duration-200 cursor-pointer ${
                      wormEnabled ? 'bg-teal-600' : 'bg-slate-300'
                    }`}
                  >
                    <span className={`w-3.5 h-3.5 bg-white rounded-full absolute top-0.5 left-0.5 transition-transform duration-200 shadow-sm ${
                      wormEnabled ? 'translate-x-5' : 'translate-x-0'
                    }`} />
                  </button>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed">
                  <strong>Enforcement:</strong> Enforces Write-Once-Read-Many storage on all clinical events. System actions cannot be edited, overwritten, or erased, guaranteeing 100% forensic non-repudiation during compliance audits.
                </p>
                <div className="text-[10px] font-mono text-slate-500 bg-white p-2 rounded border border-slate-200/80">
                  <strong>Rule:</strong> <code className="text-teal-700 font-bold">PERMIT INSERT ONLY &bull; DENY UPDATE, DELETE, TRUNCATE ON logs</code>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 4. TAB 3: LIVE DIAGNOSTIC INSPECTOR (Test any patient against the 5-point stack) */}
      {activeTab === 'diagnostic' && (
        <div className="space-y-6">
          <div className="bg-white rounded-2xl border border-slate-200/80 p-6 shadow-sm space-y-6">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 pb-4 border-b border-slate-100">
              <div>
                <div className="flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-teal-600" />
                  <h3 className="text-base font-extrabold text-slate-900 uppercase tracking-wider">
                    Live Security Agent Diagnostic Inspector
                  </h3>
                </div>
                <p className="text-xs text-slate-500 font-medium mt-1">
                  Select any patient block from the ledger to inspect its live mathematical proof, hash invariants, and cryptographic signature in real-time.
                </p>
              </div>

              {/* Patient Selector */}
              <div className="flex items-center gap-2 w-full md:w-auto">
                <span className="text-[10px] font-mono uppercase font-bold text-slate-500">Inspect Block:</span>
                <select
                  value={selectedInspectPatientId}
                  onChange={(e) => setSelectedInspectPatientId(e.target.value)}
                  className="bg-slate-50 border border-slate-200 rounded-lg px-3 py-1.5 text-xs font-bold text-slate-800 outline-none focus:ring-1 focus:ring-teal-500 cursor-pointer"
                >
                  {patients.map((p, idx) => (
                    <option key={p.id} value={p.id}>
                      Block #{idx + 1}: {p.name} ({p.status})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Diagnostic Results Card */}
            {selectedPatient && (
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                {/* Left: Patient Metadata */}
                <div className="lg:col-span-5 bg-slate-50 border border-slate-200/80 rounded-xl p-5 space-y-3">
                  <div className="flex justify-between items-center pb-2 border-b border-slate-200/60">
                    <span className="text-[10px] font-mono text-slate-400 uppercase font-bold">Node Identity</span>
                    <span className="text-xs font-bold font-mono text-teal-800 bg-teal-50 px-2 py-0.5 rounded border border-teal-200">
                      {selectedPatient.id}
                    </span>
                  </div>

                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-500">Patient Name:</span>
                      <strong className="text-slate-900">{selectedPatient.name}</strong>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Diagnosis:</span>
                      <strong className="text-slate-900 text-right">{selectedPatient.diagnosis}</strong>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Prescription:</span>
                      <strong className="text-slate-900 font-mono text-teal-800">{selectedPatient.medication} ({selectedPatient.dosage})</strong>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Clinical Status:</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        selectedPatient.status === 'Stable' ? 'bg-emerald-100 text-emerald-800' :
                        selectedPatient.status === 'Critical' ? 'bg-rose-100 text-rose-800' : 'bg-amber-100 text-amber-800'
                      }`}>{selectedPatient.status}</span>
                    </div>
                  </div>

                  <div className="pt-3 border-t border-slate-200/60 space-y-1.5 font-mono text-[10px]">
                    <div className="text-slate-400 font-bold uppercase">Stored Hashes in DB:</div>
                    <div className="truncate text-slate-600 bg-white p-1.5 rounded border border-slate-200">
                      <strong>hash:</strong> {selectedPatient.hash || 'NONE'}
                    </div>
                    <div className="truncate text-slate-600 bg-white p-1.5 rounded border border-slate-200">
                      <strong>prev:</strong> {selectedPatient.prevHash || '00000000000000000000000000000000'}
                    </div>
                    <div className="truncate text-slate-600 bg-white p-1.5 rounded border border-slate-200">
                      <strong>sig:</strong> {selectedPatient.signature || 'NONE'}
                    </div>
                  </div>
                </div>

                {/* Right: Real-time Cryptographic Assertion Results */}
                <div className="lg:col-span-7 bg-white border border-slate-200/80 rounded-xl p-5 space-y-4 shadow-sm flex flex-col justify-between">
                  <div className="space-y-3">
                    <div className="flex justify-between items-center pb-2 border-b border-slate-100">
                      <span className="text-[10px] font-mono text-slate-400 uppercase font-bold">5-Point Cryptographic Assertion Check</span>
                      <span className={`text-xs font-bold font-mono px-2.5 py-0.5 rounded-full ${
                        isOverallSecure ? 'bg-emerald-100 text-emerald-800 border border-emerald-300' : 'bg-rose-100 text-rose-800 border border-rose-300 animate-pulse'
                      }`}>
                        {isOverallSecure ? 'LEDGER VERIFIED SECURE' : 'COMPROMISED RECORD DETECTED'}
                      </span>
                    </div>

                    {/* Assertion 1: Local SHA-256 */}
                    <div className={`p-3 rounded-lg border flex items-start justify-between gap-3 text-xs ${
                      isHashValid ? 'bg-emerald-50/50 border-emerald-200 text-emerald-900' : 'bg-rose-50 border-rose-200 text-rose-900'
                    }`}>
                      <div className="flex items-start gap-2">
                        {isHashValid ? <CheckCircle className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" /> : <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />}
                        <div>
                          <strong>Assertion 1: Local Invariant Hash Match</strong>
                          <p className="text-[11px] text-slate-600 mt-0.5">
                            Recomputed SHA-256 (<code className="font-mono text-[10px] text-teal-800 font-bold">{computedHash}</code>) matches stored database hash.
                          </p>
                        </div>
                      </div>
                      <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase shrink-0 ${isHashValid ? 'bg-emerald-200/60 text-emerald-800' : 'bg-rose-200 text-rose-800'}`}>
                        {isHashValid ? 'PASS' : 'FAIL'}
                      </span>
                    </div>

                    {/* Assertion 2: Blockchain Linkage */}
                    <div className={`p-3 rounded-lg border flex items-start justify-between gap-3 text-xs ${
                      isChainValid ? 'bg-emerald-50/50 border-emerald-200 text-emerald-900' : 'bg-rose-50 border-rose-200 text-rose-900'
                    }`}>
                      <div className="flex items-start gap-2">
                        {isChainValid ? <CheckCircle className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" /> : <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />}
                        <div>
                          <strong>Assertion 2: Forward Chain Continuity</strong>
                          <p className="text-[11px] text-slate-600 mt-0.5">
                            Current record's <code className="font-mono text-[10px] text-teal-800 font-bold">prevHash</code> accurately points to preceding block hash.
                          </p>
                        </div>
                      </div>
                      <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase shrink-0 ${isChainValid ? 'bg-emerald-200/60 text-emerald-800' : 'bg-rose-200 text-rose-800'}`}>
                        {isChainValid ? 'PASS' : 'FAIL'}
                      </span>
                    </div>

                    {/* Assertion 3: Digital Signature */}
                    <div className={`p-3 rounded-lg border flex items-start justify-between gap-3 text-xs ${
                      isSignatureValid ? 'bg-emerald-50/50 border-emerald-200 text-emerald-900' : 'bg-rose-50 border-rose-200 text-rose-900'
                    }`}>
                      <div className="flex items-start gap-2">
                        {isSignatureValid ? <CheckCircle className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" /> : <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />}
                        <div>
                          <strong>Assertion 3: HMAC Secret Signature Authenticity</strong>
                          <p className="text-[11px] text-slate-600 mt-0.5">
                            Validates that the digital signature was generated with the authorized 256-bit HSM master key.
                          </p>
                        </div>
                      </div>
                      <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase shrink-0 ${isSignatureValid ? 'bg-emerald-200/60 text-emerald-800' : 'bg-rose-200 text-rose-800'}`}>
                        {isSignatureValid ? 'PASS' : 'FAIL'}
                      </span>
                    </div>
                  </div>

                  {/* Recommendation / Remediation */}
                  <div className={`p-3 rounded-lg text-xs leading-relaxed font-sans ${
                    isOverallSecure ? 'bg-teal-50/70 border border-teal-100 text-teal-900' : 'bg-rose-100 border border-rose-200 text-rose-900'
                  }`}>
                    {isOverallSecure ? (
                      <div>
                        ✅ <strong>Agent Telemetry Clean:</strong> Block #{selectedIndex + 1} ({selectedPatient.name}) adheres strictly to all mathematical invariants. Dispensation of <strong className="text-slate-900">{selectedPatient.medication}</strong> is authorized and safe.
                      </div>
                    ) : (
                      <div>
                        🚨 <strong>Agent Tamper Alarm:</strong> This record failed mathematical validation! The clinical dosage is marked as untrusted. Trigger the <strong>Autonomous Self-Healing IPS</strong> to roll back this record immediately.
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 5. TAB 4: INCIDENT RESPONSE PLAYBOOKS (Interactive Playbook Simulator) */}
      {activeTab === 'playbooks' && (
        <div className="space-y-6">
          <div className="bg-white rounded-2xl border border-slate-200/80 p-6 shadow-sm space-y-6">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 pb-4 border-b border-slate-100">
              <div>
                <div className="flex items-center gap-2">
                  <FileCode className="w-5 h-5 text-teal-600" />
                  <h3 className="text-base font-extrabold text-slate-900 uppercase tracking-wider">
                    Automated Incident Response Playbooks
                  </h3>
                </div>
                <p className="text-xs text-slate-500 font-medium mt-1">
                  Test the Security Agent's automated triage workflows under simulated attack conditions.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Playbook 1 */}
              <div className={`p-4 rounded-xl border transition ${
                activePlaybook === 'direct_db_tamper' ? 'bg-teal-50/60 border-teal-300' : 'bg-slate-50 border-slate-200'
              }`}>
                <span className="text-[9px] font-mono font-bold bg-teal-100 text-teal-800 px-2 py-0.5 rounded">PLAYBOOK-01</span>
                <h4 className="text-xs font-bold text-slate-900 mt-2">Direct SQL Injection Response</h4>
                <p className="text-[11px] text-slate-500 mt-1 leading-snug">
                  Triages unauthorized direct table updates, isolates corrupted record ID, and applies automated rollback.
                </p>
                <button
                  onClick={() => handleRunPlaybook('direct_db_tamper')}
                  disabled={isRunningPlaybook}
                  className="mt-3 w-full py-1.5 bg-teal-600 hover:bg-teal-500 text-white font-bold text-[11px] rounded transition cursor-pointer disabled:opacity-50"
                >
                  {isRunningPlaybook && activePlaybook === 'direct_db_tamper' ? 'Executing Playbook...' : 'Run Simulation'}
                </button>
              </div>

              {/* Playbook 2 */}
              <div className={`p-4 rounded-xl border transition ${
                activePlaybook === 'chain_recalc_apt' ? 'bg-teal-50/60 border-teal-300' : 'bg-slate-50 border-slate-200'
              }`}>
                <span className="text-[9px] font-mono font-bold bg-teal-100 text-teal-800 px-2 py-0.5 rounded">PLAYBOOK-02</span>
                <h4 className="text-xs font-bold text-slate-900 mt-2">Chain-Shift Forgery Containment</h4>
                <p className="text-[11px] text-slate-500 mt-1 leading-snug">
                  Flags forged sequence hashes, validates private key signatures, and alerts SOC compliance auditor.
                </p>
                <button
                  onClick={() => handleRunPlaybook('chain_recalc_apt')}
                  disabled={isRunningPlaybook}
                  className="mt-3 w-full py-1.5 bg-teal-600 hover:bg-teal-500 text-white font-bold text-[11px] rounded transition cursor-pointer disabled:opacity-50"
                >
                  {isRunningPlaybook && activePlaybook === 'chain_recalc_apt' ? 'Executing Playbook...' : 'Run Simulation'}
                </button>
              </div>

              {/* Playbook 3 */}
              <div className={`p-4 rounded-xl border transition ${
                activePlaybook === 'insider_token_theft' ? 'bg-teal-50/60 border-teal-300' : 'bg-slate-50 border-slate-200'
              }`}>
                <span className="text-[9px] font-mono font-bold bg-teal-100 text-teal-800 px-2 py-0.5 rounded">PLAYBOOK-03</span>
                <h4 className="text-xs font-bold text-slate-900 mt-2">Insider Privilege Quarantine</h4>
                <p className="text-[11px] text-slate-500 mt-1 leading-snug">
                  Revokes compromised auditor tokens, freezes clinical records, and locks down database write permissions.
                </p>
                <button
                  onClick={() => handleRunPlaybook('insider_token_theft')}
                  disabled={isRunningPlaybook}
                  className="mt-3 w-full py-1.5 bg-teal-600 hover:bg-teal-500 text-white font-bold text-[11px] rounded transition cursor-pointer disabled:opacity-50"
                >
                  {isRunningPlaybook && activePlaybook === 'insider_token_theft' ? 'Executing Playbook...' : 'Run Simulation'}
                </button>
              </div>
            </div>

            {/* Playbook Live Console Output */}
            <div className="bg-slate-900 text-emerald-400 p-4 rounded-xl font-mono text-xs space-y-2 border border-slate-800">
              <div className="flex justify-between items-center text-slate-400 text-[10px] pb-1.5 border-b border-slate-800">
                <span>SECURITY_AGENT_PLAYBOOK_RUNNER.LOG</span>
                <span className="animate-pulse">{isRunningPlaybook ? '● EXECUTING STEPS' : 'IDLE / READY'}</span>
              </div>
              <div className="space-y-1.5 text-[11px] pt-1">
                <div>[00.00s] Initializing Autonomous Playbook: <span className="text-white font-bold">{activePlaybook.toUpperCase()}</span></div>
                {playbookStep >= 1 && (
                  <div className="text-teal-300">[01.20s] STEP 1: Intercepted anomalous transaction in clinical ingestion queue. Triggering hash verification...</div>
                )}
                {playbookStep >= 2 && (
                  <div className="text-amber-300">[02.40s] STEP 2: Cryptographic assertion failed on Block #01. Invariant check detected invalid hash!</div>
                )}
                {playbookStep >= 3 && (
                  <div className="text-rose-400">[03.60s] STEP 3: Locking patient node PAT-001. Dispatching tamper siren and notifying clinical auditor.</div>
                )}
                {playbookStep >= 4 && (
                  <div className="text-emerald-400 font-bold">[04.80s] STEP 4: Mitigation successful! IPS restored golden baseline. Forensic audit log recorded with immutable WORM signature.</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
