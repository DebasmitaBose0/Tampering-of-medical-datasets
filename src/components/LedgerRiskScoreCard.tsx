import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Shield, 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  RefreshCw, 
  RotateCcw, 
  Activity, 
  Database, 
  Lock, 
  ChevronDown, 
  ChevronUp, 
  Layers, 
  AlertCircle,
  FileKey
} from 'lucide-react';
import { PatientRecord, SecurityStrategy } from '../types';
import { calculateRecordHash, generateHMACSignature } from '../data';

export interface LedgerRiskScoreCardProps {
  patients: PatientRecord[];
  strategies: SecurityStrategy[];
  secretKey: string;
  onRunIntegrityScan?: () => void;
  onResetSystem?: () => void;
  isScanning?: boolean;
}

export function LedgerRiskScoreCard({
  patients,
  strategies,
  secretKey,
  onRunIntegrityScan,
  onResetSystem,
  isScanning = false
}: LedgerRiskScoreCardProps) {
  const [showBlockBreakdown, setShowBlockBreakdown] = useState<boolean>(false);

  const isChainEnabled = strategies.find(s => s.id === 'crypt_chain')?.enabled ?? true;
  const isHmacEnabled = strategies.find(s => s.id === 'hmac_sig')?.enabled ?? true;

  // --- Dynamic Calculation of Tampered Blocks vs Total Ledger Size ---
  const totalBlocks = patients.length;

  const blockDetails = patients.map((patient, idx) => {
    const prevPatient = idx > 0 ? patients[idx - 1] : null;
    const expectedPrevHash = prevPatient ? prevPatient.hash : "00000000000000000000000000000000";

    const localHash = calculateRecordHash({
      id: patient.id,
      name: patient.name,
      age: patient.age,
      bloodType: patient.bloodType,
      diagnosis: patient.diagnosis,
      medication: patient.medication,
      dosage: patient.dosage,
      status: patient.status,
      lastUpdated: patient.lastUpdated,
      updatedBy: patient.updatedBy,
      prevHash: patient.prevHash
    });

    const isHashValid = patient.hash === localHash;
    const isChainValid = !isChainEnabled || patient.prevHash === expectedPrevHash;
    const expectedSig = generateHMACSignature(patient.hash, secretKey);
    const isSignatureValid = !isHmacEnabled || patient.signature === expectedSig;

    // A block is tampered only if its data fields (hash) or digital signature were altered
    const isTampered = !isHashValid || !isSignatureValid;

    return {
      patient,
      idx,
      isTampered,
      isHashValid,
      isChainValid,
      isSignatureValid,
      localHash,
      expectedPrevHash
    };
  });

  const tamperedBlocks = blockDetails.filter(b => b.isTampered);
  const tamperedCount = tamperedBlocks.length;
  const healthyCount = totalBlocks - tamperedCount;

  // Dynamic Percentage Calculation: (tampered / total) * 100
  const riskScorePercentage = totalBlocks > 0 ? Math.round((tamperedCount / totalBlocks) * 100) : 0;
  const integrityScorePercentage = 100 - riskScorePercentage;

  // Risk Classification
  type RiskTier = 'SECURE' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  let tier: RiskTier = 'SECURE';
  let tierBadge = 'PRISTINE (0% RISK)';
  let tierColor = {
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/30',
    text: 'text-emerald-400',
    badgeBg: 'bg-emerald-500/20',
    badgeText: 'text-emerald-300',
    meterColor: 'bg-emerald-500',
    glow: 'shadow-emerald-950/40',
    cardBorder: 'border-emerald-200'
  };

  if (riskScorePercentage > 60) {
    tier = 'CRITICAL';
    tierBadge = 'CRITICAL RISK';
    tierColor = {
      bg: 'bg-rose-500/10',
      border: 'border-rose-500/30',
      text: 'text-rose-400',
      badgeBg: 'bg-rose-500/20',
      badgeText: 'text-rose-300',
      meterColor: 'bg-rose-600',
      glow: 'shadow-rose-950/40',
      cardBorder: 'border-rose-300'
    };
  } else if (riskScorePercentage > 25) {
    tier = 'HIGH';
    tierBadge = 'HIGH RISK';
    tierColor = {
      bg: 'bg-orange-500/10',
      border: 'border-orange-500/30',
      text: 'text-orange-400',
      badgeBg: 'bg-orange-500/20',
      badgeText: 'text-orange-300',
      meterColor: 'bg-orange-500',
      glow: 'shadow-orange-950/40',
      cardBorder: 'border-orange-200'
    };
  } else if (riskScorePercentage > 0) {
    tier = 'MODERATE';
    tierBadge = 'ELEVATED RISK';
    tierColor = {
      bg: 'bg-amber-500/10',
      border: 'border-amber-500/30',
      text: 'text-amber-400',
      badgeBg: 'bg-amber-500/20',
      badgeText: 'text-amber-300',
      meterColor: 'bg-amber-500',
      glow: 'shadow-amber-950/40',
      cardBorder: 'border-amber-200'
    };
  }

  // Count specific failure types
  const hashMismatchCount = blockDetails.filter(b => !b.isHashValid).length;
  const chainBrokenCount = blockDetails.filter(b => !b.isChainValid).length;
  const sigMismatchCount = blockDetails.filter(b => !b.isSignatureValid).length;

  return (
    <div id="ledger-risk-score-container" className="bg-slate-900 text-white rounded-2xl p-6 shadow-xl border border-slate-800 relative overflow-hidden">
      {/* Subtle Background Glow Elements */}
      <div className={`absolute top-0 right-0 w-96 h-96 ${riskScorePercentage > 0 ? 'bg-rose-500/5' : 'bg-teal-500/5'} rounded-full blur-3xl pointer-events-none -mr-20 -mt-20`} />
      <div className="absolute bottom-0 left-1/3 w-64 h-64 bg-slate-800/40 rounded-full blur-2xl pointer-events-none" />

      {/* Main Header & Gauge Row */}
      <div className="relative z-10">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 pb-5 border-b border-slate-800/80">
          
          {/* Left Column: Title & Dynamic Risk Calculation Description */}
          <div className="space-y-1.5 max-w-xl">
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className="text-[10px] font-mono font-black uppercase tracking-wider px-2.5 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700 flex items-center gap-1.5">
                <Activity className="w-3 h-3 text-teal-400" />
                Auditor Console Metric
              </span>
              <span className={`text-[10px] font-mono font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full ${tierColor.badgeBg} ${tierColor.badgeText} border ${tierColor.border} flex items-center gap-1`}>
                {riskScorePercentage === 0 ? (
                  <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                ) : (
                  <AlertTriangle className="w-3 h-3 text-rose-400 animate-pulse" />
                )}
                {tierBadge}
              </span>
            </div>

            <h2 className="text-xl sm:text-2xl font-black text-white tracking-tight flex items-center gap-2">
              <span>Ledger Risk Score</span>
              <span className="text-slate-500 text-base font-normal">/</span>
              <span className={`font-mono ${tierColor.text}`}>{riskScorePercentage}%</span>
            </h2>

            <p className="text-xs text-slate-300 leading-relaxed">
              {riskScorePercentage === 0 ? (
                <>All <strong className="text-white font-mono">{totalBlocks}</strong> ledger blocks are cryptographically verified. No unauthorized SQL tampering, chain broken links, or HMAC signature forge detected.</>
              ) : (
                <><strong className="text-rose-300 font-mono">{tamperedCount} of {totalBlocks}</strong> blocks ({riskScorePercentage}% of the ledger) fail cryptographic validation checks.</>
              )}
            </p>
          </div>

          {/* Right Column: Prominent Risk Score Gauge & Action Controls */}
          <div className="flex items-center gap-5 w-full lg:w-auto justify-between lg:justify-end">
            
            {/* Score Ring / Gauge */}
            <div className="flex items-center gap-3.5 bg-slate-850 bg-slate-800/60 border border-slate-700/80 p-3.5 rounded-xl shadow-inner">
              <div className="relative w-14 h-14 shrink-0 flex items-center justify-center">
                {/* SVG Progress Circle */}
                <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                  {/* Background Path */}
                  <path
                    className="text-slate-700"
                    strokeWidth="3.5"
                    stroke="currentColor"
                    fill="none"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                  {/* Dynamic Foreground Path */}
                  <path
                    className={riskScorePercentage === 0 ? 'text-emerald-500' : riskScorePercentage > 60 ? 'text-rose-500' : 'text-amber-500'}
                    strokeDasharray={`${riskScorePercentage}, 100`}
                    strokeWidth="3.5"
                    strokeLinecap="round"
                    stroke="currentColor"
                    fill="none"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                  <span className={`text-xs font-black font-mono ${tierColor.text}`}>
                    {riskScorePercentage}%
                  </span>
                </div>
              </div>

              <div className="text-left">
                <span className="text-[10px] text-slate-400 font-mono uppercase block">Ledger Threat Level</span>
                <span className={`text-xs font-black uppercase ${tierColor.text}`}>
                  {tier === 'SECURE' ? 'Low / Healthy' : tier === 'MODERATE' ? 'Moderate Risk' : tier === 'HIGH' ? 'High Risk' : 'Critical Threat'}
                </span>
                <span className="text-[10px] text-slate-400 block mt-0.5">
                  {tamperedCount} Tampered / {healthyCount} Verified
                </span>
              </div>
            </div>

            {/* Actions: Scan & Reset */}
            <div className="flex flex-col sm:flex-row lg:flex-col gap-2 shrink-0">
              {onRunIntegrityScan && (
                <button
                  id="risk-score-scan-btn"
                  onClick={onRunIntegrityScan}
                  disabled={isScanning}
                  className="px-3.5 py-1.5 bg-teal-600 hover:bg-teal-500 active:bg-teal-700 disabled:opacity-50 text-white text-xs font-bold rounded-lg transition flex items-center justify-center gap-1.5 cursor-pointer shadow-sm"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
                  <span>{isScanning ? 'Scanning...' : 'Verify Ledger'}</span>
                </button>
              )}
              {tamperedCount > 0 && onResetSystem && (
                <button
                  id="risk-score-restore-btn"
                  onClick={onResetSystem}
                  className="px-3.5 py-1.5 bg-rose-600/90 hover:bg-rose-600 active:bg-rose-700 text-white text-xs font-bold rounded-lg transition flex items-center justify-center gap-1.5 cursor-pointer shadow-sm"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Restore Baseline</span>
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Dynamic Proportion Visualizer (Block-by-Block Visual Bar) */}
        <div className="mt-5 space-y-2.5">
          <div className="flex justify-between items-center text-xs">
            <span className="text-slate-400 font-mono text-[11px] flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-slate-400" />
              Dynamic Calculation: <strong className="text-slate-200">({tamperedCount} Tampered Blocks ÷ {totalBlocks} Total Blocks) × 100% = {riskScorePercentage}% Risk</strong>
            </span>
            <span className="text-[11px] font-mono text-slate-400">
              Integrity Index: <strong className="text-emerald-400">{integrityScorePercentage}%</strong>
            </span>
          </div>

          {/* Segmented / Gradient Progress Meter */}
          <div className="h-3 w-full bg-slate-800 rounded-full overflow-hidden p-0.5 border border-slate-700/60 flex">
            <div 
              style={{ width: `${riskScorePercentage}%` }}
              className={`h-full ${tierColor.meterColor} transition-all duration-500 rounded-l-full relative`}
              title={`${riskScorePercentage}% Tampered`}
            />
            <div 
              style={{ width: `${integrityScorePercentage}%` }}
              className="h-full bg-emerald-500 transition-all duration-500 rounded-r-full"
              title={`${integrityScorePercentage}% Cryptographically Verified`}
            />
          </div>

          {/* Interactive Block-by-Block Micro Status Chips */}
          <div className="pt-2 flex flex-wrap items-center gap-1.5">
            <span className="text-[10px] text-slate-400 font-mono mr-1">Blocks Map:</span>
            {blockDetails.map((b) => (
              <div
                key={b.patient.id}
                className={`px-2 py-1 rounded text-[10px] font-mono font-bold transition flex items-center gap-1 cursor-default border ${
                  b.isTampered
                    ? 'bg-rose-950/80 border-rose-600/80 text-rose-300 shadow-sm animate-pulse'
                    : 'bg-slate-800/80 border-slate-700 text-slate-300 hover:border-emerald-500 hover:text-emerald-300'
                }`}
                title={`Block #${b.idx + 1} (${b.patient.id}) - ${b.patient.name}: ${b.isTampered ? 'TAMPERED / CORRUPTED' : 'VERIFIED'}`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${b.isTampered ? 'bg-rose-500' : 'bg-emerald-400'}`} />
                <span>#{b.idx + 1}</span>
                <span className="hidden sm:inline text-[9px] text-slate-400">{b.patient.id}</span>
                {b.isTampered && <span className="text-[9px] text-rose-400 font-extrabold">ERR</span>}
              </div>
            ))}
          </div>
        </div>

        {/* Breakdown Metric Cards Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4 pt-4 border-t border-slate-800/60 text-left">
          
          <div className="bg-slate-800/50 border border-slate-700/50 p-3 rounded-xl">
            <span className="text-[10px] text-slate-400 font-mono uppercase block">Total Ledger Size</span>
            <div className="text-lg font-black text-white font-mono mt-0.5 flex items-center gap-1.5">
              <Database className="w-4 h-4 text-teal-400" />
              <span>{totalBlocks} Blocks</span>
            </div>
            <span className="text-[10px] text-slate-500 block mt-0.5">Full audit dataset size</span>
          </div>

          <div className="bg-slate-800/50 border border-slate-700/50 p-3 rounded-xl">
            <span className="text-[10px] text-slate-400 font-mono uppercase block">Verified Clean</span>
            <div className="text-lg font-black text-emerald-400 font-mono mt-0.5 flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>{healthyCount} ({integrityScorePercentage}%)</span>
            </div>
            <span className="text-[10px] text-slate-500 block mt-0.5">Passing all SHA-256 + HMAC</span>
          </div>

          <div className={`p-3 rounded-xl border ${tamperedCount > 0 ? 'bg-rose-950/30 border-rose-800/50' : 'bg-slate-800/50 border-slate-700/50'}`}>
            <span className="text-[10px] text-slate-400 font-mono uppercase block">Tampered Blocks</span>
            <div className={`text-lg font-black font-mono mt-0.5 flex items-center gap-1.5 ${tamperedCount > 0 ? 'text-rose-400' : 'text-slate-300'}`}>
              <ShieldAlert className={`w-4 h-4 ${tamperedCount > 0 ? 'text-rose-400' : 'text-slate-400'}`} />
              <span>{tamperedCount} ({riskScorePercentage}%)</span>
            </div>
            <span className="text-[10px] text-slate-500 block mt-0.5">Failing cryptographic checks</span>
          </div>

          <div className="bg-slate-800/50 border border-slate-700/50 p-3 rounded-xl">
            <span className="text-[10px] text-slate-400 font-mono uppercase block">Active Defenses</span>
            <div className="text-lg font-black text-teal-300 font-mono mt-0.5 flex items-center gap-1.5">
              <Lock className="w-4 h-4 text-teal-400" />
              <span>{strategies.filter(s => s.enabled).length}/4 Online</span>
            </div>
            <span className="text-[10px] text-slate-500 block mt-0.5">Real-time security shields</span>
          </div>
        </div>

        {/* Toggle Detailed Block Integrity Inspector if any block is tampered */}
        {tamperedCount > 0 && (
          <div className="mt-4 pt-3 border-t border-slate-800/60">
            <button
              onClick={() => setShowBlockBreakdown(!showBlockBreakdown)}
              className="text-xs text-rose-300 hover:text-rose-200 font-bold flex items-center gap-1.5 cursor-pointer"
            >
              <AlertCircle className="w-3.5 h-3.5 text-rose-400" />
              <span>
                {showBlockBreakdown ? 'Hide Compromised Block Details' : `Inspect ${tamperedCount} Compromised Block(s) (${riskScorePercentage}% Risk)`}
              </span>
              {showBlockBreakdown ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>

            <AnimatePresence>
              {showBlockBreakdown && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="mt-3 space-y-2 overflow-hidden"
                >
                  <div className="bg-slate-950/80 border border-rose-900/60 rounded-xl p-4 space-y-3">
                    <div className="flex items-center justify-between text-xs text-rose-300 font-bold border-b border-slate-800 pb-2">
                      <span className="flex items-center gap-1.5">
                        <FileKey className="w-3.5 h-3.5 text-rose-400" />
                        Cryptographic Discrepancy Breakdown
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">
                        {hashMismatchCount} Hash Mismatches | {chainBrokenCount} Chain Breaks | {sigMismatchCount} Forged HMAC
                      </span>
                    </div>

                    <div className="space-y-2">
                      {tamperedBlocks.map(tb => (
                        <div key={tb.patient.id} className="bg-slate-900/90 border border-slate-800 p-3 rounded-lg text-xs space-y-1.5">
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-white font-mono">
                              Block #{tb.idx + 1} — {tb.patient.id} ({tb.patient.name})
                            </span>
                            <span className="px-2 py-0.5 bg-rose-900/40 text-rose-300 border border-rose-800 text-[10px] font-mono rounded font-bold">
                              COMPROMISED
                            </span>
                          </div>
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-[10px] font-mono pt-1">
                            <div className={`p-1.5 rounded ${tb.isHashValid ? 'bg-slate-800 text-slate-300' : 'bg-rose-950/60 text-rose-300 border border-rose-900'}`}>
                              <span className="text-slate-500 block">SHA-256 Hash Check:</span>
                              <strong>{tb.isHashValid ? '✓ Valid' : '✗ Hash Mismatch'}</strong>
                            </div>
                            <div className={`p-1.5 rounded ${tb.isChainValid ? 'bg-slate-800 text-slate-300' : 'bg-rose-950/60 text-rose-300 border border-rose-900'}`}>
                              <span className="text-slate-500 block">Chain Link Pointer:</span>
                              <strong>{tb.isChainValid ? '✓ Connected' : '✗ Broken Chain'}</strong>
                            </div>
                            <div className={`p-1.5 rounded ${tb.isSignatureValid ? 'bg-slate-800 text-slate-300' : 'bg-rose-950/60 text-rose-300 border border-rose-900'}`}>
                              <span className="text-slate-500 block">HMAC Signature:</span>
                              <strong>{tb.isSignatureValid ? '✓ Authenticated' : '✗ Key Mismatch'}</strong>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        )}

      </div>
    </div>
  );
}
