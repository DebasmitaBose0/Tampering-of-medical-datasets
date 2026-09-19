import React from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Activity,
  ShieldCheck,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Cpu,
  RefreshCw,
  Zap,
  Terminal,
  Clock,
  Radio
} from 'lucide-react';
import { PatientRecord } from '../types';

export interface BlockScanStatus {
  status: 'pending' | 'scanning' | 'valid' | 'invalid' | 'aborted';
  brokenFields?: string[];
  isHashValid?: boolean;
  isChainValid?: boolean;
  isHmacValid?: boolean;
  timestamp?: number;
}

interface TableScanOverlayProps {
  isScanning: boolean;
  scanningProgress: number;
  scanningBlockIndex: number | null;
  patients: PatientRecord[];
  scannedBlocksMap: Record<number, BlockScanStatus>;
  scanStatus: {
    scanned: boolean;
    valid: boolean;
    brokenIndex: number | null;
    brokenFields: string[];
    signatureMismatch: boolean;
  } | null;
  onRunScan: () => void;
  onClearScanResults?: () => void;
  onResetSystem?: () => void;
}

export const TableScanOverlay: React.FC<TableScanOverlayProps> = ({
  isScanning,
  scanningProgress,
  scanningBlockIndex,
  patients,
  scannedBlocksMap,
  scanStatus,
  onRunScan,
  onClearScanResults,
  onResetSystem,
}) => {
  const currentPatient = scanningBlockIndex !== null ? patients[scanningBlockIndex] : null;

  // Calculate live statistics from scannedBlocksMap
  const blockStatuses: BlockScanStatus[] = Object.values(scannedBlocksMap) as BlockScanStatus[];
  const validCount = blockStatuses.filter(b => b?.status === 'valid').length;
  const invalidCount = blockStatuses.filter(b => b?.status === 'invalid').length;
  const pendingCount = patients.length - validCount - invalidCount;

  // Active block verification details
  const activeBlockData = scanningBlockIndex !== null ? scannedBlocksMap[scanningBlockIndex] : null;

  return (
    <div className="w-full">
      {/* Active Scanning Animation Overlay HUD */}
      <AnimatePresence>
        {isScanning && (
          <motion.div
            initial={{ opacity: 0, y: -8, scale: 0.99 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.99 }}
            transition={{ duration: 0.25 }}
            className="relative overflow-hidden rounded-xl border border-teal-200/80 bg-gradient-to-br from-slate-900 via-teal-950 to-slate-950 text-white shadow-premium-lg mb-4"
          >
            {/* Animated High-tech Scanning Laser Beam Shimmer across background */}
            <div className="absolute inset-0 pointer-events-none scan-beam-shimmer opacity-30" />
            <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-teal-400 to-transparent animate-scan-laser" />

            <div className="p-4 sm:p-5 relative z-10 space-y-4">
              {/* Header Row */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-teal-800/60 pb-3.5">
                <div className="flex items-center gap-3">
                  <div className="relative p-2.5 rounded-lg bg-teal-500/20 border border-teal-400/40 text-teal-300 shrink-0 shadow-[0_0_15px_rgba(20,184,166,0.35)]">
                    <Activity className="w-5 h-5 animate-spin" />
                    <span className="absolute -top-1 -right-1 flex h-3 w-3">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-teal-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-3 w-3 bg-teal-400"></span>
                    </span>
                  </div>
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="px-2 py-0.5 rounded bg-teal-500 text-slate-950 text-[10px] font-black tracking-wider uppercase font-mono shadow-sm">
                        LIVE CRYPTOGRAPHIC AUDIT
                      </span>
                      <span className="text-[11px] font-mono text-teal-300 font-semibold flex items-center gap-1">
                        <Radio className="w-3 h-3 text-teal-400 animate-pulse" />
                        Scanning Ledger Nodes
                      </span>
                    </div>
                    <h3 className="text-sm sm:text-base font-extrabold text-white tracking-tight mt-0.5">
                      Sequential Block-by-Block Integrity Verification
                    </h3>
                  </div>
                </div>

                {/* Progress Metric Badge */}
                <div className="flex items-center gap-3 self-end md:self-center">
                  <div className="text-right">
                    <div className="text-[10px] font-mono uppercase text-teal-300/80 font-bold">
                      Audit Progress
                    </div>
                    <div className="text-xl sm:text-2xl font-black font-mono text-teal-300 tracking-tight flex items-center gap-1 justify-end">
                      <span>{scanningProgress}%</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Live Active Block Inspection Card */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5 items-center">
                {/* Active Block Info */}
                <div className="lg:col-span-6 bg-slate-800/80 border border-teal-700/40 rounded-lg p-3 space-y-2 backdrop-blur-sm">
                  <div className="flex items-center justify-between text-[11px] font-mono">
                    <span className="text-teal-400 font-bold flex items-center gap-1.5">
                      <Cpu className="w-3.5 h-3.5 text-teal-400 animate-pulse" />
                      ACTIVE NODE INSPECTOR
                    </span>
                    {currentPatient ? (
                      <span className="text-slate-300 font-bold bg-teal-950/80 px-2 py-0.5 rounded border border-teal-700/50">
                        Node {String((scanningBlockIndex ?? 0) + 1).padStart(2, '0')} / {String(patients.length).padStart(2, '0')}
                      </span>
                    ) : (
                      <span className="text-slate-400">Finalizing...</span>
                    )}
                  </div>

                  {currentPatient ? (
                    <div className="flex items-center gap-3 bg-slate-900/90 p-2.5 rounded border border-slate-700/60">
                      <div className="w-8 h-8 rounded-md bg-teal-600 text-white font-mono font-black text-xs flex items-center justify-center shrink-0 shadow-[0_0_10px_rgba(20,184,166,0.4)]">
                        0{scanningBlockIndex! + 1}
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="text-xs font-bold text-white truncate flex items-center gap-1.5">
                          <span>{currentPatient.name}</span>
                          <span className="text-[10px] text-teal-300 font-mono font-normal">({currentPatient.id})</span>
                        </div>
                        <div className="text-[10px] text-slate-300 truncate font-mono mt-0.5">
                          Rx: <span className="text-teal-200 font-bold">{currentPatient.medication}</span> ({currentPatient.dosage}) • {currentPatient.diagnosis}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="text-xs text-slate-400 font-mono py-2 text-center">
                      Preparing cryptographic pipeline...
                    </div>
                  )}
                </div>

                {/* 3 Verification Sub-Stages Status */}
                <div className="lg:col-span-6 grid grid-cols-3 gap-2 text-[10px] font-mono">
                  {/* Step 1: Record Hash */}
                  <div className={`p-2.5 rounded-lg border flex flex-col justify-between transition-all ${
                    activeBlockData?.status === 'valid'
                      ? 'bg-emerald-950/70 border-emerald-500/60 text-emerald-200 shadow-[0_0_10px_rgba(16,185,129,0.2)]'
                      : activeBlockData?.status === 'invalid' && activeBlockData.brokenFields?.includes('Block Hash Mismatch')
                      ? 'bg-rose-950/70 border-rose-500/60 text-rose-200 shadow-[0_0_10px_rgba(244,63,94,0.3)]'
                      : 'bg-slate-800/80 border-slate-700/60 text-slate-300'
                  }`}>
                    <div className="text-[9px] uppercase font-bold text-slate-400">1. Record Hash</div>
                    <div className="font-bold text-[11px] mt-1 flex items-center gap-1 truncate">
                      {activeBlockData?.status === 'valid' ? (
                        <>
                          <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                          <span className="text-emerald-300">SHA-256 OK</span>
                        </>
                      ) : activeBlockData?.status === 'invalid' && activeBlockData.brokenFields?.includes('Block Hash Mismatch') ? (
                        <>
                          <AlertTriangle className="w-3 h-3 text-rose-400 shrink-0" />
                          <span className="text-rose-300">MISMATCH</span>
                        </>
                      ) : (
                        <>
                          <RefreshCw className="w-3 h-3 text-teal-400 animate-spin shrink-0" />
                          <span>Computing...</span>
                        </>
                      )}
                    </div>
                  </div>

                  {/* Step 2: Parent Link (Chain) */}
                  <div className={`p-2.5 rounded-lg border flex flex-col justify-between transition-all ${
                    activeBlockData?.status === 'valid'
                      ? 'bg-emerald-950/70 border-emerald-500/60 text-emerald-200 shadow-[0_0_10px_rgba(16,185,129,0.2)]'
                      : activeBlockData?.status === 'invalid' && activeBlockData.brokenFields?.includes('Blockchain Link Breakage')
                      ? 'bg-rose-950/70 border-rose-500/60 text-rose-200 shadow-[0_0_10px_rgba(244,63,94,0.3)]'
                      : 'bg-slate-800/80 border-slate-700/60 text-slate-300'
                  }`}>
                    <div className="text-[9px] uppercase font-bold text-slate-400">2. Chain Link</div>
                    <div className="font-bold text-[11px] mt-1 flex items-center gap-1 truncate">
                      {activeBlockData?.status === 'valid' ? (
                        <>
                          <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                          <span className="text-emerald-300">LINK INTACT</span>
                        </>
                      ) : activeBlockData?.status === 'invalid' && activeBlockData.brokenFields?.includes('Blockchain Link Breakage') ? (
                        <>
                          <AlertTriangle className="w-3 h-3 text-rose-400 shrink-0" />
                          <span className="text-rose-300">BROKEN LINK</span>
                        </>
                      ) : (
                        <>
                          <RefreshCw className="w-3 h-3 text-teal-400 animate-spin shrink-0" />
                          <span>Verifying...</span>
                        </>
                      )}
                    </div>
                  </div>

                  {/* Step 3: HMAC Signature */}
                  <div className={`p-2.5 rounded-lg border flex flex-col justify-between transition-all ${
                    activeBlockData?.status === 'valid'
                      ? 'bg-emerald-950/70 border-emerald-500/60 text-emerald-200 shadow-[0_0_10px_rgba(16,185,129,0.2)]'
                      : activeBlockData?.status === 'invalid' && activeBlockData.brokenFields?.includes('HMAC Signature Authenticity Failure')
                      ? 'bg-rose-950/70 border-rose-500/60 text-rose-200 shadow-[0_0_10px_rgba(244,63,94,0.3)]'
                      : 'bg-slate-800/80 border-slate-700/60 text-slate-300'
                  }`}>
                    <div className="text-[9px] uppercase font-bold text-slate-400">3. HMAC Sig</div>
                    <div className="font-bold text-[11px] mt-1 flex items-center gap-1 truncate">
                      {activeBlockData?.status === 'valid' ? (
                        <>
                          <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                          <span className="text-emerald-300">HSM AUTH</span>
                        </>
                      ) : activeBlockData?.status === 'invalid' && activeBlockData.brokenFields?.includes('HMAC Signature Authenticity Failure') ? (
                        <>
                          <AlertTriangle className="w-3 h-3 text-rose-400 shrink-0" />
                          <span className="text-rose-300">FORGED SIG</span>
                        </>
                      ) : (
                        <>
                          <RefreshCw className="w-3 h-3 text-teal-400 animate-spin shrink-0" />
                          <span>Authenticating...</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* Progress Bar & Live Status Bar */}
              <div className="space-y-2 pt-1">
                <div className="w-full bg-slate-800 rounded-full h-3 overflow-hidden border border-teal-800/80 p-[2px] shadow-inner relative">
                  <motion.div
                    className="h-full rounded-full bg-gradient-to-r from-teal-500 via-emerald-400 to-teal-400 shadow-[0_0_12px_rgba(20,184,166,0.6)]"
                    style={{ width: `${scanningProgress}%` }}
                    transition={{ duration: 0.2 }}
                  />
                </div>

                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[10px] font-mono">
                  {/* Live Counters */}
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-700/60 font-bold flex items-center gap-1 shadow-sm">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-[0_0_6px_rgba(16,185,129,0.8)]"></span>
                      Verified Intact: {validCount}
                    </span>
                    {invalidCount > 0 && (
                      <span className="px-2 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-700/60 font-bold flex items-center gap-1 shadow-sm animate-pulse">
                        <span className="w-1.5 h-1.5 rounded-full bg-rose-400 shadow-[0_0_6px_rgba(244,63,94,0.8)]"></span>
                        Compromised: {invalidCount}
                      </span>
                    )}
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700/60 font-bold">
                      Pending: {pendingCount}
                    </span>
                  </div>

                  <div className="text-[10px] text-teal-300/80 flex items-center gap-1 font-semibold">
                    <span>Cryptographic Verification Pipeline • SHA-256 + HMAC-SHA256</span>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Post-Scan Summary Banner if scan finished and results are present */}
      {!isScanning && scanStatus && Object.keys(scannedBlocksMap).length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: -4 }}
          animate={{ opacity: 1, y: 0 }}
          className={`rounded-xl border p-3 sm:p-4 mb-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-sm ${
            scanStatus.valid
              ? 'bg-emerald-50/90 border-emerald-200 text-emerald-950 shadow-[0_0_15px_rgba(16,185,129,0.1)]'
              : 'bg-rose-50/90 border-rose-200 text-rose-950 shadow-[0_0_15px_rgba(244,63,94,0.15)]'
          }`}
        >
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg shrink-0 ${
              scanStatus.valid 
                ? 'bg-emerald-100 text-emerald-700 border border-emerald-300 shadow-[0_0_10px_rgba(16,185,129,0.3)]' 
                : 'bg-rose-100 text-rose-700 border border-rose-300 shadow-[0_0_10px_rgba(244,63,94,0.35)]'
            }`}>
              {scanStatus.valid ? (
                <ShieldCheck className="w-5 h-5 text-emerald-600" />
              ) : (
                <ShieldAlert className="w-5 h-5 text-rose-600 animate-bounce" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h4 className="font-extrabold text-xs sm:text-sm text-slate-900 flex items-center gap-1.5">
                  {scanStatus.valid ? (
                    <span className="text-emerald-800">Complete Ledger Audit Passed: 100% Cryptographically Verified</span>
                  ) : (
                    <span className="text-rose-800">Ledger Breach Detected: Integrity Compromised</span>
                  )}
                </h4>
                <span className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded ${
                  scanStatus.valid ? 'bg-emerald-200 text-emerald-900' : 'bg-rose-200 text-rose-900'
                }`}>
                  {validCount} / {patients.length} Valid Nodes
                </span>
              </div>
              <p className="text-xs text-slate-600 mt-0.5">
                {scanStatus.valid
                  ? 'All patient blocks match their SHA-256 hashes, chronological parent links, and HSM HMAC signatures.'
                  : `Breach identified at Node 0${(scanStatus.brokenIndex ?? 0) + 1} (${patients[scanStatus.brokenIndex ?? 0]?.name}): ${scanStatus.brokenFields.join(', ')}.`
                }
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 self-end sm:self-center shrink-0 flex-wrap">
            {!scanStatus.valid && onResetSystem && (
              <button
                onClick={onResetSystem}
                className="px-3 py-1.5 bg-rose-600 hover:bg-rose-700 text-white text-xs font-bold rounded-lg transition shadow-sm cursor-pointer flex items-center gap-1.5"
              >
                <RefreshCw className="w-3 h-3 text-white" />
                <span>Repair with Baseline</span>
              </button>
            )}
            <button
              onClick={onRunScan}
              className="px-3 py-1.5 bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-bold rounded-lg transition shadow-sm cursor-pointer flex items-center gap-1.5"
            >
              <RefreshCw className="w-3 h-3 text-teal-600" />
              <span>Re-Scan Ledger</span>
            </button>
            {onClearScanResults && (
              <button
                onClick={onClearScanResults}
                className="px-2.5 py-1.5 text-slate-500 hover:text-slate-800 text-xs font-bold rounded-lg transition cursor-pointer"
              >
                Dismiss
              </button>
            )}
          </div>
        </motion.div>
      )}
    </div>
  );
};
