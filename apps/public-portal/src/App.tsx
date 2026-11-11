import React, { useState } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  UploadCloud, 
  Cpu, 
  CheckCircle2, 
  XCircle, 
  RefreshCw,
  Lock
} from 'lucide-react';
import { parseAndVerifyMedia } from './lib/cryptoVerifier';
import { VerificationResult } from './lib/types';

export default function App() {
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [dragActive, setDragActive] = useState<boolean>(false);

  const handleFileUpload = async (file: File) => {
    setIsProcessing(true);
    setResult(null);
    try {
      const res = await parseAndVerifyMedia(file);
      setResult(res);
    } catch (err) {
      console.error(err);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-md px-6 py-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-indigo-600/20 border border-indigo-500/30 rounded-lg">
            <ShieldCheck className="w-6 h-6 text-indigo-400" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white">PROVE-HUMAN</h1>
            <p className="text-xs text-slate-400">Institutional Anti-Deepfake Verification Portal</p>
          </div>
        </div>
        <div className="flex items-center space-x-4 text-xs font-mono">
          <span className="flex items-center text-emerald-400 bg-emerald-950/60 border border-emerald-800/50 px-3 py-1 rounded-full">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse mr-2"></span>
            PKI TRUST REGISTRY ONLINE
          </span>
        </div>
      </header>

      <main className="flex-1 max-w-6xl w-full mx-auto px-6 py-10 flex flex-col gap-8">
        <div
          onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
          onDragLeave={() => setDragActive(false)}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-2xl p-12 text-center transition-all duration-200 cursor-pointer ${
            dragActive 
              ? 'border-indigo-500 bg-indigo-950/20 scale-[1.01]' 
              : 'border-slate-800 bg-slate-900/30 hover:border-slate-700'
          }`}
        >
          <input
            type="file"
            id="mediaInput"
            className="hidden"
            onChange={(e) => e.target.files?.[0] && handleFileUpload(e.target.files[0])}
          />
          <label htmlFor="mediaInput" className="cursor-pointer flex flex-col items-center">
            {isProcessing ? (
              <RefreshCw className="w-12 h-12 text-indigo-400 animate-spin mb-4" />
            ) : (
              <UploadCloud className="w-12 h-12 text-slate-400 mb-4" />
            )}
            <h2 className="text-xl font-semibold mb-2">
              {isProcessing ? 'Verifying Hardware Signatures & Cryptographic Hashes...' : 'Drop high-stakes media or documents to verify identity'}
            </h2>
            <p className="text-slate-400 text-sm max-w-md mb-6">
              Supports MP4, WEBM, PDF, PNG, and JPEG. All provenance signatures and hard-bindings are calculated client-side via Web Crypto.
            </p>
            <span className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-sm font-medium transition-colors shadow-lg shadow-indigo-600/20">
              Select File to Inspect
            </span>
          </label>
        </div>

        {result && (
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-2xl backdrop-blur-md">
            <div className="flex items-center justify-between pb-6 border-b border-slate-800">
              <div className="flex items-center space-x-4">
                {result.status === 'VALID' && (
                  <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-xl text-emerald-400">
                    <CheckCircle2 className="w-8 h-8" />
                  </div>
                )}
                {result.status === 'TAMPERED' && (
                  <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-xl text-rose-400">
                    <XCircle className="w-8 h-8" />
                  </div>
                )}
                {result.status === 'UNSIGNED' && (
                  <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-xl text-amber-400">
                    <ShieldAlert className="w-8 h-8" />
                  </div>
                )}
                <div>
                  <h3 className="text-2xl font-bold">
                    {result.status === 'VALID' && 'Authentic Human Capture Verified'}
                    {result.status === 'TAMPERED' && 'Cryptographic Verification Failed / Tampered'}
                    {result.status === 'UNSIGNED' && 'No C2PA Provenance Manifest Detected'}
                  </h3>
                  <p className="text-xs text-slate-400 font-mono mt-1">
                    File: {result.fileName} • {Math.round(result.fileSize / 1024)} KB • Scanned in {result.verificationDurationMs}ms
                  </p>
                </div>
              </div>
            </div>

            {result.manifest && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
                <div className="p-4 bg-slate-950/60 border border-slate-800/80 rounded-xl">
                  <div className="flex items-center space-x-2 text-indigo-400 mb-2">
                    <Cpu className="w-4 h-4" />
                    <span className="text-xs font-bold uppercase tracking-wider">Hardware Attestation</span>
                  </div>
                  <p className="text-sm font-semibold text-slate-200">{result.manifest.hardwareAttestation.enclaveType}</p>
                  <p className="text-xs text-slate-400 mt-1">Key: {result.manifest.hardwareAttestation.hardwareKeyId}</p>
                  <div className="mt-3 flex items-center text-xs">
                    <span className={`px-2 py-0.5 rounded font-mono ${
                      result.manifest.hardwareAttestation.attestationStatus === 'VERIFIED'
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/50'
                        : 'bg-rose-950 text-rose-400 border border-rose-800/50'
                    }`}>
                      {result.manifest.hardwareAttestation.attestationStatus}
                    </span>
                  </div>
                </div>

                <div className="p-4 bg-slate-950/60 border border-slate-800/80 rounded-xl">
                  <div className="flex items-center space-x-2 text-indigo-400 mb-2">
                    <Lock className="w-4 h-4" />
                    <span className="text-xs font-bold uppercase tracking-wider">SHA-256 Hard Binding</span>
                  </div>
                  <p className="text-xs font-mono text-slate-300 truncate">Stored: {result.manifest.hardBindingHash}</p>
                  <p className="text-xs font-mono text-slate-400 truncate mt-1">Computed: {result.manifest.computedHash}</p>
                  <div className="mt-3 flex items-center text-xs">
                    <span className={`px-2 py-0.5 rounded font-mono ${
                      result.manifest.isHashMatch
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/50'
                        : 'bg-rose-950 text-rose-400 border border-rose-800/50'
                    }`}>
                      {result.manifest.isHashMatch ? 'HASH MATCH EXACT' : 'BYTE DISCREPANCY DETECTED'}
                    </span>
                  </div>
                </div>

                <div className="p-4 bg-slate-950/60 border border-slate-800/80 rounded-xl">
                  <div className="flex items-center space-x-2 text-indigo-400 mb-2">
                    <ShieldCheck className="w-4 h-4" />
                    <span className="text-xs font-bold uppercase tracking-wider">Liveness Confidence</span>
                  </div>
                  <p className="text-xl font-bold text-slate-100">{(result.manifest.livenessProof.score * 100).toFixed(1)}%</p>
                  <p className="text-xs text-slate-400 mt-1">Mode: {result.manifest.livenessProof.challengeType}</p>
                  <div className="mt-3 flex items-center text-xs">
                    <span className={`px-2 py-0.5 rounded font-mono ${
                      result.manifest.livenessProof.passed
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/50'
                        : 'bg-rose-950 text-rose-400 border border-rose-800/50'
                    }`}>
                      {result.manifest.livenessProof.passed ? 'LIVENESS PASSED' : 'LIVENESS FAILURE'}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {result.errors.length > 0 && (
              <div className="mt-6 p-4 bg-rose-950/40 border border-rose-900/50 rounded-xl">
                <h4 className="text-xs font-bold text-rose-400 uppercase tracking-wider mb-2">Verification Audit Warnings</h4>
                <ul className="list-disc list-inside text-xs text-rose-300 space-y-1 font-mono">
                  {result.errors.map((err, i) => (
                    <li key={i}>{err}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
