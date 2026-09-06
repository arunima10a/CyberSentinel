import React, { useState } from 'react';
import { Shield, Activity, Lock, Search, Terminal, AlertCircle } from 'lucide-react';
import axios from 'axios';

const API_BASE = "http://localhost:8080";

function App() {
  const [scanResult, setScanResult] = useState(null);
  const [evidence, setEvidence] = useState(null);
  const [loading, setLoading] = useState(false);
  const [signature, setSignature] = useState(null);

  const runScan = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/scan`);
      setScanResult(res.data);
    } catch (err) {
      alert("Scan failed. Is the backend running?");
    }
    setLoading(false);
  };

  const protectEvidence = async () => {
    try {
      const res = await axios.get(`${API_BASE}/protect`);
      setEvidence(res.data);
    } catch (err) {
      alert("No evidence found to protect.");
    }
  };

  const signEvidence = async () => {
    try {
      const res = await axios.get(`${API_BASE}/sign`);
      setSignature(res.data);
    } catch (err) {
      alert("Signing failed.");
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 p-8 font-sans">
      {/* Header */}
      <header className="mb-12 flex items-center justify-between border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <Shield className="h-10 w-10 text-blue-500" />
          <h1 className="text-3xl font-bold tracking-tight">CyberSentinel</h1>
        </div>
        <div className="flex gap-4">
          <div className="flex items-center gap-2 rounded-full bg-green-500/10 px-4 py-1 text-sm font-medium text-green-400 border border-green-500/20">
            <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
            System Online
          </div>
        </div>
      </header>

      <div className="grid grid-cols-1 gap-8 lg:grid-cols-3">
        {/* Actions Panel */}
        <div className="space-y-6">
          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 shadow-xl">
            <h2 className="mb-4 flex items-center gap-2 text-xl font-semibold">
              <Activity className="text-blue-400" /> Operations
            </h2>
            <button
              onClick={runScan}
              disabled={loading}
              className="w-full mb-3 flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-3 font-semibold hover:bg-blue-700 transition-all disabled:opacity-50"
            >
              {loading ? "Scanning..." : "Launch Security Scan"}
            </button>
            <button
              onClick={protectEvidence}
              className="w-full flex items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-800 px-4 py-3 font-semibold hover:bg-slate-700 transition-all"
            >
              <Lock className="h-4 w-4" /> Seal Forensic Evidence
            </button>
            <button
              onClick={signEvidence}
              className="w-full flex items-center justify-center gap-2 rounded-lg border border-purple-700 bg-purple-900/20 px-4 py-3 font-semibold hover:bg-purple-800/30 transition-all text-purple-400"
            >
              Generate Digital Signature
            </button>
          </div>
        </div>

        {/* Results Panel */}
        <div className="lg:col-span-2 space-y-6">
          {/* Scan Results */}
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-6 min-h-[200px]">
            <h2 className="mb-4 flex items-center gap-2 text-xl font-semibold">
              <Terminal className="text-green-400" /> Assessment Output
            </h2>
            {scanResult ? (
              <pre className="overflow-x-auto rounded bg-black p-4 text-sm text-green-500 font-mono">
                {scanResult.output}
              </pre>
            ) : (
              <div className="flex h-32 items-center justify-center text-slate-500 italic">
                Waiting for scan initiation...
              </div>
            )}
          </div>

          {/* Evidence Details */}
          {evidence && (
            <div className="rounded-xl border border-blue-500/30 bg-blue-500/5 p-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
              <h2 className="mb-4 flex items-center gap-2 text-xl font-semibold text-blue-400">
                <Search className="h-5 w-5" /> Evidence Integrity Verified
              </h2>
              <div className="grid gap-4 text-sm">
                <div className="flex justify-between border-b border-slate-800 pb-2">
                  <span className="text-slate-400">Filename:</span>
                  <span className="font-mono">{evidence.filename}</span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-slate-400">SHA-256 Hash:</span>
                  <span className="break-all font-mono text-xs bg-black p-2 rounded text-yellow-500 border border-yellow-500/20">
                    {evidence.hash}
                  </span>
                </div>
                <div className="mt-2 text-xs text-blue-300 flex items-center gap-1">
                  <Lock className="h-3 w-3" /> AES-256-GCM Encryption Applied
                </div>
              </div>
            </div>
          )}
          {signature && (
            <div className="rounded-xl border border-purple-500/30 bg-purple-500/5 p-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
              <h2 className="mb-4 flex items-center gap-2 text-xl font-semibold text-purple-400">
                <Lock className="h-5 w-5" /> Digital Signature Generated
              </h2>
              <div className="grid gap-4 text-sm">
                <div className="flex justify-between border-b border-slate-800 pb-2">
                  <span className="text-slate-400">Signer:</span>
                  <span className="font-mono">{signature.signer}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800 pb-2">
                  <span className="text-slate-400">Status:</span>
                  <span className="font-mono">{signature.status}</span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-slate-400">RSA Signature:</span>
                  <span className="break-all font-mono text-xs bg-black p-2 rounded text-purple-300 border border-purple-500/20">
                    {signature.signature}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;