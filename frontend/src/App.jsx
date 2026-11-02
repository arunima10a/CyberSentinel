import React, { useEffect, useState } from "react";
import {
  Shield,
  Activity,
  Lock,
  Search,
  Terminal,
  AlertCircle,
  Download,
} from "lucide-react";
import axios from "axios";

const API_BASE = "http://localhost:8080";

function App() {
  const [scanResult, setScanResult] = useState(null);
  const [evidence, setEvidence] = useState(null);
  const [loading, setLoading] = useState(false);
  const [signature, setSignature] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [evaluating, setEvaluating] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState(null);
  const [searching, setSearching] = useState(false);
  const [sparkData, setSparkData] = useState(null);
  const [selectedTarget, setSelectedTarget] = useState("target-web");
  const [attackResult, setAttackResult] = useState(null);
  const [attacking, setAttacking] = useState(false);
  const [webFindings, setWebFindings] = useState(null);
  const [exploitingWeb, setExploitingWeb] = useState(false);

  const [sparkLoading, setSparkLoading] = useState(false);
  const [apiOnline, setApiOnline] = useState(false);
  const [currentUser, setCurrentUser] = useState({
    username: "admin_root",
    role: "admin",
    token: "token_admin_root",
  });
  const [auditLogs, setAuditLogs] = useState([]);

  useEffect(() => {
    const interceptorId = axios.interceptors.request.use((config) => {
      if (currentUser?.token) {
        config.headers = config.headers ?? {};
        config.headers["X-Auth-Token"] = currentUser.token;
      }
      return config;
    });

    return () => axios.interceptors.request.eject(interceptorId);
  }, [currentUser]);

  useEffect(() => {
    let active = true;
    const checkHealth = async () => {
      try {
        await axios.get(`${API_BASE}/health`, { timeout: 3000 });
        if (active) setApiOnline(true);
      } catch {
        if (active) setApiOnline(false);
      }
    };

    checkHealth();
    const interval = window.setInterval(checkHealth, 10000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, []);

  const runSparkAnalytics = async () => {
    setSparkLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/analytics/spark`);
      setSparkData(res.data);
    } catch (err) {
      alert(
        "PySpark job failed. Ensure a scan has been run and backend is live.",
      );
    } finally {
      setSparkLoading(false);
    }
  };
  const runWebExploits = async () => {
    setExploitingWeb(true);
    try {
      const res = await axios.get(`${API_BASE}/scan/web`);
      setWebFindings(res.data);
    } catch (err) {
      alert(err.response?.data || "Web vulnerability assessment failed.");
    } finally {
      setExploitingWeb(false);
    }
  };

  const runScan = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/scan?target=${selectedTarget}`);
      setScanResult(res.data);
    } catch (err) {
      alert(err.response?.data || "Scan failed.");
    } finally {
      setLoading(false);
    }
  };

  const protectEvidence = async () => {
    try {
      const res = await axios.get(`${API_BASE}/protect`);
      setEvidence(res.data);
    } catch (err) {
      alert(err.response?.data || "Protection failed.");
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

  const fetchIncidents = async () => {
    setEvaluating(true);
    try {
      const res = await axios.get(`${API_BASE}/incidents`);
      setIncidents(res.data || []);
    } catch (err) {
      console.error("Incidents fetch error:", err);
      alert("Failed to evaluate incidents. Check backend logs.");
    } finally {
      setEvaluating(false);
    }
  };

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;
    setSearching(true);
    try {
      const res = await axios.get(
        `${API_BASE}/search?q=${encodeURIComponent(searchQuery)}`,
      );
      setSearchResults(res.data);
    } catch (err) {
      alert("Search failed. Ensure backend is running.");
    } finally {
      setSearching(false);
    }
  };

  const switchRole = (role) => {
    const roleTokens = {
      admin: {
        username: "admin_root",
        role: "admin",
        token: "token_admin_root",
      },
      analyst: {
        username: "analyst_alice",
        role: "analyst",
        token: "token_analyst_123",
      },
      investigator: {
        username: "investigator_bob",
        role: "investigator",
        token: "token_investigator_456",
      },
      auditor: {
        username: "auditor_clara",
        role: "auditor",
        token: "token_auditor_789",
      },
    };
    setCurrentUser(roleTokens[role]);
  };

  const fetchAuditLogs = async () => {
    try {
      const res = await axios.get(`${API_BASE}/audit`);
      setAuditLogs(res.data);
    } catch (err) {
      alert(
        err.response?.data ||
          "Access Denied: Only Auditor or Admin can view audit logs.",
      );
    }
  };

  const runSSHAttack = async () => {
    setAttacking(true);
    try {
      const res = await axios.get(`${API_BASE}/attack/ssh`);
      setAttackResult(res.data);
    } catch (err) {
      alert(err.response?.data || "SSH Attack simulation failed.");
    } finally {
      setAttacking(false);
    }
  };
  const downloadReport = async () => {
    try {
      const res = await axios.get(`${API_BASE}/report/export`, {
        responseType: "blob",
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute(
        "download",
        `CyberSentinel_Forensic_Report_${Date.now()}.json`,
      );
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      alert(
        err.response?.data ||
          "Access Denied: Only Investigator or Admin can export forensic reports.",
      );
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 p-8 font-sans">
      {/* Header with Title and Role Selector */}
      <header className="mb-12 flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-3">
          <Shield className="h-10 w-10 text-blue-500" />
          <div>
            <h1 className="text-3xl font-bold tracking-tight">CyberSentinel</h1>
            <p className="text-xs text-slate-400">
              Security Assessment & Forensic Platform
            </p>
          </div>
        </div>

        {/* --- ROLE SELECTOR STARTS HERE --- */}
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-400 font-medium">
            Active Persona:
          </span>
          <select
            value={currentUser.role}
            onChange={(e) => switchRole(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-semibold text-slate-200 focus:border-blue-500 focus:outline-none"
          >
            <option value="admin">Admin (admin_root) - Global</option>
            <option value="analyst">
              Security Analyst (Alice) - Scan/Analyze
            </option>
            <option value="investigator">
              Forensic Investigator (Bob) - Evidence/Search
            </option>
            <option value="auditor">Auditor (Clara) - Read-only Audit</option>
          </select>
          <span className="text-xs px-2.5 py-1 rounded-full font-mono bg-blue-950 text-blue-300 border border-blue-800">
            Role: {currentUser.role.toUpperCase()}
          </span>
        </div>
        {/* --- ROLE SELECTOR ENDS HERE --- */}
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
            <button
              onClick={downloadReport}
              className="w-full flex items-center justify-center gap-2 rounded-lg border border-cyan-700 bg-cyan-950/30 px-4 py-2.5 font-semibold hover:bg-cyan-900/40 transition-all text-cyan-300 text-xs"
            >
              <Download className="h-3.5 w-3.5" /> Export Court-Ready Forensic
              Package
            </button>
          </div>
        </div>
        <button
          onClick={runSparkAnalytics}
          disabled={sparkLoading}
          className="w-full flex items-center justify-center gap-2 rounded-lg border border-amber-600 bg-amber-950/30 px-4 py-3 font-semibold hover:bg-amber-900/40 transition-all text-amber-400 disabled:opacity-50 text-sm"
        >
          <Activity className="h-4 w-4" />
          {sparkLoading
            ? "Running PySpark Job..."
            : "Run PySpark Big Data Analytics"}
        </button>

        {/* Results Panel */}
        <div className="lg:col-span-2 space-y-6">
          {/* Scan Results */}
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-6 min-h-[200px]">
            <h2 className="mb-4 flex items-center gap-2 text-xl font-semibold">
              <Terminal className="text-green-400" /> Assessment Output
            </h2>
            {scanResult ? (
              <pre className="overflow-x-auto rounded bg-black p-4 text-sm text-green-500 font-mono">
                {scanResult.raw}
              </pre>
            ) : (
              <div className="flex h-32 items-center justify-center text-slate-500 italic">
                Waiting for scan initiation...
              </div>
            )}
          </div>

          {/* Target Range Selection */}
          <div className="mb-4">
            <label className="text-xs font-semibold text-slate-400 block mb-1">
              Select Range Target:
            </label>
            <select
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-semibold text-slate-200 focus:border-blue-500 focus:outline-none"
            >
              <option value="target-web">
                Web Target (target-web) - Port 80 (Nginx)
              </option>
              <option value="target-ssh">
                SSH Lab Server (target-ssh) - Port 22 (OpenSSH)
              </option>
            </select>
          </div>

          <button
            onClick={runScan}
            disabled={loading}
            className="w-full mb-3 flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-3 font-semibold hover:bg-blue-700 transition-all disabled:opacity-50 text-sm"
          >
            {loading ? "Scanning Range..." : `Scan ${selectedTarget}`}
          </button>

          <button
            onClick={runSSHAttack}
            disabled={attacking}
            className="w-full mb-3 flex items-center justify-center gap-2 rounded-lg border border-red-700 bg-red-950/30 px-4 py-3 font-semibold hover:bg-red-900/40 transition-all text-red-400 text-sm disabled:opacity-50"
          >
            {attacking
              ? "Simulating Attack..."
              : "Simulate SSH Brute-Force Attack"}
          </button>
          <button
            onClick={runWebExploits}
            disabled={exploitingWeb}
            className="w-full flex items-center justify-center gap-2 rounded-lg border border-purple-600 bg-purple-950/40 px-4 py-2.5 font-semibold hover:bg-purple-900/50 transition-all text-purple-300 text-xs disabled:opacity-50"
          >
            <Shield className="h-3.5 w-3.5" />
            {exploitingWeb
              ? "Auditing Vulnerabilities..."
              : "Launch Web Exploit Assessment (RCE/SQLi)"}
          </button>

          {/* Confirmed High-Severity Web Exploits */}
          {webFindings && (
            <div className="rounded-xl border border-red-500/40 bg-slate-900 p-6 shadow-2xl">
              <div className="mb-4 flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <h2 className="text-xl font-bold text-red-400 flex items-center gap-2">
                    <AlertCircle className="h-5 w-5 text-red-500" /> Confirmed
                    Exploitable Vulnerabilities (
                    {webFindings.findings?.length || 0})
                  </h2>
                  <p className="text-xs text-slate-400">
                    Automated CVSS-rated vulnerability verification report
                  </p>
                </div>
                <span className="text-xs font-mono bg-red-950 text-red-300 px-3 py-1 rounded border border-red-800 font-bold">
                  {webFindings.errors?.length
                    ? "ASSESSMENT INCOMPLETE"
                    : webFindings.findings?.length
                      ? "VULNERABILITIES FOUND"
                      : "NO VULNERABILITIES FOUND"}
                </span>
              </div>

              {webFindings.errors?.length > 0 && (
                <div className="mb-4 rounded border border-amber-700 bg-amber-950/30 p-3 text-xs text-amber-300">
                  Some checks could not run: {webFindings.errors.join("; ")}
                </div>
              )}

              <div className="space-y-4">
                {(webFindings.findings || []).map((vuln, idx) => (
                  <div
                    key={idx}
                    className="rounded-lg bg-slate-950 border border-red-900/60 p-4 space-y-2"
                  >
                    <div className="flex justify-between items-start">
                      <div>
                        <h3 className="font-bold text-slate-200 text-sm flex items-center gap-2">
                          {vuln.vulnerability}
                        </h3>
                        <span className="text-xs font-mono text-purple-400">
                          Endpoint: {vuln.endpoint}
                        </span>
                      </div>
                      <div className="text-right">
                        <span className="px-2.5 py-0.5 rounded text-xs font-extrabold bg-red-950 text-red-400 border border-red-800">
                          {vuln.severity}
                        </span>
                        <p className="text-[10px] text-slate-500 font-mono mt-1">
                          CVSS: {vuln.cvss_score}
                        </p>
                      </div>
                    </div>

                    <div className="text-xs bg-slate-900 p-2.5 rounded border border-slate-800 space-y-1">
                      <div className="flex gap-2">
                        <span className="text-slate-500">Payload:</span>
                        <code className="text-amber-400 font-mono">
                          {vuln.payload_used}
                        </code>
                      </div>
                      <div className="flex flex-col gap-0.5">
                        <span className="text-slate-500">
                          Proof of Concept:
                        </span>
                        <pre className="text-green-400 font-mono text-[11px] whitespace-pre-wrap bg-black/60 p-2 rounded max-h-24 overflow-y-auto">
                          {vuln.evidence}
                        </pre>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Searchable Encrypted Vault Query */}
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="flex items-center gap-2 text-xl font-semibold text-purple-400">
                <Search className="h-5 w-5" /> Search Encrypted Vault (Blind
                Index)
              </h2>
              <span className="text-xs bg-purple-950 text-purple-300 px-2 py-1 rounded border border-purple-800">
                Zero-Knowledge Search
              </span>
            </div>

            <form onSubmit={handleSearch} className="flex gap-2">
              <input
                type="text"
                placeholder="Search encrypted records (e.g., target-web, 80, nginx, reconnaissance)..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-purple-500 focus:outline-none"
              />
              <button
                type="submit"
                disabled={searching}
                className="rounded-lg bg-purple-600 px-5 py-2 font-semibold text-white hover:bg-purple-700 transition-all disabled:opacity-50 text-sm"
              >
                {searching ? "Generating Trapdoor..." : "Search"}
              </button>
            </form>

            {searchResults && (
              <div className="mt-4 rounded-lg bg-black/50 border border-slate-800 p-4 space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-slate-400">
                    Trapdoor Token (HMAC-SHA256):
                  </span>
                  <span className="font-mono text-purple-400 truncate max-w-xs">
                    {searchResults.trapdoor_token}
                  </span>
                </div>
                <div className="flex justify-between items-center text-xs border-t border-slate-800/60 pt-2">
                  <span className="text-slate-400">
                    Matching Encrypted Artifacts:
                  </span>
                  <span className="font-bold text-slate-200">
                    {searchResults.matches_found} found
                  </span>
                </div>
                {searchResults.matching_evidence.length > 0 && (
                  <ul className="mt-2 space-y-1">
                    {searchResults.matching_evidence.map((artifact) => (
                      <li
                        key={artifact}
                        className="text-xs font-mono text-green-400 bg-slate-900 px-3 py-1.5 rounded border border-slate-800 flex items-center gap-2"
                      >
                        <Lock className="h-3 w-3 text-yellow-400" /> {artifact}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>

          {/* PySpark Big Data Traffic Analytics Panel */}
          <div className="mt-8 rounded-xl border border-amber-500/30 bg-slate-900 p-6">
            <div className="mb-4 flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-2">
                <Activity className="h-6 w-6 text-amber-400" />
                <div>
                  <h2 className="text-xl font-semibold text-amber-300">
                    PySpark Distributed Flow Analytics
                  </h2>
                  <p className="text-xs text-slate-400">
                    Large-scale network traffic baseline & anomaly computation
                  </p>
                </div>
              </div>
              <span className="text-xs bg-amber-950 text-amber-300 px-3 py-1 rounded border border-amber-800 font-mono">
                Apache Spark Standalone
              </span>
            </div>

            {sparkData ? (
              <div className="space-y-6">
                {/* Metrics Row */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
                    <span className="text-xs text-slate-400">
                      Total Analyzed Flows
                    </span>
                    <p className="text-2xl font-bold font-mono text-amber-400">
                      {sparkData.total_analyzed_flows}
                    </p>
                  </div>
                  <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
                    <span className="text-xs text-slate-400">Engine Core</span>
                    <p className="text-sm font-semibold text-slate-200 mt-1">
                      {sparkData.engine}
                    </p>
                  </div>
                  <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
                    <span className="text-xs text-slate-400">
                      Active Anomalies
                    </span>
                    <p className="text-2xl font-bold font-mono text-red-400">
                      {sparkData.anomalies_detected?.length || 0}
                    </p>
                  </div>
                </div>

                {/* Top Talkers & Protocol Distribution */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  {/* Top Talkers */}
                  <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
                    <h3 className="font-semibold text-slate-300 mb-2">
                      Top Talker Source IPs
                    </h3>
                    <ul className="space-y-2">
                      {sparkData.top_talkers?.map((talker, idx) => (
                        <li
                          key={idx}
                          className="flex justify-between items-center bg-slate-900 p-2 rounded border border-slate-800 font-mono"
                        >
                          <span className="text-slate-300">
                            {talker.src_ip}
                          </span>
                          <span className="text-amber-400 font-bold">
                            {talker.flow_count} packets
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Protocol Distribution */}
                  <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
                    <h3 className="font-semibold text-slate-300 mb-2">
                      Protocol Distribution
                    </h3>
                    <ul className="space-y-2">
                      {sparkData.protocol_distribution?.map((proto, idx) => (
                        <li
                          key={idx}
                          className="flex justify-between items-center bg-slate-900 p-2 rounded border border-slate-800 font-mono"
                        >
                          <span className="text-slate-300">
                            {proto.protocol}
                          </span>
                          <span className="text-amber-400 font-bold">
                            {proto.count}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* Spark Detected Anomalies */}
                {sparkData.anomalies_detected?.length > 0 && (
                  <div className="bg-red-950/20 border border-red-500/30 p-4 rounded-lg">
                    <h3 className="font-semibold text-red-400 text-sm mb-3">
                      Spark Anomaly Detection (Port Sweep Clustering)
                    </h3>
                    <div className="space-y-2">
                      {sparkData.anomalies_detected.map((anomaly, idx) => (
                        <div
                          key={idx}
                          className="bg-slate-950 p-3 rounded border border-red-800/60 flex justify-between items-center text-xs"
                        >
                          <div>
                            <span className="font-bold text-red-300">
                              {anomaly.type}
                            </span>
                            <p className="text-slate-400 font-mono mt-0.5">
                              Source: {anomaly.source_ip} probed{" "}
                              {anomaly.unique_ports_targeted} unique ports (
                              {anomaly.total_probes} total probes)
                            </p>
                          </div>
                          <span className="bg-red-950 text-red-400 px-2 py-1 rounded font-bold border border-red-800">
                            {anomaly.confidence}% Confidence
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-8 text-slate-500 text-sm">
                Click "Run PySpark Big Data Analytics" to process network flows
                with Apache Spark.
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
          <div className="mt-8 rounded-xl border border-red-500/30 bg-red-500/5 p-6">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="flex items-center gap-2 text-xl font-semibold text-red-400">
                <AlertCircle /> Correlation Engine: Detected Incidents
              </h2>
              <button
                onClick={fetchIncidents}
                disabled={evaluating}
                className="rounded bg-red-950 px-3 py-1 text-xs font-semibold text-red-300 border border-red-800 hover:bg-red-900 transition-all disabled:opacity-50"
              >
                {evaluating ? "Evaluating Packets..." : "Re-evaluate Rules"}
              </button>
            </div>

            <div className="space-y-4">
              {incidents.map((inc, i) => (
                <div
                  key={i}
                  className="flex items-start justify-between border-l-4 border-red-500 bg-slate-900 p-4 rounded-r"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <h3 className="font-bold text-red-100">{inc.type}</h3>
                      <span className="text-xs text-slate-400">
                        ({inc.confidence}% confidence)
                      </span>
                    </div>

                    {/* Render the dynamic real-world description */}
                    {inc.description && (
                      <p className="text-sm text-slate-300">
                        {inc.description}
                      </p>
                    )}

                    {/* Dynamic Evidence Tags */}
                    <div className="mt-2 flex flex-wrap gap-2">
                      {inc.evidence_tags?.map((tag) => (
                        <span
                          key={tag}
                          className="text-[11px] font-mono bg-red-950/80 text-red-300 px-2 py-0.5 rounded border border-red-800/60"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>

                  <span className="text-xs font-black px-2 py-1 rounded bg-red-950 text-red-400 border border-red-800">
                    {inc.severity}
                  </span>
                </div>
              ))}

              {incidents.length === 0 && (
                <div className="text-center py-6 text-slate-500 text-sm">
                  No active incidents detected. Click "Re-evaluate Rules" after
                  running a scan.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
      <AuditTrail auditLogs={auditLogs} fetchAuditLogs={fetchAuditLogs} />
    </div>
  );
}

function AuditTrail({ auditLogs, fetchAuditLogs }) {
  return (
    <div className="mt-8 rounded-xl border border-slate-800 bg-slate-900 p-6">
      <div className="mb-4 flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-semibold text-slate-200 flex items-center gap-2">
            <Lock className="h-5 w-5 text-cyan-400" /> Immutable Hash-Chained
            Audit Trail
          </h2>
          <p className="text-xs text-slate-400">
            Cryptographically chained activity log (SHA-256 previous-hash
            verification)
          </p>
        </div>
        <button
          onClick={fetchAuditLogs}
          className="rounded bg-cyan-950 px-3 py-1.5 text-xs font-semibold text-cyan-300 border border-cyan-800 hover:bg-cyan-900 transition-all"
        >
          Refresh Audit Logs
        </button>
      </div>

      {auditLogs.length > 0 ? (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 uppercase">
              <tr>
                <th className="p-3">#</th>
                <th className="p-3">Timestamp</th>
                <th className="p-3">User (Role)</th>
                <th className="p-3">Action</th>
                <th className="p-3">Status</th>
                <th className="p-3">Current Hash (SHA-256)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {auditLogs.map((log) => (
                <tr key={log.index} className="hover:bg-slate-800/40">
                  <td className="p-3 font-bold text-slate-500">{log.index}</td>
                  <td className="p-3 text-slate-400">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="p-3 font-bold text-blue-400">
                    {log.username} ({log.role})
                  </td>
                  <td className="p-3">{log.action}</td>
                  <td className="p-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        log.status === "ALLOWED"
                          ? "bg-green-950 text-green-400 border border-green-800"
                          : "bg-red-950 text-red-400 border border-red-800"
                      }`}
                    >
                      {log.status}
                    </span>
                  </td>
                  <td
                    className="p-3 truncate max-w-xs text-slate-400"
                    title={log.current_hash}
                  >
                    {(log.current_hash || "").substring(0, 16)}...
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="text-center py-6 text-slate-500 text-sm">
          Click "Refresh Audit Logs" to load the immutable audit chain.
        </div>
      )}
    </div>
  );
}

export default App;
