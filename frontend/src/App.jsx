import { useEffect, useState } from "react";
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
import "./App.css";

const API_BASE = "http://localhost:8080";
const COLORS = ["#43d9ce", "#4da9f6", "#a78bfa", "#f6bd60", "#fb7185"];
const ROLES = {
  admin: { username: "admin_root", role: "admin", token: "token_admin_root" },
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
const sev = (s) => `sev sev-${String(s || "low").toLowerCase()}`;

const Kpi = ({ label, value, hint, tone }) => (
  <div className={`kpi ${tone ? `tone-${tone}` : ""}`}>
    <span>{label}</span>
    <strong>{value ?? "—"}</strong>
    <small>{hint}</small>
  </div>
);

function App() {
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState(null);
  const [evidence, setEvidence] = useState(null);
  const [signature, setSignature] = useState(null);
  const [loading, setLoading] = useState(false);
  const [incidents, setIncidents] = useState([]);
  const [evaluating, setEvaluating] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState(null);
  const [searching, setSearching] = useState(false);
  const [sparkData, setSparkData] = useState(null);
  const [sparkLoading, setSparkLoading] = useState(false);
  const [selectedTarget, setSelectedTarget] = useState("target-web");
  const [attackResult, setAttackResult] = useState(null);
  const [attacking, setAttacking] = useState(false);
  const [webFindings, setWebFindings] = useState(null);
  const [webScanError, setWebScanError] = useState(null);
  const [exploitingWeb, setExploitingWeb] = useState(false);
  const [serviceQuery, setServiceQuery] = useState("");
  const [serviceStateFilter, setServiceStateFilter] = useState("all");
  const [apiOnline, setApiOnline] = useState(false);
  const [currentUser, setCurrentUser] = useState(ROLES.admin);
  const [auditLogs, setAuditLogs] = useState([]);
  const [tab, setTab] = useState("web");

  useEffect(() => {
    const id = axios.interceptors.request.use((config) => {
      if (currentUser?.token) {
        config.headers = config.headers ?? {};
        config.headers["X-Auth-Token"] = currentUser.token;
      }
      return config;
    });
    return () => axios.interceptors.request.eject(id);
  }, [currentUser]);

  useEffect(() => {
    let active = true;
    const check = async () => {
      try {
        await axios.get(`${API_BASE}/health`, { timeout: 3000 });
        if (active) setApiOnline(true);
      } catch {
        if (active) setApiOnline(false);
      }
    };
    check();
    const interval = window.setInterval(check, 10000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, []);

  const runSparkAnalytics = async () => {
    setSparkLoading(true);
    try {
      setSparkData((await axios.get(`${API_BASE}/analytics/spark`)).data);
    } catch {
      alert(
        "PySpark job failed. Ensure a scan has been run and backend is live.",
      );
    } finally {
      setSparkLoading(false);
    }
  };
  const runWebExploits = async () => {
    setExploitingWeb(true);
    setWebScanError(null);
    setWebFindings(null);
    setTab("web");
    try {
      setWebFindings((await axios.get(`${API_BASE}/scan/web`)).data);
    } catch (err) {
      const response = err.response?.data;
      setWebScanError(
        typeof response === "string"
          ? response
          : response?.error ||
              err.message ||
              "Web vulnerability assessment failed.",
      );
    } finally {
      setExploitingWeb(false);
    }
  };
  const runScan = async () => {
    setLoading(true);
    setScanError(null);
    try {
      setScanResult(
        (await axios.get(`${API_BASE}/scan?target=${selectedTarget}`)).data,
      );
    } catch (err) {
      setScanError(err.response?.data || "Scan failed.");
      alert(err.response?.data || "Scan failed.");
    } finally {
      setLoading(false);
    }
  };
  const protectEvidence = async () => {
    try {
      setEvidence((await axios.get(`${API_BASE}/protect`)).data);
    } catch (err) {
      alert(err.response?.data || "Protection failed.");
    }
  };
  const signEvidence = async () => {
    try {
      setSignature((await axios.get(`${API_BASE}/sign`)).data);
    } catch {
      alert("Signing failed.");
    }
  };
  const fetchIncidents = async () => {
    setEvaluating(true);
    try {
      setIncidents((await axios.get(`${API_BASE}/incidents`)).data || []);
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
      setSearchResults(
        (
          await axios.get(
            `${API_BASE}/search?q=${encodeURIComponent(searchQuery)}`,
          )
        ).data,
      );
    } catch {
      alert("Search failed. Ensure backend is running.");
    } finally {
      setSearching(false);
    }
  };
  const runSSHAttack = async () => {
    setAttacking(true);
    try {
      setAttackResult((await axios.get(`${API_BASE}/attack/ssh`)).data);
    } catch (err) {
      alert(err.response?.data || "SSH Attack simulation failed.");
    } finally {
      setAttacking(false);
    }
  };
  const fetchAuditLogs = async () => {
    try {
      setAuditLogs((await axios.get(`${API_BASE}/audit`)).data);
    } catch (err) {
      alert(
        err.response?.data ||
          "Access Denied: Only Auditor or Admin can view audit logs.",
      );
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

  const services = scanResult?.services || [];
  const visibleServices = services.filter((s) => {
    const q = serviceQuery.trim().toLowerCase();
    const hit =
      !q ||
      [s.port, s.protocol, s.state, s.service, s.version].some((v) =>
        String(v ?? "")
          .toLowerCase()
          .includes(q),
      );
    return (
      hit &&
      (serviceStateFilter === "all" ||
        s.state?.toLowerCase() === serviceStateFilter)
    );
  });
  const openCount = services.filter(
    (s) => s.state?.toLowerCase() === "open",
  ).length;
  const protocolRows = sparkData?.protocol_distribution || [];
  const talkerRows = sparkData?.top_talkers || [];
  const anomalies = sparkData?.anomalies_detected || [];
  const protocolTotal = protocolRows.reduce(
    (sum, r) => sum + (Number(r.count) || 0),
    0,
  );
  const talkerMax = Math.max(
    0,
    ...talkerRows.map((r) => Number(r.flow_count) || 0),
  );
  const captureState = loading
    ? "scanning"
    : scanError
      ? "failed"
      : scanResult
        ? "complete"
        : "idle";
  const stateTitle = {
    scanning: "Assessment in progress",
    complete: "Latest assessment complete",
    failed: "Assessment failed",
    idle: "Ready for assessment",
  }[captureState];
  const stateDetail =
    captureState === "complete"
      ? `Target: ${scanResult.target}`
      : captureState === "scanning"
        ? `Scanning ${selectedTarget}`
        : captureState === "failed"
          ? String(scanError)
          : "Run a port scan to populate the network inventory.";
  const findings = webFindings?.findings || [];

  return (
    <div className="app-shell">
      <div className="app-container mx-auto max-w-[1480px] space-y-5 px-4 py-6 sm:px-6 lg:px-8">
        <header className="app-header flex flex-wrap items-center justify-between gap-4 px-5 py-3.5">
          <div className="flex items-center gap-3">
            <div className="brand-mark">
              <Shield className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight">
                CyberSentinel
              </h1>
              <p className="text-xs text-slate-400">
                Security operations and forensics
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <span
              className={`system-status ${apiOnline ? "is-online" : "is-offline"}`}
            >
              <span className="status-dot" />
              {apiOnline ? "API connected" : "API offline"}
            </span>
            <select
              value={currentUser.role}
              onChange={(e) => setCurrentUser(ROLES[e.target.value])}
              aria-label="Select active demo role"
              className="role-select px-3 py-2 text-xs font-semibold text-slate-200"
            >
              <option value="admin">Admin · admin_root</option>
              <option value="analyst">Analyst · Alice</option>
              <option value="investigator">Investigator · Bob</option>
              <option value="auditor">Auditor · Clara</option>
            </select>
            <span className="role-pill">{currentUser.role}</span>
          </div>
        </header>

        <section className="capture-banner" aria-live="polite">
          <div className="capture-indicator">
            <span className={`capture-pulse ${captureState}`} />
            <div>
              <p className="eyebrow">Network intelligence</p>
              <strong>{stateTitle}</strong>
              <span>{stateDetail}</span>
            </div>
          </div>
          <div className="hero-actions">
            <select
              id="scan-target"
              aria-label="Lab target"
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
              className="target-select"
            >
              <option value="target-web">Web target · HTTP</option>
              <option value="target-ssh">SSH target · Port 22</option>
            </select>
            <button
              onClick={runScan}
              disabled={loading}
              className="action-primary disabled:opacity-50"
            >
              <Search className="h-4 w-4" />
              {loading ? "Scanning…" : "Run port scan"}
            </button>
            <button
              onClick={runWebExploits}
              disabled={exploitingWeb}
              className="action-secondary disabled:opacity-50"
            >
              <Shield className="h-4 w-4" />
              {exploitingWeb ? "Checking…" : "Assess web vulnerabilities"}
            </button>
            <button
              onClick={runSSHAttack}
              disabled={attacking}
              className="action-quiet disabled:opacity-50"
            >
              <Activity className="h-4 w-4" />
              {attacking ? "Running…" : "SSH simulation"}
            </button>
          </div>
        </section>

        <section className="kpi-strip" aria-label="Key metrics">
          <Kpi
            label="Services discovered"
            value={scanResult ? services.length : null}
            hint={scanResult ? `on ${scanResult.target}` : "Run a port scan"}
            tone="accent"
          />
          <Kpi
            label="Open ports"
            value={scanResult ? openCount : null}
            hint="from latest scan"
            tone="ok"
          />
          <Kpi
            label="Packet records analyzed"
            value={sparkData?.total_analyzed_flows}
            hint={sparkData?.engine || "Run flow analytics"}
          />
          <Kpi
            label="Flow anomalies"
            value={sparkData ? anomalies.length : null}
            hint="port sweep clustering"
            tone={anomalies.length ? "warn" : undefined}
          />
          <Kpi
            label="Correlated incidents"
            value={incidents.length}
            hint="rule engine"
            tone={incidents.length ? "bad" : undefined}
          />
        </section>

        <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
          <div className="min-w-0 space-y-5">
            <section className="assessment-card p-5 sm:p-6">
              <div className="panel-head">
                <div>
                  <h2>
                    <Terminal className="h-4 w-4 text-sky-300" />
                    Port scan results
                  </h2>
                  <p>Services returned by the latest Nmap assessment</p>
                </div>
                <span className="target-chip">
                  {scanResult?.target || selectedTarget}
                </span>
              </div>
              {scanResult ? (
                <>
                  <div className="table-toolbar" style={{ marginTop: 0 }}>
                    <p className="table-title">
                      {visibleServices.length} of {services.length} services
                    </p>
                    <div className="table-filters">
                      <label className="table-search">
                        <Search className="h-4 w-4" />
                        <input
                          aria-label="Search discovered services"
                          placeholder="Search ports, service…"
                          value={serviceQuery}
                          onChange={(e) => setServiceQuery(e.target.value)}
                        />
                      </label>
                      <select
                        aria-label="Filter service state"
                        value={serviceStateFilter}
                        onChange={(e) => setServiceStateFilter(e.target.value)}
                      >
                        <option value="all">All states</option>
                        <option value="open">Open</option>
                        <option value="closed">Closed</option>
                        <option value="filtered">Filtered</option>
                      </select>
                    </div>
                  </div>
                  {visibleServices.length ? (
                    <div className="data-table-wrap">
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>State</th>
                            <th>Service</th>
                            <th>Version / details</th>
                          </tr>
                        </thead>
                        <tbody>
                          {visibleServices.map((s, i) => (
                            <tr key={`${s.port}-${s.protocol}-${i}`}>
                              <td className="mono-cell">{s.port}</td>
                              <td>{s.protocol?.toUpperCase() || "—"}</td>
                              <td>
                                <span
                                  className={`severity-chip ${s.state?.toLowerCase() === "open" ? "severity-open" : "severity-neutral"}`}
                                >
                                  {s.state || "Unknown"}
                                </span>
                              </td>
                              <td className="service-name">
                                {s.service || "Unknown"}
                              </td>
                              <td className="muted-cell">{s.version || "—"}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div className="empty-state p-6 text-center text-sm text-slate-400">
                      {services.length
                        ? "No services match these filters."
                        : "The scan returned no service rows. Raw scanner output is below."}
                    </div>
                  )}
                  <details className="raw-output">
                    <summary>View raw Nmap output</summary>
                    <pre className="scan-output mt-3 overflow-x-auto p-4 text-xs leading-6">
                      {scanResult.raw}
                    </pre>
                  </details>
                </>
              ) : (
                <div className="empty-state flex min-h-36 flex-col items-center justify-center px-6 text-center">
                  <Terminal className="mb-3 h-6 w-6 text-slate-600" />
                  <p className="text-sm font-medium text-slate-300">
                    {scanError
                      ? "The scan could not complete"
                      : "No scan results yet"}
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    {scanError
                      ? String(scanError)
                      : "Choose a lab target and run a port scan."}
                  </p>
                </div>
              )}
            </section>

            <section className="analytics-card p-5 sm:p-6">
              <div className="panel-head">
                <div>
                  <h2>
                    <Activity className="h-4 w-4 text-sky-300" />
                    Network flow intelligence
                  </h2>
                  <p>Aggregated flow analysis from the Spark engine</p>
                </div>
                <button
                  onClick={runSparkAnalytics}
                  disabled={sparkLoading}
                  className="action-quiet inline-flex items-center gap-2 px-3 py-2 text-xs font-semibold disabled:opacity-50"
                >
                  <Activity className="h-3.5 w-3.5" />
                  {sparkLoading ? "Analyzing flows…" : "Run flow analytics"}
                </button>
              </div>
              {sparkData ? (
                <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
                  <div className="chart-panel">
                    <div className="chart-heading">
                      <div>
                        <h3>Top source IPs</h3>
                        <p>Ranked by captured packet records</p>
                      </div>
                      <span className="chart-badge">
                        {talkerRows.length} sources
                      </span>
                    </div>
                    {talkerRows.length ? (
                      <ul className="talker-list">
                        {talkerRows.map((t, i) => (
                          <li key={`${t.src_ip}-${i}`}>
                            <div className="talker-label">
                              <span>{t.src_ip}</span>
                              <strong>{t.flow_count}</strong>
                            </div>
                            <div className="bar-track">
                              <span
                                style={{
                                  width: `${talkerMax ? Math.max(3, (Number(t.flow_count) / talkerMax) * 100) : 0}%`,
                                }}
                              />
                            </div>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <div className="chart-empty">
                        No source IP aggregates returned.
                      </div>
                    )}
                  </div>
                  <div className="chart-panel">
                    <div className="chart-heading">
                      <div>
                        <h3>Protocol distribution</h3>
                        <p>Share of captured packet records</p>
                      </div>
                      <span className="chart-badge">
                        {protocolTotal} packets
                      </span>
                    </div>
                    {protocolRows.length && protocolTotal > 0 ? (
                      <div className="protocol-chart">
                        <svg
                          viewBox="0 0 120 120"
                          role="img"
                          aria-label="Protocol distribution donut chart"
                        >
                          <circle
                            className="donut-track"
                            cx="60"
                            cy="60"
                            r="45"
                          />
                          {(() => {
                            let offset = 0;
                            return protocolRows.map((p, i) => {
                              const dash =
                                (Math.max(0, Number(p.count) || 0) /
                                  protocolTotal) *
                                282.743;
                              const seg = (
                                <circle
                                  key={`${p.protocol}-${i}`}
                                  cx="60"
                                  cy="60"
                                  r="45"
                                  fill="none"
                                  stroke={COLORS[i % 5]}
                                  strokeWidth="12"
                                  strokeDasharray={`${dash} ${282.743 - dash}`}
                                  strokeDashoffset={-offset}
                                  transform="rotate(-90 60 60)"
                                >
                                  <title>{`${p.protocol}: ${p.count}`}</title>
                                </circle>
                              );
                              offset += dash;
                              return seg;
                            });
                          })()}
                        </svg>
                        <div className="protocol-legend">
                          {protocolRows.map((p, i) => (
                            <div
                              className="legend-row"
                              key={`${p.protocol}-${i}`}
                            >
                              <span className={`legend-dot color-${i % 5}`} />
                              <span>{p.protocol}</span>
                              <strong>{p.count}</strong>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <div className="chart-empty">
                        No protocol distribution available.
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="empty-state p-8 text-center text-sm text-slate-400">
                  Run flow analytics to see top source IPs and protocol mix from
                  captured flows.
                </div>
              )}
            </section>
          </div>

          <aside className="space-y-5">
            <section className="surface-card p-5">
              <div className="panel-head">
                <div>
                  <h2>
                    <AlertCircle className="h-4 w-4 text-red-400" />
                    Detections
                  </h2>
                  <p>Correlated incidents and flow anomalies</p>
                </div>
                <button
                  onClick={fetchIncidents}
                  disabled={evaluating}
                  className="action-quiet px-3 py-1.5 text-xs font-semibold disabled:opacity-50"
                >
                  {evaluating ? "Evaluating…" : "Re-evaluate rules"}
                </button>
              </div>
              <div className="space-y-3">
                {incidents.map((inc, i) => (
                  <div key={i} className="row-item">
                    <div className="flex items-start justify-between gap-3">
                      <h3 className="text-sm font-semibold">{inc.type}</h3>
                      <span className={sev(inc.severity)}>{inc.severity}</span>
                    </div>
                    <p className="mt-0.5 text-xs text-slate-500">
                      {inc.confidence}% confidence
                    </p>
                    {inc.description && (
                      <p className="mt-2 text-sm text-slate-300">
                        {inc.description}
                      </p>
                    )}
                    {inc.evidence_tags?.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {inc.evidence_tags.map((t) => (
                          <span key={t} className="tag">
                            {t}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
                {anomalies.map((a, i) => (
                  <div key={`a${i}`} className="row-item is-warn">
                    <div className="flex items-start justify-between gap-3">
                      <h3 className="text-sm font-semibold">{a.type}</h3>
                      <span className="sev sev-medium">{a.confidence}%</span>
                    </div>
                    <p className="mt-2 font-mono text-xs text-slate-400">
                      {a.source_ip} probed {a.unique_ports_targeted} unique
                      ports ({a.total_probes} probes)
                    </p>
                  </div>
                ))}
                {!incidents.length && !anomalies.length && (
                  <div className="empty-state p-5 text-center text-sm text-slate-400">
                    No detections yet. Run a scan, then re-evaluate rules.
                  </div>
                )}
              </div>
            </section>

            <section className="surface-card p-5">
              <div className="panel-head">
                <div>
                  <h2>
                    <Lock className="h-4 w-4 text-violet-300" />
                    Evidence custody
                  </h2>
                  <p>Seal, sign and export captured evidence</p>
                </div>
              </div>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-3 xl:grid-cols-1">
                <button
                  onClick={protectEvidence}
                  className="action-quiet flex items-center justify-center gap-2 px-3 py-2.5 text-xs font-semibold"
                >
                  <Lock className="h-3.5 w-3.5" />
                  Seal latest capture
                </button>
                <button
                  onClick={signEvidence}
                  className="action-quiet flex items-center justify-center gap-2 px-3 py-2.5 text-xs font-semibold"
                >
                  <Shield className="h-3.5 w-3.5" />
                  Sign evidence hash
                </button>
                <button
                  onClick={downloadReport}
                  className="action-quiet flex items-center justify-center gap-2 px-3 py-2.5 text-xs font-semibold"
                >
                  <Download className="h-3.5 w-3.5" />
                  Export report
                </button>
              </div>
              {evidence && (
                <div className="mt-4 space-y-2 text-xs">
                  <p className="font-semibold text-sky-300">
                    Sealed with AES-256-GCM
                  </p>
                  <p className="text-slate-400">
                    File{" "}
                    <span className="font-mono text-slate-200">
                      {evidence.filename}
                    </span>
                  </p>
                  <span className="hash">SHA-256 {evidence.hash}</span>
                </div>
              )}
              {signature && (
                <div className="mt-4 space-y-2 text-xs">
                  <p className="font-semibold text-violet-300">
                    Signed by {signature.signer} · {signature.status}
                  </p>
                  <span className="hash">{signature.signature}</span>
                </div>
              )}
            </section>

            {attackResult && (
              <section className="surface-card p-5">
                <div className="panel-head">
                  <div>
                    <h2>
                      <Activity className="h-4 w-4 text-amber-300" />
                      SSH simulation
                    </h2>
                    <p>
                      Simulated connection attempts; no passwords are
                      authenticated
                    </p>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    ["Target", attackResult.target],
                    ["Attempts", attackResult.attempts],
                    ["Connections", attackResult.failed_logins],
                    ["Duration", attackResult.duration],
                  ].map(([l, v]) => (
                    <div key={l} className="metric-tile">
                      <span>{l}</span>
                      <strong>{v ?? "—"}</strong>
                    </div>
                  ))}
                </div>
              </section>
            )}
          </aside>
        </div>

        <section className="surface-card p-5 sm:p-6">
          <div className="tabs" role="tablist">
            {[
              [
                "web",
                `Web findings${webFindings ? ` (${findings.length})` : ""}`,
              ],
              ["vault", "Vault search"],
              ["audit", "Audit trail"],
            ].map(([k, l]) => (
              <button
                key={k}
                role="tab"
                aria-selected={tab === k}
                onClick={() => setTab(k)}
                className={`tab ${tab === k ? "is-active" : ""}`}
              >
                {l}
              </button>
            ))}
          </div>

          {tab === "web" &&
            (webScanError ? (
              <div className="row-item is-warn text-sm" role="alert">
                <strong>Assessment request failed</strong>
                <p className="mt-1 text-xs text-slate-400">{webScanError}</p>
                <button
                  onClick={runWebExploits}
                  className="action-quiet mt-3 px-3 py-2 text-xs font-semibold"
                >
                  Retry assessment
                </button>
              </div>
            ) : exploitingWeb ? (
              <div
                className="empty-state p-8 text-center text-sm text-slate-400"
                role="status"
              >
                <span className="capture-pulse scanning mx-auto mb-3" />
                Running six checks against the lab web target…
              </div>
            ) : webFindings ? (
              <div className="space-y-4">
                <div className="assessment-summary">
                  <div>
                    <p className="eyebrow">WEB ASSESSMENT</p>
                    <h3>
                      {webFindings.total_vulnerabilities ?? findings.length}{" "}
                      confirmed finding
                      {(webFindings.total_vulnerabilities ??
                        findings.length) === 1
                        ? ""
                        : "s"}
                    </h3>
                    <p>
                      Target:{" "}
                      <span className="font-mono">{webFindings.target}</span>
                      {webFindings.timestamp
                        ? ` · ${new Date(webFindings.timestamp).toLocaleString()}`
                        : ""}
                    </p>
                  </div>
                  <span
                    className={`sev ${findings.length ? "sev-high" : "sev-low"}`}
                  >
                    {findings.length ? "FINDINGS CONFIRMED" : "NO FINDINGS"}
                  </span>
                </div>
                {webFindings.errors?.length > 0 && (
                  <div className="row-item is-warn text-xs text-amber-300">
                    <strong>Some checks could not complete</strong>
                    <ul className="mt-2 list-disc space-y-1 pl-5">
                      {webFindings.errors.map((error, i) => (
                        <li key={`${error}-${i}`}>{error}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {webFindings.checks?.length > 0 && (
                  <details className="checks-details">
                    <summary>
                      Assessment checks ({webFindings.checks.length})
                    </summary>
                    <div className="mt-3 space-y-2">
                      {webFindings.checks.map((check, i) => (
                        <div
                          className="check-row"
                          key={`${check.endpoint}-${i}`}
                        >
                          <div>
                            <strong>{check.name}</strong>
                            <p>
                              {check.endpoint} · {check.detail}
                            </p>
                          </div>
                          <span
                            className={`check-status check-${String(check.status).toLowerCase()}`}
                          >
                            {check.status.replaceAll("_", " ")}
                          </span>
                        </div>
                      ))}
                    </div>
                  </details>
                )}
                {!findings.length && !webFindings.errors?.length && (
                  <div className="empty-state p-6 text-center text-sm text-slate-400">
                    All checks completed; no vulnerabilities were confirmed.
                  </div>
                )}
                {findings.map((v, i) => (
                  <div key={`${v.endpoint}-${i}`} className="row-item">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <h3 className="text-sm font-semibold">
                          {v.name || "Detected vulnerability"}
                        </h3>
                        <p className="mt-1 font-mono text-xs text-slate-400">
                          {v.endpoint}
                        </p>
                      </div>
                      <div className="text-right">
                        <span className={sev(v.severity)}>{v.severity}</span>
                        <p className="mt-1 font-mono text-[11px] text-slate-500">
                          CVSS {v.cvss}
                        </p>
                      </div>
                    </div>
                    <p className="mt-3 text-xs text-slate-500">Test payload</p>
                    <code className="break-all text-amber-300">
                      {v.payload}
                    </code>
                    <p className="mt-3 text-xs text-slate-500">
                      Verification evidence
                    </p>
                    <pre className="hash max-h-36 overflow-y-auto whitespace-pre-wrap">
                      {v.proof}
                    </pre>
                    <p className="mt-2 text-[10px] font-semibold tracking-wide text-rose-300">
                      {v.status?.replaceAll("_", " ")}
                    </p>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state p-8 text-center text-sm text-slate-400">
                Run “Assess web vulnerabilities” to check the lab web target.
              </div>
            ))}

          {tab === "vault" && (
            <div>
              <p className="mb-3 text-sm text-slate-400">
                Search sealed evidence with a blind index. The server matches
                HMAC trapdoor tokens, never the plaintext query.
              </p>
              <form onSubmit={handleSearch} className="flex gap-2">
                <input
                  type="text"
                  aria-label="Search encrypted records"
                  placeholder="Search encrypted records (e.g. target-web, 80, nginx)…"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="flex-1 bg-slate-800 border border-slate-600 rounded-md px-4 py-2 text-sm text-white placeholder-slate-400 focus:outline-none focus:border-blue-500"
                />
                <button
                  type="submit"
                  disabled={searching}
                  className="px-5 py-2 text-sm font-semibold text-white disabled:opacity-50"
                >
                  {searching ? "Generating trapdoor…" : "Search"}
                </button>
              </form>
              {searchResults && (
                <div className="mt-4 space-y-3 text-xs">
                  <div>
                    <p className="mb-1 text-slate-400">
                      Trapdoor token (HMAC-SHA256)
                    </p>
                    <span className="hash">{searchResults.trapdoor_token}</span>
                  </div>
                  <p className="text-slate-300">
                    <strong>{searchResults.matches_found}</strong> matching
                    encrypted artifacts
                  </p>
                  <ul className="space-y-1.5">
                    {searchResults.matching_evidence.map((a) => (
                      <li
                        key={a}
                        className="row-item flex items-center gap-2 font-mono"
                        style={{ borderLeftColor: "var(--ok)" }}
                      >
                        <Lock className="h-3 w-3 text-amber-300" />
                        {a}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {tab === "audit" && (
            <div>
              <div className="panel-head">
                <p style={{ margin: 0 }}>
                  Hash-chained activity log. Each entry carries the SHA-256 of
                  the one before it.
                </p>
                <button
                  onClick={fetchAuditLogs}
                  className="action-quiet px-3 py-1.5 text-xs font-semibold"
                >
                  Refresh audit logs
                </button>
              </div>
              {auditLogs.length ? (
                <div className="data-table-wrap">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>Time</th>
                        <th>User (role)</th>
                        <th>Action</th>
                        <th>Status</th>
                        <th>Hash</th>
                      </tr>
                    </thead>
                    <tbody>
                      {auditLogs.map((log) => (
                        <tr key={log.index}>
                          <td className="mono-cell">{log.index}</td>
                          <td>
                            {new Date(log.timestamp).toLocaleTimeString()}
                          </td>
                          <td className="service-name">
                            {log.username} ({log.role})
                          </td>
                          <td>{log.action}</td>
                          <td>
                            <span
                              className={`severity-chip ${log.status === "ALLOWED" ? "severity-open" : "sev-high"}`}
                            >
                              {log.status}
                            </span>
                          </td>
                          <td
                            className="muted-cell font-mono"
                            title={log.current_hash}
                          >
                            {(log.current_hash || "").substring(0, 16)}…
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty-state p-8 text-center text-sm text-slate-400">
                  Refresh to load the audit chain. Only Auditor and Admin roles
                  can view it.
                </div>
              )}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

export default App;
