import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import PriorityTable from "./PriorityTable";
import SeverityChart from "./SeverityChart";
import TierPie from "./TierPie";

const TIER_META = {
  P0: { label: "Fix now", color: "#ef4444" },
  P1: { label: "This sprint", color: "#f97316" },
  P2: { label: "Backlog", color: "#eab308" },
  P3: { label: "Monitor", color: "#64748b" },
};

export default function Dashboard() {
  const [repos, setRepos] = useState([]);
  const [selectedRepo, setSelectedRepo] = useState(""); // "" = all repos
  const [findings, setFindings] = useState([]);
  const [stats, setStats] = useState(null);
  const [onlyReachable, setOnlyReachable] = useState(false);
  const [tierFilter, setTierFilter] = useState("");
  const [triageFilter, setTriageFilter] = useState("active"); // "active" | "all" | "triaged"
  const [searchQuery, setSearchQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [orgInput, setOrgInput] = useState("");
  const [lastScannedOrg, setLastScannedOrg] = useState(
    () => localStorage.getItem("last_scanned_org") || ""
  );
  const [downloading, setDownloading] = useState(false);
  const [reportMsg, setReportMsg] = useState(null);
  const [showGuideModal, setShowGuideModal] = useState(false);

  // Live SSE Scan Progress State
  const [scanProgress, setScanProgress] = useState({
    isOpen: false,
    jobId: null,
    title: "",
    percent: 0,
    phase: "idle",
    message: "",
    status: "idle",
    logs: [],
  });

  // Local / ZIP Scanner Modal State
  const [showLocalModal, setShowLocalModal] = useState(false);
  const [localTab, setLocalTab] = useState("path"); // "path" | "upload"
  const [localPath, setLocalPath] = useState(".");
  const [localName, setLocalName] = useState("");
  const [selectedZipFile, setSelectedZipFile] = useState(null);
  const [uploadProjectName, setUploadProjectName] = useState("");
  const [localScanLoading, setLocalScanLoading] = useState(false);

  const logsEndRef = useRef(null);

  const scrollToBottom = () => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  };

  useEffect(() => {
    if (scanProgress.isOpen) {
      scrollToBottom();
    }
  }, [scanProgress.logs, scanProgress.isOpen]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const repoParam = selectedRepo ? Number(selectedRepo) : undefined;
      const [r, f, s] = await Promise.all([
        api.getRepositories(),
        api.getFindings(repoParam),
        api.getStats(repoParam),
      ]);
      setRepos(r);
      setFindings(f);
      setStats(s);

      // Auto-detect last scanned org if not set yet
      if (!lastScannedOrg && r.length > 0) {
        const recentlyScanned = r.find((x) => x.last_scanned_at) || r[0];
        const detectedOrg = recentlyScanned?.full_name?.split("/")[0];
        if (detectedOrg && detectedOrg !== "local" && detectedOrg !== "upload") {
          setLastScannedOrg(detectedOrg);
          localStorage.setItem("last_scanned_org", detectedOrg);
        }
      }
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [selectedRepo, lastScannedOrg]);

  useEffect(() => {
    load();
  }, [load]);

  const handleTriageUpdated = (findingId, triageData) => {
    setFindings((prev) =>
      prev.map((f) =>
        f.id === findingId
          ? {
            ...f,
            triage_status: triageData.triage_status,
            triage_notes: triageData.triage_notes,
            triaged_by: triageData.triaged_by,
            triaged_at: triageData.triaged_at,
          }
          : f
      )
    );
    // Refresh stats in background
    const repoParam = selectedRepo ? Number(selectedRepo) : undefined;
    api.getStats(repoParam).then(setStats).catch(() => { });
  };

  const visible = useMemo(
    () =>
      findings.filter((x) => {
        const matchesTier = !tierFilter || x.risk_tier === tierFilter;
        const matchesReach = !onlyReachable || x.reachable === true;

        // Triage filter
        const isTriaged = x.triage_status && x.triage_status !== "open";
        let matchesTriage = true;
        if (triageFilter === "active") {
          matchesTriage = !isTriaged;
        } else if (triageFilter === "triaged") {
          matchesTriage = isTriaged;
        }

        const q = searchQuery.toLowerCase().trim();
        const matchesQuery =
          !q ||
          x.dependency?.name?.toLowerCase().includes(q) ||
          x.vulnerability?.cve_id?.toLowerCase().includes(q) ||
          x.vulnerability?.osv_id?.toLowerCase().includes(q) ||
          x.threat_analysis?.vuln_type?.toLowerCase().includes(q) ||
          x.repository?.toLowerCase().includes(q) ||
          (x.triage_notes && x.triage_notes.toLowerCase().includes(q));

        return matchesTier && matchesReach && matchesTriage && matchesQuery;
      }),
    [findings, tierFilter, onlyReachable, triageFilter, searchQuery]
  );

  const startStreamListener = (jobId, title) => {
    setScanProgress({
      isOpen: true,
      jobId,
      title,
      percent: 5,
      phase: "Starting scan…",
      message: "Initializing real-time scan telemetry stream…",
      status: "running",
      logs: [
        {
          time: new Date().toLocaleTimeString(),
          message: `Job initialized: ${title}`,
          type: "info",
        },
      ],
    });

    api.subscribeScanProgress(
      jobId,
      (event) => {
        setScanProgress((prev) => {
          const newLog = {
            time: new Date(event.timestamp ? event.timestamp * 1000 : Date.now()).toLocaleTimeString(),
            message: event.message || JSON.stringify(event),
            type: event.type || "progress",
            repo: event.repo,
          };
          return {
            ...prev,
            percent: event.percent !== undefined ? event.percent : prev.percent,
            phase: event.phase || prev.phase,
            message: event.message || prev.message,
            status: event.status || prev.status,
            logs: [...prev.logs, newLog],
          };
        });
      },
      (err) => {
        setScanProgress((prev) => ({
          ...prev,
          status: "failed",
          message: `Scan failed or disconnected: ${err.message || err}`,
          logs: [
            ...prev.logs,
            {
              time: new Date().toLocaleTimeString(),
              message: `Error: ${err.message || err}`,
              type: "error",
            },
          ],
        }));
      },
      (completionData) => {
        setScanProgress((prev) => ({
          ...prev,
          status: "completed",
          percent: 100,
          phase: "Completed",
          message: completionData.message || "Scan finished successfully!",
          logs: [
            ...prev.logs,
            {
              time: new Date().toLocaleTimeString(),
              message: "✨ Scan finished! Refreshing dependency risk intelligence…",
              type: "success",
            },
          ],
        }));
        load();
      }
    );
  };

  const triggerOrgScan = async () => {
    const org = orgInput.trim();
    if (!org) return;
    setLastScannedOrg(org);
    localStorage.setItem("last_scanned_org", org);
    try {
      const res = await api.triggerScan(org);
      if (res.job_id) {
        startStreamListener(res.job_id, `GitHub Org Scan: ${org}`);
      }
    } catch (err) {
      setError(`Failed to trigger scan: ${err.message}`);
    }
  };

  const handleTriggerLocalScan = async (e) => {
    e.preventDefault();
    if (!localPath.trim()) return;
    setLocalScanLoading(true);
    try {
      const res = await api.scanLocal(localPath.trim(), localName.trim() || undefined);
      setShowLocalModal(false);
      if (res.job_id) {
        startStreamListener(res.job_id, `Local Scan: ${localName.trim() || localPath.trim()}`);
      }
    } catch (err) {
      setError(`Local scan failed: ${err.message}`);
    } finally {
      setLocalScanLoading(false);
    }
  };

  const handleTriggerZipUpload = async (e) => {
    e.preventDefault();
    if (!selectedZipFile) return;
    setLocalScanLoading(true);
    try {
      const res = await api.scanUpload(selectedZipFile, uploadProjectName.trim() || undefined);
      setShowLocalModal(false);
      setSelectedZipFile(null);
      if (res.job_id) {
        startStreamListener(res.job_id, `ZIP Upload Scan: ${uploadProjectName.trim() || selectedZipFile.name}`);
      }
    } catch (err) {
      setError(`ZIP upload scan failed: ${err.message}`);
    } finally {
      setLocalScanLoading(false);
    }
  };

  const handleDownloadRepoReport = async () => {
    if (!selectedRepo) return;
    const repoObj = repos.find((r) => String(r.id) === String(selectedRepo));
    const repoName = repoObj ? repoObj.full_name : `repo-${selectedRepo}`;
    try {
      setDownloading(true);
      setReportMsg("Generating plain-English repo report…");
      await api.downloadRepoReport(selectedRepo, repoName);
      setReportMsg("Markdown report downloaded.");
      setTimeout(() => setReportMsg(null), 3500);
    } catch (err) {
      setError(`Failed to download report: ${err.message}`);
    } finally {
      setDownloading(false);
    }
  };

  const handleDownloadRepoPdf = async () => {
    if (!selectedRepo) return;
    const repoObj = repos.find((r) => String(r.id) === String(selectedRepo));
    const repoName = repoObj ? repoObj.full_name : `repo-${selectedRepo}`;
    try {
      setDownloading(true);
      setReportMsg("Generating styled PDF executive report…");
      await api.downloadRepoPdfReport(selectedRepo, repoName);
      setReportMsg("Executive PDF downloaded.");
      setTimeout(() => setReportMsg(null), 3500);
    } catch (err) {
      setError(`Failed to download PDF report: ${err.message}`);
    } finally {
      setDownloading(false);
    }
  };

  const handleDownloadOrgReport = async () => {
    const org =
      orgInput.trim() ||
      lastScannedOrg ||
      (repos.length > 0 ? repos[0].full_name.split("/")[0] : "");

    if (!org) {
      setError("Please enter or scan an organization first to download an org report.");
      return;
    }
    try {
      setDownloading(true);
      setReportMsg(`Generating plain-English executive report for ${org}…`);
      await api.downloadOrgReport(org);
      setReportMsg("Full report downloaded.");
      setTimeout(() => setReportMsg(null), 3500);
    } catch (err) {
      setError(`Failed to download full report: ${err.message}`);
    } finally {
      setDownloading(false);
    }
  };

  const handleDownloadOrgPdf = async () => {
    const org =
      orgInput.trim() ||
      lastScannedOrg ||
      (repos.length > 0 ? repos[0].full_name.split("/")[0] : "");

    if (!org) {
      setError("Please enter or scan an organization first to download an org report.");
      return;
    }
    try {
      setDownloading(true);
      setReportMsg(`Generating organization-wide executive PDF for ${org}…`);
      await api.downloadOrgPdfReport(org);
      setReportMsg("Organization PDF downloaded.");
      setTimeout(() => setReportMsg(null), 3500);
    } catch (err) {
      setError(`Failed to download organization PDF: ${err.message}`);
    } finally {
      setDownloading(false);
    }
  };

  const kpis = [
    { label: "Active Findings", value: stats?.active_findings ?? stats?.total_findings ?? 0, accent: "#f87171" },
    { label: "P0 — Fix now", value: stats?.by_tier?.P0 ?? 0, accent: "#ef4444" },
    { label: "P1 — This sprint", value: stats?.by_tier?.P1 ?? 0, accent: "#f97316" },
    { label: "Reachable in code", value: stats?.reachable_count ?? 0, accent: "#38bdf8" },
    { label: "Triaged / Suppressed", value: stats?.triaged_count ?? 0, accent: "#a78bfa" },
    { label: "Total findings", value: stats?.total_findings ?? 0 },
  ];

  return (
    <div className="dashboard">
      <header className="toolbar">
        <div className="toolbar-brand">
          <h1>🛡️ Dependency Risk & Threat Dashboard</h1>
        </div>

        <select
          value={selectedRepo}
          onChange={(e) => setSelectedRepo(e.target.value)}
        >
          <option value="">All repositories ({repos.length})</option>
          {repos.map((r) => (
            <option key={r.id} value={r.id}>
              {r.full_name} ({r.exposure_tier})
            </option>
          ))}
        </select>

        <button className="btn" onClick={load} disabled={loading} title="Reload findings">
          ↻ Refresh
        </button>

        <button
          className="btn local-btn"
          onClick={() => setShowLocalModal(true)}
          title="Scan a local folder or upload a ZIP archive without GitHub token"
        >
          📁 Scan Local / ZIP
        </button>

        <button
          className="btn guide-btn"
          onClick={() => setShowGuideModal(true)}
          title="Explain risk tiers, reachability, and threat scenarios"
        >
          📖 Risk Guide
        </button>

        {selectedRepo && (
          <>
            <button
              className="btn pdf-btn"
              onClick={handleDownloadRepoPdf}
              disabled={downloading}
              title="Download Formatted Executive PDF for the selected repository"
            >
              📄 Repo PDF
            </button>
            <button
              className="btn"
              onClick={handleDownloadRepoReport}
              disabled={downloading}
              title="Download Plain-English Markdown report for the selected repository"
            >
              📥 Repo MD
            </button>
          </>
        )}

        <button
          className="btn pdf-btn"
          onClick={handleDownloadOrgPdf}
          disabled={downloading}
          title="Download Organization Executive PDF Report"
        >
          📄 Org PDF
        </button>

        <button
          className="btn"
          onClick={handleDownloadOrgReport}
          disabled={downloading}
          title="Download combined Plain-English Markdown report for the organization"
        >
          📑 Org MD
        </button>

        <div className="scan-box">
          <input
            placeholder="GitHub org / user…"
            value={orgInput}
            onChange={(e) => setOrgInput(e.target.value)}
          />
          <button className="btn primary" onClick={triggerOrgScan}>
            Scan org
          </button>
        </div>

        {reportMsg && <span className="hint report-hint">{reportMsg}</span>}
      </header>

      {error && <div className="banner error">⚠️ {error}</div>}
      {loading && <div className="banner">Loading dependency intelligence…</div>}

      {!loading && !error && (
        <>
          <section className="kpis">
            {kpis.map((k) => (
              <div className="kpi card" key={k.label}>
                <div
                  className="kpi-value"
                  style={k.accent ? { color: k.accent } : null}
                >
                  {k.value}
                </div>
                <div className="kpi-label">{k.label}</div>
              </div>
            ))}
          </section>

          <section className="charts">
            <div className="card">
              <h3>Vulnerabilities by severity</h3>
              <SeverityChart data={stats?.by_severity ?? {}} />
            </div>
            <div className="card">
              <h3>Action priority tiers</h3>
              <TierPie data={stats?.by_tier ?? {}} />
            </div>
          </section>

          <section className="filters card">
            <div className="filter-item">
              <label>Triage State:</label>
              <select
                value={triageFilter}
                onChange={(e) => setTriageFilter(e.target.value)}
                className="filter-select"
              >
                <option value="active">🔴 Active Findings Only (Default)</option>
                <option value="all">🌐 All Findings (Active + Triaged)</option>
                <option value="triaged">🛡️ Triaged Only (False Positives / Accepted)</option>
              </select>
            </div>

            <div className="filter-item">
              <label>Risk Tier:</label>
              <select
                value={tierFilter}
                onChange={(e) => setTierFilter(e.target.value)}
              >
                <option value="">All Tiers (P0 – P3)</option>
                {Object.entries(TIER_META).map(([t, m]) => (
                  <option key={t} value={t}>
                    {t} — {m.label}
                  </option>
                ))}
              </select>
            </div>

            <div className="filter-item">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={onlyReachable}
                  onChange={(e) => setOnlyReachable(e.target.checked)}
                />
                <strong>Only Reachable</strong> (Actively imported)
              </label>
            </div>

            <div className="filter-item search-item">
              <input
                type="text"
                className="search-input"
                placeholder="Search package, CVE, vuln type, or triage note..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>

            <span className="hint count-hint">{visible.length} findings displayed</span>
          </section>

          <PriorityTable
            findings={visible}
            onTriageUpdated={handleTriageUpdated}
          />
        </>
      )}

      {/* Real-Time SSE Scan Progress Modal */}
      {scanProgress.isOpen && (
        <div className="modal-backdrop">
          <div className="modal-content scan-progress-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="scan-modal-title">
                <h2>⚡ Live Scan Engine Telemetry</h2>
                <span className={`status-pill ${scanProgress.status}`}>
                  {scanProgress.status === "running" && "🔄 Scanning..."}
                  {scanProgress.status === "completed" && "✅ Finished"}
                  {scanProgress.status === "failed" && "❌ Failed"}
                </span>
              </div>
              {scanProgress.status !== "running" && (
                <button
                  className="modal-close"
                  onClick={() => setScanProgress((prev) => ({ ...prev, isOpen: false }))}
                >
                  ✕
                </button>
              )}
            </div>

            <div className="modal-body">
              <div className="scan-job-heading">
                <h3>{scanProgress.title}</h3>
                <div className="scan-phase-tag">{scanProgress.phase}</div>
              </div>

              {/* Animated Progress Bar */}
              <div className="progress-bar-track">
                <div
                  className={`progress-bar-fill ${scanProgress.status}`}
                  style={{ width: `${Math.max(scanProgress.percent, 5)}%` }}
                />
              </div>
              <div className="progress-bar-labels">
                <span>{scanProgress.message}</span>
                <strong>{scanProgress.percent}%</strong>
              </div>

              {/* Streaming Terminal Log Window */}
              <div className="log-terminal">
                <div className="log-terminal-header">
                  <span>TERMINAL LOG STREAM</span>
                  <span className="terminal-job-id">ID: {scanProgress.jobId}</span>
                </div>
                <div className="log-terminal-body">
                  {scanProgress.logs.map((l, i) => (
                    <div key={i} className={`log-line ${l.type}`}>
                      <span className="log-time">[{l.time}]</span>{" "}
                      {l.repo && <span className="log-repo">[{l.repo}]</span>}{" "}
                      <span className="log-msg">{l.message}</span>
                    </div>
                  ))}
                  <div ref={logsEndRef} />
                </div>
              </div>
            </div>

            <div className="modal-footer">
              {scanProgress.status === "running" ? (
                <span className="dim text-sm">Streaming live telemetry via Server-Sent Events…</span>
              ) : (
                <button
                  className="btn primary"
                  onClick={() => setScanProgress((prev) => ({ ...prev, isOpen: false }))}
                >
                  View Updated Dashboard
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Local Folder & ZIP Upload Scanner Modal */}
      {showLocalModal && (
        <div className="modal-backdrop" onClick={() => setShowLocalModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>📁 Local & Offline Project Scanner</h2>
              <button className="modal-close" onClick={() => setShowLocalModal(false)}>
                ✕
              </button>
            </div>

            <div className="modal-tabs">
              <button
                className={`tab-btn ${localTab === "path" ? "active" : ""}`}
                onClick={() => setLocalTab("path")}
              >
                📂 Local Server Path
              </button>
              <button
                className={`tab-btn ${localTab === "upload" ? "active" : ""}`}
                onClick={() => setLocalTab("upload")}
              >
                📦 Upload Project ZIP
              </button>
            </div>

            <div className="modal-body">
              {localTab === "path" ? (
                <form onSubmit={handleTriggerLocalScan}>
                  <p className="lead-text">
                    Scan any local project folder directly on your server or machine without needing GitHub tokens or internet repos.
                  </p>
                  <div className="form-group">
                    <label><strong>Directory Path:</strong></label>
                    <input
                      type="text"
                      value={localPath}
                      onChange={(e) => setLocalPath(e.target.value)}
                      placeholder="e.g. . or C:\Users\Projects\my-app"
                      className="form-input"
                      required
                    />
                    <span className="dim text-xs">Use <code>.</code> to scan current workspace, or provide absolute folder path.</span>
                  </div>

                  <div className="form-group">
                    <label><strong>Repository / Project Label (Optional):</strong></label>
                    <input
                      type="text"
                      value={localName}
                      onChange={(e) => setLocalName(e.target.value)}
                      placeholder="e.g. local/my-service"
                      className="form-input"
                    />
                  </div>

                  <div className="modal-footer">
                    <button type="button" className="btn" onClick={() => setShowLocalModal(false)}>
                      Cancel
                    </button>
                    <button type="submit" className="btn primary" disabled={localScanLoading}>
                      {localScanLoading ? "Starting…" : "Start Local Scan"}
                    </button>
                  </div>
                </form>
              ) : (
                <form onSubmit={handleTriggerZipUpload}>
                  <p className="lead-text">
                    Upload a <code>.zip</code> archive of your codebase to discover dependencies, query OSV, and run AST reachability.
                  </p>
                  <div className="form-group">
                    <label><strong>Select Project ZIP:</strong></label>
                    <input
                      type="file"
                      accept=".zip"
                      onChange={(e) => setSelectedZipFile(e.target.files?.[0] || null)}
                      className="form-input-file"
                      required
                    />
                  </div>

                  <div className="form-group">
                    <label><strong>Project Name:</strong></label>
                    <input
                      type="text"
                      value={uploadProjectName}
                      onChange={(e) => setUploadProjectName(e.target.value)}
                      placeholder="e.g. payments-backend"
                      className="form-input"
                    />
                  </div>

                  <div className="modal-footer">
                    <button type="button" className="btn" onClick={() => setShowLocalModal(false)}>
                      Cancel
                    </button>
                    <button type="submit" className="btn primary" disabled={!selectedZipFile || localScanLoading}>
                      {localScanLoading ? "Uploading & Scanning…" : "Upload & Scan ZIP"}
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Non-Technical Guide & Stakeholder Explainer Modal */}
      {showGuideModal && (
        <div className="modal-backdrop" onClick={() => setShowGuideModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>📖 Non-Technical Risk & Threat Guide</h2>
              <button className="modal-close" onClick={() => setShowGuideModal(false)}>
                ✕
              </button>
            </div>
            <div className="modal-body">
              <p className="lead-text">
                This dashboard translates technical CVE security advisories into clear, prioritized business risk.
              </p>

              <div className="guide-section">
                <h3>1. Priority Action Tiers</h3>
                <div className="guide-grid">
                  <div className="guide-card p0">
                    <strong>🔴 P0 (Fix Now - Emergency)</strong>
                    <p>Critical severity AND directly imported by production code. High danger of active exploitation. Target SLA: &lt; 48 hours.</p>
                  </div>
                  <div className="guide-card p1">
                    <strong>🟠 P1 (This Sprint - High Priority)</strong>
                    <p>High severity issues in reachable code or critical issues with minor constraints. Remediate in the active sprint.</p>
                  </div>
                  <div className="guide-card p2">
                    <strong>🟡 P2 (Backlog - Moderate Risk)</strong>
                    <p>Moderate severity issues or packages behind internal firewalls. Schedule for upcoming releases.</p>
                  </div>
                  <div className="guide-card p3">
                    <strong>⚪ P3 (Monitor - Low Danger)</strong>
                    <p>Low severity, dev-only tools, or packages verified to not be imported by your code.</p>
                  </div>
                </div>
              </div>

              <div className="guide-section">
                <h3>2. Security Triage & Risk Acceptance</h3>
                <p>
                  Not every vulnerability is exploitable in your specific environment. Security teams can triage findings directly on the dashboard:
                </p>
                <ul>
                  <li><strong>🛡️ Accepted Risk:</strong> The library is behind a private VPC or in a dev sandbox where the flaw cannot be triggered.</li>
                  <li><strong>🚫 False Positive:</strong> The vulnerable submodule or function is not utilized by your product features.</li>
                  <li><strong>🔒 Mitigated:</strong> Compensating controls (e.g., WAF regex, input sanitization) prevent exploitation.</li>
                  <li><strong>⏳ Snoozed:</strong> Scheduled for remediation in an upcoming refactoring sprint.</li>
                </ul>
              </div>

              <div className="guide-section">
                <h3>3. Why "Code Reachability" Matters</h3>
                <p>
                  Traditional scanners trigger alarms whenever a vulnerable package is listed in <code>package.json</code> or <code>requirements.txt</code>.
                  However, modern applications only call a fraction of their installed code.
                </p>
                <ul>
                  <li><strong>🟢 Reachable:</strong> Your source code contains active <code>import</code> or <code>require</code> statements for this package. Attackers can reach the flawed code through your application.</li>
                  <li><strong>⚪ Not Reached:</strong> The package is installed as a sub-dependency or unused library, but never imported in application code. Exploit danger is significantly reduced.</li>
                </ul>
              </div>

              <div className="guide-section">
                <h3>4. Common Exploit Types Explained</h3>
                <ul>
                  <li><strong>Remote Code Execution (RCE):</strong> Attacker runs arbitrary commands on your server, taking full control.</li>
                  <li><strong>SQL Injection:</strong> Attacker manipulates database queries to steal or alter customer data.</li>
                  <li><strong>Prototype Pollution:</strong> Modifies JavaScript object behavior, leading to bypasses or crashes.</li>
                  <li><strong>Server-Side Request Forgery (SSRF):</strong> Tricks your server into revealing internal keys or private microservices.</li>
                  <li><strong>Denial of Service (DoS):</strong> Freezes or crashes your server, disrupting user access.</li>
                </ul>
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn primary" onClick={() => setShowGuideModal(false)}>
                Got it, close guide
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
