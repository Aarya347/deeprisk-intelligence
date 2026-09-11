import React, { useState } from "react";
import { api } from "../api";

const TIER_META = {
  P0: { label: "Fix now", color: "#ef4444" },
  P1: { label: "This sprint", color: "#f97316" },
  P2: { label: "Backlog", color: "#eab308" },
  P3: { label: "Monitor", color: "#64748b" },
};

const TRIAGE_META = {
  open: { label: "Active", className: "triage-active", icon: "🔴" },
  accepted_risk: { label: "Accepted Risk", className: "triage-accepted", icon: "🛡️" },
  false_positive: { label: "False Positive", className: "triage-fp", icon: "🚫" },
  mitigated: { label: "Mitigated", className: "triage-mitigated", icon: "🔒" },
  snoozed: { label: "Snoozed", className: "triage-snoozed", icon: "⏳" },
};

function ReachBadge({ reachable }) {
  if (reachable === true) return <span className="badge red" title="Package is imported by your code">Reachable</span>;
  if (reachable === false) return <span className="badge gray" title="Package installed but not imported">Not reached</span>;
  return <span className="badge gray">Unknown</span>;
}

function TriageBadge({ status }) {
  const meta = TRIAGE_META[status] || TRIAGE_META.open;
  return (
    <span className={`badge ${meta.className}`} title={`Triage Status: ${meta.label}`}>
      {meta.icon} {meta.label}
    </span>
  );
}

export default function PriorityTable({ findings, onTriageUpdated }) {
  const [expanded, setExpanded] = useState(null);
  const [triagingFinding, setTriagingFinding] = useState(null);
  const [triageStatus, setTriageStatus] = useState("accepted_risk");
  const [triageNotes, setTriageNotes] = useState("");
  const [triagerName, setTriagerName] = useState(() => localStorage.getItem("triager_name") || "SecOps Team");
  const [savingTriage, setSavingTriage] = useState(false);
  const [triageError, setTriageError] = useState(null);

  const openTriageModal = (f, e) => {
    e.stopPropagation();
    setTriagingFinding(f);
    setTriageStatus(f.triage_status !== "open" ? f.triage_status : "accepted_risk");
    setTriageNotes(f.triage_notes || "");
    setTriageError(null);
  };

  const handleSaveTriage = async (e) => {
    e.preventDefault();
    if (!triagingFinding) return;
    setSavingTriage(true);
    setTriageError(null);
    try {
      localStorage.setItem("triager_name", triagerName);
      const res = await api.triageFinding(triagingFinding.id, triageStatus, triageNotes, triagerName);
      if (onTriageUpdated) {
        onTriageUpdated(triagingFinding.id, res);
      }
      setTriagingFinding(null);
    } catch (err) {
      setTriageError(err.message || "Failed to update triage status");
    } finally {
      setSavingTriage(false);
    }
  };

  if (!findings.length) return <p className="empty">No findings match the active filters.</p>;

  return (
    <>
      <table className="findings">
        <thead>
          <tr>
            <th>Tier</th>
            <th>Score</th>
            <th>Status</th>
            <th>Repo</th>
            <th>Package</th>
            <th>Vulnerability</th>
            <th>CVSS</th>
            <th>Severity</th>
            <th>Reachable</th>
            <th>Fixed in</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => {
            const open = expanded === f.id;
            const threat = f.threat_analysis || {};
            const isTriaged = f.triage_status && f.triage_status !== "open";

            return (
              <React.Fragment key={f.id}>
                <tr
                  className={`clickable ${isTriaged ? "row-triaged" : ""}`}
                  onClick={() => setExpanded(open ? null : f.id)}
                >
                  <td>
                    <span className="badge" style={{ background: TIER_META[f.risk_tier]?.color || "#64748b" }}>
                      {f.risk_tier}
                    </span>
                  </td>
                  <td><strong>{f.risk_score.toFixed(1)}</strong></td>
                  <td><TriageBadge status={f.triage_status} /></td>
                  <td>{f.repository}</td>
                  <td>
                    <strong>{f.dependency.name}</strong>
                    <span className="dim"> @{f.dependency.version || "?"}</span>
                    {f.dependency.is_dev && <span className="badge gray">dev</span>}
                  </td>
                  <td className="mono">{f.vulnerability.cve_id || f.vulnerability.osv_id}</td>
                  <td>{f.vulnerability.cvss_score ?? "—"}</td>
                  <td>
                    <span className={`sev ${f.vulnerability.severity?.toLowerCase() ?? "none"}`}>
                      {f.vulnerability.severity ?? "N/A"}
                    </span>
                  </td>
                  <td><ReachBadge reachable={f.reachable} /></td>
                  <td className="mono dim">{f.vulnerability.fixed_versions?.join(", ") || "—"}</td>
                  <td>
                    <button
                      className="btn-sm triage-btn"
                      onClick={(e) => openTriageModal(f, e)}
                      title="Mark as False Positive, Risk Accepted, or Mitigated"
                    >
                      🛡️ Triage
                    </button>
                  </td>
                </tr>

                {open && (
                  <tr className="detail-row">
                    <td colSpan={11}>
                      <div className="detail">
                        <div className="detail-header">
                          <div className="detail-title">
                            <span className="vuln-category-badge">
                              {threat.vuln_type || "Security Vulnerability"}
                            </span>
                            <h3>{f.vulnerability.summary || "No summary provided"}</h3>
                          </div>
                          <div className="detail-actions">
                            <button
                              className="btn primary btn-sm"
                              onClick={(e) => openTriageModal(f, e)}
                            >
                              🛡️ Triage Decision
                            </button>
                            {threat.attack_vector_label && (
                              <div className="vector-pill" title="Attack vector and accessibility">
                                🌐 {threat.attack_vector_label}
                              </div>
                            )}
                          </div>
                        </div>

                        {/* If triaged, display dedicated audit banner */}
                        {isTriaged && (
                          <div className="triage-audit-banner">
                            <div className="triage-audit-header">
                              <strong>{TRIAGE_META[f.triage_status]?.icon} Triage Status: {TRIAGE_META[f.triage_status]?.label}</strong>
                              <span className="dim text-xs">
                                Triaged by <strong>{f.triaged_by || "SecOps"}</strong> {f.triaged_at ? `on ${new Date(f.triaged_at).toLocaleDateString()}` : ""}
                              </span>
                            </div>
                            {f.triage_notes && (
                              <p className="triage-audit-notes">
                                <em>"{f.triage_notes}"</em>
                              </p>
                            )}
                          </div>
                        )}

                        {/* Plain-English & Unpatched Threat Breakdown */}
                        <div className="threat-cards-grid">
                          <div className="threat-box plain-english-box">
                            <div className="threat-box-title">
                              💡 In Plain English (What this means)
                            </div>
                            <p>{threat.plain_english || f.vulnerability.summary || "Security flaw in dependency."}</p>
                          </div>

                          <div className="threat-box exploit-box">
                            <div className="threat-box-title">
                              🚨 What happens if left unpatched? (Exploit Scenario)
                            </div>
                            <p>
                              {threat.threat_scenario ||
                                "If left unpatched, an attacker may exploit this weakness through malicious inputs or network calls."}
                            </p>
                            {threat.business_impact && (
                              <div className="threat-impact">
                                <strong>Business Impact: </strong>
                                {threat.business_impact}
                              </div>
                            )}
                          </div>
                        </div>

                        {/* Remediation Guidance */}
                        <div className="remediation-box">
                          <div className="remediation-title">🛠️ Recommended Action / Safe Patch</div>
                          <p>{threat.remediation || "Upgrade to the latest patched version."}</p>
                        </div>

                        {/* Technical Deep Dive: Rationale & Reachability Evidence */}
                        <div className="cols">
                          <div>
                            <h4>📊 Why this risk score ({f.risk_score.toFixed(2)})</h4>
                            <ul className="rationale-list">
                              {(f.rationale || []).map((r, i) => (
                                <li key={i}>{r}</li>
                              ))}
                            </ul>
                          </div>
                          <div>
                            <h4>
                              🔍 First-party reachability evidence ({f.evidence?.method || "static-analysis"})
                            </h4>
                            {(f.evidence?.imports || []).length ? (
                              <pre>
                                {f.evidence.imports
                                  .map((h) =>
                                    typeof h === "string"
                                      ? h
                                      : `${h.file}:${h.line}  ${h.statement}`
                                  )
                                  .join("\n")}
                              </pre>
                            ) : (
                              <pre className="dim">(Package is not directly imported in scanned code)</pre>
                            )}
                          </div>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            );
          })}
        </tbody>
      </table>

      {/* Triage Decision Modal */}
      {triagingFinding && (
        <div className="modal-backdrop" onClick={() => setTriagingFinding(null)}>
          <div className="modal-content triage-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>🛡️ Security Triage Decision</h2>
              <button className="modal-close" onClick={() => setTriagingFinding(null)}>
                ✕
              </button>
            </div>
            <form onSubmit={handleSaveTriage}>
              <div className="modal-body">
                <div className="triage-target-info">
                  <strong>Target:</strong> {triagingFinding.dependency.name} @ {triagingFinding.dependency.version} ({triagingFinding.vulnerability.cve_id || triagingFinding.vulnerability.osv_id})
                  <div className="dim text-xs">Repo: {triagingFinding.repository} | Risk Score: {triagingFinding.risk_score.toFixed(1)} ({triagingFinding.risk_tier})</div>
                </div>

                {triageError && <div className="banner error">{triageError}</div>}

                <div className="form-group">
                  <label><strong>Triage Decision Status:</strong></label>
                  <select
                    value={triageStatus}
                    onChange={(e) => setTriageStatus(e.target.value)}
                    className="form-select"
                  >
                    <option value="open">🔴 Active (Open / Unresolved)</option>
                    <option value="accepted_risk">🛡️ Accepted Risk (Internal, firewall-isolated, or sandbox)</option>
                    <option value="false_positive">🚫 False Positive (Not applicable to our usage/feature)</option>
                    <option value="mitigated">🔒 Mitigated (Compensating controls / WAF rule in place)</option>
                    <option value="snoozed">⏳ Snoozed (Scheduled for future refactor / 30 days)</option>
                  </select>
                </div>

                <div className="form-group">
                  <label><strong>Justification / Audit Notes:</strong></label>
                  <textarea
                    rows={3}
                    placeholder="Explain why this risk is accepted, mitigated, or false positive (e.g., 'Internal microservice behind VPC; untrusted user input is impossible')."
                    value={triageNotes}
                    onChange={(e) => setTriageNotes(e.target.value)}
                    className="form-textarea"
                  />
                </div>

                <div className="form-group">
                  <label><strong>Reviewer / Engineer Name:</strong></label>
                  <input
                    type="text"
                    value={triagerName}
                    onChange={(e) => setTriagerName(e.target.value)}
                    placeholder="e.g. Security Lead"
                    className="form-input"
                    required
                  />
                </div>
              </div>

              <div className="modal-footer">
                <button type="button" className="btn" onClick={() => setTriagingFinding(null)}>
                  Cancel
                </button>
                <button type="submit" className="btn primary" disabled={savingTriage}>
                  {savingTriage ? "Saving Decision…" : "Save Triage Decision"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
