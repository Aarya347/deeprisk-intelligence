const jsonHeaders = { "Content-Type": "application/json" };

async function handle(res) {
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

async function downloadFile(url, fallbackFilename) {
  const res = await fetch(url);
  if (!res.ok) {
    let errDetail = `${res.status} ${res.statusText}`;
    try {
      const errJson = await res.json();
      if (errJson.detail) errDetail = errJson.detail;
    } catch {
      // ignore json parse error
    }
    throw new Error(errDetail);
  }
  const blob = await res.blob();
  const downloadUrl = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = downloadUrl;

  const disposition = res.headers.get("Content-Disposition") || "";
  let filename = fallbackFilename;
  const match = disposition.match(/filename="?([^";]+)"?/i);
  if (match && match[1]) {
    filename = match[1];
  }

  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(downloadUrl);
}

export const api = {
  getRepositories: () => fetch("/api/repositories").then(handle),
  getFindings: (repoId, tier, triageStatus) => {
    const params = new URLSearchParams();
    if (repoId) params.append("repository_id", repoId);
    if (tier) params.append("tier", tier);
    if (triageStatus) params.append("triage_status", triageStatus);
    const qs = params.toString();
    return fetch(`/api/findings${qs ? `?${qs}` : ""}`).then(handle);
  },
  getStats: (repoId) =>
    fetch(`/api/stats${repoId ? `?repository_id=${repoId}` : ""}`).then(handle),
  triggerScan: (org) =>
    fetch("/api/scan", { method: "POST", headers: jsonHeaders, body: JSON.stringify({ github_org: org }) }).then(handle),
  scanLocal: (path, name) =>
    fetch("/api/scan/local", { method: "POST", headers: jsonHeaders, body: JSON.stringify({ path, name }) }).then(handle),
  scanUpload: (file, projectName) => {
    const formData = new FormData();
    formData.append("file", file);
    if (projectName) formData.append("project_name", projectName);
    return fetch("/api/scan/upload", { method: "POST", body: formData }).then(handle);
  },
  triageFinding: (findingId, status, notes = "", user = "Security Team") =>
    fetch(`/api/findings/${findingId}/triage`, {
      method: "PATCH",
      headers: jsonHeaders,
      body: JSON.stringify({ status, notes, user }),
    }).then(handle),
  subscribeScanProgress: (jobId, onEvent, onError, onComplete) => {
    const es = new EventSource(`/api/scan/progress/${jobId}`);
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (onEvent) onEvent(data);
        if (data.type === "job_completed" || data.status === "completed") {
          es.close();
          if (onComplete) onComplete(data);
        } else if (data.type === "job_failed" || data.status === "failed") {
          es.close();
          if (onError) onError(new Error(data.message || "Scan failed"));
        }
      } catch (err) {
        console.error("Error parsing SSE data", err);
      }
    };
    es.onerror = (err) => {
      es.close();
      if (onError) onError(err);
    };
    return () => es.close();
  },
  setExposure: (repoId, tier) =>
    fetch(`/api/repositories/${repoId}`, { method: "PATCH", headers: jsonHeaders, body: JSON.stringify({ exposure_tier: tier }) }).then(handle),
  downloadRepoReport: (repoId, repoName = "repository") => {
    const safe = repoName.replace(/[\/\\]/g, "-");
    return downloadFile(`/api/reports/${repoId}`, `${safe}-report.md`);
  },
  downloadRepoPdfReport: (repoId, repoName = "repository") => {
    const safe = repoName.replace(/[\/\\]/g, "-");
    return downloadFile(`/api/reports/${repoId}/pdf`, `${safe}-executive-report.pdf`);
  },
  downloadOrgReport: (orgName) => {
    const safe = (orgName || "org").replace(/[\/\\]/g, "-");
    return downloadFile(`/api/reports/org/${encodeURIComponent(orgName)}`, `${safe}-report.md`);
  },
  downloadOrgPdfReport: (orgName) => {
    const safe = (orgName || "org").replace(/[\/\\]/g, "-");
    return downloadFile(`/api/reports/org/${encodeURIComponent(orgName)}/pdf`, `${safe}-executive-report.pdf`);
  },
};
