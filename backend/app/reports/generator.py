from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.vulns.impact_analyzer import analyze_vulnerability_impact


def _escape_md(text: str | None) -> str:
    if not text:
        return "—"
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def _calculate_stats(findings_rows: list[tuple[Any, Any, Any]]) -> dict[str, Any]:
    """Calculate summary metrics for a list of (Finding, Dependency, Vulnerability) tuples."""
    by_tier = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    reachable_count = 0
    not_reached_count = 0
    unknown_reach_count = 0

    for f, _, v in findings_rows:
        tier = f.risk_tier if f.risk_tier in by_tier else "P3"
        by_tier[tier] += 1

        sev = (getattr(v, "severity", None) or "UNKNOWN").upper()
        if sev in by_severity:
            by_severity[sev] += 1
        else:
            by_severity["UNKNOWN"] += 1

        if f.reachable is True:
            reachable_count += 1
        elif f.reachable is False:
            not_reached_count += 1
        else:
            unknown_reach_count += 1

    total = len(findings_rows)
    return {
        "total": total,
        "by_tier": by_tier,
        "by_severity": by_severity,
        "reachable_count": reachable_count,
        "not_reached_count": not_reached_count,
        "unknown_reach_count": unknown_reach_count,
        "immediate_attention": by_tier["P0"] + by_tier["P1"],
    }


def _generate_plain_english_summary(stats: dict[str, Any]) -> str:
    total = stats["total"]
    immediate = stats["immediate_attention"]
    not_reached = stats["not_reached_count"]
    p0 = stats["by_tier"]["P0"]
    p1 = stats["by_tier"]["P1"]

    if total == 0:
        return "✅ **No security vulnerabilities found.** All scanned dependencies are clean and up to date."

    parts = [
        f"**{total}** total finding{'s' if total != 1 else ''} identified across the scanned codebase.",
    ]
    if immediate > 0:
        verb = "requires" if immediate == 1 else "require"
        parts.append(
            f"⚠️ **{immediate}** {verb} immediate attention (**{p0}** P0 — Fix Now, **{p1}** P1 — This Sprint)."
        )
    else:
        parts.append("✅ No critical P0 or high P1 vulnerabilities require emergency response.")

    if not_reached > 0:
        noun = "finding is" if not_reached == 1 else "findings are"
        parts.append(
            f"🛡️ **{not_reached}** {noun} lower risk because the vulnerable package is not imported or reachable by your first-party application code."
        )

    return " ".join(parts)


def _format_findings_table(findings_rows: list[tuple[Any, Any, Any]]) -> str:
    if not findings_rows:
        return "_No findings recorded for this repository._\n"

    lines = [
        "| Package | Installed Ver | CVE / OSV ID | Base CVSS | Severity | Reachable in Code? | Safe Fixed Version | Risk Tier |",
        "| :--- | :--- | :--- | :---: | :---: | :---: | :--- | :---: |",
    ]

    for f, dep, v in findings_rows:
        pkg_name = _escape_md(dep.name)
        pkg_ver = _escape_md(dep.version) or "—"
        vuln_id = _escape_md(v.cve_id or v.osv_id)
        cvss = f"{float(v.cvss_score):.1f}" if v.cvss_score is not None else "—"
        sev = (getattr(v, "severity", None) or "UNKNOWN").upper()
        reachable_str = "🟢 Yes" if f.reachable is True else ("⚪ No" if f.reachable is False else "❓ Unknown")
        fixed_ver = _escape_md(", ".join(v.fixed_versions)) if getattr(v, "fixed_versions", None) else "—"
        tier = f.risk_tier

        lines.append(
            f"| `{pkg_name}` | {pkg_ver} | `{vuln_id}` | {cvss} | {sev} | {reachable_str} | {fixed_ver} | **{tier}** |"
        )

    return "\n".join(lines) + "\n"


def _format_high_priority_threat_analysis(findings_rows: list[tuple[Any, Any, Any]]) -> str:
    """Format detailed exploit scenarios and plain-English threat breakdowns for high-priority findings."""
    high_priority = [item for item in findings_rows if item[0].risk_tier in ("P0", "P1")]

    if not high_priority:
        return "_No P0 or P1 high-priority vulnerabilities detected. Routine monitoring recommended._\n"

    lines = []
    for idx, (f, dep, v) in enumerate(high_priority, 1):
        vuln_id = v.cve_id or v.osv_id
        score_val = f"{float(f.risk_score):.2f}"
        cvss_val = f"{float(v.cvss_score):.1f}" if v.cvss_score is not None else "N/A"
        sev_val = (getattr(v, "severity", None) or "UNKNOWN").upper()
        reachable_str = "🟢 Reachable (Actively imported in first-party code)" if f.reachable is True else (
            "⚪ Not Reached (Installed but no imports detected in code)" if f.reachable is False else "❓ Reachability Unknown"
        )

        raw_osv = getattr(v, "raw", None) if isinstance(getattr(v, "raw", None), dict) else None
        details_text = raw_osv.get("details") if raw_osv else None

        analysis = analyze_vulnerability_impact(
            summary=getattr(v, "summary", None),
            details=details_text,
            cvss_vector=getattr(v, "cvss_vector", None),
            cvss_score=float(v.cvss_score) if getattr(v, "cvss_score", None) is not None else None,
            fixed_versions=getattr(v, "fixed_versions", None),
            raw_osv=raw_osv,
            pkg_name=dep.name,
        )

        tier_badge = "🔴 P0 (Fix Now)" if f.risk_tier == "P0" else "🟠 P1 (This Sprint)"

        lines.append(f"### {idx}. [{f.risk_tier}] `{dep.name}` @ `{dep.version or 'unknown'}` — {vuln_id}")
        lines.append("")
        lines.append(f"- **Vulnerability Classification:** **{analysis.vuln_type}**")
        lines.append(f"- **Priority Tier & Risk Score:** {tier_badge} | Score: `{score_val}` / 10.0 (Base CVSS: `{cvss_val}` - {sev_val})")
        lines.append(f"- **Code Reachability:** {reachable_str}")
        lines.append("")
        lines.append(f"> **💡 In Plain English:**  ")
        lines.append(f"> {analysis.plain_english}")
        lines.append("")
        lines.append(f"> **🚨 What happens if left unpatched? (Exploit Threat Scenario):**  ")
        lines.append(f"> {analysis.threat_scenario}")
        lines.append("")
        lines.append(f"> **💼 Potential Business & Operational Impact:**  ")
        lines.append(f"> {analysis.business_impact}")
        lines.append("")
        lines.append(f"- **🌐 Attack Vector & Conditions:** `{analysis.attack_vector_label}` (Complexity: `{analysis.attack_complexity}`)")
        lines.append(f"- **🛠️ Recommended Fix:** {analysis.remediation}")
        lines.append("")

        lines.append("- **Priority Scoring Rationale:**")
        if f.rationale and isinstance(f.rationale, list):
            for r in f.rationale:
                lines.append(f"  - {r}")
        else:
            lines.append("  - Calculated from base CVSS, reachability in code, and repository exposure tier.")

        evidence_imports = (f.evidence or {}).get("imports", [])
        if evidence_imports:
            method = (f.evidence or {}).get("method", "static-analysis")
            lines.append(f"- **First-Party Code Import Evidence ({method}):**")
            lines.append("  ```text")
            for imp in evidence_imports:
                if isinstance(imp, dict):
                    file_loc = imp.get("file", "")
                    line_num = imp.get("line", "")
                    stmt = imp.get("statement", "")
                    lines.append(f"  {file_loc}:{line_num}  {stmt}")
                else:
                    lines.append(f"  {imp}")
            lines.append("  ```")

        lines.append("")

    return "\n".join(lines)


def _format_stakeholder_glossary() -> str:
    """Non-technical reference and terminology guide for executives and developers."""
    return """## 📖 Non-Technical Stakeholder Guide & FAQ

This section explains key security metrics in plain, everyday language for project managers, executives, and developers:

### 1. Risk Priority Tiers (P0 – P3)
- **🔴 P0 (Fix Now - Emergency)**: Critical severity and actively imported by your production code. Represents immediate danger of exploitation. **Target Action**: Patch or deploy workaround within 24–48 hours.
- **🟠 P1 (Fix This Sprint - High Priority)**: High severity or reachable medium risk. Could be leveraged by attackers under realistic conditions. **Target Action**: Patch in the current development sprint (1–2 weeks).
- **🟡 P2 (Backlog - Moderate Risk)**: Medium severity vulnerabilities or packages with limited exposure. **Target Action**: Schedule upgrade in upcoming maintenance cycles.
- **⚪ P3 (Monitor - Low Risk)**: Low severity issues, dev-only tools, or packages verified to be unreachable by first-party code. **Target Action**: Update during routine dependency refreshes.

### 2. What is "Code Reachability"?
Traditional scanners look only at `package.json` or `requirements.txt` and assume every package is equally dangerous. 
**Reachability Analysis** inspects your actual application source code:
- **🟢 Reachable**: Your source code directly imports and invokes functions from this package. If the library has a security flaw, attackers can trigger it through your application.
- **⚪ Not Reached**: The package is present in your lockfile or dependency tree, but none of your first-party code imports it. The real-world risk of exploitation is significantly lower.

### 3. Understanding CVSS Scores
The **Common Vulnerability Scoring System (CVSS)** scores theoretical severity from `0.0` to `10.0`:
- `9.0 - 10.0`: **Critical** (Typically zero-interaction, remote code execution or complete system takeover).
- `7.0 - 8.9`: **High** (Direct data theft, severe disruption, or authentication bypass).
- `4.0 - 6.9`: **Medium** (Requires specific conditions or elevated permissions).
- `0.1 - 3.9`: **Low** (Minor information leaks or low-impact defects).
"""


def generate_repository_markdown_report(repo: Any, findings_rows: list[tuple[Any, Any, Any]]) -> str:
    """Generate a comprehensive Markdown report for a single repository's latest scan."""
    findings_rows = sorted(findings_rows, key=lambda x: float(x[0].risk_score or 0.0), reverse=True)
    stats = _calculate_stats(findings_rows)

    scan_date_str = (
        repo.last_scanned_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        if getattr(repo, "last_scanned_at", None)
        else "Never scanned"
    )

    report_lines = [
        f"# 🛡️ Dependency Risk & Vulnerability Report: {repo.github_full_name}",
        "",
        "## Repository Overview",
        "",
        f"- **Repository:** `{repo.github_full_name}`",
        f"- **Scan Date:** {scan_date_str}",
        f"- **Exposure Tier:** `{repo.exposure_tier}` (Internet-facing services receive elevated risk scoring)",
        f"- **Primary Language:** {repo.primary_language or 'N/A'}",
        f"- **Default Branch:** `{repo.default_branch or 'main'}`",
        "",
        "## Executive Summary",
        "",
        _generate_plain_english_summary(stats),
        "",
        "## Summary Statistics",
        "",
        "| Metric | Count | Description |",
        "| :--- | :---: | :--- |",
        f"| **Total Findings** | **{stats['total']}** | Total known vulnerabilities matched in lockfiles and manifests |",
        f"| 🔴 **P0 (Fix Now)** | **{stats['by_tier']['P0']}** | Emergency priority — critical & reachable in first-party code |",
        f"| 🟠 **P1 (This Sprint)** | **{stats['by_tier']['P1']}** | High priority — remediate during current sprint |",
        f"| 🟡 **P2 (Backlog)** | **{stats['by_tier']['P2']}** | Moderate risk — plan for next maintenance release |",
        f"| ⚪ **P3 (Monitor)** | **{stats['by_tier']['P3']}** | Low risk / dev-only / unreached dependencies |",
        f"| 🟢 **Reachable in First-Party Code** | **{stats['reachable_count']}** | Packages confirmed to be imported and used by your code |",
        f"| ⚪ **Not Reached** | **{stats['not_reached_count']}** | Packages installed but not imported (lower exploitation danger) |",
        "",
        "## 🚨 Threat Analysis: What Happens If Left Unpatched? (P0 / P1)",
        "",
        _format_high_priority_threat_analysis(findings_rows),
        "## 📋 All Discovered Findings",
        "",
        _format_findings_table(findings_rows),
        "",
        _format_stakeholder_glossary(),
        "",
        "---",
        f"_Report generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} by Dependency Risk Dashboard_",
    ]

    return "\n".join(report_lines)


def generate_org_markdown_report(org_name: str, repos_with_findings: list[tuple[Any, list[tuple[Any, Any, Any]]]]) -> str:
    """Generate a combined Markdown report across all repositories for an organization/user."""
    all_findings: list[tuple[Any, Any, Any]] = []
    repo_stats_list = []

    for repo, f_rows in repos_with_findings:
        sorted_f = sorted(f_rows, key=lambda x: float(x[0].risk_score or 0.0), reverse=True)
        r_stats = _calculate_stats(sorted_f)
        repo_stats_list.append((repo, sorted_f, r_stats))
        all_findings.extend(sorted_f)

    all_stats = _calculate_stats(all_findings)
    total_repos = len(repos_with_findings)
    scanned_repos = sum(1 for repo, _, _ in repo_stats_list if getattr(repo, "last_scanned_at", None))

    report_lines = [
        f"# 🛡️ Organization Dependency Risk Report: {org_name}",
        "",
        "## Executive Summary",
        "",
        f"Combined security risk assessment across **{total_repos}** repositories in organization `{org_name}` (**{scanned_repos}** scanned).",
        "",
        _generate_plain_english_summary(all_stats),
        "",
        "## Organization Aggregate Statistics",
        "",
        "| Metric | Count | Description |",
        "| :--- | :---: | :--- |",
        f"| **Total Repositories** | **{total_repos}** | Total repos discovered in organization |",
        f"| **Repositories Scanned** | **{scanned_repos}** | Repositories with completed security scans |",
        f"| **Total Vulnerability Findings** | **{all_stats['total']}** | Total vulnerability matches across all repos |",
        f"| 🔴 **P0 (Fix Now)** | **{all_stats['by_tier']['P0']}** | Critical, reachable vulnerabilities across org |",
        f"| 🟠 **P1 (This Sprint)** | **{all_stats['by_tier']['P1']}** | High priority issues requiring remediation |",
        f"| 🟡 **P2 (Backlog)** | **{all_stats['by_tier']['P2']}** | Moderate risk issues |",
        f"| ⚪ **P3 (Monitor)** | **{all_stats['by_tier']['P3']}** | Low risk or unreached dependencies |",
        f"| 🟢 **Reachable in Code** | **{all_stats['reachable_count']}** | Vulnerabilities with confirmed import callpaths |",
        f"| ⚪ **Not Reached** | **{all_stats['not_reached_count']}** | Lower immediate danger (not imported) |",
        "",
        "## Repository Overview",
        "",
        "| Repository | Exposure | Language | Last Scanned | Total | P0 | P1 | P2 | P3 | Reachable |",
        "| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]

    for repo, _, r_stats in repo_stats_list:
        scan_date_str = (
            repo.last_scanned_at.strftime("%Y-%m-%d %H:%M")
            if getattr(repo, "last_scanned_at", None)
            else "Never"
        )
        report_lines.append(
            f"| `{repo.github_full_name}` | `{repo.exposure_tier}` | {repo.primary_language or '—'} | {scan_date_str} | {r_stats['total']} | {r_stats['by_tier']['P0']} | {r_stats['by_tier']['P1']} | {r_stats['by_tier']['P2']} | {r_stats['by_tier']['P3']} | {r_stats['reachable_count']} |"
        )

    report_lines.extend(["", "## Detailed Repository Breakdowns", ""])

    for repo, f_rows, r_stats in repo_stats_list:
        scan_date_str = (
            repo.last_scanned_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            if getattr(repo, "last_scanned_at", None)
            else "Never scanned"
        )

        report_lines.extend([
            f"### 📦 Repository: {repo.github_full_name}",
            "",
            f"- **Exposure Tier:** `{repo.exposure_tier}` | **Language:** {repo.primary_language or 'N/A'} | **Last Scanned:** {scan_date_str}",
            f"- **Findings Summary:** {r_stats['total']} total ({r_stats['by_tier']['P0']} P0, {r_stats['by_tier']['P1']} P1, {r_stats['by_tier']['P2']} P2, {r_stats['by_tier']['P3']} P3) — {r_stats['reachable_count']} reachable.",
            "",
        ])

        if r_stats["immediate_attention"] > 0:
            report_lines.extend([
                "#### 🚨 Threat Analysis: What Happens If Left Unpatched? (P0 / P1)",
                "",
                _format_high_priority_threat_analysis(f_rows),
            ])

        report_lines.extend([
            "#### 📋 All Discovered Findings",
            "",
            _format_findings_table(f_rows),
            "",
        ])

    report_lines.extend([
        _format_stakeholder_glossary(),
        "",
        "---",
        f"_Report generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} by Dependency Risk Dashboard_",
    ])

    return "\n".join(report_lines)
