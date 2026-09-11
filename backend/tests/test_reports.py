from datetime import datetime
from unittest.mock import MagicMock
from app.reports.generator import (
    generate_repository_markdown_report,
    generate_org_markdown_report,
    _calculate_stats,
    _generate_plain_english_summary,
)


def _make_mock_finding(
    risk_score=8.5,
    risk_tier="P0",
    reachable=True,
    pkg_name="axios",
    pkg_ver="1.6.2",
    cve="CVE-2024-39338",
    osv="GHSA-8hc4-vh64-cxmj",
    cvss=7.8,
    sev="HIGH",
    rationale=None,
    fixed_versions=None,
):
    finding = MagicMock()
    finding.risk_score = risk_score
    finding.risk_tier = risk_tier
    finding.reachable = reachable
    finding.rationale = rationale or ["CVSS 7.8 (high) - base severity", "Reachable: package imported in first-party code (x1.15)"]
    finding.evidence = {"method": "npm-static-imports", "imports": [{"file": "src/api.js", "line": 2, "statement": "import axios from 'axios';"}]}

    dep = MagicMock()
    dep.name = pkg_name
    dep.version = pkg_ver

    vuln = MagicMock()
    vuln.cve_id = cve
    vuln.osv_id = osv
    vuln.cvss_score = cvss
    vuln.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    vuln.severity = sev
    vuln.summary = "Server-Side Request Forgery in axios"
    vuln.fixed_versions = fixed_versions or ["1.7.4"]
    vuln.raw = {"details": "Allows attackers to make requests to internal network."}

    return (finding, dep, vuln)


def test_calculate_stats():
    f0 = _make_mock_finding(risk_score=9.0, risk_tier="P0", reachable=True, sev="HIGH")
    f1 = _make_mock_finding(risk_score=7.0, risk_tier="P1", reachable=True, sev="HIGH")
    f2 = _make_mock_finding(risk_score=4.0, risk_tier="P2", reachable=False, sev="MEDIUM")
    f3 = _make_mock_finding(risk_score=2.0, risk_tier="P3", reachable=False, sev="LOW")

    stats = _calculate_stats([f0, f1, f2, f3])
    assert stats["total"] == 4
    assert stats["by_tier"]["P0"] == 1
    assert stats["by_tier"]["P1"] == 1
    assert stats["by_tier"]["P2"] == 1
    assert stats["by_tier"]["P3"] == 1
    assert stats["reachable_count"] == 2
    assert stats["not_reached_count"] == 2
    assert stats["immediate_attention"] == 2


def test_plain_english_summary():
    f0 = _make_mock_finding(risk_score=9.0, risk_tier="P0", reachable=True)
    f3 = _make_mock_finding(risk_score=2.0, risk_tier="P3", reachable=False)

    stats = _calculate_stats([f0, f3])
    summary = _generate_plain_english_summary(stats)

    assert "**2** total findings identified" in summary
    assert "**1** requires immediate attention" in summary
    assert "**1** finding is lower risk because the vulnerable package is not imported" in summary


def test_generate_repository_markdown_report():
    repo = MagicMock()
    repo.github_full_name = "test-org/test-repo"
    repo.exposure_tier = "internet"
    repo.primary_language = "Python"
    repo.default_branch = "main"
    repo.last_scanned_at = datetime(2026, 8, 24, 12, 0, 0)

    f0 = _make_mock_finding(risk_score=9.0, risk_tier="P0", reachable=True)
    f1 = _make_mock_finding(risk_score=3.0, risk_tier="P3", reachable=False)

    md = generate_repository_markdown_report(repo, [f0, f1])

    assert "Dependency Risk & Vulnerability Report: test-org/test-repo" in md
    assert "- **Exposure Tier:** `internet`" in md
    assert "## Summary Statistics" in md
    assert "## 🚨 Threat Analysis: What Happens If Left Unpatched? (P0 / P1)" in md
    assert "Server-Side Request Forgery" in md
    assert "What happens if left unpatched?" in md
    assert "## 📖 Non-Technical Stakeholder Guide & FAQ" in md
    assert "| `axios` | 1.6.2 | `CVE-2024-39338` |" in md


def test_generate_org_markdown_report():
    repo1 = MagicMock()
    repo1.github_full_name = "test-org/repo-1"
    repo1.exposure_tier = "internet"
    repo1.primary_language = "JavaScript"
    repo1.last_scanned_at = datetime(2026, 8, 24, 12, 0, 0)

    repo2 = MagicMock()
    repo2.github_full_name = "test-org/repo-2"
    repo2.exposure_tier = "internal"
    repo2.primary_language = "Python"
    repo2.last_scanned_at = datetime(2026, 8, 24, 12, 5, 0)

    f0 = _make_mock_finding(risk_score=9.0, risk_tier="P0", reachable=True)
    f1 = _make_mock_finding(risk_score=2.5, risk_tier="P3", reachable=False)

    repos_with_findings = [
        (repo1, [f0]),
        (repo2, [f1]),
    ]

    md = generate_org_markdown_report("test-org", repos_with_findings)

    assert "Organization Dependency Risk Report: test-org" in md
    assert "## Organization Aggregate Statistics" in md
    assert "## Repository Overview" in md
    assert "| `test-org/repo-1` |" in md
    assert "| `test-org/repo-2` |" in md
    assert "Repository: test-org/repo-1" in md
    assert "What Happens If Left Unpatched?" in md
    assert "Non-Technical Stakeholder Guide" in md


def test_generate_repository_pdf_report():
    from app.reports.pdf_generator import generate_repository_pdf_report

    repo = MagicMock()
    repo.github_full_name = "test-org/test-repo"
    repo.exposure_tier = "internet"
    repo.primary_language = "Python"
    repo.default_branch = "main"
    repo.last_scanned_at = datetime(2026, 8, 24, 12, 0, 0)

    f0 = _make_mock_finding(risk_score=9.0, risk_tier="P0", reachable=True)
    f0[0].triage_status = "open"
    f1 = _make_mock_finding(risk_score=3.0, risk_tier="P3", reachable=False)
    f1[0].triage_status = "accepted_risk"

    pdf_bytes = generate_repository_pdf_report(repo, [f0, f1])
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")


def test_generate_org_pdf_report():
    from app.reports.pdf_generator import generate_org_pdf_report

    repo1 = MagicMock()
    repo1.github_full_name = "test-org/repo-1"
    repo1.exposure_tier = "internet"
    repo1.primary_language = "JavaScript"
    repo1.last_scanned_at = datetime(2026, 8, 24, 12, 0, 0)

    f0 = _make_mock_finding(risk_score=9.0, risk_tier="P0", reachable=True)
    f0[0].triage_status = "open"

    repos_with_findings = [(repo1, [f0])]
    pdf_bytes = generate_org_pdf_report("test-org", repos_with_findings)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")
