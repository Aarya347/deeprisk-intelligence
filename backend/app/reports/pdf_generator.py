from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.reports.generator import _calculate_stats, _generate_plain_english_summary
from app.vulns.impact_analyzer import analyze_vulnerability_impact


def _build_pdf_styles():
    base_styles = getSampleStyleSheet()
    
    styles = {
        "title": ParagraphStyle(
            "DocTitle",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0F172A"),
        ),
        "subtitle": ParagraphStyle(
            "DocSubtitle",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=15,
            textColor=colors.HexColor("#475569"),
        ),
        "h1": ParagraphStyle(
            "Heading1_Custom",
            parent=base_styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1E293B"),
            spaceBefore=14,
            spaceAfter=6,
        ),
        "h2": ParagraphStyle(
            "Heading2_Custom",
            parent=base_styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#2563EB"),
            spaceBefore=10,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "Body_Custom",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13.5,
            textColor=colors.HexColor("#1E293B"),
        ),
        "body_bold": ParagraphStyle(
            "Body_Bold",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9.5,
            leading=13.5,
            textColor=colors.HexColor("#0F172A"),
        ),
        "callout": ParagraphStyle(
            "Callout",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13.5,
            textColor=colors.HexColor("#0C4A6E"),
        ),
        "threat_title": ParagraphStyle(
            "ThreatTitle",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=14,
            textColor=colors.HexColor("#0F172A"),
        ),
        "threat_box": ParagraphStyle(
            "ThreatBox",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12.5,
            textColor=colors.HexColor("#334155"),
        ),
        "table_cell": ParagraphStyle(
            "TableCell",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=10.5,
            textColor=colors.HexColor("#1E293B"),
        ),
        "table_cell_bold": ParagraphStyle(
            "TableCellBold",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10.5,
            textColor=colors.HexColor("#0F172A"),
        ),
        "table_header": ParagraphStyle(
            "TableHeader",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11,
            textColor=colors.white,
        ),
        "badge_p0": ParagraphStyle(
            "BadgeP0",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=10,
            textColor=colors.HexColor("#DC2626"),
        ),
        "badge_p1": ParagraphStyle(
            "BadgeP1",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=10,
            textColor=colors.HexColor("#EA580C"),
        ),
        "badge_p2": ParagraphStyle(
            "BadgeP2",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=10,
            textColor=colors.HexColor("#CA8A04"),
        ),
        "badge_p3": ParagraphStyle(
            "BadgeP3",
            parent=base_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=10,
            textColor=colors.HexColor("#64748B"),
        ),
        "footer": ParagraphStyle(
            "Footer",
            parent=base_styles["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#94A3B8"),
            alignment=1,
        ),
    }
    return styles


def generate_repository_pdf_report(repo: Any, findings_rows: list[tuple[Any, Any, Any]]) -> bytes:
    """Generate a high-quality executive PDF report for a single repository."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = _build_pdf_styles()
    story = []

    findings_rows = sorted(findings_rows, key=lambda x: float(x[0].risk_score or 0.0), reverse=True)
    stats = _calculate_stats(findings_rows)

    scan_date_str = (
        repo.last_scanned_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        if getattr(repo, "last_scanned_at", None)
        else "Never scanned"
    )

    # 1. Header Banner
    story.append(Paragraph("🛡️ Security & Dependency Risk Report", styles["title"]))
    story.append(Paragraph(f"Repository: <b>{repo.github_full_name}</b> | Scan Date: {scan_date_str}", styles["subtitle"]))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563EB"), spaceAfter=12))

    # 2. Executive Overview Grid
    overview_data = [
        [
            Paragraph(f"<b>Exposure Tier:</b> {repo.exposure_tier.upper()}", styles["body"]),
            Paragraph(f"<b>Primary Language:</b> {repo.primary_language or 'N/A'}", styles["body"]),
            Paragraph(f"<b>Default Branch:</b> {repo.default_branch or 'main'}", styles["body"]),
        ]
    ]
    overview_table = Table(overview_data, colWidths=[180, 180, 180])
    overview_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(overview_table)
    story.append(Spacer(1, 12))

    # 3. Summary Callout Box
    plain_summary_raw = _generate_plain_english_summary(stats)
    # Clean markdown formatting for reportlab XML
    plain_summary_clean = plain_summary_raw.replace("**", "<b>").replace("<b>", "<b>", 1)
    # simple bold conversion
    import re
    cleaned_summary = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", plain_summary_raw)

    summary_table = Table([[Paragraph(cleaned_summary, styles["callout"])]], colWidths=[540])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0F9FF")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#BAE6FD")),
        ("PADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 14))

    # 4. KPI Summary Cards Table
    story.append(Paragraph("📊 Summary Risk Metrics", styles["h1"]))
    kpi_data = [
        [
            Paragraph("<b>Total Findings</b>", styles["table_cell_bold"]),
            Paragraph("🔴 <b>P0 (Fix Now)</b>", styles["table_cell_bold"]),
            Paragraph("🟠 <b>P1 (This Sprint)</b>", styles["table_cell_bold"]),
            Paragraph("🟡 <b>P2 (Backlog)</b>", styles["table_cell_bold"]),
            Paragraph("⚪ <b>P3 (Monitor)</b>", styles["table_cell_bold"]),
            Paragraph("🟢 <b>Reachable</b>", styles["table_cell_bold"]),
        ],
        [
            Paragraph(f"<font size='12'><b>{stats['total']}</b></font>", styles["table_cell"]),
            Paragraph(f"<font size='12' color='#DC2626'><b>{stats['by_tier']['P0']}</b></font>", styles["table_cell"]),
            Paragraph(f"<font size='12' color='#EA580C'><b>{stats['by_tier']['P1']}</b></font>", styles["table_cell"]),
            Paragraph(f"<font size='12' color='#CA8A04'><b>{stats['by_tier']['P2']}</b></font>", styles["table_cell"]),
            Paragraph(f"<font size='12' color='#64748B'><b>{stats['by_tier']['P3']}</b></font>", styles["table_cell"]),
            Paragraph(f"<font size='12' color='#16A34A'><b>{stats['reachable_count']}</b></font>", styles["table_cell"]),
        ],
    ]
    kpi_table = Table(kpi_data, colWidths=[90, 90, 90, 90, 90, 90])
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 14))

    # 5. P0 / P1 Exploit Threat Analysis Deep Dive
    high_priority = [item for item in findings_rows if item[0].risk_tier in ("P0", "P1")]
    if high_priority:
        story.append(Paragraph("🚨 High-Priority Threat Analysis (P0 / P1)", styles["h1"]))
        story.append(Paragraph("Detailed exploit scenarios and business impacts for critical/high reachable findings:", styles["body"]))
        story.append(Spacer(1, 8))

        for idx, (f, dep, v) in enumerate(high_priority, 1):
            vuln_id = v.cve_id or v.osv_id
            score_val = f"{float(f.risk_score):.1f}"
            cvss_val = f"{float(v.cvss_score):.1f}" if v.cvss_score is not None else "N/A"
            sev_val = (getattr(v, "severity", None) or "UNKNOWN").upper()
            reachable_str = "🟢 Reachable (Actively Imported)" if f.reachable is True else "⚪ Not Reached"

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

            tier_style = styles["badge_p0"] if f.risk_tier == "P0" else styles["badge_p1"]
            threat_block = [
                [
                    Paragraph(f"<b>#{idx} [{f.risk_tier}] {dep.name} @ {dep.version or '?'}</b> — {vuln_id}", styles["threat_title"]),
                    Paragraph(f"Score: <b>{score_val}/10.0</b> (CVSS: {cvss_val} {sev_val}) | {reachable_str}", styles["body"]),
                ],
                [
                    Paragraph(f"<b>Classification:</b> {analysis.vuln_type} | <b>Vector:</b> {analysis.attack_vector_label}", styles["body_bold"]),
                    Paragraph(f"<b>Recommended Fix:</b> {analysis.remediation}", styles["body_bold"]),
                ],
                [
                    Paragraph(f"<b>💡 In Plain English:</b> {analysis.plain_english}", styles["threat_box"]),
                    Paragraph(f"<b>🚨 Exploit Threat Scenario:</b> {analysis.threat_scenario}", styles["threat_box"]),
                ],
            ]

            t_table = Table(threat_block, colWidths=[270, 270])
            bg_color = colors.HexColor("#FEF2F2") if f.risk_tier == "P0" else colors.HexColor("#FFF7ED")
            border_color = colors.HexColor("#FECACA") if f.risk_tier == "P0" else colors.HexColor("#FED7AA")
            t_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), bg_color),
                ("BOX", (0, 0), (-1, -1), 1, border_color),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(KeepTogether([t_table, Spacer(1, 8)]))

        story.append(Spacer(1, 10))

    # 6. All Discovered Findings Table
    story.append(Paragraph("📋 Complete Vulnerability Inventory", styles["h1"]))
    headers = [
        Paragraph("Tier", styles["table_header"]),
        Paragraph("Score", styles["table_header"]),
        Paragraph("Status", styles["table_header"]),
        Paragraph("Package", styles["table_header"]),
        Paragraph("Vulnerability", styles["table_header"]),
        Paragraph("CVSS", styles["table_header"]),
        Paragraph("Reachable", styles["table_header"]),
        Paragraph("Fixed In", styles["table_header"]),
    ]
    table_rows = [headers]

    for f, dep, v in findings_rows:
        tier_style = (
            styles["badge_p0"] if f.risk_tier == "P0" else
            (styles["badge_p1"] if f.risk_tier == "P1" else
             (styles["badge_p2"] if f.risk_tier == "P2" else styles["badge_p3"]))
        )
        score_val = f"{float(f.risk_score):.1f}"
        pkg_text = f"<b>{dep.name}</b><br/><font color='#64748B'>@{dep.version or '?'}</font>"
        vuln_text = v.cve_id or v.osv_id or "—"
        cvss_text = f"{float(v.cvss_score):.1f}" if v.cvss_score is not None else "—"
        reach_text = "🟢 Yes" if f.reachable is True else ("⚪ No" if f.reachable is False else "—")
        fixed_text = ", ".join(v.fixed_versions) if getattr(v, "fixed_versions", None) else "—"
        triage_status_text = (f.triage_status or "open").replace("_", " ").title()

        table_rows.append([
            Paragraph(f.risk_tier, tier_style),
            Paragraph(score_val, styles["table_cell_bold"]),
            Paragraph(triage_status_text, styles["table_cell"]),
            Paragraph(pkg_text, styles["table_cell"]),
            Paragraph(vuln_text, styles["table_cell"]),
            Paragraph(cvss_text, styles["table_cell"]),
            Paragraph(reach_text, styles["table_cell"]),
            Paragraph(fixed_text, styles["table_cell"]),
        ])

    findings_table = Table(table_rows, colWidths=[40, 40, 65, 115, 105, 45, 55, 75])
    findings_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(findings_table)
    story.append(Spacer(1, 16))

    # 7. Stakeholder Reference FAQ Footer
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8))
    story.append(Paragraph(
        f"Dependency Risk & Exploit Assessment Report • Generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} • Page 1",
        styles["footer"],
    ))

    doc.build(story)
    return buffer.getvalue()


def generate_org_pdf_report(
    org_name: str,
    repos_with_findings: list[tuple[Any, list[tuple[Any, Any, Any]]]],
) -> bytes:
    """Generate a combined executive PDF report across all repositories in an organization."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = _build_pdf_styles()
    story = []

    all_findings = []
    repo_stats_list = []
    for repo, f_rows in repos_with_findings:
        sorted_f = sorted(f_rows, key=lambda x: float(x[0].risk_score or 0.0), reverse=True)
        r_stats = _calculate_stats(sorted_f)
        repo_stats_list.append((repo, sorted_f, r_stats))
        all_findings.extend(sorted_f)

    all_stats = _calculate_stats(all_findings)
    total_repos = len(repos_with_findings)
    scanned_repos = sum(1 for repo, _, _ in repo_stats_list if getattr(repo, "last_scanned_at", None))

    # 1. Header Banner
    story.append(Paragraph("🛡️ Executive Organization Risk Report", styles["title"]))
    story.append(Paragraph(f"Organization: <b>{org_name}</b> | Total Repositories: {total_repos} ({scanned_repos} scanned)", styles["subtitle"]))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563EB"), spaceAfter=12))

    # 2. Executive Summary Box
    import re
    cleaned_summary = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", _generate_plain_english_summary(all_stats))
    summary_table = Table([[Paragraph(cleaned_summary, styles["callout"])]], colWidths=[540])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0F9FF")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#BAE6FD")),
        ("PADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 14))

    # 3. Org KPI Grid
    story.append(Paragraph("📊 Organization-Wide Vulnerability Metrics", styles["h1"]))
    kpi_data = [
        [
            Paragraph("<b>Total Findings</b>", styles["table_cell_bold"]),
            Paragraph("🔴 <b>P0 (Emergency)</b>", styles["table_cell_bold"]),
            Paragraph("🟠 <b>P1 (High)</b>", styles["table_cell_bold"]),
            Paragraph("🟡 <b>P2 (Medium)</b>", styles["table_cell_bold"]),
            Paragraph("⚪ <b>P3 (Low)</b>", styles["table_cell_bold"]),
            Paragraph("🟢 <b>Reachable</b>", styles["table_cell_bold"]),
        ],
        [
            Paragraph(f"<font size='12'><b>{all_stats['total']}</b></font>", styles["table_cell"]),
            Paragraph(f"<font size='12' color='#DC2626'><b>{all_stats['by_tier']['P0']}</b></font>", styles["table_cell"]),
            Paragraph(f"<font size='12' color='#EA580C'><b>{all_stats['by_tier']['P1']}</b></font>", styles["table_cell"]),
            Paragraph(f"<font size='12' color='#CA8A04'><b>{all_stats['by_tier']['P2']}</b></font>", styles["table_cell"]),
            Paragraph(f"<font size='12' color='#64748B'><b>{all_stats['by_tier']['P3']}</b></font>", styles["table_cell"]),
            Paragraph(f"<font size='12' color='#16A34A'><b>{all_stats['reachable_count']}</b></font>", styles["table_cell"]),
        ],
    ]
    kpi_table = Table(kpi_data, colWidths=[90, 90, 90, 90, 90, 90])
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 14))

    # 4. Repository Rollup Table
    story.append(Paragraph("📦 Repository Inventory & Risk Status", styles["h1"]))
    repo_headers = [
        Paragraph("Repository", styles["table_header"]),
        Paragraph("Exposure", styles["table_header"]),
        Paragraph("Language", styles["table_header"]),
        Paragraph("Total", styles["table_header"]),
        Paragraph("P0", styles["table_header"]),
        Paragraph("P1", styles["table_header"]),
        Paragraph("P2", styles["table_header"]),
        Paragraph("P3", styles["table_header"]),
        Paragraph("Reachable", styles["table_header"]),
    ]
    repo_rows = [repo_headers]

    for repo, _, r_stats in repo_stats_list:
        repo_rows.append([
            Paragraph(f"<b>{repo.github_full_name}</b>", styles["table_cell"]),
            Paragraph(repo.exposure_tier.upper(), styles["table_cell"]),
            Paragraph(repo.primary_language or "—", styles["table_cell"]),
            Paragraph(str(r_stats["total"]), styles["table_cell_bold"]),
            Paragraph(f"<font color='#DC2626'><b>{r_stats['by_tier']['P0']}</b></font>", styles["table_cell"]),
            Paragraph(f"<font color='#EA580C'><b>{r_stats['by_tier']['P1']}</b></font>", styles["table_cell"]),
            Paragraph(f"<font color='#CA8A04'><b>{r_stats['by_tier']['P2']}</b></font>", styles["table_cell"]),
            Paragraph(str(r_stats["by_tier"]["P3"]), styles["table_cell"]),
            Paragraph(f"<font color='#16A34A'><b>{r_stats['reachable_count']}</b></font>", styles["table_cell"]),
        ])

    repos_table = Table(repo_rows, colWidths=[150, 60, 65, 45, 40, 40, 40, 40, 60])
    repos_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(repos_table)
    story.append(Spacer(1, 16))

    # Footer
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8))
    story.append(Paragraph(
        f"Organization Vulnerability & Threat Assessment Report • Generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} • Dependency Risk Dashboard",
        styles["footer"],
    ))

    doc.build(story)
    return buffer.getvalue()
