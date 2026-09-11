from app.vulns.impact_analyzer import analyze_vulnerability_impact, _parse_cvss_vector


def test_cvss_vector_parsing():
    parsed = _parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert "Remote Network" in parsed["vector_label"]
    assert "Low" in parsed["complexity"]
    assert "None" in parsed["privileges"]
    assert "None" in parsed["interaction"]

    local_parsed = _parse_cvss_vector("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
    assert "Local System" in local_parsed["vector_label"]
    assert "High" in local_parsed["complexity"]
    assert "High" in local_parsed["privileges"]
    assert "Required" in local_parsed["interaction"]


def test_rce_impact_analysis():
    analysis = analyze_vulnerability_impact(
        summary="Remote Code Execution vulnerability in log4j",
        details="A flaw in JNDI lookup allows an attacker to execute arbitrary Java code.",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        cvss_score=10.0,
        fixed_versions=["2.17.1"],
        pkg_name="log4j-core",
    )
    assert analysis.vuln_type == "Remote Code Execution (RCE)"
    assert "run their own commands" in analysis.plain_english
    assert "unpatched" in analysis.threat_scenario
    assert "CRITICAL" in analysis.business_impact
    assert "`2.17.1`" in analysis.remediation


def test_sqli_impact_analysis():
    analysis = analyze_vulnerability_impact(
        summary="SQL Injection flaw in query builder",
        details="Improper neutralization of special elements used in an SQL Command.",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=8.5,
        fixed_versions=["3.4.0"],
        pkg_name="typeorm",
    )
    assert analysis.vuln_type == "SQL Injection"
    assert "database queries" in analysis.plain_english
    assert "unpatched" in analysis.threat_scenario


def test_prototype_pollution_impact_analysis():
    analysis = analyze_vulnerability_impact(
        summary="Prototype pollution in lodash.merge",
        details="Can overwrite Object.prototype properties.",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        cvss_score=7.3,
        fixed_versions=["4.17.21"],
        raw_osv={"database_specific": {"cwe_ids": ["CWE-1321"]}},
        pkg_name="lodash",
    )
    assert analysis.vuln_type == "Prototype Pollution"
    assert "JavaScript object prototypes" in analysis.plain_english


def test_fallback_impact_analysis():
    analysis = analyze_vulnerability_impact(
        summary="Unspecified defect in custom-package",
        details="Some rare corner case.",
        cvss_vector=None,
        cvss_score=4.0,
        fixed_versions=None,
        pkg_name="custom-pkg",
    )
    assert "custom-pkg" in analysis.plain_english
    assert "unpatched" in analysis.threat_scenario
