from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class ThreatAnalysis:
    vuln_type: str
    plain_english: str
    threat_scenario: str
    attack_vector_label: str
    attack_complexity: str
    business_impact: str
    remediation: str
    cwe_list: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Knowledge base of known vulnerability patterns, their plain-English meaning,
# exploit mechanics if left unpatched, and business impact.
_VULN_PATTERNS = [
    {
        "keywords": [r"remote code execution", r"\brce\b", r"arbitrary code", r"command injection", r"code execution"],
        "cwes": ["CWE-78", "CWE-94", "CWE-502", "CWE-88", "CWE-77"],
        "vuln_type": "Remote Code Execution (RCE)",
        "plain_english": "Allows an attacker to run their own commands and software directly on your server or application without authorization.",
        "threat_scenario": (
            "If this dependency remains unpatched, an external attacker can send a specially crafted request "
            "containing embedded operating system commands or serialized payloads. Because the package fails to sanitize "
            "this input, your server executes the attacker's code with the privileges of your application process."
        ),
        "business_impact": "CRITICAL — Complete server compromise, unauthorized access to databases and secrets, persistent backdoors, and data exfiltration.",
        "default_remediation": "Immediately upgrade to the fixed version. As an emergency mitigation, strictly validate, reject, or sanitize all user inputs passed into this library.",
    },
    {
        "keywords": [r"sql injection", r"\bsqli\b"],
        "cwes": ["CWE-89"],
        "vuln_type": "SQL Injection",
        "plain_english": "Allows an attacker to manipulate backend database queries through untrusted user inputs.",
        "threat_scenario": (
            "If left unpatched, an attacker can input malicious SQL syntax into forms or API parameters. "
            "The vulnerable library fails to properly escape this text, causing the database to execute arbitrary SQL commands."
        ),
        "business_impact": "CRITICAL — Unauthorized reading or alteration of entire databases, theft of customer records and passwords, or full database deletion.",
        "default_remediation": "Upgrade the vulnerable library immediately and verify that all database interactions use parameterized queries / prepared statements.",
    },
    {
        "keywords": [r"prototype pollution"],
        "cwes": ["CWE-1321"],
        "vuln_type": "Prototype Pollution",
        "plain_english": "Allows an attacker to inject properties into base JavaScript object prototypes, altering the behavior of the entire application.",
        "threat_scenario": (
            "If left unpatched, an attacker submits JSON payloads with reserved keys like `__proto__` or `constructor.prototype`. "
            "When the package performs deep object merging or cloning, it modifies global object attributes. This can bypass security checks or trigger secondary remote code execution."
        ),
        "business_impact": "HIGH — Application crashes (DoS), authentication bypasses, or unexpected code execution paths throughout the runtime environment.",
        "default_remediation": "Upgrade to the patched version. Alternatively, freeze prototypes (`Object.freeze(Object.prototype)`) or validate input keys to strip `__proto__` and `constructor`.",
    },
    {
        "keywords": [r"server-side request forgery", r"\bssrf\b"],
        "cwes": ["CWE-918"],
        "vuln_type": "Server-Side Request Forgery (SSRF)",
        "plain_english": "Tricks your server into making unintended network requests to internal systems or cloud metadata endpoints.",
        "threat_scenario": (
            "If left unpatched, an attacker supplies internal URLs (such as `http://169.254.169.254` or `http://localhost:port`). "
            "The library fetches these URLs from inside your network perimeter, exposing internal microservices and cloud provider credentials."
        ),
        "business_impact": "HIGH — Exposure of internal infrastructure, stealing cloud IAM credentials from metadata services, and pivoting into private networks.",
        "default_remediation": "Upgrade the dependency, and enforce strict URL allowlists and egress firewalls preventing server requests to internal IP ranges (127.0.0.1, 10.0.0.0/8, 169.254.169.254).",
    },
    {
        "keywords": [r"path traversal", r"directory traversal", r"\.\./"],
        "cwes": ["CWE-22", "CWE-23", "CWE-36"],
        "vuln_type": "Path / Directory Traversal",
        "plain_english": "Allows an attacker to read or overwrite restricted files on the server by manipulating file path references.",
        "threat_scenario": (
            "If left unpatched, an attacker uses path sequences like `../../etc/passwd` or `..\\..\\sensitive_file` in file upload or download parameters. "
            "The vulnerable library fails to sanitize these relative paths, accessing arbitrary files outside the intended folder."
        ),
        "business_impact": "HIGH — Leakage of application configuration, API keys, source code, or system credentials; potential file overwrites leading to system instability.",
        "default_remediation": "Upgrade to the safe version. Ensure your code resolves absolute canonical paths and verifies they stay strictly within designated root directories.",
    },
    {
        "keywords": [r"cross-site scripting", r"\bxss\b"],
        "cwes": ["CWE-79"],
        "vuln_type": "Cross-Site Scripting (XSS)",
        "plain_english": "Allows attackers to inject malicious browser scripts that execute in the sessions of other users or administrators.",
        "threat_scenario": (
            "If left unpatched, unsanitized user content rendered by this package injects `<script>` tags into web pages. "
            "When victims view the page, the script executes inside their browser session."
        ),
        "business_impact": "MEDIUM-HIGH — Session hijacking, stealing authentication tokens/cookies, defacing web pages, or performing unauthorized actions on behalf of logged-in users.",
        "default_remediation": "Upgrade the library and ensure contextual HTML encoding and a robust Content Security Policy (CSP) are active.",
    },
    {
        "keywords": [r"denial of service", r"\bdos\b", r"redos", r"regular expression denial", r"infinite loop", r"memory exhaustion", r"cpu exhaustion", r"crash"],
        "cwes": ["CWE-400", "CWE-1333", "CWE-770", "CWE-674"],
        "vuln_type": "Denial of Service (DoS)",
        "plain_english": "Causes the application or server to freeze, consume 100% CPU/memory, or crash when processing crafted inputs.",
        "threat_scenario": (
            "If left unpatched, an attacker sends specially crafted input strings that trigger catastrophic backtracking in regular expressions or uncontrolled resource loops. "
            "This starves the server of CPU/RAM, causing timeouts and outage for legitimate users."
        ),
        "business_impact": "MEDIUM — Service disruption, application downtime, unavailable APIs, and increased cloud computing infrastructure costs.",
        "default_remediation": "Upgrade to the patched version. Apply rate limiting and maximum length limits on input payloads.",
    },
    {
        "keywords": [r"authentication bypass", r"improper authentication", r"authorization bypass", r"privilege escalation"],
        "cwes": ["CWE-287", "CWE-306", "CWE-862", "CWE-863", "CWE-269"],
        "vuln_type": "Authentication / Authorization Bypass",
        "plain_english": "Allows an unauthenticated or low-privileged user to access restricted functions or impersonate other accounts.",
        "threat_scenario": (
            "If left unpatched, flaws in token verification, session handling, or access check logic allow an attacker to forge tokens or bypass permission checks, gaining unauthorized administrative access."
        ),
        "business_impact": "CRITICAL — Unauthorized administrative control, account takeover, and full disclosure of restricted organizational assets.",
        "default_remediation": "Upgrade the package immediately and perform an audit of all active sessions and permissions.",
    },
    {
        "keywords": [r"information disclosure", r"sensitive data", r"credential leak", r"token leak", r"memory leak"],
        "cwes": ["CWE-200", "CWE-319", "CWE-538"],
        "vuln_type": "Information / Credential Exposure",
        "plain_english": "Exposes sensitive internal data, passwords, cryptographic keys, or system logs to unauthorized parties.",
        "threat_scenario": (
            "If left unpatched, the package inadvertently logs, caches, or transmits sensitive values (such as auth headers, API tokens, or memory buffers) in plaintext or error responses visible to attackers."
        ),
        "business_impact": "MEDIUM-HIGH — Exposure of secrets, compliance violations (GDPR/HIPAA), and reconnaissance data aiding further attacks.",
        "default_remediation": "Upgrade the library and rotate any secrets or tokens that may have been exposed through logs or network traces.",
    },
]


def _parse_cvss_vector(cvss_vector: str | None) -> dict[str, str]:
    """Parse key CVSS v3/v4 metrics into human-readable labels."""
    metrics: dict[str, str] = {
        "vector_label": "Remote Network (Internet)",
        "complexity": "Low (Easy to exploit)",
        "privileges": "None (No login required)",
        "interaction": "None (Automated / Zero-click)",
    }
    if not cvss_vector:
        return metrics

    vec = cvss_vector.upper()

    # Attack Vector (AV)
    if "AV:N" in vec:
        metrics["vector_label"] = "Remote Network (Internet accessible)"
    elif "AV:A" in vec:
        metrics["vector_label"] = "Adjacent Network (Local LAN / VPN)"
    elif "AV:L" in vec:
        metrics["vector_label"] = "Local System (Requires file access or local execution)"
    elif "AV:P" in vec:
        metrics["vector_label"] = "Physical Device Access"

    # Attack Complexity (AC)
    if "AC:L" in vec:
        metrics["complexity"] = "Low (Readily exploitable with minimal preconditions)"
    elif "AC:H" in vec:
        metrics["complexity"] = "High (Requires specific timing, configurations, or complex conditions)"

    # Privileges Required (PR)
    if "PR:N" in vec:
        metrics["privileges"] = "None (Unauthenticated — open to any remote attacker)"
    elif "PR:L" in vec:
        metrics["privileges"] = "Low (Requires a standard user account)"
    elif "PR:H" in vec:
        metrics["privileges"] = "High (Requires administrative or elevated privileges)"

    # User Interaction (UI)
    if "UI:N" in vec:
        metrics["interaction"] = "None (Zero-click — can be triggered without user participation)"
    elif "UI:R" in vec:
        metrics["interaction"] = "Required (Requires a victim user to click a link or open a file)"

    return metrics


def analyze_vulnerability_impact(
    summary: str | None,
    details: str | None,
    cvss_vector: str | None,
    cvss_score: float | None,
    fixed_versions: list[str] | None,
    raw_osv: dict | None = None,
    pkg_name: str = "",
) -> ThreatAnalysis:
    """Synthesize a plain-English, non-technical explanation and unpatched exploit scenario

    for any vulnerability record.
    """
    text = f"{summary or ''} {details or ''}".lower()
    raw = raw_osv or {}
    db_spec = raw.get("database_specific", {}) or {}
    cwes = db_spec.get("cwe_ids", []) or []

    # Match against pattern catalog
    matched_pattern = None
    for pat in _VULN_PATTERNS:
        # Check CWE matches
        if any(cwe.upper() in [c.upper() for c in cwes] for cwe in pat["cwes"]):
            matched_pattern = pat
            break
        # Check keyword matches in summary and details
        if any(re.search(kw, text) for kw in pat["keywords"]):
            matched_pattern = pat
            break

    cvss_info = _parse_cvss_vector(cvss_vector)

    if matched_pattern:
        vuln_type = matched_pattern["vuln_type"]
        plain_english = matched_pattern["plain_english"]
        threat_scenario = matched_pattern["threat_scenario"]
        business_impact = matched_pattern["business_impact"]
        remediation_template = matched_pattern["default_remediation"]
    else:
        # Generic fallback
        vuln_type = "Security Flaw / Vulnerability"
        plain_english = (
            f"A security defect in package '{pkg_name or 'the dependency'}' that allows unexpected or insecure behavior "
            "when handling specific inputs or operations."
        )
        threat_scenario = (
            f"If '{pkg_name or 'this package'}' remains unpatched in your application, an attacker may exploit "
            f"this defect via {cvss_info['vector_label'].lower()} ({cvss_info['privileges'].lower()}). "
            "This can lead to unauthorized data disclosure, process corruption, or degraded system availability."
        )
        business_impact = "Potential confidentiality, integrity, or availability risk depending on how this library is used in your code."
        remediation_template = "Upgrade to a patched version as soon as possible."

    # Build actionable remediation text
    if fixed_versions and len(fixed_versions) > 0:
        clean_versions = ", ".join(f"`{v}`" for v in fixed_versions[:3])
        remediation = f"Upgrade `{pkg_name}` to version {clean_versions}. Verify dependencies after upgrade."
    else:
        remediation = f"{remediation_template} No official patch listed yet — consider using alternative libraries or restricting untrusted inputs."

    return ThreatAnalysis(
        vuln_type=vuln_type,
        plain_english=plain_english,
        threat_scenario=threat_scenario,
        attack_vector_label=cvss_info["vector_label"],
        attack_complexity=cvss_info["complexity"],
        business_impact=business_impact,
        remediation=remediation,
        cwe_list=[str(c) for c in cwes] if cwes else [],
    )
