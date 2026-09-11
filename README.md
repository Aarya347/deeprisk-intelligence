# DeepRisk Intelligence

### Automated Dependency & Vulnerability Risk Analysis

DeepRisk Intelligence is a security analysis platform that scans GitHub
repositories for vulnerable dependencies, checks whether those vulnerabilities
are actually reachable from first-party code, calculates a risk score, and
presents the results through a prioritized security dashboard.

The goal is to move beyond simply asking:

> "Is this dependency vulnerable?"

and instead answer:

> "How much does this vulnerability actually matter to this repository?"

DeepRisk combines vulnerability severity, code reachability, repository exposure,
dependency type, and known exploitation status to prioritize the risks that
deserve attention first.

---

## Key Features

- **GitHub Organization Scanning**
  - Discovers repositories within a GitHub organization.
  - Scans supported dependency manifests.

- **Dependency Detection**
  - Supports JavaScript/Node.js dependencies through `package.json`.
  - Supports Python dependencies through `requirements.txt`.
  - Uses lockfiles where available for improved version resolution.

- **Vulnerability Matching**
  - Cross-checks dependencies against the
    [OSV.dev](https://osv.dev/) vulnerability database.
  - Tracks vulnerability identifiers, severity, CVSS scores, and fixed versions.

- **Reachability Analysis**
  - Checks whether vulnerable packages are actually imported by
    first-party code.
  - Distinguishes between vulnerable packages that are used and those that
    appear to be unused.

- **Risk Scoring**
  - Calculates a risk score using multiple factors:
    - CVSS severity
    - Code reachability
    - Repository exposure
    - Direct vs. transitive dependency
    - Development-only dependencies
    - Known exploited vulnerabilities

- **Prioritized Risk Tiers**

  | Tier | Meaning |
  |------|---------|
  | **P0** | Fix now |
  | **P1** | Fix this sprint |
  | **P2** | Backlog |
  | **P3** | Monitor |

- **Security Dashboard**
  - Total findings
  - Critical/high/medium/low severity distribution
  - Risk-priority distribution
  - Reachable vulnerability count
  - Repositories scanned
  - Filterable vulnerability findings

---

## How It Works

```text
GitHub Organization
        │
        ▼
Repository Discovery
        │
        ▼
Dependency Extraction
        │
        ├── package.json
        └── requirements.txt
        │
        ▼
Version Resolution
        │
        ▼
OSV.dev Vulnerability Matching
        │
        ▼
Reachability Analysis
        │
        ▼
Risk Scoring
        │
        ├── CVSS severity
        ├── Reachability
        ├── Repository exposure
        ├── Direct / transitive
        ├── Dev / production
        └── Known exploitation
        │
        ▼
Prioritized Findings
        │
        ▼
DeepRisk Intelligence Dashboard
