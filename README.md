# Automated Dependency & Vulnerability Risk Dashboard

Scans a GitHub org's repos, cross-checks dependencies against OSV.dev,
checks whether vulnerable packages are actually imported by first-party
code (reachability), scores risk, and shows a prioritized dashboard.

## Quickstart

```bash
# 1. Infrastructure
docker compose up -d db

# 2. Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp ../.env.example .env            # set GITHUB_TOKEN (repo scope: read-only is enough)
uvicorn app.main:app --reload      # tables auto-create on boot

# 3. Trigger a scan
curl -X POST localhost:8000/api/scan \
  -H 'Content-Type: application/json' -d '{"github_org": "your-org-name"}'

# 4. Frontend
cd ../frontend && npm install && npm run dev
# → http://localhost:5173
```

## Running tests

```bash
cd backend
pytest
```

## Known limitations (deliberate v1 trade-offs)

- **Version resolution**: unpinned `package.json` ranges without a lockfile
  fall back to a "floor guess" (`^1.2.3` → `1.2.3`), flagged via
  `version_source='guess'`. Lockfile parsing currently resolves top-level
  packages only.
- **Reachability is import-level (L1)**: zero setup and few false negatives,
  but "imported somewhere" ≠ "vulnerable function called." Symbol-level
  diffing (L2) and call-graph analysis (L3) are the upgrade path.
- **Direct vs. transitive**: v1 reads manifests, so everything is marked
  direct. Lockfile/SBOM (CycloneDX) parsing would unlock a real dependency
  graph.
- **Scans run as in-process background tasks** — swap for Celery/RQ + a job
  queue before scanning orgs with hundreds of repos; OSV/GitHub responses
  should also get HTTP caching (ETags) to respect rate limits.
- **No auth/UI for exposure tiers yet** — set `exposure_tier` via
  `PATCH /api/repositories/{id}`; it materially changes rankings.

## Roadmap

1. ~~Learn Git/GitHub fundamentals hands-on~~
2. ~~Basic repo scanner + dependency parser~~
3. ~~CVE matching pipeline~~
4. ~~Basic dashboard~~
5. ~~Reachability analysis (AST/static analysis)~~
6. ~~Risk scoring engine~~
7. Ongoing: commit hygiene, docs, portfolio polish
