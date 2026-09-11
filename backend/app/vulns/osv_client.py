from __future__ import annotations

from typing import Sequence

import httpx

from app.config import settings

# Mid-band representatives when a record only carries a textual severity
# (GitHub-advisory imports often lack CVSS vectors).
_SEVERITY_FALLBACK = {"LOW": 2.5, "MODERATE": 5.5, "MEDIUM": 5.5, "HIGH": 7.8, "CRITICAL": 9.3}


def score_from_vector(vector: str) -> float | None:
    try:
        if vector.startswith("CVSS:4"):
            from cvss import CVSS4
            return round(CVSS4(vector).base_score(), 1)
        from cvss import CVSS3
        return round(CVSS3(vector).base_score(), 1)
    except Exception:
        return None


def severity_band(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def parse_osv_vuln(v: dict, ecosystem: str, pkg_name: str) -> dict:
    """Flatten an OSV record into our vulnerabilities-table shape."""
    score, vector = None, None
    for sev in v.get("severity", []):
        if str(sev.get("type", "")).startswith("CVSS"):
            s = score_from_vector(sev.get("score", ""))
            if s is not None:
                score, vector = s, sev["score"]
                break
    ds = v.get("database_specific", {}) or {}
    if score is None:
        score = _SEVERITY_FALLBACK.get(str(ds.get("severity", "")).upper())

    fixed: set[str] = set()
    for aff in v.get("affected", []):
        p = aff.get("package", {})
        if p.get("ecosystem") == ecosystem and p.get("name") == pkg_name:
            for rng in aff.get("ranges", []):
                for ev in rng.get("events", []):
                    if "fixed" in ev:
                        fixed.add(ev["fixed"])

    cve = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), ds.get("cve_id"))
    return {
        "osv_id": v["id"],
        "cve_id": cve,
        "summary": v.get("summary") or (v.get("details") or "")[:300],
        "cvss_score": score,
        "cvss_vector": vector,
        "severity": severity_band(score),
        "fixed_versions": sorted(fixed) or None,
        "raw": v,
    }


class OSVClient:
    def __init__(self, base_url: str | None = None):
        self._client = httpx.Client(base_url=base_url or settings.osv_api_base, timeout=30.0)
        self._detail_cache: dict[str, dict] = {}

    def query_batch(self, queries: Sequence[dict]) -> list[list[str]]:
        """queries: [{'package': {'ecosystem': 'PyPI', 'name': 'requests'}, 'version': '2.28.0'}, ...]
        Returns parallel list of advisory-ID lists (empty = clean)."""
        results: list[list[str]] = [[] for _ in queries]
        for i in range(0, len(queries), 100):          # API max batch = 100
            chunk = queries[i : i + 100]
            r = self._client.post("/querybatch", json={"queries": chunk})
            r.raise_for_status()
            for offset, res in enumerate(r.json().get("results", [])):
                results[i + offset] = [v["id"] for v in (res or {}).get("vulns", [])]
        return results

    def hydrate(self, osv_ids: Sequence[str]) -> list[dict]:
        """Fetch full OSV records (deduplicated, in-memory cached)."""
        out, seen = [], set()
        for vid in osv_ids:
            if vid in seen:
                continue
            seen.add(vid)
            if vid not in self._detail_cache:
                r = self._client.get(f"/vulns/{vid}")
                if r.status_code == 404:
                    continue
                r.raise_for_status()
                self._detail_cache[vid] = r.json()
            out.append(self._detail_cache[vid])
        return out
