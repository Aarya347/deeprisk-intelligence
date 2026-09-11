from __future__ import annotations

import dataclasses
import os
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Dependency, Finding, Repository, Scan, Vulnerability
from app.reachability.npm_static import assess_npm_dependency, build_npm_import_index
from app.reachability.python_ast import assess_python_dependency, build_import_index
from app.scanner.events import scan_events
from app.scanner.parsers.npm import best_guess_version, parse_package_lock
from app.scanner.parsers.registry import parse_dep_file
from app.scoring.risk_score import RiskInput, compute_risk
from app.vulns.osv_client import OSVClient, parse_osv_vuln

IGNORED_DIRS = {
    ".git", ".venv", "venv", "env", "node_modules", ".next", "dist",
    "build", "__pycache__", ".pytest_cache", ".idea", ".vscode", "coverage"
}


def _find_manifest_files(root: Path) -> list[Path]:
    manifests: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune ignored directories
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS and not d.startswith(".")]
        for f in filenames:
            if f in ("requirements.txt", "package.json", "package-lock.json") or f.endswith("-requirements.txt"):
                manifests.append(Path(dirpath) / f)
    return manifests


def _upsert_local_repository(db: Session, repo_name: str, primary_lang: str | None = None) -> Repository:
    repo = db.scalar(select(Repository).where(Repository.github_full_name == repo_name))
    if repo is None:
        repo = Repository(github_full_name=repo_name, default_branch="local", exposure_tier="internal")
        db.add(repo)
    if primary_lang:
        repo.primary_language = primary_lang
    return repo


def _upsert_dependency(db: Session, repo_id: int, dep) -> Dependency:
    version = dep.version or ""
    row = db.scalar(
        select(Dependency).where(
            Dependency.repository_id == repo_id,
            Dependency.ecosystem == dep.ecosystem,
            Dependency.name == dep.name,
            Dependency.version == version,
        )
    )
    if row is None:
        row = Dependency(
            repository_id=repo_id, ecosystem=dep.ecosystem, name=dep.name,
            version=version, raw_specifier=dep.raw_specifier,
            is_dev=dep.is_dev, source_file=dep.source_file,
        )
        db.add(row)
    else:
        row.raw_specifier, row.is_dev, row.source_file = dep.raw_specifier, dep.is_dev, dep.source_file
    return row


def _upsert_vulnerability(db: Session, rec: dict) -> Vulnerability:
    row = db.scalar(select(Vulnerability).where(Vulnerability.osv_id == rec["osv_id"]))
    if row is None:
        row = Vulnerability(osv_id=rec["osv_id"])
        db.add(row)
    for k, v in rec.items():
        setattr(row, k, v)
    return row


def scan_local_path(
    db: Session,
    folder_path: Path | str,
    repo_name: str | None = None,
    osv: OSVClient | None = None,
    job_id: str | None = None,
) -> Scan:
    root = Path(folder_path).resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Directory not found: {folder_path}")

    if not repo_name:
        repo_name = f"local/{root.name}"
    elif not ("/" in repo_name):
        repo_name = f"local/{repo_name}"

    if osv is None:
        osv = OSVClient()

    def emit(phase: str, percent: int, msg: str):
        if job_id:
            scan_events.emit(job_id, {
                "type": "progress",
                "repo": repo_name,
                "phase": phase,
                "percent": percent,
                "message": msg,
            })

    emit("manifests", 10, f"Scanning manifests in {root.name}...")

    repo = _upsert_local_repository(db, repo_name)
    db.commit()

    scan = Scan(repository_id=repo.id, status="running")
    db.add(scan)
    db.flush()

    stats = {"dependencies": 0, "queried": 0, "vuln_matches": 0, "reachable": 0}

    # 1. Discover manifests
    manifest_paths = _find_manifest_files(root)
    emit("manifests", 25, f"Found {len(manifest_paths)} manifest files.")

    # 2. Parse manifests
    lock_resolved: dict[str, str] = {}
    for p in manifest_paths:
        if p.name == "package-lock.json":
            try:
                lock_text = p.read_text(encoding="utf-8", errors="replace")
                lock_resolved.update(parse_package_lock(lock_text))
            except Exception:
                pass

    dep_rows: list[Dependency] = []
    languages_detected = set()

    for p in manifest_paths:
        if p.name == "package-lock.json":
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            rel_path = str(p.relative_to(root)).replace("\\", "/")
            for dep in parse_dep_file(rel_path, content):
                if dep.ecosystem == "PyPI":
                    languages_detected.add("Python")
                elif dep.ecosystem == "npm":
                    languages_detected.add("JavaScript")

                version, version_source = dep.version, ("pin" if dep.version else "none")
                if dep.ecosystem == "npm":
                    if not version and dep.name in lock_resolved:
                        version, version_source = lock_resolved[dep.name], "lockfile"
                    if not version:
                        version, guess_src = best_guess_version(dep.raw_specifier)
                        version_source = version_source if version is None else guess_src
                elif not version:
                    version, version_source = best_guess_version(dep.raw_specifier)

                dep = dataclasses.replace(dep, version=version)
                row = _upsert_dependency(db, repo.id, dep)
                row.version_source = version_source
                dep_rows.append(row)
                stats["dependencies"] += 1
        except Exception as e:
            emit("warning", 30, f"Error reading {p.name}: {e}")

    if languages_detected:
        repo.primary_language = "/".join(sorted(languages_detected))

    db.flush()

    # 3. OSV vulnerability matching
    query_rows = [d for d in dep_rows if d.version]
    queries = [
        {"package": {"ecosystem": d.ecosystem, "name": d.name}, "version": d.version}
        for d in query_rows
    ]
    emit("osv", 45, f"Querying OSV database for {len(query_rows)} resolved dependencies...")
    id_lists = osv.query_batch(queries) if queries else []
    stats["queried"] = len(query_rows)

    pairs: list[tuple[Dependency, Vulnerability]] = []
    for dep_row, osv_ids in zip(query_rows, id_lists):
        for vdict in osv.hydrate(osv_ids):
            rec = parse_osv_vuln(vdict, dep_row.ecosystem, dep_row.name)
            vuln_row = _upsert_vulnerability(db, rec)
            pairs.append((dep_row, vuln_row))
            stats["vuln_matches"] += 1
    db.flush()

    # 4. AST Reachability Analysis directly on local filesystem
    emit("reachability", 65, f"Analyzing source code reachability for {len(pairs)} vulnerability matches...")
    py_index = npm_index = None
    if pairs:
        ecosystems = {d.ecosystem for d, _ in pairs}
        if "PyPI" in ecosystems:
            py_index = build_import_index(root)
        if "npm" in ecosystems:
            npm_index = build_npm_import_index(root)

    # 5. Score & persist findings
    emit("scoring", 85, "Computing risk scores and priority tiers...")
    for dep_row, vuln_row in pairs:
        reachable: bool | None = None
        evidence: dict = {}
        if dep_row.ecosystem == "PyPI" and py_index is not None:
            result = assess_python_dependency(dep_row.name, py_index)
            reachable, evidence = result.reachable, {
                "method": "python-ast-imports",
                "imports": [vars(h) for h in result.hits],
            }
        elif dep_row.ecosystem == "npm" and npm_index is not None:
            result = assess_npm_dependency(dep_row.name, npm_index)
            reachable, evidence = result.reachable, {
                "method": "npm-static-imports",
                "imports": result.hits,
            }
        if reachable:
            stats["reachable"] += 1

        risk = compute_risk(RiskInput(
            cvss_score=float(vuln_row.cvss_score or 0.0),
            reachable=reachable,
            exposure_tier=repo.exposure_tier,
            is_direct=True,
            is_dev=dep_row.is_dev,
        ))
        db.add(Finding(
            scan_id=scan.id, repository_id=repo.id,
            dependency_id=dep_row.id, vulnerability_id=vuln_row.id,
            reachable=reachable, evidence=evidence,
            risk_score=risk.score, risk_tier=risk.tier, rationale=risk.rationale,
            triage_status="open",
        ))

    scan.status, scan.stats, scan.finished_at = "completed", stats, datetime.now(timezone.utc)
    repo.last_scan_id, repo.last_scanned_at = scan.id, scan.finished_at
    db.commit()

    emit("completed", 100, f"Scan finished: {stats['dependencies']} deps, {stats['vuln_matches']} vulns ({stats['reachable']} reachable).")
    return scan


def scan_uploaded_zip(
    db: Session,
    zip_bytes: bytes,
    project_name: str = "uploaded-app",
    osv: OSVClient | None = None,
    job_id: str | None = None,
) -> Scan:
    tmp_dir = tempfile.mkdtemp(prefix="depdash-upload-")
    try:
        zip_path = Path(tmp_dir) / "project.zip"
        zip_path.write_bytes(zip_bytes)
        extract_dir = Path(tmp_dir) / "src"
        extract_dir.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as zf:
            # Safe zip extraction: avoid path traversal
            for member in zf.infolist():
                target_path = extract_dir / member.filename
                if not target_path.resolve().is_relative_to(extract_dir.resolve()):
                    raise ValueError(f"Unsafe path in ZIP archive: {member.filename}")
            zf.extractall(extract_dir)

        # If archive contains a single top-level directory, descend into it
        children = [c for c in extract_dir.iterdir() if c.is_dir() and not c.name.startswith(".")]
        scan_root = children[0] if len(children) == 1 and not any(f.is_file() for f in extract_dir.iterdir()) else extract_dir

        safe_name = f"upload/{project_name.strip() or 'app'}"
        return scan_local_path(db, scan_root, repo_name=safe_name, osv=osv, job_id=job_id)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
