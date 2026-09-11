from __future__ import annotations

import dataclasses
import shutil
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Dependency, Finding, Repository, Scan, Vulnerability
from app.reachability.npm_static import assess_npm_dependency, build_npm_import_index
from app.reachability.python_ast import assess_python_dependency, build_import_index
from app.scanner.github import GitHubClient
from app.scanner.parsers.npm import best_guess_version, parse_package_lock
from app.scanner.parsers.registry import parse_dep_file, select_dep_file_paths
from app.scoring.risk_score import RiskInput, compute_risk
from app.vulns.osv_client import OSVClient, parse_osv_vuln


def _upsert_repository(db: Session, gh_repo: dict) -> Repository:
    full_name = gh_repo["full_name"]
    repo = db.scalar(select(Repository).where(Repository.github_full_name == full_name))
    if repo is None:
        repo = Repository(github_full_name=full_name)
        db.add(repo)
    repo.default_branch = gh_repo.get("default_branch") or "main"
    repo.primary_language = gh_repo.get("language")
    repo.is_archived = bool(gh_repo.get("archived"))
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


def _extract_tarball_safe(tar_path: str, dest: str) -> None:
    with tarfile.open(tar_path, "r:gz") as tf:
        for member in tf.getmembers():
            p = Path(member.name)
            if p.is_absolute() or ".." in p.parts:
                raise ValueError(f"Unsafe tar member: {member.name}")
        tf.extractall(dest, filter="data" if hasattr(tarfile, "data_filter") else None)


from app.scanner.events import scan_events


def scan_repository(
    db: Session,
    gh: GitHubClient,
    osv: OSVClient,
    repo: Repository,
    job_id: str | None = None,
    repo_index: int = 1,
    total_repos: int = 1,
) -> Scan:
    scan = Scan(repository_id=repo.id, status="running")
    db.add(scan)
    db.flush()

    branch = repo.default_branch or "main"
    stats = {"dependencies": 0, "queried": 0, "vuln_matches": 0, "reachable": 0}

    def emit(phase: str, pct: int, msg: str):
        if job_id:
            scan_events.emit(job_id, {
                "type": "progress",
                "repo": repo.github_full_name,
                "repo_index": repo_index,
                "total_repos": total_repos,
                "phase": phase,
                "percent": pct,
                "message": msg,
            })

    emit("manifests", int((repo_index - 1) / total_repos * 100) + 2, f"[{repo_index}/{total_repos}] Discovering manifests in {repo.github_full_name}...")

    # ---- 1. Discover manifests ------------------------------------------
    tree_paths, _truncated = gh.tree_paths(repo.github_full_name, branch)
    dep_file_paths = select_dep_file_paths(tree_paths)

    # ---- 2. Parse manifests (+ lockfile resolution) ----------------------
    lock_resolved: dict[str, str] = {}
    if "package-lock.json" in tree_paths:
        lock_text = gh.get_text_file(repo.github_full_name, "package-lock.json", branch)
        if lock_text:
            lock_resolved = parse_package_lock(lock_text)

    dep_rows: list[Dependency] = []
    for path in dep_file_paths:
        content = gh.get_text_file(repo.github_full_name, path, branch)
        if not content:
            continue
        for dep in parse_dep_file(path, content):
            version, version_source = dep.version, ("pin" if dep.version else "none")
            if dep.ecosystem == "npm":
                if not version and dep.name in lock_resolved:
                    version, version_source = lock_resolved[dep.name], "lockfile"
                if not version:
                    version, guess_src = best_guess_version(dep.raw_specifier)
                    version_source = version_source if version is None else guess_src
                    if version:
                        version_source = guess_src
            elif not version:
                version, version_source = best_guess_version(dep.raw_specifier)
            dep = dataclasses.replace(dep, version=version)
            row = _upsert_dependency(db, repo.id, dep)
            row.version_source = version_source
            dep_rows.append(row)
            stats["dependencies"] += 1
    db.flush()

    # ---- 3. OSV batch matching -------------------------------------------
    query_rows = [d for d in dep_rows if d.version]
    queries = [
        {"package": {"ecosystem": d.ecosystem, "name": d.name}, "version": d.version}
        for d in query_rows
    ]
    emit("osv", int((repo_index - 0.6) / total_repos * 100), f"Querying OSV vulnerability DB for {len(query_rows)} packages...")
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

    # ---- 4. Reachability (needs source) -----------------------------------
    tmp = None
    py_index = npm_index = None
    if pairs:
        emit("reachability", int((repo_index - 0.3) / total_repos * 100), f"Downloading code and running AST reachability on {len(pairs)} matches...")
        ecosystems = {d.ecosystem for d, _ in pairs}
        tmp = tempfile.mkdtemp(prefix="depdash-src-")
        tar_path = str(Path(tmp) / "src.tar.gz")
        gh.download_tarball(repo.github_full_name, branch, tar_path)
        _extract_tarball_safe(tar_path, tmp)
        src_root = next(Path(tmp).iterdir())  # tarball wraps everything in repo-<sha>/
        if "PyPI" in ecosystems:
            py_index = build_import_index(src_root)
        if "npm" in ecosystems:
            npm_index = build_npm_import_index(src_root)

    # ---- 5. Score + persist findings ---------------------------------------
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

    if tmp and Path(tmp).exists():
        shutil.rmtree(tmp, ignore_errors=True)

    scan.status, scan.stats, scan.finished_at = "completed", stats, datetime.now(timezone.utc)
    repo.last_scan_id, repo.last_scanned_at = scan.id, scan.finished_at
    emit("repo_done", int(repo_index / total_repos * 100), f"Completed {repo.github_full_name}: {stats['dependencies']} deps, {stats['vuln_matches']} vulns ({stats['reachable']} reachable).")
    return scan


def scan_organization(
    db: Session,
    gh: GitHubClient,
    osv: OSVClient,
    org: str,
    job_id: str | None = None,
) -> list[int]:
    scan_ids = []
    if job_id:
        scan_events.emit(job_id, {
            "type": "progress",
            "phase": "listing_repos",
            "percent": 5,
            "message": f"Fetching repository list for '{org}' from GitHub...",
        })

    repos_list = list(gh.list_org_repos(org))
    total = len(repos_list)
    if total == 0:
        if job_id:
            scan_events.emit(job_id, {
                "type": "job_completed",
                "status": "completed",
                "percent": 100,
                "message": f"No eligible repositories found for org '{org}'.",
            })
        return []

    if job_id:
        scan_events.emit(job_id, {
            "type": "progress",
            "phase": "starting_scans",
            "percent": 10,
            "message": f"Found {total} repositories. Beginning dependency & reachability scans...",
        })

    for idx, gh_repo in enumerate(repos_list, start=1):
        repo = _upsert_repository(db, gh_repo)
        db.commit()
        try:
            scan = scan_repository(db, gh, osv, repo, job_id=job_id, repo_index=idx, total_repos=total)
            scan_ids.append(scan.id)
        except Exception as exc:  # isolate failures per-repo
            failed = Scan(repository_id=repo.id, status="failed", error=str(exc)[:500],
                          finished_at=datetime.now(timezone.utc))
            db.add(failed)
            if job_id:
                scan_events.emit(job_id, {
                    "type": "warning",
                    "repo": repo.github_full_name,
                    "message": f"Scan failed for {repo.github_full_name}: {exc}",
                })
        db.commit()

    if job_id:
        scan_events.emit(job_id, {
            "type": "job_completed",
            "status": "completed",
            "percent": 100,
            "message": f"Organization scan finished for '{org}'. Scanned {len(scan_ids)}/{total} repositories.",
        })
    return scan_ids