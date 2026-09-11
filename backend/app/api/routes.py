import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, Response, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db.models import Dependency, Finding, Repository, Scan, Vulnerability
from app.reports.generator import (
    generate_org_markdown_report,
    generate_repository_markdown_report,
)
from app.reports.pdf_generator import (
    generate_org_pdf_report,
    generate_repository_pdf_report,
)
from app.scanner.events import scan_events
from app.scanner.github import GitHubClient
from app.scanner.local import scan_local_path, scan_uploaded_zip
from app.scanner.orchestrator import scan_organization
from app.vulns.impact_analyzer import analyze_vulnerability_impact
from app.vulns.osv_client import OSVClient
from app.config import settings

router = APIRouter(prefix="/api")

VALID_TIERS = {"internet", "internal", "library", "unknown"}
VALID_TRIAGE_STATUSES = {"open", "accepted_risk", "false_positive", "mitigated", "snoozed"}


class ScanRequest(BaseModel):
    github_org: str


class LocalScanRequest(BaseModel):
    path: str
    name: str | None = None


class ExposureUpdate(BaseModel):
    exposure_tier: str


class TriageUpdate(BaseModel):
    status: str
    notes: str | None = None
    user: str | None = "Security Team"


@router.post("/scan", status_code=202)
def trigger_scan(body: ScanRequest, tasks: BackgroundTasks, db: Session = Depends(get_db)):
    if not settings.github_token:
        raise HTTPException(400, "GITHUB_TOKEN is not configured in backend/.env")
    job_id = f"scan-{uuid.uuid4().hex[:8]}"
    scan_events.start_job(job_id, f"GitHub Org Scan: {body.github_org}")
    tasks.add_task(_run_org_scan, body.github_org, job_id)
    return {"job_id": job_id, "detail": f"Scan of org '{body.github_org}' started"}


def _run_org_scan(org: str, job_id: str | None = None) -> None:
    from app.db.session import SessionLocal
    db = SessionLocal()
    try:
        scan_organization(db, GitHubClient(settings.github_token), OSVClient(), org, job_id=job_id)
    except Exception as e:
        if job_id:
            scan_events.emit(job_id, {
                "type": "job_failed",
                "status": "failed",
                "message": f"Scan failed: {e}",
            })
    finally:
        db.close()


@router.get("/scan/progress/{job_id}")
async def get_scan_progress(job_id: str):
    return StreamingResponse(
        scan_events.subscribe(job_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/scan/local", status_code=202)
def trigger_local_scan(body: LocalScanRequest, tasks: BackgroundTasks):
    job_id = f"local-{uuid.uuid4().hex[:8]}"
    title = f"Local Scan: {body.name or body.path}"
    scan_events.start_job(job_id, title)
    tasks.add_task(_run_local_scan, body.path, body.name, job_id)
    return {"job_id": job_id, "detail": f"Local scan for '{body.path}' started"}


def _run_local_scan(path: str, name: str | None, job_id: str) -> None:
    from app.db.session import SessionLocal
    db = SessionLocal()
    try:
        scan_local_path(db, path, repo_name=name, job_id=job_id)
        scan_events.emit(job_id, {
            "type": "job_completed",
            "status": "completed",
            "percent": 100,
            "message": f"Local scan for '{name or path}' completed successfully.",
        })
    except Exception as e:
        scan_events.emit(job_id, {
            "type": "job_failed",
            "status": "failed",
            "message": f"Local scan failed: {e}",
        })
    finally:
        db.close()


@router.post("/scan/upload", status_code=202)
async def trigger_zip_upload_scan(
    tasks: BackgroundTasks,
    file: UploadFile = File(...),
    project_name: str = Form("uploaded-app"),
):
    if not file.filename.endswith(".zip"):
        raise HTTPException(400, "Only .zip files are supported")

    content = await file.read()
    job_id = f"upload-{uuid.uuid4().hex[:8]}"
    clean_name = project_name.strip() or file.filename.rsplit(".", 1)[0]
    scan_events.start_job(job_id, f"ZIP Upload Scan: {clean_name}")
    tasks.add_task(_run_upload_scan, content, clean_name, job_id)
    return {"job_id": job_id, "detail": f"Upload scan for '{clean_name}' started"}


def _run_upload_scan(zip_bytes: bytes, project_name: str, job_id: str) -> None:
    from app.db.session import SessionLocal
    db = SessionLocal()
    try:
        scan_uploaded_zip(db, zip_bytes, project_name=project_name, job_id=job_id)
        scan_events.emit(job_id, {
            "type": "job_completed",
            "status": "completed",
            "percent": 100,
            "message": f"ZIP scan for '{project_name}' completed successfully.",
        })
    except Exception as e:
        scan_events.emit(job_id, {
            "type": "job_failed",
            "status": "failed",
            "message": f"ZIP scan failed: {e}",
        })
    finally:
        db.close()


@router.patch("/findings/{finding_id}/triage")
def triage_finding(finding_id: int, body: TriageUpdate, db: Session = Depends(get_db)):
    if body.status not in VALID_TRIAGE_STATUSES:
        raise HTTPException(422, f"status must be one of {sorted(VALID_TRIAGE_STATUSES)}")
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Finding not found")

    finding.triage_status = body.status
    finding.triage_notes = body.notes
    finding.triaged_by = body.user or "Security Team"
    finding.triaged_at = datetime.now(timezone.utc)
    db.commit()

    return {
        "id": finding.id,
        "triage_status": finding.triage_status,
        "triage_notes": finding.triage_notes,
        "triaged_by": finding.triaged_by,
        "triaged_at": finding.triaged_at.isoformat() if finding.triaged_at else None,
        "detail": f"Finding triaged as '{finding.triage_status}'",
    }


@router.get("/repositories")
def list_repositories(db: Session = Depends(get_db)):
    repos = db.scalars(select(Repository).order_by(Repository.github_full_name)).all()
    return [
        {
            "id": r.id, "full_name": r.github_full_name, "default_branch": r.default_branch,
            "primary_language": r.primary_language, "exposure_tier": r.exposure_tier,
            "last_scanned_at": r.last_scanned_at.isoformat() if r.last_scanned_at else None,
        }
        for r in repos
    ]


@router.patch("/repositories/{repo_id}")
def update_exposure(repo_id: int, body: ExposureUpdate, db: Session = Depends(get_db)):
    if body.exposure_tier not in VALID_TIERS:
        raise HTTPException(422, f"exposure_tier must be one of {sorted(VALID_TIERS)}")
    repo = db.get(Repository, repo_id)
    if repo is None:
        raise HTTPException(404, "Repository not found")
    repo.exposure_tier = body.exposure_tier
    db.commit()
    return {"detail": "updated"}


def _latest_findings_query(db: Session):
    """Findings from each repository's most recent completed scan."""
    return (
        db.query(Finding, Dependency, Vulnerability, Repository)
        .join(Dependency, Finding.dependency_id == Dependency.id)
        .join(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
        .join(Repository, Finding.repository_id == Repository.id)
        .filter(Finding.scan_id == Repository.last_scan_id)
    )


@router.get("/findings")
def get_findings(
    repository_id: int | None = None,
    tier: str | None = Query(None, pattern="^(P0|P1|P2|P3)$"),
    triage_status: str | None = Query(None),
    limit: int = Query(500, le=2000),
    db: Session = Depends(get_db),
):
    q = _latest_findings_query(db)
    if repository_id:
        q = q.filter(Finding.repository_id == repository_id)
    if tier:
        q = q.filter(Finding.risk_tier == tier)

    if triage_status == "open":
        q = q.filter((Finding.triage_status == "open") | (Finding.triage_status.is_(None)))
    elif triage_status == "triaged":
        q = q.filter((Finding.triage_status != "open") & (Finding.triage_status.is_not(None)))
    elif triage_status in VALID_TRIAGE_STATUSES:
        q = q.filter(Finding.triage_status == triage_status)

    rows = q.order_by(Finding.risk_score.desc()).limit(limit).all()

    return [
        {
            "id": f.id,
            "repository": repo.github_full_name,
            "exposure_tier": repo.exposure_tier,
            "dependency": {"name": dep.name, "version": dep.version,
                           "ecosystem": dep.ecosystem, "is_dev": dep.is_dev},
            "vulnerability": {
                "osv_id": v.osv_id, "cve_id": v.cve_id, "summary": v.summary,
                "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
                "severity": v.severity,
                "fixed_versions": v.fixed_versions or [],
            },
            "threat_analysis": analyze_vulnerability_impact(
                summary=v.summary,
                details=(v.raw or {}).get("details") if isinstance(v.raw, dict) else None,
                cvss_vector=v.cvss_vector,
                cvss_score=float(v.cvss_score) if v.cvss_score is not None else None,
                fixed_versions=v.fixed_versions,
                raw_osv=v.raw if isinstance(v.raw, dict) else None,
                pkg_name=dep.name,
            ).to_dict(),
            "reachable": f.reachable,
            "evidence": f.evidence,
            "risk_score": float(f.risk_score),
            "risk_tier": f.risk_tier,
            "rationale": f.rationale,
            "triage_status": f.triage_status or "open",
            "triage_notes": f.triage_notes,
            "triaged_by": f.triaged_by,
            "triaged_at": f.triaged_at.isoformat() if f.triaged_at else None,
        }
        for f, dep, v, repo in rows
    ]


@router.get("/stats")
def get_stats(repository_id: int | None = None, db: Session = Depends(get_db)):
    base = _latest_findings_query(db)
    if repository_id:
        base = base.filter(Finding.repository_id == repository_id)

    by_tier = dict(base.with_entities(Finding.risk_tier, func.count()).group_by(Finding.risk_tier).all())
    by_severity = dict(
        base.with_entities(Vulnerability.severity, func.count())
        .group_by(Vulnerability.severity).all()
    )
    reachable_count = base.filter(Finding.reachable.is_(True)).count()

    # Triage stats
    triaged_count = base.filter(
        (Finding.triage_status != "open") & (Finding.triage_status.is_not(None))
    ).count()
    active_count = base.filter(
        (Finding.triage_status == "open") | (Finding.triage_status.is_(None))
    ).count()

    repos_scanned = (
        db.query(func.count(func.distinct(Finding.repository_id)))
        .filter(Finding.scan_id == Repository.last_scan_id).scalar() or 0
    )
    return {
        "total_findings": sum(by_tier.values()),
        "active_findings": active_count,
        "triaged_count": triaged_count,
        "by_tier": by_tier,
        "by_severity": by_severity,
        "reachable_count": reachable_count,
        "repos_scanned": repos_scanned,
    }


@router.get("/reports/org/{org_name}")
def get_org_report(org_name: str, db: Session = Depends(get_db)):
    repos = (
        db.query(Repository)
        .filter(
            (Repository.github_full_name.ilike(f"{org_name}/%"))
            | (Repository.github_full_name.ilike(org_name))
        )
        .order_by(Repository.github_full_name)
        .all()
    )
    if not repos:
        raise HTTPException(404, f"No repositories found for org '{org_name}'")

    repos_with_findings = []
    for repo in repos:
        f_rows = []
        if repo.last_scan_id:
            f_rows = (
                db.query(Finding, Dependency, Vulnerability)
                .join(Dependency, Finding.dependency_id == Dependency.id)
                .join(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
                .filter(Finding.repository_id == repo.id)
                .filter(Finding.scan_id == repo.last_scan_id)
                .order_by(Finding.risk_score.desc())
                .all()
            )
        repos_with_findings.append((repo, f_rows))

    report_md = generate_org_markdown_report(org_name, repos_with_findings)
    safe_name = org_name.replace("/", "-").replace("\\", "-").replace(" ", "_")
    filename = f"{safe_name}-dependency-risk-report.md"

    return Response(
        content=report_md,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/reports/{repository_id}")
def get_repository_report(repository_id: int, db: Session = Depends(get_db)):
    repo = db.get(Repository, repository_id)
    if repo is None:
        raise HTTPException(404, "Repository not found")

    findings_rows = []
    if repo.last_scan_id:
        findings_rows = (
            db.query(Finding, Dependency, Vulnerability)
            .join(Dependency, Finding.dependency_id == Dependency.id)
            .join(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
            .filter(Finding.repository_id == repo.id)
            .filter(Finding.scan_id == repo.last_scan_id)
            .order_by(Finding.risk_score.desc())
            .all()
        )

    report_md = generate_repository_markdown_report(repo, findings_rows)
    safe_name = (
        repo.github_full_name.replace("/", "-").replace("\\", "-").replace(" ", "_")
    )
    filename = f"{safe_name}-dependency-risk-report.md"

    return Response(
        content=report_md,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/reports/org/{org_name}/pdf")
def get_org_pdf_report(org_name: str, db: Session = Depends(get_db)):
    repos = (
        db.query(Repository)
        .filter(
            (Repository.github_full_name.ilike(f"{org_name}/%"))
            | (Repository.github_full_name.ilike(org_name))
        )
        .order_by(Repository.github_full_name)
        .all()
    )
    if not repos:
        raise HTTPException(404, f"No repositories found for org '{org_name}'")

    repos_with_findings = []
    for repo in repos:
        f_rows = []
        if repo.last_scan_id:
            f_rows = (
                db.query(Finding, Dependency, Vulnerability)
                .join(Dependency, Finding.dependency_id == Dependency.id)
                .join(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
                .filter(Finding.repository_id == repo.id)
                .filter(Finding.scan_id == repo.last_scan_id)
                .order_by(Finding.risk_score.desc())
                .all()
            )
        repos_with_findings.append((repo, f_rows))

    pdf_bytes = generate_org_pdf_report(org_name, repos_with_findings)
    safe_name = org_name.replace("/", "-").replace("\\", "-").replace(" ", "_")
    filename = f"{safe_name}-executive-risk-report.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/reports/{repository_id}/pdf")
def get_repository_pdf_report(repository_id: int, db: Session = Depends(get_db)):
    repo = db.get(Repository, repository_id)
    if repo is None:
        raise HTTPException(404, "Repository not found")

    findings_rows = []
    if repo.last_scan_id:
        findings_rows = (
            db.query(Finding, Dependency, Vulnerability)
            .join(Dependency, Finding.dependency_id == Dependency.id)
            .join(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
            .filter(Finding.repository_id == repo.id)
            .filter(Finding.scan_id == repo.last_scan_id)
            .order_by(Finding.risk_score.desc())
            .all()
        )

    pdf_bytes = generate_repository_pdf_report(repo, findings_rows)
    safe_name = (
        repo.github_full_name.replace("/", "-").replace("\\", "-").replace(" ", "_")
    )
    filename = f"{safe_name}-executive-risk-report.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

