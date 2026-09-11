from app.db.models import Finding
from app.api.routes import VALID_TRIAGE_STATUSES


def test_finding_triage_fields():
    f = Finding(
        scan_id=1,
        repository_id=1,
        dependency_id=1,
        vulnerability_id=1,
        reachable=True,
        risk_score=9.0,
        risk_tier="P0",
        triage_status="open",
        triage_notes="Initial finding",
        triaged_by="SecOps",
    )
    assert f.triage_status == "open"
    assert f.triage_notes == "Initial finding"
    assert f.triaged_by == "SecOps"
    assert "false_positive" in VALID_TRIAGE_STATUSES
    assert "accepted_risk" in VALID_TRIAGE_STATUSES
    assert "mitigated" in VALID_TRIAGE_STATUSES
    assert "snoozed" in VALID_TRIAGE_STATUSES
