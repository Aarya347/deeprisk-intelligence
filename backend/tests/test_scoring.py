from app.scoring.risk_score import RiskInput, compute_risk

def test_reachable_internet_critical_is_p0():
    r = compute_risk(RiskInput(cvss_score=9.8, reachable=True, exposure_tier="internet"))
    assert r.score > 9.8 and r.tier == "P0"

def test_unreachable_internal_dev_dep_downgraded():
    r = compute_risk(RiskInput(cvss_score=9.8, reachable=False, exposure_tier="internal", is_dev=True))
    # 9.8 * 0.55 (unreachable) * 0.85 (internal) * 0.70 (dev-only) ≈ 3.2,
    # which correctly lands in the lowest urgency tier — the combination
    # of "not reachable" + "internal" + "dev-only" should heavily discount
    # even a critical CVSS score. This is the scorer working as designed.
    assert r.tier == "P3"
    assert r.score < 4.0

def test_unknown_everything_keeps_base():
    r = compute_risk(RiskInput(cvss_score=7.5))
    assert abs(r.score - 7.5) < 0.01 and r.tier == "P1"
