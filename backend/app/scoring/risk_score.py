from __future__ import annotations

from dataclasses import dataclass, field

EXPOSURE_FACTOR = {"internet": 1.15, "unknown": 1.0, "library": 0.90, "internal": 0.85}
REACHABILITY_FACTOR = {True: 1.15, False: 0.55, None: 1.0}   # None = unanalyzed
DIRECT_FACTOR = {True: 1.0, False: 0.90}                     # transitive slightly down-weighted
DEV_FACTOR = {True: 0.70, False: 1.0}                        # dev-only deps matter less
KEV_BONUS = 0.75                                             # listed exploited vulnerability

TIER_THRESHOLDS = [(8.0, "P0"), (6.0, "P1"), (4.0, "P2")]
TIER_LABELS = {"P0": "Fix now", "P1": "Fix this sprint", "P2": "Backlog", "P3": "Monitor"}


@dataclass
class RiskInput:
    cvss_score: float
    reachable: bool | None = None
    exposure_tier: str = "unknown"
    is_direct: bool = True
    is_dev: bool = False
    known_exploited: bool = False


@dataclass
class RiskResult:
    score: float
    tier: str
    tier_label: str
    rationale: list[str] = field(default_factory=list)


def _band_label(score: float) -> str:
    for threshold, label in ((9.0, "critical"), (7.0, "high"), (4.0, "medium")):
        if score >= threshold:
            return label
    return "low" if score > 0 else "none"


def compute_risk(inp: RiskInput) -> RiskResult:
    rationale: list[str] = [
        f"CVSS {inp.cvss_score:.1f} ({_band_label(inp.cvss_score)}) — base severity"
    ]

    reach_f = REACHABILITY_FACTOR[inp.reachable]
    if inp.reachable is True:
        rationale.append(f"Reachable: vulnerable package is imported by first-party code (×{reach_f})")
    elif inp.reachable is False:
        rationale.append(f"Not reached: no imports found in first-party code (×{reach_f})")
    else:
        rationale.append("Reachability unknown (×1.0)")

    expo_f = EXPOSURE_FACTOR[inp.exposure_tier]
    exposure_desc = {
        "internet": "internet-facing service", "internal": "internal system",
        "library": "published library", "unknown": "exposure unknown",
    }[inp.exposure_tier]
    rationale.append(f"Repository exposure: {exposure_desc} (×{expo_f})")

    score = inp.cvss_score * reach_f * expo_f * DIRECT_FACTOR[inp.is_direct] * DEV_FACTOR[inp.is_dev]

    if not inp.is_direct:
        rationale.append("Transitive dependency (×0.90)")
    if inp.is_dev:
        rationale.append("Dev-only dependency — not shipped to production (×0.70)")
    if inp.known_exploited:
        score += KEV_BONUS
        rationale.append(f"Listed as actively exploited (CISA KEV) (+{KEV_BONUS})")

    score = round(min(score, 10.0), 2)
    tier = next((t for threshold, t in TIER_THRESHOLDS if score >= threshold), "P3")
    return RiskResult(score=score, tier=tier, tier_label=TIER_LABELS[tier], rationale=rationale)
