"""Risk scoring helpers — pure functions, no DB or Flask deps."""

CONTROL_EFFECTIVENESS_REDUCTIONS = {
    1: 0.10,  # Minimal
    2: 0.25,  # Low
    3: 0.35,  # Moderate
    4: 0.50,  # High
    5: 0.65,  # Full
}

CONTROL_EFFECTIVENESS_LABELS = {
    1: "Minimal",
    2: "Low",
    3: "Moderate",
    4: "High",
    5: "Full",
}

LIKELIHOOD_LABELS = {
    1: "Rare",
    2: "Unlikely",
    3: "Possible",
    4: "Likely",
    5: "Almost Certain",
}

IMPACT_LABELS = {
    1: "Negligible",
    2: "Minor",
    3: "Moderate",
    4: "Major",
    5: "Critical",
}


def inherent_score(likelihood: int, impact: int) -> int | None:
    if likelihood and impact:
        return likelihood * impact
    return None


def residual_score(likelihood: int, impact: int, control_effectiveness: int | None) -> float | None:
    score = inherent_score(likelihood, impact)
    if score is None:
        return None
    if not control_effectiveness:
        return float(score)
    reduction = CONTROL_EFFECTIVENESS_REDUCTIONS.get(control_effectiveness, 0)
    return round(score * (1 - reduction), 1)


def rag_status(residual: float | None, red_threshold: int = 15, amber_threshold: int = 9) -> str:
    if residual is None:
        return "UNKNOWN"
    if residual >= red_threshold:
        return "RED"
    elif residual >= amber_threshold:
        return "AMBER"
    return "GREEN"


def exceeds_appetite(residual: float | None, appetite_threshold: int = 8) -> bool:
    if residual is None:
        return False
    return residual > appetite_threshold


def next_risk_id(prefix: str, last_seq: int) -> str:
    return f"{prefix}-{last_seq + 1:04d}"
