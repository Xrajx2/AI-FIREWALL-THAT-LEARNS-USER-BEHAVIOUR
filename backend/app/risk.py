from __future__ import annotations


def clamp_risk_score(score: float) -> float:
    return max(0.0, min(100.0, float(score or 0.0)))


def score_to_risk_level(score: float) -> str:
    normalized = clamp_risk_score(score)
    if normalized <= 30.0:
        return "Normal"
    if normalized <= 70.0:
        return "Suspicious"
    return "Dangerous"


def score_to_recommended_action(score: float) -> str:
    normalized = clamp_risk_score(score)
    if normalized <= 30.0:
        return "allow"
    if normalized <= 70.0:
        return "monitor"
    return "block"


def is_risky(score: float) -> bool:
    return clamp_risk_score(score) > 30.0
