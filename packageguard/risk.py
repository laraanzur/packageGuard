SEVERITY_POINTS = {
    "low": 1,
    "medium": 3,
    "high": 6,
    "critical": 20,
}


def compute_score(findings):
    score = 0
    for finding in findings or []:
        severity = str(finding.get("severity", "")).lower()
        score += SEVERITY_POINTS.get(severity, 0)
    return score


def classify_risk(score):
    if score <= 0:
        return "clean"
    if score >= 20:
        return "critical"
    if score >= 12:
        return "high"
    if score >= 8:
        return "medium"
    return "low"


def evaluate_risk(findings):
    score = compute_score(findings)
    risk = classify_risk(score)
    return score, risk
