SEVERITY_POINTS = {
    "low": 1,
    "medium": 3,
    "high": 6,
    "critical": 20,
}


def confidence_value(raw_value):
    try:
        value = float(raw_value)
    except (TypeError, ValueError):
        return 0.6

    if value < 0:
        return 0.0
    if value > 1:
        return 1.0
    return value


def severity_weight(severity):
    return SEVERITY_POINTS.get(str(severity or "").lower(), 0)


def finding_score(finding):
    base = severity_weight(finding.get("severity"))
    confidence = confidence_value(finding.get("confidence"))
    return base * confidence


def count_by_severity(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings or []:
        severity = str(finding.get("severity", "")).lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def compute_score(findings):
    score = 0.0
    for finding in findings or []:
        score += finding_score(finding)
    return round(score, 2)


def classify_risk(score):
    if score <= 0:
        return "clean"
    if score >= 30:
        return "critical"
    if score >= 20:
        return "high"
    if score >= 10:
        return "medium"
    return "low"


def evaluate_risk(findings):
    score = compute_score(findings)
    risk = classify_risk(score)
    return score, risk
