import json
import os
from urllib import request, error

from packageguard.risk import count_by_severity, finding_score


def build_summary_payload(report, metadata, max_findings=5):
    findings = report.get("findings") or []
    chain_findings = []
    other_findings = []
    for finding in findings:
        rule_id = finding.get("rule_id", "")
        rule_id = str(rule_id)
        if finding.get("source") == "behavior-chain" or rule_id.startswith("chain-"):
            chain_findings.append(finding)
        else:
            other_findings.append(finding)

    chain_findings.sort(key=finding_score, reverse=True)
    other_findings.sort(key=finding_score, reverse=True)
    sorted_findings = chain_findings + other_findings

    counts = count_by_severity(findings)

    top_findings = []
    for finding in sorted_findings[:max_findings]:
        summary = finding.get("explanation_recommendation")
        if not summary:
            summary = ""
        else:
            summary = str(summary).strip()
            if len(summary) > 200:
                summary = summary[:197].rstrip() + "..."
        top_findings.append(
            {
                "severity": finding.get("severity"),
                "title": finding.get("title"),
                "summary": summary,
            }
        )

    package_name = report.get("package_name")
    if not package_name:
        package_name = "unknown"
    package_version = report.get("package_version")
    if not package_version:
        package_version = "unknown"

    return {
        "package": f"{package_name}@{package_version}",
        "risk": report.get("risk"),
        "score": report.get("score"),
        "finding_counts": counts,
        "top_findings": top_findings,
        "package_trust": metadata
    }


def build_prompt(payload):
    return (
        "You are PackageGuard, a safety assistant. "
        "Summarize the scan results for a non-technical user. "
        "Use 2 to 4 short sentences. Keep it under 70 words. "
        "Explain the overall risk and the main behaviors in plain language. "
        "Do not mention rule IDs, tags, filenames, code, or any technical jargon. "
        "Do not include recommendations or steps. "
        "Do not use bullet points, headings, or markdown. "
        "Output only the summary text without any preface.\n\n"
        "Scan data (JSON):\n"
        + json.dumps(payload, indent=2)
    )

def _ollama_generate(model, prompt, timeout=30):
    base = os.environ.get("OLLAMA_HOST")
    if not base:
        base = "http://localhost:11434"
    url = base.rstrip("/") + "/api/generate"

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }
    data = json.dumps(payload).encode("utf-8")
    request_obj = request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(request_obj, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except error.URLError as exc:
        raise RuntimeError("Failed to reach Ollama: " + str(exc))

    result = json.loads(body)

    if "error" in result:
        raise RuntimeError(result["error"])

    return str(result.get("response", "")).strip()

def summarize_report(report, metadata, model, max_findings=5, timeout=30):
    payload = build_summary_payload(report, metadata, max_findings=max_findings)
    prompt = build_prompt(payload)
    response = _ollama_generate(model, prompt, timeout=timeout)
    text = str(response or "").strip()
    if len(text) <= 600:
        return text
    cut = text.rfind(".", 0, 600)
    if cut > 0:
        return text[: cut + 1]
    return text[:600].rstrip() + "..."
