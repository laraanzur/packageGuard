import json
import os
import socket
from urllib import request, error


def _is_chain_finding(finding):
	rule_id = str(finding.get("rule_id", ""))
	return finding.get("source") == "behavior-chain" or rule_id.startswith("chain-")


def _severity_rank(severity):
	order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
	return order.get(str(severity or "").lower(), 4)


def _sort_findings(findings):
	return sorted(
		findings,
		key=lambda finding: (
			0 if _is_chain_finding(finding) else 1,
			_severity_rank(finding.get("severity")),
		),
	)


def _shorten(text, limit=200):
	if not text:
		return ""
	text = str(text).strip()
	if len(text) <= limit:
		return text
	return text[: limit - 3].rstrip() + "..."


def build_summary_payload(report, max_findings=5):
	findings = report.get("findings") or []
	sorted_findings = _sort_findings(findings)
	counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
	for finding in findings:
		severity = str(finding.get("severity", "")).lower()
		if severity in counts:
			counts[severity] += 1

	top_findings = []
	for finding in sorted_findings[:max_findings]:
		top_findings.append(
			{
				"severity": finding.get("severity"),
				"title": finding.get("title"),
				"summary": _shorten(finding.get("explanation_recommendation")),
			}
		)

	return {
		"package": f"{report.get('package_name', 'unknown')}@{report.get('package_version', 'unknown')}",
		"risk": report.get("risk"),
		"score": report.get("score"),
		"finding_counts": counts,
		"top_findings": top_findings,
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


def _ollama_url():
	base = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
	return base.rstrip("/") + "/api/generate"


def _ollama_generate(model, prompt, timeout=30):
	payload = {
		"model": model,
		"prompt": prompt,
		"stream": False,
	}
	data = json.dumps(payload).encode("utf-8")
	request_obj = request.Request(
		_ollama_url(),
		data=data,
		headers={"Content-Type": "application/json"},
		method="POST",
	)
	try:
		with request.urlopen(request_obj, timeout=timeout) as response:
			body = response.read().decode("utf-8")
			result = json.loads(body)
	except (error.URLError, socket.timeout) as exc:
		raise RuntimeError("Failed to reach Ollama: " + str(exc))
	except ValueError as exc:
		raise RuntimeError("Invalid response from Ollama: " + str(exc))

	if "error" in result:
		raise RuntimeError(result["error"])

	return str(result.get("response", "")).strip()


def _trim_summary(text, limit=600):
	text = str(text or "").strip()
	if len(text) <= limit:
		return text
	cut = text.rfind(".", 0, limit)
	if cut > 0:
		return text[: cut + 1]
	return text[:limit].rstrip() + "..."



def summarize_report(report, model, max_findings=5, timeout=30):
	payload = build_summary_payload(report, max_findings=max_findings)
	prompt = build_prompt(payload)
	response = _ollama_generate(model, prompt, timeout=timeout)
	return _trim_summary(response)
