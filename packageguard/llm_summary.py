import json
import os
import socket
from urllib import request, error

from packageguard.risk import count_by_severity, finding_score


def _shorten(text, limit=200):
	if not text:
		return ""
	text = str(text).strip()
	if len(text) <= limit:
		return text
	return text[: limit - 3].rstrip() + "..."


def build_summary_payload(report, max_findings=5):
	findings = report.get("findings") or []
	chain_findings = []
	other_findings = []
	for finding in findings:
		rule_id = str(finding.get("rule_id", ""))
		if finding.get("source") == "behavior-chain" or rule_id.startswith("chain-"):
			chain_findings.append(finding)
		else:
			other_findings.append(finding)

	chain_findings = sorted(chain_findings, key=finding_score, reverse=True)
	other_findings = sorted(other_findings, key=finding_score, reverse=True)
	sorted_findings = chain_findings + other_findings

	counts = count_by_severity(findings)

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
