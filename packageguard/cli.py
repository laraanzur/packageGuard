import argparse
import os
import sys

from packageguard.scanner import scan_package


def _supports_color():
	return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


_USE_COLOR = _supports_color()


def _style(text, *codes):
	if not _USE_COLOR or not codes:
		return text
	return "".join(codes) + text + "\x1b[0m"


def _severity_style(severity):
	severity = str(severity or "").lower()
	if severity == "critical":
		return ("\x1b[31m", "\x1b[1m")
	if severity == "high":
		return ("\x1b[31m",)
	if severity == "medium":
		return ("\x1b[33m",)
	if severity == "low":
		return ("\x1b[36m",)
	if severity == "clean":
		return ("\x1b[32m",)
	return ()


def _format_location(finding):
	file = finding.get("file") or "unknown"
	line = finding.get("line")
	if line is None:
		return str(file)
	return f"{file}:{line}"


def _total_js_files(files):
	return (
		len(files.get("js", []))
		+ len(files.get("mjs", []))
		+ len(files.get("cjs", []))
	)


def _count_by_severity(findings):
	counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
	for finding in findings:
		severity = str(finding.get("severity", "")).lower()
		if severity in counts:
			counts[severity] += 1
	return counts


def _get_tags(finding):
	tags = finding.get("tags") or []
	flat = []
	for tag in tags:
		if isinstance(tag, list):
			flat.extend(tag)
		else:
			flat.append(tag)
	return [tag for tag in flat if tag]


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


def _recommendation_for_risk(risk):
	risk = str(risk or "").lower()
	return {
		"clean": "No suspicious behavior detected. Proceed with standard review practices.",
		"low": "Proceed with caution and review the flagged code paths.",
		"medium": "Manual review is recommended before installing this package.",
		"high": "Do not install unless the behavior has been manually reviewed and verified.",
		"critical": "Do not install this package unless the behavior has been manually reviewed and verified.",
	}.get(risk, "Manual review is recommended before installing this package.")


def print_report(report, llm_name=None):
	package_name = report.get("package_name", "unknown")
	package_version = report.get("package_version", "unknown")
	risk = str(report.get("risk", "unknown"))
	score = report.get("score", 0)
	files = report.get("files") or {}
	findings = report.get("findings") or []

	header = _style("PackageGuard scan report", "\x1b[1m")
	print(header)
	print("=" * 40)
	print(f"Package: {package_name}@{package_version}")

	risk_label = _style(risk.upper(), *_severity_style(risk))
	print(f"Risk: {risk_label} ({score} points)")
	print(f"JS files scanned: {_total_js_files(files)}")

	counts = _count_by_severity(findings)
	summary = (
		f"critical:{counts['critical']} "
		f"high:{counts['high']} "
		f"medium:{counts['medium']} "
		f"low:{counts['low']}"
	)
	print(f"Findings: {len(findings)} ({summary})")

	if llm_name:
		print("\nSummary:")
		print("")

	print("Top findings:")
	print("")

	if not findings:
		print("None")
		print("\nRecommendation:")
		print(_recommendation_for_risk(risk))
		return

	sorted_findings = _sort_findings(findings)
	_print_findings(sorted_findings)

	print("Recommendation:")
	print(_recommendation_for_risk(risk))


def _print_findings(findings):
	for index, finding in enumerate(findings, start=1):
		severity = str(finding.get("severity", "unknown")).lower()
		severity_label = _style(severity.upper(), *_severity_style(severity))
		title = finding.get("title", "unknown")
		rule_id = finding.get("rule_id", "unknown")
		location = _format_location(finding)

		print(f"{index}. [{severity_label}] {title}")
		print(f"   Rule: {rule_id}")
		print(f"   File: {location}")

		evidence = finding.get("evidence")
		if evidence:
			print(f"   Evidence: {evidence}")

		tags = ", ".join(_get_tags(finding))
		if tags:
			print(f"   Tags: {tags}")

		print()


parser = argparse.ArgumentParser('PackageGuard Demo')
parser.add_argument('--path', '-i', help='Input file to scan for vulnerabilities')
parser.add_argument('--llm', help='Enable LLM summary output')
args = parser.parse_args()

result = scan_package(args.path)
print_report(result, args.llm)
