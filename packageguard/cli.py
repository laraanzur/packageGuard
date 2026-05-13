import argparse
import os
import sys
from pathlib import Path
import shutil
import subprocess
import tempfile

from packageguard.scanner import scan_package
from packageguard.llm_summary import summarize_report


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


def _print_typosquat(report):
	typosquat = report.get("typosquat") or {}
	if not typosquat:
		return
	risk = str(typosquat.get("risk", "clean")).lower()
	if risk == "clean":
		return

	label = _style(risk.upper(), *_severity_style(risk))
	print(f"Typosquatting possibility: {label}")

	match = typosquat.get("match")
	if match:
		print(f"Did you mean {_style(match, * _severity_style('medium'))}?")

	print("")


def _resolve_npm_command():
	npm_path = os.environ.get("NPM_PATH")
	if npm_path and Path(npm_path).exists():
		return npm_path

	for candidate in ("npm", "npm.cmd", "npm.exe"):
		found = shutil.which(candidate)
		if found:
			return found

	if os.name == "nt":
		for env_name in ("NVM_SYMLINK", "NVM_HOME"):
			base = os.environ.get(env_name)
			if not base:
				continue
			candidate = Path(base) / "npm.cmd"
			if candidate.exists():
				return str(candidate)

	return None


def _resolve_scan_target(raw_target):
	if not raw_target:
		return None, None

	path = Path(raw_target)
	if path.exists():
		return str(path), None

	temp_dir = tempfile.mkdtemp(prefix="packageguard_scan_")
	try:
		npm_cmd = _resolve_npm_command()
		if not npm_cmd:
			shutil.rmtree(temp_dir, ignore_errors=True)
			print("npm is not available on PATH. Set NPM_PATH or add npm to PATH to scan package names.")
			raise SystemExit(1)
		result = subprocess.run(
			[npm_cmd, "pack", raw_target],
			cwd=temp_dir,
			capture_output=True,
			text=True,
			check=True,
		)
		if result.stdout:
			print(result.stdout.strip())
	except FileNotFoundError:
		shutil.rmtree(temp_dir, ignore_errors=True)
		print("npm is not available on PATH. Set NPM_PATH or add npm to PATH to scan package names.")
		raise SystemExit(1)
	except subprocess.CalledProcessError as exc:
		shutil.rmtree(temp_dir, ignore_errors=True)
		print("Failed to download package via npm pack.")
		if exc.stdout:
			print(exc.stdout.strip())
		if exc.stderr:
			print(exc.stderr.strip())
		raise SystemExit(1)

	tgz_files = sorted(
		Path(temp_dir).glob("*.tgz"),
		key=lambda item: item.stat().st_mtime,
		reverse=True,
	)
	if not tgz_files:
		shutil.rmtree(temp_dir, ignore_errors=True)
		print("npm pack did not produce a .tgz file.")
		raise SystemExit(1)

	return str(tgz_files[0]), lambda: shutil.rmtree(temp_dir, ignore_errors=True)


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
	_print_typosquat(report)	
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
		try:
			summary = summarize_report(report, llm_name)
		except Exception as exc:
			print(f"Summary unavailable: {exc}")
		else:
			print(summary or "Summary unavailable.")
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
parser.add_argument('target', nargs='?', help='Path to package or npm package name')
parser.add_argument('--path', '-i', help='Path to package (legacy)')
parser.add_argument('--llm', help='Enable LLM summary output')
args = parser.parse_args()

target_arg = args.path or args.target
if not target_arg:
	parser.error("Provide a path or npm package name")

target, cleanup = _resolve_scan_target(target_arg)
try:
	result = scan_package(target)
	print_report(result, args.llm)
finally:
	if cleanup:
		cleanup()
