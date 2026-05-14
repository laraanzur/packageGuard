import argparse
import os
import sys
from pathlib import Path
import shutil
import subprocess
import tempfile

from packageguard.scanner import scan_package
from packageguard.llm_summary import summarize_report
from packageguard.risk import count_by_severity, finding_score


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
	return len(files)


def _get_tags(finding):
	tags = finding.get("tags") or []
	flat = []
	for tag in tags:
		if isinstance(tag, list):
			flat.extend(tag)
		else:
			flat.append(tag)
	return [tag for tag in flat if tag]


def _recommendation_for_risk(risk):
	risk = str(risk or "").lower()
	return {
		"clean": "No suspicious behavior detected. Proceed with standard review practices.",
		"low": "Proceed with caution and review the flagged code paths.",
		"medium": "Manual review is recommended before installing this package.",
		"high": "Do not install unless the behavior has been manually reviewed and verified.",
		"critical": "Do not install this package unless the behavior has been manually reviewed and verified.",
	}.get(risk, "Manual review is recommended before installing this package.")


def _format_value(value):
	if value is None or value == "":
		return "unknown"
	return str(value)


def _format_days(value):
	if value is None:
		return "unknown"
	return f"{value} days"


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
	package_trust = report.get("package_trust") or {}

	header = _style("PackageGuard scan report", "\x1b[1m")
	print(header)
	print("=" * 60)
	print("")
	print(f"Package: {package_name}@{package_version}")
	print("")

	if package_trust.get("status") == "similar":
		print(_style("!!! POSSIBLE PACKAGE NAME CONFUSION !!!", *_severity_style("CRITICAL")))
		print("-" * 60)
		print(f"You are scanning:      {package_name}")
		match = package_trust.get("match")
		if match:
			print(f"Closest popular match: {match}")
		print("")

	if llm_name:
		print("Summary")
		print("-" * 60)
		try:
			summary = summarize_report(report, llm_name)
		except Exception as exc:
			print(f"Summary unavailable: {exc}")
		else:
			print(summary or "Summary unavailable.")
		print("")

	trust_risk = str(package_trust.get("risk", "clean")).lower()
	trust_label = _style(trust_risk.upper(), *_severity_style(trust_risk))
	print(f"Package trust risk [{trust_label}]")
	print("-" * 60)
	status = package_trust.get("status")
	if status == "similar":
		name_similarity = "similar"
	elif status == "exact":
		name_similarity = "exact match"
	else:
		name_similarity = "not detected"
	print(f"Name similarity to popular packages: {name_similarity}")

	metadata = package_trust.get("metadata") or {}
	print(f"Downloads last week: {_format_value(metadata.get('downloads_last_week'))}")
	print(f"Package age: {_format_days(metadata.get('age_days'))}")
	print(f"Created: {_format_value(metadata.get('created'))}")
	print(f"Days since last modification: {_format_days(metadata.get('days_since_modified'))}")
	print("")

	analysis_label = _style(risk.upper(), *_severity_style(risk))
	print(f"Static code analysis risk [{analysis_label}]")
	print("-" * 60)
	print(f"Score: {score}")
	print(f"JS files scanned: {_total_js_files(files)}")

	counts = count_by_severity(findings)
	summary = (
		f"critical:{counts['critical']} "
		f"high:{counts['high']} "
		f"medium:{counts['medium']} "
		f"low:{counts['low']}"
	)

	print(f"Findings: {len(findings)} ({summary})")
	print("Top findings:")
	print("")

	if not findings:
		print("None")
		print("")
		print("Recommendation")
		print("-" * 60)
		print(_recommendation_for_risk(risk))
		return

	sorted_findings = sorted(findings, key=finding_score, reverse=True)[:15]
	_print_findings(sorted_findings)

	print("Recommendation")
	print("-" * 60)
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
