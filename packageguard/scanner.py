import json
from pathlib import Path
import re
from packageguard.rules import REGEX, LIFECYCLE_SCRIPTS, SCRIPT_PATTERNS
from packageguard.behavior_chains import apply_behavior_chains
from packageguard.risk import evaluate_risk
from packageguard.package_trust import evaluate_package_trust
import tarfile
import tempfile
import zipfile
import shutil
import shlex
import subprocess

def find_package_root(root):

    # Find all package.json files
    matches = [p for p in root.rglob("package.json") if "node_modules" not in p.parts]

    # Choose the one with shortest relative path from root
    matches.sort(key=lambda p: len(p.relative_to(root).parts))

    return matches[0].parent

def prepare_scan_target(path):
    # Case 1: If path is a directory, it doesnt need unzipping
    if path.is_dir():
        return path, lambda: None

    # Case 2: Zipped file - .tar.gz or .tgz
    if (path.is_file() and path.suffixes[-2:] == [".tar", ".gz"]) or (path.is_file() and path.suffix == ".tgz"):
        # Make a temporary directory and extract files in it
        temp_dir = tempfile.mkdtemp(prefix="packageguard_")

        with tarfile.open(path, "r:gz") as tar:
            tar.extractall(temp_dir)

        # Posix path to temporary directory
        root = Path(temp_dir)
        extracted_root = find_package_root(root)

        # Define cleanup function for after the end of the program
        def cleanup():
            shutil.rmtree(temp_dir, ignore_errors=True)

        return extracted_root, cleanup
    
    # Case 3: Zipped file - .zip
    if path.is_file() and path.suffix == ".zip":
        # Make a temporary directory and extract files in it
        temp_dir = tempfile.mkdtemp(prefix="packageguard_")

        with zipfile.ZipFile(path, "r") as zip_ref:
            zip_ref.extractall(temp_dir)

        # Path to temporary directory
        root = Path(temp_dir)
        extracted_root = find_package_root(root)
        
        # Define cleanup function for after the end of the program
        def cleanup():
            shutil.rmtree(temp_dir, ignore_errors=True)

        return extracted_root, cleanup

def extract_script_file(cmd):
    # Get script from command (if it exists)
    try:
        parts = shlex.split(cmd, posix=False)
    except ValueError:
        return None

    for part in parts[1:]:
        if part.endswith((".js", ".cjs", ".mjs")):
            return part

    return None

def find_line_number(raw_text, name_needle, command_needle=None):
    for line_number, line in enumerate(raw_text.splitlines(), start=1):
        if name_needle in line and (command_needle is None or command_needle in line):
            return line_number
    return None

def search_package_json(clean_path):
    # Load the file
    # with open(clean_path / 'package.json', 'r') as f:
    #     package_json = json.load(f)
    
    raw_text = (clean_path / 'package.json').read_text(errors="ignore")
    package_json = json.loads(raw_text)
        
    # Scan through it
    findings = []
    lifecycle_findings = set()

    # Find the scripts section, then go through every script
    scripts = package_json.get("scripts", {})

    # Find lifecycle scripts
    for name, command in scripts.items():
        line_number = find_line_number(raw_text, f'"{name}"', command_needle=command)
        if name in LIFECYCLE_SCRIPTS:
            script_file = extract_script_file(command)
            if script_file:
                lifecycle_findings.add(script_file)
            findings.append({
                "rule_id": "lifecycle-script",
                "title": "Lifecycle script",
                "severity": "high",
                "confidence": "",
                "file": f"package.json",
                "line": line_number,
                "evidence": f"{name}: {command}",
                "explanation_recommendation": "",
                "tags": ["lifecycle"],
                "source": "package.json"
            })

        # Match certain script patterns to commans
        for rule in SCRIPT_PATTERNS:
            if re.search(rule["pattern"], command, re.IGNORECASE):
                findings.append({
                    "rule_id": rule["id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "confidence": "",
                    "file": "package.json",
                    "line": line_number,
                    "evidence": f"{name}: {command}",
                    "explanation_recommendation": "",
                    "tags": rule["tags"],
                    "source": "package.json-regex"
                })
    
    return findings, package_json, lifecycle_findings

def find_js_files(clean_path):
    output = []

    # Walk through package dir
    for file in clean_path.rglob("*"):
        # Skip node_modules, dist, and build directories #TODO maybe skip some additional files
        if "node_modules" in file.parts or "dist" in file.parts or "build" in file.parts:
            continue
        
        if file.suffix in [".js", ".mjs", ".cjs"]:
            output.append(str(file))

    return output 

def scan_js_file_ast(file):
    ast_scanner = Path(__file__).parent / "ast_scanner.js"

    result = subprocess.run(
        ["node", str(ast_scanner), str(file)],
        capture_output=True,
        text=True,
        check=False
    )

    ast_findings = json.loads(result.stdout)

    return ast_findings

def relative_file_path(file, clean_path):
    return str(Path(file).relative_to(clean_path)).replace("\\", "/")

def mark_lifecycle_reachable(finding, file, clean_path, lifecycle_files):
    rel_file = relative_file_path(file, clean_path)
    finding["file"] = rel_file

    tags = set(finding.get("tags", []))

    for lifecycle_file in lifecycle_files:
        lifecycle_file = lifecycle_file.replace("\\", "/")
        if rel_file == lifecycle_file:
            tags.add("lifecycle-reachable")

    finding["tags"] = sorted(tags)
    return finding

def dedupe_findings(findings):
    seen = set()
    unique = []
    counts = {}
    max_per_rule_per_file = 3

    for finding in findings:
        key = (
            finding.get("rule_id"),
            finding.get("file"),
            finding.get("line"),
            finding.get("evidence"),
        )

        if key in seen:
            continue

        count_key = (finding.get("rule_id"), finding.get("file"))
        if counts.get(count_key, 0) >= max_per_rule_per_file:
            continue

        seen.add(key)
        counts[count_key] = counts.get(count_key, 0) + 1
        unique.append(finding)

    return unique

def scan_js_files(output, findings, clean_path, lifecycle_findings):
    for file in output:
        file = Path(file)

        # 1. Integrate AST based finding
        ast_findings = scan_js_file_ast(file)
        
        for finding in ast_findings:
            finding = mark_lifecycle_reachable(finding, file, clean_path, lifecycle_findings)
            findings.append(finding)
        
        # 2. Apply regex rules
        lines = file.read_text(errors="ignore").splitlines()
        for line_number, line in enumerate(lines, start=1):
            for rule in REGEX:
                if re.search(rule["pattern"], line, re.IGNORECASE):
                    finding ={
                        "rule_id": rule["id"],
                        "title": rule["title"],
                        "severity": rule["severity"],
                        "confidence": "",
                        "file": str(file),
                        "line": line_number,
                        "evidence": line.strip(),
                        "explanation_recommendation": "",
                        "tags": rule["tags"],
                        "source": "regex"
                    }
                    finding = mark_lifecycle_reachable(finding, file, clean_path, lifecycle_findings)
                    findings.append(finding)

    return findings



def scan_package(path):
    # Set path to the package you are exploring
    package_path = Path(path)
    clean_path, cleanup = prepare_scan_target(package_path)

    report = {}

    try:
        # package.json findings
        findings, package_json, lifecycle = search_package_json(clean_path)
        
        package_trust = evaluate_package_trust(package_json.get("name", ""))

        # Find JS files to scan, and then scan them
        all_js_files = find_js_files(clean_path)
        findings = scan_js_files(all_js_files, findings, clean_path,lifecycle)
        
        # Deduplicate findings
        findings = dedupe_findings(findings)

        # Apply behavior chains and calculate risk score
        findings = apply_behavior_chains(findings)
        score, risk = evaluate_risk(findings)
        
        # Make a report
        report = {
            "package_name": package_json.get("name", "unknown"),
            "package_version": package_json.get("version", "unknown"),
            "risk": risk,
            "score": score,
            "package_trust": package_trust,
            "files": all_js_files,
            "findings": findings,
        }
        return report
    
    finally:
        cleanup()