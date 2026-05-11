import json
from pathlib import Path
import re
from packageguard.rules import JS_RULES, LIFECYCLE_SCRIPTS, SCRIPT_PATTERNS
import tarfile
import tempfile
import zipfile
import shutil

from pathlib import Path

def find_package_root(root: Path) -> Path:

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

def search_package_json(clean_path):
    # Load the file
    with open(clean_path / 'package.json', 'r') as f:
        package_json = json.load(f)
        
    # Scan through it
    findings = []

    # Find the scripts section, then go through every script
    scripts = package_json.get("scripts", {})


    # Find lifecycle scripts
    for name, command in scripts.items():
        if name in LIFECYCLE_SCRIPTS:
            findings.append({
                "rule": "lifecycle-script",
                "severity": "high",
                "file": "package.json",
                "snippet": f"{name}: {command}",
                "message": f"Package defines npm lifecycle script '{name}', which can execute during installation.",
            })

        # Match certain script patterns to commans
        for rule in SCRIPT_PATTERNS:
            if re.search(rule["pattern"], command, re.IGNORECASE):
                findings.append({
                    "rule": rule["id"],
                    "severity": rule["severity"],
                    "file": "package.json",
                    "snippet": f"{name}: {command}",
                    "message": rule["message"],
                })
    
    return findings, package_json

def find_js_files(clean_path):
    output = {}
    js_files = []
    mjs_files = []
    cjs_files = []

    # Walk through package dir
    for file in clean_path.rglob("*"):
        # Skip node_modules, dist, and build directories #TODO maybe skip some additional files
        if "node_modules" in file.parts or "dist" in file.parts or "build" in file.parts:
            continue
        
        if file.suffix == ".js":
            js_files.append(str(file))
        elif file.suffix == ".mjs":
            mjs_files.append(str(file))
        elif file.suffix == ".cjs":
            cjs_files.append(str(file))

    # Add files to output and serialize to JSON
    output['js'] = js_files
    output['mjs'] = mjs_files
    output['cjs'] = cjs_files

    # with open('output.json', 'w') as f:
    #     json.dump(output, f)

    return output 

def scan_js_files(output, findings):
    for group in output:
        for file in output[group]:
            file = Path(file)
            lines = file.read_text(errors="ignore").splitlines()
            for line_number, line in enumerate(lines, start=1):
                for rule in JS_RULES:
                    if re.search(rule["pattern"], line, re.IGNORECASE):
                        findings.append({
                            "rule": rule["id"],
                            "severity": rule["severity"],
                            "file": str(file),
                            "snippet": line.strip(),
                            "message": rule["message"],
                        })
    
    return findings

def overall_score(findings):
    severity_points = {
            "low": 1,
            "medium": 2,
            "high": 4,
            "critical": 6,
        }

    score = 0
    for finding in findings:
        score += severity_points.get(finding["severity"], 0)

    if score >= 12:
        risk = "critical"
    elif score >= 7:
        risk = "high"
    elif score >= 3:
        risk = "medium"
    else:
        risk = "low"
    
    return score, risk


def scan_package(path):
    # Set path to the package you are exploring
    package_path = Path(path)
    clean_path, cleanup = prepare_scan_target(package_path)

    report = {}

    try:
        # package.json findings
        findings, package_json = search_package_json(clean_path)
        
        # Find JS files to scan, and then scan them
        all_js_files = find_js_files(clean_path)
        findings = scan_js_files(all_js_files, findings)

        # Calculate risk score
        score, risk = overall_score(findings)
        
        # Make a report
        report = {
            "package_name": package_json.get("name", "unknown"),
            "package_version": package_json.get("version", "unknown"),
            "risk": risk,
            "score": score,
            "files": all_js_files,
            "findings": findings,
        }
        return report
    
    finally:
        cleanup()