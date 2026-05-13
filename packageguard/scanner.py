import json
from pathlib import Path
import re
from packageguard.rules import JS_RULES, LIFECYCLE_SCRIPTS, SCRIPT_PATTERNS
from packageguard.behavior_chains import apply_behavior_chains
from packageguard.risk import evaluate_risk
from packageguard.typosquat import evaluate_typosquatting
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
            script_file = extract_script_file(command)
            findings.append({
                "rule_id": "lifecycle-script",
                "title": "Lifecycle script",
                "severity": "high",
                "confidence": "",
                "file": f"package.json -> scripts -> {script_file if script_file else name}",
                "line": None,
                "evidence": f"{name}: {command}",
                "explanation_recommendation": "",
                "tags": ["lifecycle-reachable"]
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
                    "line": None,
                    "evidence": f"{name}: {command}",
                    "explanation_recommendation": "",
                    "tags": rule["id"].split("-")
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

def scan_js_files(output, findings):
    for group in output:
        for file in output[group]:
            file = Path(file)
            # Integrate AST based finding
            ast_findings = scan_js_file_ast(file)
            findings.extend(ast_findings)
            lines = file.read_text(errors="ignore").splitlines()
            for line_number, line in enumerate(lines, start=1):
                for rule in JS_RULES:
                    if re.search(rule["pattern"], line, re.IGNORECASE):
                        findings.append({
                            "rule_id": rule["id"],
                            "title": rule["title"],
                            "severity": rule["severity"],
                            "confidence": "",
                            "file": str(file),
                            "line": line_number,
                            "evidence": line.strip(),
                            "message": rule["message"],
                            "explanation_recommendation": "",
                            "tags": rule["id"].split("-")
                        })
    
    return findings



def scan_package(path):
    # Set path to the package you are exploring
    package_path = Path(path)
    clean_path, cleanup = prepare_scan_target(package_path)

    report = {}

    try:
        # package.json findings
        findings, package_json = search_package_json(clean_path)
        
        typosquat = evaluate_typosquatting(package_json.get("name", ""))

        # Find JS files to scan, and then scan them
        all_js_files = find_js_files(clean_path)
        findings = scan_js_files(all_js_files, findings)

        # Apply behavior chains and calculate risk score
        findings = apply_behavior_chains(findings)
        score, risk = evaluate_risk(findings)
        
        # Make a report
        report = {
            "package_name": package_json.get("name", "unknown"),
            "package_version": package_json.get("version", "unknown"),
            "risk": risk,
            "score": score,
            "typosquat": typosquat,
            "files": all_js_files,
            "findings": findings,
        }
        return report
    
    finally:
        cleanup()