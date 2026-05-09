import json
from pathlib import Path
import re
from packageguard.rules import RULES

def scan_package(path):
    # Set path to the package you are exploring
    package_path = Path(path)
    output = {}
    js_files = []
    mjs_files = []
    cjs_files = []
    report = {}

    # Load package.json for package and extract vulnerabilities
    with open(package_path / 'package.json', 'r') as f:
        vulnerabilities = json.load(f)

    output['vulnerabilities'] = vulnerabilities['scripts']

    # Walk through package dir
    for file in package_path.rglob("*"):
        # Skip node_modules, dist, and build directories
        if "node_modules" in file.parts or "dist" in file.parts or "build" in file.parts:
            continue
        
        if file.suffix == ".js":
            js_files.append(str(file))
        elif file.suffix == ".mjs":
            mjs_files.append(str(file))
        elif file.suffix == ".cjs":
            cjs_files.append(str(file))

    # Add files to output and serialize to JSON
    output['files'] = {}
    output['files']['js'] = js_files
    output['files']['mjs'] = mjs_files
    output['files']['cjs'] = cjs_files

    # with open('output.json', 'w') as f:
    #     json.dump(output, f)
    
    # Scan files
    # TODO: add package.json
    for group in output['files']:
        for file in output['files'][group]:
            file = Path(file)
            content = file.read_text(errors="ignore")
            points = 0
            for rule in RULES:
                if re.search(rule["pattern"], content):
                    points += rule["severity"]
            report[file] = points

    return report