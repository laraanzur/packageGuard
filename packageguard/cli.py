import argparse
from packageguard.scanner import scan_package


def print_report(report):
    print()
    print("PackageGuard scan report")
    print("=" * 40)
    print(f"Package: {report['package_name']}@{report['package_version']}")
    print(f"Risk: {report['risk'].upper()} ({report['score']} points)")

    total_files = (
        len(report["files"]["js"])
        + len(report["files"]["mjs"])
        + len(report["files"]["cjs"])
    )

    print(f"JS files scanned: {total_files}")
    print()

    if not report["findings"]:
        print("No suspicious findings detected.")
        return

    print("Findings:")
    print("-" * 40)

    for finding in report["findings"]:
        location = finding["file"]

        print(f"[{finding['severity'].upper()}] {location} - {finding['rule']}")
        print(f"  {finding['message']}")

        if finding["snippet"]:
            print(f"  > {finding['snippet']}")

        print()

parser = argparse.ArgumentParser('PackageGuard Demo')
parser.add_argument('--path', '-i', help='Input file to scan for vulnerabilities')
args = parser.parse_args()

result = scan_package(args.path)
print_report(result)
