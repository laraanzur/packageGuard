import argparse
from packageguard.scanner import scan_package

parser = argparse.ArgumentParser('PackageGuard Demo')
parser.add_argument('--path', '-i', help='Input file to scan for vulnerabilities')
args = parser.parse_args()

result = scan_package(args.path)
print(result)
