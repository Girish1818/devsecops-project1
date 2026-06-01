import json
import sys

with open(sys.argv[1]) as f:
    data = json.load(f)

critical = 0
high = 0
total = 0

for result in data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):
        severity = vuln.get("Severity", "").upper()
        title = vuln.get("Title", "No title")
        vuln_id = vuln.get("VulnerabilityID", "")
        pkg = vuln.get("PkgName", "")
        total += 1

        if severity == "CRITICAL":
            critical += 1
            print(f"[CRITICAL] {vuln_id} in {pkg}: {title}")
        elif severity == "HIGH":
            high += 1
            print(f"[HIGH]     {vuln_id} in {pkg}: {title}")

print(f"\n--- Trivy Summary ---")
print(f"Total vulnerabilities : {total}")
print(f"Critical              : {critical}")
print(f"High                  : {high}")

if critical > 0:
    print(f"\n[GATE FAILED] {critical} CRITICAL vulnerabilities found.")
    print("Pipeline blocked. Fix critical findings before deploying.")
    sys.exit(1)
else:
    print(f"\n[GATE PASSED] No critical vulnerabilities found.")
    print("Image cleared for ECR push.")
    sys.exit(0)