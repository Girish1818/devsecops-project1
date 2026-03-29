import json
import sys

# Load the Trivy JSON output
# sys.argv[1] means "the first argument passed to this script"
# We will run it as: python3 trivy-check.py trivy-results.json
with open(sys.argv[1]) as f:
    data = json.load(f)

# Counters for each severity level
critical = 0
high = 0
total = 0

# data["Results"] is a list — one entry per scanned target
# (OS packages, Python packages, etc.)
# Each Result has a "Vulnerabilities" list
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

# Print summary
print(f"\n--- Summary ---")
print(f"Total vulnerabilities : {total}")
print(f"Critical              : {critical}")
print(f"High                  : {high}")

# The pipeline gate decision
# If ANY critical exists — block the pipeline
if critical > 0:
    print(f"\n[GATE FAILED] {critical} CRITICAL vulnerabilities found.")
    print("Pipeline blocked. Fix critical findings before deploying.")
    sys.exit(1)  # Exit code 1 = failure — GitHub Actions will see this and stop
else:
    print(f"\n[GATE PASSED] No critical vulnerabilities found.")
    sys.exit(0)  # Exit code 0 = success — pipeline continues