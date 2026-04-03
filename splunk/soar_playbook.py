import json
import sys
import requests
from datetime import datetime


def page_splunk_oncall(spoc_url, cve_id, package, severity, image_name, fixed_version):
    # Build the SPOC alert payload
    # entity_id uses cve_id + package so duplicate alerts
    # for the same CVE don't create multiple incidents
    payload = {
        "message_type": "CRITICAL",
        "entity_id": f"cve-{cve_id}-{package}",
        "entity_display_name": f"CRITICAL CVE: {cve_id} in {package}",
        "state_message": (
            f"CVE ID: {cve_id}\n"
            f"Package: {package}\n"
            f"Severity: {severity}\n"
            f"Image: {image_name}\n"
            f"Fixed in version: {fixed_version}\n"
            f"Detected at: {datetime.now().isoformat()}\n"
            f"Action required: Update {package} to {fixed_version} immediately"
        ),
        "monitoring_tool": "Splunk DevSecOps Pipeline"
    }

    response = requests.post(
        spoc_url,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=10
    )

    return response.status_code, response.text


def create_github_issue(github_token, repo, cve_id, package,
                        severity, image_name, fixed_version):
    # GitHub Issues API endpoint
    # repo format is "owner/repo-name"
    url = f"https://api.github.com/repos/{repo}/issues"

    # Build the issue body in Markdown format
    # GitHub renders this as formatted text in the issue
    body = f"""## Security Alert — CRITICAL CVE Detected

| Field | Value |
|-------|-------|
| CVE ID | [{cve_id}](https://avd.aquasec.com/nvd/{cve_id.lower()}) |
| Package | {package} |
| Severity | {severity} |
| Image | {image_name} |
| Fixed Version | {fixed_version} |
| Detected | {datetime.now().isoformat()} |

## Required Action
Update `{package}` to version `{fixed_version}` in your Dockerfile or requirements.txt.

## How to fix
1. Update the package version in `app/requirements.txt`
2. Rebuild the Docker image
3. Re-run the pipeline to confirm the CVE is resolved

*This issue was automatically created by the DevSecOps SOAR playbook.*
"""

    payload = {
        "title": f"[CRITICAL] {cve_id} in {package} — immediate action required",
        "body": body,
        "labels": []
    }

    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json"
    }

    response = requests.post(url, json=payload, headers=headers, timeout=10)
    return response.status_code, response.json()


def main():
    print("SOAR Playbook starting...")

    if len(sys.argv) != 4:
        print("Usage: python3 soar_playbook.py <trivy-json> <spoc-url> <github-token>")
        sys.exit(1)

    trivy_file = sys.argv[1]
    spoc_url = sys.argv[2]
    github_token = sys.argv[3]

    # GitHub repo in owner/repo format
    repo = "Girish1818/devsecops-project1"

    # Load Trivy results
    with open(trivy_file, 'r') as f:
        data = json.load(f)

    image_name = data.get('ArtifactName', 'unknown')
    results = data.get('Results', [])

    critical_findings = []

    # Find all CRITICAL CVEs
    for result in results:
        for vuln in result.get('Vulnerabilities') or []:
            if vuln.get('Severity', '').upper() == 'CRITICAL':
                critical_findings.append({
                    'cve_id': vuln.get('VulnerabilityID', 'unknown'),
                    'package': vuln.get('PkgName', 'unknown'),
                    'severity': vuln.get('Severity', 'unknown'),
                    'fixed_version': vuln.get('FixedVersion', 'no fix available'),
                    'image_name': image_name
                })

    print(f"Critical findings found: {len(critical_findings)}")

    if not critical_findings:
        print("No CRITICAL CVEs found — no action required.")
        sys.exit(0)

    # Process each critical finding
    for finding in critical_findings:
        cve_id = finding['cve_id']
        package = finding['package']
        severity = finding['severity']
        fixed_version = finding['fixed_version']

        print(f"\nProcessing: {cve_id} in {package}")

        # Step 1 — Page Splunk On-Call
        print(f"  Paging SPOC...")
        status, response = page_splunk_oncall(
            spoc_url, cve_id, package, severity, image_name, fixed_version
        )
        if status == 200:
            print(f"  SPOC paged successfully")
        else:
            print(f"  SPOC failed: {status} — {response}")

        # Step 2 — Create GitHub Issue
        print(f"  Creating GitHub Issue...")
        status, response = create_github_issue(
            github_token, repo, cve_id, package,
            severity, image_name, fixed_version
        )
        if status == 201:
            issue_url = response.get('html_url', 'unknown')
            print(f"  Issue created: {issue_url}")
        else:
            print(f"  GitHub Issue failed: {status} — {response}")

    print(f"\n--- SOAR Summary ---")
    print(f"Critical CVEs processed: {len(critical_findings)}")
    print(f"SPOC alerts sent: {len(critical_findings)}")
    print(f"GitHub Issues created: {len(critical_findings)}")


main()