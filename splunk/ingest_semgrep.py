import json
import sys
import requests
from datetime import datetime


def send_to_splunk(event, url, token):
    payload = {
        "event": event,
        "index": "devsecops_semgrep",
        "sourcetype": "_json"
    }
    headers = {
        "Authorization": f"Splunk {token}",
        "Content-Type": "application/json",
        "X-Splunk-Request-Channel": "devsecops-semgrep-channel"
    }
    response = requests.post(
        f"{url}/services/collector/event",
        json=payload,
        headers=headers,
        timeout=10
    )
    return response.status_code, response.text


def main():
    print("Semgrep ingestion starting...")

    if len(sys.argv) != 4:
        print("Usage: python3 ingest_semgrep.py <sarif-file> <hec-url> <hec-token>")
        sys.exit(1)

    sarif_file = sys.argv[1]
    hec_url = sys.argv[2]
    hec_token = sys.argv[3]

    print(f"Reading from: {sarif_file}")
    print(f"Sending to: {hec_url}")
    print(f"Token: {hec_token[:8]}...")

    with open(sarif_file, 'r') as f:
        data = json.load(f)

    runs = data.get('runs', [])
    if not runs:
        print("No runs found in SARIF file.")
        sys.exit(1)

    findings = runs[0].get('results', [])
    print(f"Total findings: {len(findings)}")

    scan_time = datetime.now().isoformat()
    events_built = []

    for result in findings:
        rule_id = result.get('ruleId', 'unknown')
        message = result.get('message', {}).get('text', 'unknown')

        locations = result.get('locations', [])
        if locations:
            phys = locations[0].get('physicalLocation', {})
            file_path = phys.get('artifactLocation', {}).get('uri', 'unknown')
            region = phys.get('region', {})
            line_number = region.get('startLine', 'unknown')
            snippet = region.get('snippet', {}).get('text', 'none')
        else:
            file_path = 'unknown'
            line_number = 'unknown'
            snippet = 'none'

        event = {
            "scan_time": scan_time,
            "tool": "semgrep",
            "rule_id": rule_id,
            "message": message,
            "file_path": file_path,
            "line_number": line_number,
            "code_snippet": snippet
        }
        events_built.append(event)

    if events_built:
        print(f"\nFirst event sample:")
        print(json.dumps(events_built[0], indent=2))
    else:
        print("No findings to send — scan came back clean.")

    print(f"\nSending {len(events_built)} events to Splunk...")
    sent = 0
    failed = 0

    for event in events_built:
        status_code, response_text = send_to_splunk(event, hec_url, hec_token)
        if status_code == 200:
            sent += 1
        else:
            failed += 1
            print(f"Failed: {event['rule_id']} — {response_text}")

    print(f"\n--- Ingestion Summary ---")
    print(f"Total sent  : {sent}")
    print(f"Total failed: {failed}")
    print(f"Splunk index: devsecops_semgrep")


main()