import json
import sys
from urllib import response
import requests

def main():
    print("Ingestion trivy to splunk")

if len(sys.argv) != 4:
    print("Usage: python3 ingest_trivy.py <trivy-json> <hex-url> <hec-token>")
    sys.exit(1)

trivy_json = sys.argv[1]
hex_url = sys.argv[2]
hec_token = sys.argv[3]

print(f"Reading Trivy JSON from {trivy_json}...")
print(f"Sending to: {hex_url}")
print(f"token: {hec_token[:8]}...")

with open(trivy_json) as f:
    data = json.load(f)

image_name = data.get('ArtifactName', 'unknown')
scan_time = data.get('CreatedAT', 'unknown')
results = data.get('Results', [])

print(f"Image scanned: {image_name}")
print(f"Scan time: {scan_time}")
print(f"Result section found: {len(results)}") 

events_built = []

for result in results:
    target = result.get('Target', 'unknown')
    vulnerabilities = result.get('Vulnerabilities', [])

    for vuln in vulnerabilities:
        event = {
            "image": image_name,
            "scan_time": scan_time,
            "target": target,
            "vulnerability_id": vuln.get('VulnerabilityID', 'unknown'),
            "pkg_name": vuln.get('PkgName', 'unknown'),
            "installed_version": vuln.get('InstalledVersion', 'unknown'),
            "fixed_version": vuln.get('FixedVersion', 'unknown'),
            "severity": vuln.get('Severity', 'unknown'),
            "title": vuln.get('Title', 'unknown'),
        }
        events_built.append(event)

print(f"Total events built: {len(events_built)}")
print("First event sample:")
print(json.dumps(events_built[0], indent=2))        

def send_to_splunk(events, url, token):
    payload = {
        "event": events,
        "index": "devsecops_trivy",
        "sourcetype": "_json"
    }
    headers = {
        "Authorization": f"Splunk {hec_token}",
        "Content-Type": "application/json",
        "X-Splunk-Request-Channel": "devsecops-trivy-channel"
    }
    response = requests.post(
        f"{hex_url}/services/collector/event",
        json=payload,
        headers=headers,
        timeout=10
    )

    return response.status_code, response.text

print(f"\n Sending {len(events_built)} events to Splunk...")
sent =0
failed=0

for event in events_built:
    status_code, response_text = send_to_splunk(event, hex_url, hec_token)
    if status_code == 200:
        sent += 1
    else:
        failed += 1
        print(f"Failed to send event: {event['vulnerability_id']} - Status: {status_code} - Response: {response_text}")

print(f"\n ---Ingestion Summary ---")
print(f"Successfully sent: {sent}")
print(f"Failed to send: {failed}")
print(f" Splunk index: devsecops_trivy")        