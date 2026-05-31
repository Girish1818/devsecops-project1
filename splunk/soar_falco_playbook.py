import json
import sys
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from kubernetes import client, config
from datetime import datetime


def isolate_pod(namespace, pod_name):
    """
    Add quarantine=true label to compromised pod.
    This activates the isolation NetworkPolicy instantly.
    """
    try:
        config.load_kube_config()
        v1 = client.CoreV1Api()

        # Patch the pod with quarantine label
        body = {
            "metadata": {
                "labels": {
                    "quarantine": "true"
                }
            }
        }

        v1.patch_namespaced_pod(
            name=pod_name,
            namespace=namespace,
            body=body
        )
        print(f"  Pod {pod_name} isolated successfully")
        return True

    except Exception as e:
        print(f"  Failed to isolate pod: {e}")
        return False


def page_spoc(spoc_url, rule, priority, pod_name, namespace):
    """
    Send alert to Splunk On-Call (SPOC) via REST endpoint.
    """
    payload = {
        "message_type": "CRITICAL",
        "entity_id": f"falco-{rule}-{pod_name}",
        "entity_display_name": f"Falco Alert: {rule}",
        "state_message": (
            f"Rule: {rule}\n"
            f"Priority: {priority}\n"
            f"Pod: {pod_name}\n"
            f"Namespace: {namespace}\n"
            f"Action taken: Pod isolated (quarantine=true label applied)\n"
            f"Detected at: {datetime.now().isoformat()}"
        ),
        "monitoring_tool": "Falco + SOAR Playbook"
    }

    try:
        response = requests.post(
            spoc_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        print(f"  SPOC paged: {response.status_code}")
        return response.status_code == 200
    except Exception as e:
        print(f"  SPOC failed: {e}")
        return False


def create_github_issue(github_token, repo, rule, priority, pod_name, namespace):
    """
    Create GitHub Issue with incident details.
    """
    url = f"https://api.github.com/repos/{repo}/issues"

    body = f"""## Security Incident — Falco Runtime Alert

| Field | Value |
|-------|-------|
| Rule | {rule} |
| Priority | {priority} |
| Pod | {pod_name} |
| Namespace | {namespace} |
| Detected | {datetime.now().isoformat()} |
| Action | Pod isolated via NetworkPolicy |

## What happened
Falco detected suspicious runtime behaviour in the Flask pod.
The pod has been automatically isolated by applying `quarantine=true` label.
The isolation NetworkPolicy blocks all ingress and egress traffic.

## Next steps
1. Investigate pod logs: `kubectl logs {pod_name} -n {namespace}`
2. Check Falco events in Splunk: `index=devsecops_falco`
3. Forensic investigation of the pod
4. Delete compromised pod: `kubectl delete pod {pod_name} -n {namespace}`
5. Redeploy clean pod from pipeline

*This issue was automatically created by the Falco SOAR playbook.*
"""

    payload = {
        "title": f"[CRITICAL] Falco Alert: {rule} in {pod_name}",
        "body": body,
        "labels": []
    }

    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        if response.status_code == 201:
            print(f"  GitHub Issue created: {response.json().get('html_url')}")
            return True
        else:
            print(f"  GitHub Issue failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"  GitHub Issue failed: {e}")
        return False


class FalcoWebhookHandler(BaseHTTPRequestHandler):
    """
    HTTP webhook handler that receives Falco alerts from Falcosidekick.
    Falcosidekick POSTs JSON alerts to this endpoint.
    """

    def do_POST(self):
        # Read the incoming POST body
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        # Send 200 OK immediately so Falcosidekick doesn't retry
        self.send_response(200)
        self.end_headers()

        try:
            alert = json.loads(post_data.decode('utf-8'))
            self.process_alert(alert)
        except Exception as e:
            print(f"Error processing alert: {e}")

    def process_alert(self, alert):
        rule = alert.get('rule', 'unknown')
        priority = alert.get('priority', 'unknown')
        output_fields = alert.get('output_fields', {})

        pod_name = output_fields.get('k8s.pod.name', 'unknown')
        namespace = output_fields.get('k8s.ns.name', 'flask-app')

        print(f"\n--- Falco Alert Received ---")
        print(f"Rule:      {rule}")
        print(f"Priority:  {priority}")
        print(f"Pod:       {pod_name}")
        print(f"Namespace: {namespace}")
        print(f"Time:      {alert.get('time', 'unknown')}")

        # Only respond to CRITICAL and ERROR alerts
        if priority.lower() not in ['critical', 'error']:
            print(f"  Priority {priority} — monitoring only, no action taken")
            return

        print(f"  CRITICAL alert — initiating automated response...")

        # Step 1 — Isolate the pod
        print(f"  Step 1: Isolating pod...")
        isolate_pod(namespace, pod_name)

        # Step 2 — Page SPOC
        print(f"  Step 2: Paging SPOC...")
        page_spoc(
            SPOC_URL, rule, priority, pod_name, namespace
        )

        # Step 3 — Create GitHub Issue
        print(f"  Step 3: Creating GitHub Issue...")
        create_github_issue(
            GITHUB_TOKEN, GITHUB_REPO, rule, priority, pod_name, namespace
        )

        print(f"--- Response complete ---\n")

    def log_message(self, format, *args):
        # Suppress default HTTP server logs — use our own
        pass


def main():
    if len(sys.argv) != 4:
        print("Usage: python3 soar_falco_playbook.py <spoc-url> <github-token> <github-repo>")
        sys.exit(1)

    global SPOC_URL, GITHUB_TOKEN, GITHUB_REPO
    SPOC_URL = sys.argv[1]
    GITHUB_TOKEN = sys.argv[2]
    GITHUB_REPO = sys.argv[3]

    port = 9000
    server = HTTPServer(('0.0.0.0', port), FalcoWebhookHandler)
    print(f"SOAR Playbook webhook server started on port {port}")
    print(f"Waiting for Falco alerts from Falcosidekick...")
    print(f"Repo: {GITHUB_REPO}")
    server.serve_forever()


main()