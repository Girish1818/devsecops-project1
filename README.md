# DevSecOps Project 1 — Secure CI/CD Pipeline

A production-grade DevSecOps pipeline integrating four security scanning
tools into GitHub Actions, with AWS ECR deployment and secrets management.

## Architecture
```
Developer commits code
        ↓
Pre-commit hook (Gitleaks) — blocks secrets before git history
        ↓
GitHub Actions triggered on push to main
        ↓
┌─────────────┬─────────────┬──────────────┬──────────────┐
│ SAST        │ SCA         │ Secrets      │ IaC          │
│ Semgrep     │ Trivy       │ Gitleaks     │ Checkov      │
│ 8 findings  │ 127 CVEs    │ 0 leaks      │ 6 findings   │
└─────────────┴─────────────┴──────────────┴──────────────┘
        ↓ (all must pass)
Deploy gate
        ↓
Build and push to ECR (OIDC — no stored credentials)
        ↓
AWS Secrets Manager (runtime secret injection)
```

## Target application

A deliberately vulnerable Python Flask app with three real
vulnerabilities for demonstration purposes:

- SQL injection via string concatenation (line 55)
- Command injection via subprocess shell=True (line 70)
- Hardcoded Flask secret key — replaced by AWS Secrets Manager

## Security tools

### Semgrep — SAST
Scans Python source code for vulnerability patterns.
Runs 290 rules automatically. Custom rule written for
hardcoded Flask secret key (CWE-798).
Output: SARIF uploaded to GitHub Security tab.

### Trivy — SCA + Container
Scans Docker image layers for CVEs in OS packages and
Python dependencies. Found 127 vulnerabilities (3 CRITICAL)
in python:3.9-slim. Gate script blocks pipeline on any CRITICAL.
Output: JSON parsed by trivy-check.py.

### Gitleaks — Secrets detection
Scans git history for accidentally committed secrets.
Custom .gitleaks.toml rules for Flask secret keys and
AWS credentials. Pre-commit hook blocks commits containing secrets.

### Checkov — IaC security
Scans Terraform for cloud misconfigurations.
13 checks passed, 6 findings including missing KMS
encryption and S3 access logging.

## AWS integration

- ECR repository with scan-on-push and AES256 encryption
- OIDC federation — GitHub Actions assumes IAM role via JWT
  exchange. No stored AWS credentials anywhere.
- AWS Secrets Manager — Flask secret key fetched at runtime
  via boto3. Never hardcoded, never in environment variables.
- IAM least-privilege — role scoped to single ECR repo and
  single Secrets Manager path.

## Pipeline gate logic

Each scanner exits with code 1 on critical findings.
GitHub Actions treats non-zero exit as job failure.
The deploy-gate job uses `needs: [sast, sca, secrets, iac]`
— it never starts if any upstream job fails.
The ECR push job uses `needs: [deploy-gate]` — images
only reach ECR after passing all four security gates.

## Key security decisions

| Decision | Why |
|---|---|
| python:3.9-slim as target | Demonstrates CVE impact of base image choice |
| OIDC over stored keys | Short-lived credentials, no rotation needed |
| SHA-based image tags | Every image traceable to exact commit |
| Least-privilege IAM | Compromise of role cannot affect other resources |
| Pre-commit hooks | Catch secrets before they enter git history |

## Local development
```bash
# Setup
python3 -m venv venv
source venv/bin/activate
pip3 install -r app/requirements.txt

# Run app (uses fallback secret locally)
python3 app/app.py

# Run scanners locally
semgrep --config=auto app/
trivy image vulnapp
gitleaks detect --source . --no-git --verbose
checkov -d terraform/
```

## Project structure
```
devsecops-project1/
├── app/
│   ├── app.py              # Vulnerable Flask app
│   └── requirements.txt    # Python dependencies
├── terraform/
│   └── main.tf             # AWS infrastructure as code
├── rules/
│   └── custom.yaml         # Custom Semgrep rules
├── .github/
│   └── workflows/
│       └── security-pipeline.yml  # GitHub Actions pipeline
├── .gitleaks.toml          # Custom Gitleaks rules
├── Dockerfile              # Container definition
└── trivy-check.py          # Trivy gate script
```