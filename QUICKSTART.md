# Quick Start Guide

Get started with K8s Security Auditor in 5 minutes.

## Prerequisites

- Kubernetes cluster access
- Valid kubeconfig file
- Go 1.21+ (for building from source)

## Installation

### Option 1: Download Binary (Recommended)

```bash
# Linux
curl -L https://github.com/hassansallam/k8s-security-auditor/releases/latest/download/k8s-security-auditor-linux-amd64 -o k8s-security-auditor
chmod +x k8s-security-auditor
sudo mv k8s-security-auditor /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/hassansallam/k8s-security-auditor/releases/latest/download/k8s-security-auditor-darwin-amd64 -o k8s-security-auditor
chmod +x k8s-security-auditor
sudo mv k8s-security-auditor /usr/local/bin/

# macOS (Apple Silicon)
curl -L https://github.com/hassansallam/k8s-security-auditor/releases/latest/download/k8s-security-auditor-darwin-arm64 -o k8s-security-auditor
chmod +x k8s-security-auditor
sudo mv k8s-security-auditor /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/hassansallam/k8s-security-auditor/releases/latest/download/k8s-security-auditor-windows-amd64.exe" -OutFile "k8s-security-auditor.exe"
# Add to PATH manually
```

### Option 2: Build from Source

```bash
git clone https://github.com/hassansallam/k8s-security-auditor.git
cd k8s-security-auditor
make build
sudo make install
```

### Option 3: Docker

```bash
docker pull hassansallam/k8s-security-auditor:latest
docker run --rm -v ~/.kube:/root/.kube hassansallam/k8s-security-auditor:latest
```

## First Audit

Run your first security audit:

```bash
k8s-security-auditor
```

This will:
1. Connect to your current kubeconfig context
2. Scan all namespaces
3. Run 28 security rules
4. Output a markdown report

## Common Commands

```bash
# Audit specific namespace
k8s-security-auditor -n production

# JSON output for CI/CD
k8s-security-auditor -o json

# Save report to file
k8s-security-auditor -o markdown -f security-report.md

# Verbose mode
k8s-security-auditor -v

# Preview auto-fixes
k8s-security-auditor --fix --dry-run --diff

# Apply safe fixes
k8s-security-auditor --fix
```

## Understanding the Output

### Severity Levels

- **Critical**: Immediate attention required - direct path to cluster compromise
- **High**: Significant security risk - should be fixed soon
- **Medium**: Security risk requiring specific conditions
- **Low**: Best practices and defense-in-depth

### Key Sections

1. **Executive Summary**: High-level overview of findings
2. **Critical Findings**: Must-fix issues
3. **High/Medium/Low Findings**: Prioritized by severity
4. **Remediation**: Exact YAML and commands to fix each issue

### Example Finding

```markdown
### Privileged Container Detected

**ID**: WL-001 | **Severity**: Critical | **Category**: Workload Security

**Affected Resource**: `Pod/production/nginx-7d8f6c9b4-xk2m9`

**Evidence**:
- container: nginx
- privileged: true

**Impact**: Privileged containers can access all host devices...

**Remediation**: Remove privileged flag from container

**Verification**: `kubectl get pod ...`
```

## Next Steps

1. **Review Critical Findings**: Start with the most severe issues
2. **Test Fixes**: Use `--dry-run` before applying changes
3. **Apply Remediations**: Follow the exact YAML provided
4. **Verify**: Run the verification commands
5. **Re-audit**: Confirm issues are resolved

## Integration

### CI/CD Pipeline

```yaml
# GitHub Actions
- name: K8s Security Audit
  run: |
    k8s-security-auditor -o json | \
    jq -e '.summary.by_severity.Critical == 0 and .summary.by_severity.High == 0'
```

### Scheduled Scans

```bash
# Cron job (daily at 2 AM)
0 2 * * * /usr/local/bin/k8s-security-auditor -o json -f /var/log/k8s-audit-$(date +\%Y\%m\%d).json
```

## Troubleshooting

### "Cannot list nodes: forbidden"

Your kubeconfig user lacks permissions. The tool needs read access to:
- pods, services, secrets, configmaps, serviceaccounts
- roles, rolebindings, clusterroles, clusterrolebindings
- nodes, namespaces

### "Context does not exist"

Verify your kubeconfig:
```bash
kubectl config get-contexts
kubectl config use-context <your-context>
```

### Large Cluster Takes Long

For clusters with 500+ pods:
```bash
# Audit specific namespace
k8s-security-auditor -n critical-apps
```

## Getting Help

- **Documentation**: [README.md](README.md)
- **Examples**: [EXAMPLES.md](EXAMPLES.md)
- **Issues**: https://github.com/hassansallam/k8s-security-auditor/issues
- **Security**: [SECURITY.md](SECURITY.md)

## What's Next?

- Read [EXAMPLES.md](EXAMPLES.md) for advanced usage
- Set up [CI/CD integration](README.md#cicd-integration)
- Try the [Python plugin](plugins/README.md) for enhanced analysis
- Review [SECURITY.md](SECURITY.md) for safe deployment

Happy auditing! 🔒
