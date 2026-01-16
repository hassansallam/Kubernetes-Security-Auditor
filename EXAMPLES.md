# Usage Examples

## Basic Audits

### Audit Entire Cluster

```bash
k8s-security-auditor
```

Output:
```
Connected to cluster: https://prod.example.com (server: v1.28.0)
Collecting cluster data...
Collected resources: 5 nodes, 12 namespaces, 145 pods, 67 services
Running 28 security rules...
Found 47 security findings

# Kubernetes Security Audit Report

**Generated**: 2024-01-16T10:30:00Z
...
```

### Audit Specific Namespace

```bash
k8s-security-auditor -n production
```

Only analyzes resources in the `production` namespace.

### Use Different Kubeconfig

```bash
k8s-security-auditor --kubeconfig ~/.kube/staging-config
```

### Use Specific Context

```bash
k8s-security-auditor --context prod-us-west
```

### Verbose Mode

```bash
k8s-security-auditor -v
```

Output:
```
Connected to cluster: https://prod.example.com (server: v1.28.0)
Starting security audit...
Collecting cluster data...
Collected resources: 5 nodes, 12 namespaces, 145 pods, 67 services
Running 28 security rules...
  [1/28] Evaluating WL-001: Privileged Container Detection
  [2/28] Evaluating WL-002: Host Namespace Usage
  ...
Found 47 security findings
```

## Output Formats

### JSON Output

```bash
k8s-security-auditor -o json
```

```json
{
  "findings": [
    {
      "id": "WL-001",
      "name": "Privileged Container Detected",
      "severity": "Critical",
      "resource": {
        "kind": "Pod",
        "namespace": "production",
        "name": "nginx-7d8f6c9b4-xk2m9"
      },
      "evidence": {
        "container": "nginx",
        "privileged": "true"
      },
      ...
    }
  ],
  "summary": {
    "total_findings": 47,
    "by_severity": {
      "Critical": 3,
      "High": 12,
      "Medium": 20,
      "Low": 12
    }
  }
}
```

### SARIF Output

```bash
k8s-security-auditor -o sarif -f results.sarif
```

SARIF format is compatible with GitHub Security tab, Azure DevOps, and other security platforms.

### Save to File

```bash
k8s-security-auditor -o markdown -f security-report.md
```

## Auto-Remediation

### Dry Run (Preview Changes)

```bash
k8s-security-auditor --fix --dry-run
```

Output:
```
Applying automatic fixes...

--- Fix for: Privilege Escalation Allowed ---
Resource: Pod/production/nginx-7d8f6c9b4-xk2m9
Remediation:
spec:
  containers:
  - name: nginx
    securityContext:
      allowPrivilegeEscalation: false

Would apply fix for: Privilege Escalation Allowed (dry-run mode)
Would apply fix for: Missing Seccomp Profile (dry-run mode)
...

Summary: Would apply 12 fixes
```

### Show Diffs

```bash
k8s-security-auditor --fix --dry-run --diff
```

Shows detailed diffs for each proposed change.

### Apply Safe Fixes

```bash
k8s-security-auditor --fix
```

Applies only safe, non-risky fixes automatically.

### Apply All Fixes (Including Risky)

```bash
k8s-security-auditor --fix --approve-risky
```

⚠️ **Warning**: This may disrupt workloads. Test in staging first.

## Real-World Scenarios

### Scenario 1: New Cluster Audit

You've just inherited a Kubernetes cluster and want to assess its security posture.

```bash
# Generate comprehensive report
k8s-security-auditor -o markdown -f cluster-audit-$(date +%Y%m%d).md -v

# Also generate JSON for tracking
k8s-security-auditor -o json -f cluster-audit-$(date +%Y%m%d).json
```

Review the markdown report and prioritize critical findings.

### Scenario 2: Pre-Production Validation

Before promoting to production, audit your staging cluster:

```bash
k8s-security-auditor --context staging -n myapp -o json | \
  jq '.summary.by_severity | select(.Critical > 0 or .High > 0)' && \
  echo "FAIL: Critical or High findings in staging" && exit 1 || \
  echo "PASS: No critical/high findings"
```

### Scenario 3: Continuous Monitoring

Set up daily audits and alert on new findings:

```bash
#!/bin/bash
# daily-audit.sh

TODAY=$(date +%Y%m%d)
k8s-security-auditor -o json -f /var/log/k8s-audit/audit-$TODAY.json

CRITICAL=$(jq '.summary.by_severity.Critical' /var/log/k8s-audit/audit-$TODAY.json)
HIGH=$(jq '.summary.by_severity.High' /var/log/k8s-audit/audit-$TODAY.json)

if [ "$CRITICAL" -gt 0 ]; then
  echo "ALERT: $CRITICAL critical findings!" | mail -s "K8s Security Alert" security@example.com
fi
```

### Scenario 4: Compliance Reporting

Generate monthly compliance reports:

```bash
# Generate full report
k8s-security-auditor -o json -f compliance-$(date +%Y-%m).json

# Use Python plugin for executive summary
python3 plugins/agentic_reasoner.py \
  --input compliance-$(date +%Y-%m).json \
  --output compliance-$(date +%Y-%m)-executive.md \
  --mode executive

# Send to compliance team
cat compliance-$(date +%Y-%m)-executive.md | \
  mail -s "Monthly K8s Security Compliance Report" compliance@example.com
```

### Scenario 5: Remediation Campaign

Systematically fix issues in a namespace:

```bash
# 1. Audit and save results
k8s-security-auditor -n production -o json -f before.json

# 2. Generate remediation plan
python3 plugins/agentic_reasoner.py \
  --input before.json \
  --output remediation-plan.md \
  --mode remediation

# 3. Fix safe issues automatically
k8s-security-auditor -n production --fix --diff | tee fixes-applied.log

# 4. Verify improvements
k8s-security-auditor -n production -o json -f after.json

# 5. Compare
echo "Before: $(jq '.summary.total_findings' before.json) findings"
echo "After: $(jq '.summary.total_findings' after.json) findings"
```

## Advanced Usage

### Filter by Severity

```bash
# Show only critical findings
k8s-security-auditor -o json | jq '.findings[] | select(.severity == "Critical")'

# Count by severity
k8s-security-auditor -o json | jq '.summary.by_severity'
```

### Filter by Category

```bash
# Show only RBAC findings
k8s-security-auditor -o json | jq '.findings[] | select(.category == "RBAC")'
```

### Export for Jira/Tickets

```bash
# Generate CSV for import
k8s-security-auditor -o json | jq -r '
  ["ID","Name","Severity","Resource","Remediation"],
  (.findings[] | [.id, .name, .severity, .resource.name, .remediation]) |
  @csv
' > findings.csv
```

### Compare Two Audits

```bash
# Baseline audit
k8s-security-auditor -o json -f baseline.json

# ... make changes ...

# New audit
k8s-security-auditor -o json -f current.json

# Compare
jq -s '
  .[0].findings as $baseline |
  .[1].findings as $current |
  {
    "fixed": ($baseline | map(.id) - ($current | map(.id))),
    "new": ($current | map(.id) - ($baseline | map(.id))),
    "baseline_count": ($baseline | length),
    "current_count": ($current | length)
  }
' baseline.json current.json
```

### Integration with Python Plugin

```bash
# Full workflow
k8s-security-auditor -o json -f audit.json

# Generate different types of analysis
python3 plugins/agentic_reasoner.py --input audit.json --output executive.md --mode executive
python3 plugins/agentic_reasoner.py --input audit.json --output technical.md --mode technical
python3 plugins/agentic_reasoner.py --input audit.json --output remediation.md --mode remediation
python3 plugins/agentic_reasoner.py --input audit.json --output patterns.md --mode patterns
```

## Troubleshooting

### Permission Denied

```bash
k8s-security-auditor
# Error: failed to list nodes: nodes is forbidden: User "john" cannot list resource "nodes"
```

**Solution**: Ensure your kubeconfig has sufficient RBAC permissions. The tool needs:
- `get`, `list` on pods, services, secrets, configmaps, serviceaccounts, roles, rolebindings, clusterroles, clusterrolebindings
- `get`, `list` on nodes (for cluster-wide checks)

### Context Not Found

```bash
k8s-security-auditor --context nonexistent
# Error: context "nonexistent" does not exist
```

**Solution**: Check available contexts:
```bash
kubectl config get-contexts
```

### Large Cluster Performance

For very large clusters (1000+ pods), the audit may take time. Use verbose mode to track progress:

```bash
k8s-security-auditor -v
```

Or limit to specific namespaces:
```bash
k8s-security-auditor -n critical-namespace
```

## Best Practices

1. **Regular Audits**: Run weekly or after significant cluster changes
2. **Version Control**: Store audit results in Git to track security posture over time
3. **CI/CD Integration**: Block deployments with critical/high findings
4. **Staged Remediation**: Fix critical issues first, then work down severity levels
5. **Test Fixes**: Always use `--dry-run` before applying fixes in production
6. **Combine Tools**: Use alongside other security tools (kube-bench, falco, OPA)
7. **Document Exceptions**: If a finding is acceptable risk, document why
