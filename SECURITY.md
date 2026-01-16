# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the K8s Security Auditor, please report it responsibly:

1. **DO NOT** open a public GitHub issue
2. Email: security@vibecoding.com (or your designated security contact)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Security Considerations

### Tool Permissions

This tool requires read access to Kubernetes resources. It needs:

- `get`, `list` permissions on:
  - pods, services, secrets, configmaps, serviceaccounts
  - roles, rolebindings, clusterroles, clusterrolebindings
  - nodes, namespaces, persistentvolumes, persistentvolumeclaims

When using `--fix`, it also requires:
- `update`, `patch` permissions on relevant resources

**Recommendation**: Run the auditor with a dedicated ServiceAccount that has only these permissions.

### Example RBAC for Auditor

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: k8s-security-auditor
  namespace: security-tools
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: k8s-security-auditor
rules:
- apiGroups: [""]
  resources:
    - nodes
    - namespaces
    - pods
    - services
    - secrets
    - configmaps
    - serviceaccounts
    - persistentvolumes
    - persistentvolumeclaims
  verbs: ["get", "list"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources:
    - roles
    - rolebindings
    - clusterroles
    - clusterrolebindings
  verbs: ["get", "list"]
- apiGroups: ["networking.k8s.io"]
  resources:
    - networkpolicies
  verbs: ["get", "list"]
# Add update/patch only if using --fix
# - apiGroups: [""]
#   resources: ["pods", "services"]
#   verbs: ["update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: k8s-security-auditor
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: k8s-security-auditor
subjects:
- kind: ServiceAccount
  name: k8s-security-auditor
  namespace: security-tools
```

### Data Sensitivity

This tool accesses sensitive cluster information:

- Secret names (not values, unless specific RBAC grants)
- RBAC configurations
- Pod specifications
- Network policies

**Recommendations**:

1. Store audit results securely (encrypt at rest)
2. Limit access to audit reports (they reveal cluster security posture)
3. Sanitize logs before sharing externally
4. Use `--namespace` to limit scope when possible

### Auto-Remediation Safety

The `--fix` flag modifies cluster resources. To use safely:

1. **Always test in non-production first**
2. **Use `--dry-run` to preview changes**
3. **Review diffs with `--diff`**
4. **Understand the "risky" flag** - changes marked risky may break workloads
5. **Have rollback plan** - keep backups of resources before fixing

### Python Plugin Security

If using the optional Python plugin:

- Review plugin code before use (it's open source)
- Run plugin in isolated environment if processing untrusted audit results
- Plugin has no cluster access - it only reads JSON files

### Supply Chain Security

To verify the integrity of releases:

1. Download from official GitHub releases only
2. Verify checksums (SHA256 provided with releases)
3. Check GPG signatures (coming soon)
4. Build from source if concerned about supply chain attacks

### Known Limitations

1. **No mutation detection**: Tool assumes cluster state doesn't change during audit
2. **Read-only by default**: Won't detect runtime behaviors, only configurations
3. **Point-in-time**: Audit reflects state at time of execution
4. **Requires network access**: Needs connectivity to Kubernetes API server

### Security Best Practices

When deploying this tool:

1. Use dedicated ServiceAccount with minimal permissions
2. Run on a schedule (cron, CI/CD) rather than keeping running
3. Store results in secure location
4. Audit the auditor's access logs
5. Keep the tool updated for latest security checks
6. Rotate ServiceAccount credentials regularly

## Supported Versions

We provide security updates for:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Acknowledgments

We thank the following for responsible disclosure:

- (No reports yet)

## Security Features

This tool implements several security features:

1. **Evidence-based reporting**: Never speculates about security issues
2. **Read-only default**: Requires explicit `--fix` for mutations
3. **Dry-run mode**: Preview changes before applying
4. **Approval required**: Risky changes need `--approve-risky`
5. **No secrets in output**: Secret values are never displayed (only metadata)
6. **Grounded findings**: All findings reference official documentation

## Compliance

This tool helps assess compliance with:

- CIS Kubernetes Benchmark
- NSA/CISA Kubernetes Hardening Guide
- Kubernetes Pod Security Standards
- OWASP Kubernetes Security Cheat Sheet

It does NOT guarantee compliance - always consult with compliance experts.
