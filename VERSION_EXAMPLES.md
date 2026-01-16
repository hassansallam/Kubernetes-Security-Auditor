# Kubernetes Version Support Examples

This document provides practical examples of using the K8s Security Auditor with different Kubernetes versions.

## Quick Reference

| Kubernetes Version | Status | Key Features | Recommended Use |
|-------------------|--------|--------------|-----------------|
| 1.24 | ✅ Supported | Pod Security Standards introduced | Baseline security |
| 1.25 | ✅ Supported | Enhanced PSS, improved SA tokens | Production ready |
| 1.26 | ✅ Recommended | Stable security features | Most deployments |
| 1.27 | ✅ Recommended | Seccomp improvements | Security-focused |
| 1.28 | ✅ Recommended | AppArmor enhancements | Latest stable |
| 1.29 | ✅ Fully Supported | Advanced admission policies | Modern clusters |
| 1.30 | ✅ Fully Supported | Latest security APIs | Cutting-edge |
| 1.31 | ✅ Fully Supported | Enhanced security contexts | Future-ready |
| 1.32 | ✅ Fully Supported | Beta security features | Early adopters |
| 1.33 | ✅ Fully Supported | Experimental features | Testing |
| 1.34 | ✅ Fully Supported | Latest enhancements | Beta testing |
| 1.35 | ✅ Latest | Current stable | Latest features |

## Checking Your Cluster Version

### Using kubectl

```bash
# Show client and server versions
kubectl version --short

# Output:
# Client Version: v1.28.3
# Server Version: v1.28.3

# Get detailed version info
kubectl version -o json | jq '.serverVersion'
```

### Using the Auditor

```bash
# Show version information
k8s-security-auditor --show-version

# Output:
# Cluster: https://prod-k8s.example.com (server: v1.28.3)
# Kubernetes Version: v1.28.3
# Major: 1, Minor: 28

# Check if running latest version
k8s-security-auditor --check-latest

# Output:
# Current cluster version: v1.28.3
# Checking latest Kubernetes version via Context7 MCP...
# Latest stable version: v1.35.0
# Your cluster is 7 minor versions behind
# Note: Kubernetes versions 1.24-1.35 are fully supported by this tool
```

## Version-Specific Examples

### Example 1: Kubernetes 1.24

**Cluster**: Running K8s 1.24.10

```bash
k8s-security-auditor -v

# Output shows:
# Connected to cluster: https://k8s-124.example.com (server: v1.24.10)
# Cluster version: v1.24.10
# Context7 MCP: Fetching Kubernetes 1.24 documentation...
```

**What Gets Checked**:
- ✅ Pod Security Standards (newly introduced in 1.23+)
- ✅ Basic RBAC rules
- ✅ Workload security contexts
- ⚠️  Some advanced features may suggest upgrade

**Sample Finding**:
```markdown
### Pod Security Standards Not Enforced (CP-003)

**Cluster Version**: v1.24.10
**Severity**: High
**Documentation**: https://kubernetes.io/docs/v1.24/concepts/security/pod-security-standards/

Your cluster (v1.24.10) supports Pod Security Standards.
This is the first stable version with PSS support.

**Recommendation**: Apply PSS labels to namespaces for security enforcement.
```

### Example 2: Kubernetes 1.28

**Cluster**: Running K8s 1.28.3

```bash
k8s-security-auditor -v --mcp-server http://localhost:3000

# Output shows:
# Connected to cluster: https://prod-k8s.example.com (server: v1.28.3)
# Cluster version: v1.28.3
# Context7 MCP: Connected at http://localhost:3000
# Fetching Kubernetes 1.28 documentation...
# Starting security audit with 28 rules...
```

**What Gets Checked**:
- ✅ Full Pod Security Standards validation
- ✅ Enhanced seccomp profiles
- ✅ AppArmor profile validation
- ✅ Advanced RBAC checks
- ✅ Service account token improvements

**Sample Finding**:
```markdown
### Missing Seccomp Profile (WL-009)

**Cluster Version**: v1.28.3
**Severity**: Medium
**Documentation**: https://kubernetes.io/docs/v1.28/tutorials/security/seccomp/

Kubernetes 1.28 has enhanced seccomp support. Consider using RuntimeDefault profile.

**Remediation** (for K8s 1.28):
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
```

**Note**: In K8s 1.28+, RuntimeDefault is the recommended baseline.
```

### Example 3: Kubernetes 1.35 (Latest)

**Cluster**: Running K8s 1.35.0

```bash
k8s-security-auditor -v

# Output shows:
# Connected to cluster: https://latest-k8s.example.com (server: v1.35.0)
# Cluster version: v1.35.0
# Context7 MCP: Fetching Kubernetes 1.35 documentation...
# Note: You are running the latest stable Kubernetes version!
```

**What Gets Checked**:
- ✅ All security rules with latest APIs
- ✅ Cutting-edge security features
- ✅ Future-proof recommendations
- ✅ Latest admission policies

**Sample Finding**:
```markdown
### Advanced Security Policy Available (CP-004)

**Cluster Version**: v1.35.0
**Severity**: Info
**Documentation**: https://kubernetes.io/docs/v1.35/concepts/security/pod-security-admission/

Your cluster supports the latest Pod Security Admission features introduced in 1.35.
Consider enabling advanced security policies.

**Remediation** (for K8s 1.35):
```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: advanced-pod-security
spec:
  # Latest 1.35 features...
```
```

## Version Comparison

### Running Multiple Clusters

```bash
# Audit Dev cluster (K8s 1.27)
k8s-security-auditor --context dev-cluster -o json -f dev-audit.json

# Audit Staging cluster (K8s 1.28)
k8s-security-auditor --context staging-cluster -o json -f staging-audit.json

# Audit Production cluster (K8s 1.28)
k8s-security-auditor --context prod-cluster -o json -f prod-audit.json

# Compare findings
jq '.cluster_version' dev-audit.json staging-audit.json prod-audit.json
```

### Version-Specific Reports

```bash
# Generate version-tagged report
VERSION=$(k8s-security-auditor --show-version | grep "Kubernetes Version" | cut -d: -f2 | tr -d ' ')
k8s-security-auditor -o markdown -f audit-${VERSION}.md
```

## Context7 Integration by Version

### Without Context7 (Offline Mode)

```bash
k8s-security-auditor --offline -v

# Output:
# Connected to cluster: https://k8s.example.com (server: v1.28.3)
# Running in offline mode (no Context7 MCP)
# Using bundled documentation references
# Starting security audit...
```

**Result**: Generic documentation links like:
- https://kubernetes.io/docs/concepts/security/pod-security-standards/

### With Context7 (Version-Specific)

```bash
k8s-security-auditor --mcp-server http://localhost:3000 -v

# Output:
# Connected to cluster: https://k8s.example.com (server: v1.28.3)
# Cluster version: v1.28.3
# Context7 MCP: Connected at http://localhost:3000
# Fetching Kubernetes 1.28 documentation...
# Starting security audit...
```

**Result**: Version-specific documentation links like:
- https://kubernetes.io/docs/v1.28/concepts/security/pod-security-standards/

## Upgrade Planning

### Checking Upgrade Path

```bash
# Current cluster
k8s-security-auditor --show-version
# Output: Kubernetes Version: v1.27.5

# Check what's latest
k8s-security-auditor --check-latest
# Output: Latest stable version: v1.35.0

# Audit current state
k8s-security-auditor -o json -f pre-upgrade-audit.json

# After upgrading to 1.28...
# Audit again
k8s-security-auditor -o json -f post-upgrade-audit.json

# Compare findings
diff pre-upgrade-audit.json post-upgrade-audit.json
```

### Version-Specific Security Improvements

**Upgrading from 1.27 to 1.28**:
```bash
# Before upgrade (1.27)
k8s-security-auditor -v

# Findings will show:
# - Basic seccomp support
# - Standard AppArmor checks
# - PSS with 1.27 features

# After upgrade (1.28)
k8s-security-auditor -v

# Findings will show:
# - Enhanced seccomp profiles (1.28 features)
# - Improved AppArmor validation
# - PSS with 1.28 enhancements
# - New security features available
```

## CI/CD Integration by Version

### Version-Aware Pipeline

```yaml
# .github/workflows/k8s-audit.yml
name: Kubernetes Security Audit

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        k8s-version: ['1.27', '1.28', '1.29', '1.30', '1.35']
    services:
      context7:
        image: modelcontextprotocol/context7-server:latest
        ports:
          - 3000:3000
    steps:
      - name: Setup Kubernetes ${{ matrix.k8s-version }}
        uses: helm/kind-action@v1
        with:
          version: v${{ matrix.k8s-version }}.0

      - name: Run Security Audit
        run: |
          ./k8s-security-auditor \
            --mcp-server http://localhost:3000 \
            -o sarif \
            -f results-${{ matrix.k8s-version }}.sarif

      - name: Upload Results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results-${{ matrix.k8s-version }}.sarif
```

### Version-Conditional Checks

```bash
# Script to run different checks based on version
#!/bin/bash

VERSION=$(k8s-security-auditor --show-version | grep "Minor" | cut -d: -f2 | tr -d ' ')

if [ "$VERSION" -ge 30 ]; then
  echo "Running checks for K8s 1.30+"
  k8s-security-auditor --include-experimental
elif [ "$VERSION" -ge 28 ]; then
  echo "Running checks for K8s 1.28-1.29"
  k8s-security-auditor --enhanced-checks
else
  echo "Running standard checks for K8s 1.24-1.27"
  k8s-security-auditor
fi
```

## Troubleshooting Version Issues

### Version Detection Not Working

```bash
# Check API server access
kubectl cluster-info

# Verify RBAC permissions for discovery
kubectl auth can-i get --all-namespaces nodes

# Try with verbose output
k8s-security-auditor --show-version -v
```

### Context7 Not Finding Version Docs

```bash
# Test Context7 directly
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "method": "resources/read",
    "params": {
      "uri": "kubernetes://docs/1.28/pod-security-standards"
    }
  }'

# Use offline mode as fallback
k8s-security-auditor --offline
```

### Unsupported Version Warning

If you see a warning about unsupported versions:

```bash
# For K8s < 1.24
# Warning: Kubernetes version 1.23.x is not fully supported
# Some checks may not apply. Consider upgrading to 1.24+

# For K8s > 1.35
# Warning: Kubernetes version 1.36.x is newer than tested versions
# Most checks should work, but some may need updates
```

**Solution**: The tool will still work, but some checks may be skipped or warnings issued.

## Best Practices

### 1. Always Check Version First

```bash
k8s-security-auditor --show-version
```

### 2. Use Context7 for Production

```bash
# Start Context7
docker run -d -p 3000:3000 modelcontextprotocol/context7-server:latest

# Run audit with version-specific docs
k8s-security-auditor -v
```

### 3. Regular Version Checks

```bash
# Add to cron (daily at 2 AM)
0 2 * * * k8s-security-auditor --check-latest | mail -s "K8s Version Check" admin@example.com
```

### 4. Document Your Version

```bash
# Add to audit reports
echo "Cluster Version: $(k8s-security-auditor --show-version)" > audit-metadata.txt
k8s-security-auditor -o markdown >> audit-report.md
```

## Version Migration Checklist

When upgrading Kubernetes:

- [ ] Run audit on current version
- [ ] Save baseline results
- [ ] Check `--check-latest` for target version
- [ ] Review Context7 docs for new version features
- [ ] Perform upgrade
- [ ] Run audit on new version
- [ ] Compare results with baseline
- [ ] Address new findings specific to new version

## Support Matrix

| Feature | K8s 1.24 | K8s 1.27 | K8s 1.28 | K8s 1.35 |
|---------|----------|----------|----------|----------|
| PSS | ✅ | ✅ | ✅ | ✅ |
| RBAC | ✅ | ✅ | ✅ | ✅ |
| Seccomp | ⚠️ Basic | ✅ | ✅ Enhanced | ✅ Latest |
| AppArmor | ✅ | ✅ | ✅ Enhanced | ✅ Latest |
| Network Policies | ✅ | ✅ | ✅ | ✅ |
| SA Tokens | ⚠️ Legacy | ✅ | ✅ | ✅ |
| Admission Policies | ⚠️ Limited | ✅ | ✅ | ✅ Advanced |

## Additional Resources

- **Kubernetes Release Notes**: https://kubernetes.io/releases/
- **Version Skew Policy**: https://kubernetes.io/releases/version-skew-policy/
- **Upgrade Guide**: https://kubernetes.io/docs/tasks/administer-cluster/cluster-upgrade/
- **Context7 Documentation**: [CONTEXT7_INTEGRATION.md](CONTEXT7_INTEGRATION.md)
