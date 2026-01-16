# Kubernetes Security Auditor

A production-grade, evidence-driven Kubernetes security auditing CLI tool that performs comprehensive security analysis of Kubernetes clusters.

## Features

### Comprehensive Security Coverage

- **Control Plane**: API Server audit logging, admission controllers, Pod Security Standards
- **Authentication & Authorization**: RBAC analysis, service account configuration, privilege escalation checks
- **Workload Security**: SecurityContext validation, privileged containers, host namespace usage, capabilities
- **Network Security**: NetworkPolicy enforcement, default-deny policies
- **Secrets Management**: Encryption at rest, secret exposure detection, service account tokens
- **Supply Chain**: Image tag validation, registry trust, pull policy analysis

### Evidence-Based Reporting

Every finding includes:
- **Affected Resource**: Exact Kubernetes resource (namespace/name/kind)
- **Evidence**: Specific fields and values observed
- **Impact**: Why it's dangerous
- **Exploit Path**: High-level attack scenario
- **Severity**: Low/Medium/High/Critical
- **Remediation**: Concrete YAML/commands to fix
- **Verification**: Commands to confirm the fix worked

### Multiple Output Formats

- **JSON**: Machine-readable for CI/CD integration
- **SARIF**: Standard format for security tools (GitHub, Azure DevOps)
- **Markdown**: Human-readable reports with formatting

### Auto-Remediation (Optional)

- Safe, deterministic fixes with `--fix`
- Dry-run mode with `--dry-run`
- Diff preview with `--diff`
- Risky changes require `--approve-risky`

### Optional Python Plugin

Advanced agentic reasoning for:
- Executive summaries
- Pattern analysis
- Remediation planning
- Deep-dive technical analysis

## Installation

### Download Pre-built Binaries

Download the latest release for your platform from the [Releases page](https://github.com/hassansallam/Kubernetes-Security-Auditor/releases/latest).

#### Linux (amd64)
```bash
curl -L https://github.com/hassansallam/Kubernetes-Security-Auditor/releases/latest/download/k8s-security-auditor-linux-amd64 -o k8s-security-auditor
chmod +x k8s-security-auditor
sudo mv k8s-security-auditor /usr/local/bin/
```

#### Linux (arm64)
```bash
curl -L https://github.com/hassansallam/Kubernetes-Security-Auditor/releases/latest/download/k8s-security-auditor-linux-arm64 -o k8s-security-auditor
chmod +x k8s-security-auditor
sudo mv k8s-security-auditor /usr/local/bin/
```

#### macOS (Intel)
```bash
curl -L https://github.com/hassansallam/Kubernetes-Security-Auditor/releases/latest/download/k8s-security-auditor-darwin-amd64 -o k8s-security-auditor
chmod +x k8s-security-auditor
sudo mv k8s-security-auditor /usr/local/bin/
```

#### macOS (Apple Silicon)
```bash
curl -L https://github.com/hassansallam/Kubernetes-Security-Auditor/releases/latest/download/k8s-security-auditor-darwin-arm64 -o k8s-security-auditor
chmod +x k8s-security-auditor
sudo mv k8s-security-auditor /usr/local/bin/
```

#### Windows (amd64)
Download [k8s-security-auditor-windows-amd64.exe](https://github.com/hassansallam/Kubernetes-Security-Auditor/releases/latest/download/k8s-security-auditor-windows-amd64.exe) and add to your PATH.

#### Verify Installation
```bash
k8s-security-auditor --show-version
```

### Prerequisites

- Access to a Kubernetes cluster
- Valid kubeconfig file

### Supported Kubernetes Versions

This tool is compatible with **all Kubernetes versions from 1.24 to 1.35 (latest)** and automatically detects your cluster version to apply version-appropriate security checks:

- **Kubernetes 1.24+** (Tested and supported)
- **Kubernetes 1.25-1.29** (Fully supported with all features)
- **Kubernetes 1.30-1.35** (Latest versions - full support)

The tool uses `client-go` v0.31.0 with backward compatibility to work with any Kubernetes cluster that supports:
- Core API (v1)
- RBAC API (rbac.authorization.k8s.io/v1)
- Networking API (networking.k8s.io/v1)
- Pod Security Admission (admission.k8s.io/v1)

#### Version-Specific Features

- **Kubernetes 1.23+**: Pod Security Standards (PSS) checks
- **Kubernetes 1.25+**: Enhanced Pod Security Admission validation
- **Kubernetes 1.27+**: Seccomp profile validation improvements
- **Kubernetes 1.28+**: AppArmor profile enhancements
- **Kubernetes 1.30+**: Latest security features and APIs

The tool automatically detects your cluster version and fetches version-specific documentation from the official Kubernetes documentation to ensure accurate security recommendations.

### Build from Source

```bash
git clone https://github.com/hassansallam/Kubernetes-Security-Auditor.git
cd k8s-security-auditor
go mod download
go build -o k8s-security-auditor .
```

### Install

```bash
# Linux/macOS
sudo mv k8s-security-auditor /usr/local/bin/

# Windows
# Move k8s-security-auditor.exe to a directory in your PATH
```

## Usage

### Basic Audit

```bash
# Audit entire cluster (default: markdown output)
k8s-security-auditor

# Audit specific namespace
k8s-security-auditor -n production

# Use specific kubeconfig
k8s-security-auditor --kubeconfig ~/.kube/config-prod

# Use specific context
k8s-security-auditor --context prod-cluster
```

### Output Formats

```bash
# JSON output
k8s-security-auditor -o json

# SARIF output (for GitHub security tab)
k8s-security-auditor -o sarif -f results.sarif

# Markdown report
k8s-security-auditor -o markdown -f report.md
```

### Auto-Remediation

```bash
# Dry-run: see what would be fixed
k8s-security-auditor --fix --dry-run

# Show diffs for proposed changes
k8s-security-auditor --fix --dry-run --diff

# Apply safe fixes
k8s-security-auditor --fix

# Apply all fixes including risky ones (be careful!)
k8s-security-auditor --fix --approve-risky
```

### Verbose Output

```bash
k8s-security-auditor -v
```

### Python Plugin

```bash
# Generate audit results
k8s-security-auditor -o json -f audit.json

# Generate enhanced analysis
python3 plugins/agentic_reasoner.py --input audit.json --output enhanced.md --mode all
```

## Context7 MCP Integration

The K8s Security Auditor integrates with [Context7 MCP Server](https://github.com/modelcontextprotocol/servers/tree/main/src/context7) to fetch version-specific Kubernetes documentation in real-time. This ensures security recommendations are always grounded in the official documentation for your cluster's specific version.

### What is Context7 MCP?

Context7 is a Model Context Protocol (MCP) server that provides access to official Kubernetes documentation across all versions. The auditor uses it to:

1. **Auto-detect cluster version** - Identifies your running Kubernetes version (e.g., v1.28.3)
2. **Fetch version-specific docs** - Retrieves documentation for your exact version (not generic latest)
3. **Ground findings** - All security findings reference official K8s docs for your version
4. **Stay updated** - Check for latest Kubernetes version and compare with your cluster

### Setting Up Context7 MCP

#### Option 1: Using Docker (Recommended)

```bash
# Run Context7 MCP server
docker run -d -p 3000:3000 \
  --name context7-mcp \
  modelcontextprotocol/context7-server:latest

# Verify it's running
curl http://localhost:3000/health
```

#### Option 2: From Source

```bash
# Clone the MCP servers repository
git clone https://github.com/modelcontextprotocol/servers.git
cd servers/src/context7

# Install dependencies
npm install

# Start the server
npm start
```

#### Option 3: Using Claude Desktop Integration

If you're using Claude Desktop, Context7 MCP can be configured in your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "context7": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-context7"]
    }
  }
}
```

### Using the Auditor with Context7

Once Context7 MCP is running, the auditor will automatically connect to it:

```bash
# Auditor auto-detects Context7 at http://localhost:3000
k8s-security-auditor -v

# Use custom Context7 server URL
k8s-security-auditor --mcp-server http://context7.example.com:3000

# View cluster version info
k8s-security-auditor --show-version

# Compare with latest Kubernetes version
k8s-security-auditor --check-latest
```

### How Version-Specific Documentation Works

1. **Cluster Detection**: Auditor connects to your cluster and detects version (e.g., `v1.28.3`)
2. **Version Parsing**: Extracts major.minor version (`1.28`)
3. **Documentation Fetch**: Queries Context7 MCP for `kubernetes://docs/1.28/<topic>`
4. **Finding Generation**: Each security finding includes links to version-specific docs
5. **Remediation Guidance**: Recommendations use APIs/features available in your version

### Example Version-Specific Finding

```markdown
### Pod Security Standards Not Enforced (CP-003)

**Cluster Version**: v1.28.3
**Documentation**: https://kubernetes.io/docs/v1.28/concepts/security/pod-security-standards/

Your cluster is running Kubernetes 1.28.3, which fully supports Pod Security Standards.
The remediation steps below are verified for your specific version...
```

### Benefits

- **Accurate Recommendations**: No suggestions for features not in your K8s version
- **Version-Aware**: Different checks for K8s 1.24 vs 1.35
- **Always Grounded**: Links to official docs, not third-party sources
- **Up-to-Date**: Compare your cluster version with latest release

### Offline Mode

If Context7 MCP is not available, the auditor falls back to:
- Bundled documentation references
- Generic Kubernetes documentation links
- Best-effort version compatibility checks

```bash
# Run without Context7 (offline mode)
k8s-security-auditor --offline
```

## Example Output

### Markdown Report Sample

```markdown
# Kubernetes Security Audit Report

**Generated**: 2024-01-16T10:30:00Z
**Cluster**: https://prod-cluster.example.com (server: v1.28.0)

## Executive Summary

Total findings: 47

### Findings by Severity

| Severity | Count |
|----------|-------|
| Critical | 3     |
| High     | 12    |
| Medium   | 20    |
| Low      | 12    |

## Critical Findings

### Privileged Container Detected

**ID**: WL-001 | **Severity**: Critical | **Category**: Workload Security

**Affected Resource**: `Pod/production/nginx-7d8f6c9b4-xk2m9`

**Evidence**:
- container: nginx
- privileged: true
- field: .spec.containers[].securityContext.privileged

**Impact**: Privileged containers can access all host devices, bypass SELinux/AppArmor,
and have unrestricted access to host resources. This effectively grants root access to the host.

**Exploit Path**:
```
1. Attacker gains access to privileged container
2. Mount host filesystem via /dev
3. Escape container and gain root on host
4. Pivot to other nodes or access cluster secrets
```

**Remediation**: Remove privileged flag from container 'nginx' in pod 'production/nginx-7d8f6c9b4-xk2m9'

```yaml
# Remove privileged flag from container 'nginx'
spec:
  containers:
  - name: nginx
    securityContext:
      privileged: false
```

**Verification**: `kubectl get pod nginx-7d8f6c9b4-xk2m9 -n production -o jsonpath='{.spec.containers[?(@.name=="nginx")].securityContext.privileged}'`
```

## Security Rules

### Workload Security (10 rules)

- **WL-001**: Privileged Container Detection
- **WL-002**: Host Namespace Usage (hostNetwork, hostPID, hostIPC)
- **WL-003**: HostPath Volume Detection
- **WL-004**: Container Running as Root
- **WL-005**: Writable Root Filesystem
- **WL-006**: Excessive Linux Capabilities
- **WL-007**: Privilege Escalation Allowed
- **WL-008**: Missing Resource Limits
- **WL-009**: Missing Seccomp Profile
- **WL-010**: Missing AppArmor Profile

### RBAC (7 rules)

- **RBAC-001**: Cluster Admin Binding Detection
- **RBAC-002**: Wildcard RBAC Permissions
- **RBAC-003**: Broad Secrets Access
- **RBAC-004**: Privilege Escalation Permissions (escalate, bind, impersonate)
- **RBAC-005**: Default Service Account Usage
- **RBAC-006**: Node Proxy Permissions
- **RBAC-007**: Pod Exec Permissions

### Secrets Management (3 rules)

- **SEC-001**: Secrets Encryption At Rest
- **SEC-002**: Secret Exposed in Environment Variable
- **SEC-003**: Automatic Service Account Token Mounting

### Network Security (2 rules)

- **NET-001**: Missing Network Policy
- **NET-002**: Missing Default Deny Policy

### Control Plane (3 rules)

- **CP-001**: API Server Audit Logging
- **CP-002**: Admission Controllers Configuration
- **CP-003**: Pod Security Standards Enforcement

### Supply Chain (3 rules)

- **SC-001**: Mutable Image Tag (latest, no tag, non-versioned)
- **SC-002**: Untrusted Image Registry
- **SC-003**: Weak Image Pull Policy

**Total**: 28 security rules

## CI/CD Integration

### GitHub Actions

```yaml
name: Kubernetes Security Audit

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 1'  # Weekly

jobs:
  k8s-security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup kubeconfig
        run: |
          mkdir -p ~/.kube
          echo "${{ secrets.KUBECONFIG }}" > ~/.kube/config

      - name: Run K8s Security Audit
        run: |
          curl -L https://github.com/hassansallam/Kubernetes-Security-Auditor/releases/latest/download/k8s-security-auditor-linux-amd64 -o k8s-security-auditor
          chmod +x k8s-security-auditor
          ./k8s-security-auditor -o sarif -f results.sarif

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif

      - name: Fail on Critical/High findings
        run: |
          ./k8s-security-auditor -o json -f results.json
          CRITICAL=$(jq '.summary.by_severity.Critical' results.json)
          HIGH=$(jq '.summary.by_severity.High' results.json)
          if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
            echo "Critical or High severity findings detected!"
            exit 1
          fi
```

### GitLab CI

```yaml
k8s-security-audit:
  stage: security
  image: alpine:latest
  before_script:
    - apk add --no-cache curl jq
    - curl -L https://github.com/hassansallam/Kubernetes-Security-Auditor/releases/latest/download/k8s-security-auditor-linux-amd64 -o k8s-security-auditor
    - chmod +x k8s-security-auditor
  script:
    - ./k8s-security-auditor -o json -f results.json
    - cat results.json | jq .
  artifacts:
    reports:
      sast: results.json
    paths:
      - results.json
  only:
    - main
    - merge_requests
```

## Architecture

```
k8s-security-auditor/
├── main.go                  # Entry point
├── cmd/
│   └── root.go             # CLI commands and flags
├── pkg/
│   ├── client/
│   │   └── client.go       # Kubernetes client wrapper
│   ├── audit/
│   │   ├── types.go        # Core types (Finding, Results, etc.)
│   │   └── auditor.go      # Main audit orchestration
│   ├── rules/
│   │   ├── rules.go        # Rule interface and registry
│   │   ├── workload.go     # Workload security rules
│   │   ├── rbac.go         # RBAC rules
│   │   ├── secrets.go      # Secrets management rules
│   │   ├── network.go      # Network security rules
│   │   ├── controlplane.go # Control plane rules
│   │   └── supplychain.go  # Supply chain rules
│   └── output/
│       ├── json.go         # JSON formatter
│       ├── sarif.go        # SARIF formatter
│       └── markdown.go     # Markdown formatter
└── plugins/
    ├── agentic_reasoner.py # Python plugin for AI analysis
    └── README.md           # Plugin documentation
```

## Design Principles

1. **Evidence-Driven**: Never hallucinate - if evidence is missing, report it
2. **Grounded in Documentation**: All findings reference official Kubernetes docs
3. **Production-Ready**: Single binary, no external dependencies for core functionality
4. **Actionable**: Every finding includes exact remediation steps
5. **Safe by Default**: Read-only unless explicitly using `--fix`
6. **Extensible**: Plugin architecture for advanced analysis

## Contributing

Contributions welcome! Please:

1. Add tests for new rules
2. Include references to official Kubernetes documentation
3. Provide both evidence and remediation for findings
4. Follow the existing rule structure

## License

MIT License - see LICENSE file for details

## Acknowledgments

Grounded in:
- Kubernetes Official Documentation
- CNCF Security Best Practices
- CIS Kubernetes Benchmark
- NSA/CISA Kubernetes Hardening Guide

Built with:
- [client-go](https://github.com/kubernetes/client-go)
- [cobra](https://github.com/spf13/cobra)

## Support

- Issues: https://github.com/hassansallam/Kubernetes-Security-Auditor/issues
- Documentation: https://github.com/hassansallam/Kubernetes-Security-Auditor/wiki
