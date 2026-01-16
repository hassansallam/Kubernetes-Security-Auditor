# Project Structure

This document explains the architecture and organization of the K8s Security Auditor codebase.

## Directory Layout

```
k8s-security-auditor/
├── cmd/                    # CLI command definitions
│   └── root.go            # Main cobra command with flags
├── pkg/                   # Core application packages
│   ├── audit/             # Audit orchestration
│   │   ├── auditor.go     # Main audit engine
│   │   └── types.go       # Core types (Finding, Results, etc.)
│   ├── client/            # Kubernetes client wrapper
│   │   └── client.go      # K8s API client and data collection
│   ├── output/            # Output formatters
│   │   ├── json.go        # JSON output
│   │   ├── markdown.go    # Markdown report generator
│   │   └── sarif.go       # SARIF format for security tools
│   └── rules/             # Security rules library
│       ├── rules.go       # Rule interface and registry
│       ├── workload.go    # Workload security rules (WL-*)
│       ├── rbac.go        # RBAC rules (RBAC-*)
│       ├── secrets.go     # Secrets management (SEC-*)
│       ├── network.go     # Network security (NET-*)
│       ├── controlplane.go # Control plane (CP-*)
│       └── supplychain.go # Supply chain (SC-*)
├── plugins/               # Optional enhancement plugins
│   ├── agentic_reasoner.py # Python AI analysis plugin
│   └── README.md          # Plugin documentation
├── main.go                # Application entry point
├── go.mod                 # Go dependencies
├── go.sum                 # Go dependency checksums
├── Makefile               # Build automation
├── Dockerfile             # Container image definition
├── .gitignore             # Git ignore patterns
├── README.md              # Main documentation
├── QUICKSTART.md          # Quick start guide
├── EXAMPLES.md            # Usage examples
├── CONTRIBUTING.md        # Contribution guidelines
├── SECURITY.md            # Security policy
├── LICENSE                # MIT license
└── PROJECT_STRUCTURE.md   # This file
```

## Architecture Overview

### Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLI (cmd/root.go)                        │
│  Handles flags, kubeconfig, output format selection             │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Auditor (pkg/audit/auditor.go)                 │
│  Orchestrates audit: collect data → run rules → format output   │
└──────────────┬──────────────────────────────────┬───────────────┘
               │                                   │
               ▼                                   ▼
┌──────────────────────────────┐   ┌─────────────────────────────┐
│  Client (pkg/client/)        │   │  Rules (pkg/rules/)         │
│  - Kubernetes API access     │   │  - Workload security        │
│  - Resource collection       │   │  - RBAC analysis            │
│  - ClusterData assembly      │   │  - Secrets management       │
└──────────────────────────────┘   │  - Network policies         │
                                    │  - Control plane            │
                                    │  - Supply chain             │
                                    └──────────────┬──────────────┘
                                                   │
                                                   ▼
                                    ┌──────────────────────────────┐
                                    │  Findings (pkg/audit/types)  │
                                    │  - Evidence                  │
                                    │  - Impact                    │
                                    │  - Remediation               │
                                    └──────────────┬───────────────┘
                                                   │
                                                   ▼
                                    ┌──────────────────────────────┐
                                    │  Output (pkg/output/)        │
                                    │  - JSON / SARIF / Markdown   │
                                    └──────────────────────────────┘
```

## Data Flow

1. **CLI Initialization** ([cmd/root.go](cmd/root.go))
   - Parse flags
   - Load kubeconfig
   - Initialize Kubernetes client

2. **Client Setup** ([pkg/client/client.go](pkg/client/client.go))
   - Connect to cluster
   - Authenticate
   - Build clientset

3. **Data Collection** ([pkg/client/client.go](pkg/client/client.go))
   - List all relevant resources
   - Assemble ClusterData structure
   - Handle namespace scoping

4. **Rule Execution** ([pkg/audit/auditor.go](pkg/audit/auditor.go))
   - Spawn goroutines for each rule
   - Execute rules in parallel
   - Collect findings with mutex

5. **Auto-Fix (Optional)** ([pkg/audit/auditor.go](pkg/audit/auditor.go))
   - Filter fixable findings
   - Apply or simulate changes
   - Update finding status

6. **Output Generation** ([pkg/output/](pkg/output/))
   - Format findings
   - Generate summary
   - Write to stdout or file

## Key Types

### Finding ([pkg/audit/types.go](pkg/audit/types.go))

```go
type Finding struct {
    ID              string            // Unique rule ID (e.g., "WL-001")
    Name            string            // Human-readable name
    Description     string            // What is being checked
    Severity        Severity          // Low/Medium/High/Critical
    Category        string            // Security domain
    Resource        ResourceRef       // Affected K8s resource
    Evidence        map[string]string // Observed values
    Impact          string            // Why it's dangerous
    ExploitPath     string            // Attack scenario
    Remediation     string            // How to fix
    RemediationYAML string            // Exact YAML fix
    Verification    string            // How to verify fix
    References      []string          // Official docs
    CanAutoFix      bool              // Safe to auto-fix?
    IsRisky         bool              // Might break workload?
    Applied         bool              // Was fix applied?
}
```

### ClusterData ([pkg/client/client.go](pkg/client/client.go))

```go
type ClusterData struct {
    Nodes                 []corev1.Node
    Namespaces            []corev1.Namespace
    Pods                  []corev1.Pod
    Services              []corev1.Service
    ServiceAccounts       []corev1.ServiceAccount
    Secrets               []corev1.Secret
    ConfigMaps            []corev1.ConfigMap
    Roles                 []rbacv1.Role
    RoleBindings          []rbacv1.RoleBinding
    ClusterRoles          []rbacv1.ClusterRole
    ClusterRoleBindings   []rbacv1.ClusterRoleBinding
    // ... more resources
}
```

### Rule Interface ([pkg/rules/rules.go](pkg/rules/rules.go))

```go
type Rule interface {
    Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding
    Metadata() RuleMetadata
}
```

## Adding New Rules

### Step 1: Create Rule Type

Add to appropriate file in [pkg/rules/](pkg/rules/):

```go
type MyNewRule struct{}

func (r *MyNewRule) Metadata() RuleMetadata {
    return RuleMetadata{
        ID:          "WL-011",
        Name:        "My Security Check",
        Description: "Checks for X",
        Category:    audit.CategoryWorkload,
        Severity:    audit.SeverityHigh,
        References:  []string{"https://kubernetes.io/docs/..."},
    }
}

func (r *MyNewRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
    // Implementation
}
```

### Step 2: Register Rule

Add to `GetXXXRules()` function:

```go
func GetWorkloadRules() []Rule {
    return []Rule{
        // ... existing rules
        &MyNewRule{},
    }
}
```

### Step 3: Document

Update [README.md](README.md) security rules section.

## Testing

```bash
# Unit tests
go test ./pkg/...

# Integration test (requires cluster)
make run

# Build test
make build
```

## Build Process

```bash
# Development build
make build

# Multi-platform builds
make build-all

# Docker image
make docker-build
```

## Dependencies

### Go Packages

- `k8s.io/client-go` - Kubernetes client
- `k8s.io/api` - Kubernetes API types
- `github.com/spf13/cobra` - CLI framework

See [go.mod](go.mod) for complete list.

### Python Plugin (Optional)

- Python 3.6+
- Standard library only (no external deps)

## Concurrency Model

- **Data Collection**: Sequential (single API calls)
- **Rule Execution**: Concurrent (one goroutine per rule)
- **Finding Collection**: Thread-safe (mutex-protected)
- **Auto-Fix**: Sequential (to prevent conflicts)

## Performance Considerations

- Rules run in parallel for speed
- ClusterData collected once, shared across rules
- No caching between runs (audit is point-in-time)
- Large clusters (1000+ pods): ~30-60 seconds

## Error Handling

- API errors: Fail fast, return error to user
- Rule errors: Logged, don't stop other rules
- Output errors: Return error, exit non-zero

## Security Considerations

- Read-only by default
- No secret values in output (metadata only)
- Requires explicit `--fix` for mutations
- Risky changes need `--approve-risky`
- No network access except K8s API

## Extension Points

### Add New Rule Category

1. Create new file: `pkg/rules/mycategory.go`
2. Implement rules
3. Add `GetMyCategoryRules()` function
4. Register in `GetAllRules()` in [pkg/rules/rules.go](pkg/rules/rules.go)

### Add New Output Format

1. Create new file: `pkg/output/myformat.go`
2. Implement `FormatMyFormat(results *audit.Results) ([]byte, error)`
3. Add case in [cmd/root.go](cmd/root.go) switch statement

### Add Python Plugin Mode

Add new mode in [plugins/agentic_reasoner.py](plugins/agentic_reasoner.py):

```python
if args.mode == 'mymode':
    output = generate_my_analysis(reasoner)
```

## Code Style

- Follow standard Go conventions
- Use `gofmt` for formatting
- Keep functions under 50 lines when possible
- Document exported types and functions
- Use meaningful variable names

## Git Workflow

- `main` branch: Stable releases
- Feature branches: `feature/rule-name`
- Bug fixes: `fix/issue-description`
- Docs: `docs/description`

## Release Process

1. Update version in code
2. Update CHANGELOG
3. Tag release: `git tag v1.2.3`
4. Push tag: `git push origin v1.2.3`
5. GitHub Actions builds and publishes

## Troubleshooting Development

### Import Errors

```bash
go mod tidy
go mod download
```

### Build Fails

```bash
make clean
make deps
make build
```

### Tests Fail

Ensure you have a test cluster or use mocks.

## Resources

- [Kubernetes API Reference](https://kubernetes.io/docs/reference/kubernetes-api/)
- [client-go Examples](https://github.com/kubernetes/client-go/tree/master/examples)
- [SARIF Spec](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

## Questions?

See [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue.
