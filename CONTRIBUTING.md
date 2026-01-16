# Contributing to K8s Security Auditor

Thank you for your interest in contributing! This document provides guidelines for contributions.

## Code of Conduct

Be respectful, inclusive, and constructive. We're all here to improve Kubernetes security.

## How to Contribute

### Reporting Bugs

Open a GitHub issue with:
- Description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Kubernetes version and cluster info
- Tool version and command used

### Suggesting Features

Open a GitHub issue with:
- Use case and motivation
- Proposed solution
- Alternative approaches considered
- Example output (if applicable)

### Contributing Code

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/my-new-rule`
3. **Make your changes**
4. **Test thoroughly**
5. **Commit with clear messages**: `git commit -m "Add WL-011: Check for init container security"`
6. **Push to your fork**: `git push origin feature/my-new-rule`
7. **Open a Pull Request**

## Adding New Security Rules

### Rule Structure

Each rule should implement the `Rule` interface:

```go
type Rule interface {
    Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding
    Metadata() RuleMetadata
}
```

### Rule Template

```go
type MyNewRule struct{}

func (r *MyNewRule) Metadata() RuleMetadata {
    return RuleMetadata{
        ID:          "CAT-###",  // Category prefix + number
        Name:        "Clear, Specific Name",
        Description: "One-line description of what is checked",
        Category:    audit.CategoryWorkload,  // or other category
        Severity:    audit.SeverityHigh,
        References: []string{
            "https://kubernetes.io/docs/relevant-doc",
        },
    }
}

func (r *MyNewRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
    var findings []audit.Finding
    meta := r.Metadata()

    // Iterate over relevant resources
    for _, resource := range evalCtx.ClusterData.Pods {
        // Check for security issue
        if hasIssue(resource) {
            findings = append(findings, audit.Finding{
                ID:          meta.ID,
                Name:        meta.Name,
                Description: meta.Description,
                Severity:    meta.Severity,
                Category:    meta.Category,
                Resource: audit.ResourceRef{
                    Kind:      "Pod",
                    Namespace: resource.Namespace,
                    Name:      resource.Name,
                },
                Evidence: map[string]string{
                    "field": "value observed",
                },
                Impact: "Why this is dangerous and what attacker can do",
                ExploitPath: "1. Attacker does X\n2. Then Y\n3. Gains Z",
                Remediation: "Specific steps to fix, including YAML",
                RemediationYAML: generateFixYAML(resource),
                Verification: "kubectl command to verify fix",
                References: meta.References,
                CanAutoFix: false,  // true if safe to auto-fix
                IsRisky:    false,  // true if fix might break workloads
            })
        }
    }

    return findings
}
```

### Rule Guidelines

1. **Evidence-Based**: Only report what you can observe in the cluster state
2. **Actionable**: Every finding must include specific remediation steps
3. **Grounded**: Reference official Kubernetes documentation
4. **Severity Accurate**:
   - Critical: Direct path to cluster compromise
   - High: Significant security risk, easy to exploit
   - Medium: Security risk requiring specific conditions
   - Low: Defense-in-depth, best practices
5. **Clear Impact**: Explain why it matters in security terms
6. **Exploit Path**: Show realistic attack scenario
7. **Verification**: Provide command to confirm fix worked

### Rule Naming Convention

- **ID**: `CATEGORY-###` (e.g., `WL-001`, `RBAC-005`)
- **Category Prefixes**:
  - `WL`: Workload Security
  - `RBAC`: RBAC and Authorization
  - `SEC`: Secrets Management
  - `NET`: Network Security
  - `CP`: Control Plane
  - `SC`: Supply Chain
  - `RT`: Runtime Security (future)

### Adding Your Rule

1. Add rule to appropriate file (e.g., `pkg/rules/workload.go`)
2. Register in `GetXXXRules()` function
3. Write tests in `pkg/rules/workload_test.go` (if tests exist)
4. Update README.md to list new rule
5. Add example to EXAMPLES.md

## Testing

```bash
# Run tests
make test

# Build
make build

# Test manually against a cluster
make run
```

### Test Cases

Each rule should have tests covering:
- Positive case (issue detected)
- Negative case (no issue)
- Edge cases

Example:
```go
func TestMyNewRule(t *testing.T) {
    rule := &MyNewRule{}

    // Test case 1: Issue detected
    evalCtx := &EvaluationContext{
        ClusterData: &client.ClusterData{
            Pods: []corev1.Pod{
                // Pod with issue
            },
        },
    }
    findings := rule.Evaluate(context.Background(), evalCtx)
    assert.Equal(t, 1, len(findings))

    // Test case 2: No issue
    evalCtx.ClusterData.Pods = []corev1.Pod{
        // Pod without issue
    }
    findings = rule.Evaluate(context.Background(), evalCtx)
    assert.Equal(t, 0, len(findings))
}
```

## Code Style

- Run `go fmt` before committing
- Follow standard Go conventions
- Use meaningful variable names
- Add comments for complex logic
- Keep functions focused and small

## Documentation

Update documentation when:
- Adding new rules
- Changing CLI flags
- Adding new output formats
- Changing behavior

Files to update:
- `README.md` - Main documentation
- `EXAMPLES.md` - Usage examples
- `SECURITY.md` - Security considerations (if relevant)

## Commit Messages

Use clear, descriptive commit messages:

Good:
```
Add WL-011: Check for init container security context
Fix RBAC-003 false positive for system:serviceaccounts
Update README with new network policy rules
```

Bad:
```
fixes
update stuff
WIP
```

## Pull Request Process

1. Ensure all tests pass
2. Update documentation
3. Add examples if applicable
4. Describe changes in PR description
5. Link related issues
6. Wait for review
7. Address review comments
8. Squash commits if requested

### PR Checklist

- [ ] Tests pass
- [ ] Code is formatted (`go fmt`)
- [ ] Documentation updated
- [ ] Examples added (if applicable)
- [ ] Commit messages are clear
- [ ] PR description explains changes

## Review Process

Maintainers will review:
- Code quality and style
- Test coverage
- Documentation completeness
- Security implications
- Performance impact

Reviews typically take 2-5 days. Please be patient!

## Release Process

Releases follow semantic versioning:
- Major: Breaking changes
- Minor: New features, backward compatible
- Patch: Bug fixes

Maintainers handle releases. Contributors don't need to worry about this.

## Questions?

Open a GitHub issue with the `question` label, or start a discussion.

## License

By contributing, you agree your contributions will be licensed under the MIT License.

## Recognition

Contributors will be acknowledged in release notes and the README.

Thank you for making Kubernetes more secure! 🔒
