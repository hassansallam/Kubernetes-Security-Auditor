package audit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hassansallam/Kubernetes-Security-Auditor/pkg/client"
	"github.com/hassansallam/Kubernetes-Security-Auditor/pkg/rules"
)

// Auditor orchestrates security audit execution
type Auditor struct {
	client *client.Client
	config Config
	rules  []rules.Rule
}

// NewAuditor creates a new security auditor
func NewAuditor(client *client.Client, config Config) *Auditor {
	return &Auditor{
		client: client,
		config: config,
		rules:  rules.GetAllRules(),
	}
}

// Run executes the complete security audit
func (a *Auditor) Run(ctx context.Context) (*Results, error) {
	startTime := time.Now()

	// Collect cluster data
	if a.config.Verbose {
		fmt.Println("Collecting cluster data...")
	}

	data, err := a.client.CollectClusterData(ctx, a.config.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to collect cluster data: %w", err)
	}

	if a.config.Verbose {
		fmt.Printf("Collected resources: %d nodes, %d namespaces, %d pods, %d services\n",
			len(data.Nodes), len(data.Namespaces), len(data.Pods), len(data.Services))
		fmt.Printf("Running %d security rules...\n", len(a.rules))
	}

	// Execute rules concurrently
	findings := a.executeRules(ctx, data)

	if a.config.Verbose {
		fmt.Printf("Found %d security findings\n", len(findings))
	}

	// Apply fixes if requested
	if a.config.Fix {
		findings = a.applyFixes(ctx, findings)
	}

	// Generate results
	results := &Results{
		Findings:    findings,
		Summary:     a.generateSummary(findings),
		ClusterInfo: a.client.GetClusterInfo(),
		Timestamp:   startTime.Format(time.RFC3339),
		AuditConfig: a.config,
	}

	return results, nil
}

// executeRules runs all rules concurrently against cluster data
func (a *Auditor) executeRules(ctx context.Context, data *client.ClusterData) []Finding {
	var (
		mu       sync.Mutex
		findings []Finding
		wg       sync.WaitGroup
	)

	// Create evaluation context
	evalCtx := &rules.EvaluationContext{
		ClusterData: data,
		Config:      a.config,
	}

	// Execute each rule in parallel
	for _, rule := range a.rules {
		wg.Add(1)
		go func(r rules.Rule) {
			defer wg.Done()

			ruleFindings := r.Evaluate(ctx, evalCtx)

			mu.Lock()
			findings = append(findings, ruleFindings...)
			mu.Unlock()
		}(rule)
	}

	wg.Wait()

	return findings
}

// applyFixes attempts to automatically remediate findings
func (a *Auditor) applyFixes(ctx context.Context, findings []Finding) []Finding {
	if a.config.Verbose {
		fmt.Println("\nApplying automatic fixes...")
	}

	for i := range findings {
		finding := &findings[i]

		// Skip if can't auto-fix
		if !finding.CanAutoFix {
			continue
		}

		// Skip risky fixes without approval
		if finding.IsRisky && !a.config.ApproveRisky {
			if a.config.Verbose {
				fmt.Printf("Skipping risky fix for: %s (use --approve-risky to enable)\n", finding.Name)
			}
			continue
		}

		// Show diff if requested
		if a.config.ShowDiff {
			fmt.Printf("\n--- Fix for: %s ---\n", finding.Name)
			fmt.Printf("Resource: %s\n", finding.Resource)
			fmt.Printf("Remediation:\n%s\n", finding.RemediationYAML)
		}

		// Apply fix (or simulate in dry-run mode)
		if !a.config.DryRun {
			if err := a.applyFix(ctx, finding); err != nil {
				if a.config.Verbose {
					fmt.Printf("Failed to apply fix for %s: %v\n", finding.Name, err)
				}
				continue
			}
			finding.Applied = true
			if a.config.Verbose {
				fmt.Printf("Applied fix for: %s\n", finding.Name)
			}
		} else {
			if a.config.Verbose {
				fmt.Printf("Would apply fix for: %s (dry-run mode)\n", finding.Name)
			}
		}
	}

	return findings
}

// applyFix applies a single remediation
func (a *Auditor) applyFix(ctx context.Context, finding *Finding) error {
	// This is a placeholder - actual implementation would use client-go to apply changes
	// For production, this would parse RemediationYAML and apply using appropriate API calls
	return fmt.Errorf("remediation not yet implemented")
}

// generateSummary creates aggregate statistics
func (a *Auditor) generateSummary(findings []Finding) Summary {
	summary := Summary{
		TotalFindings: len(findings),
		BySeverity: map[Severity]int{
			SeverityLow:      0,
			SeverityMedium:   0,
			SeverityHigh:     0,
			SeverityCritical: 0,
		},
		ByCategory:   make(map[string]int),
		FixesApplied: 0,
	}

	for _, f := range findings {
		summary.BySeverity[f.Severity]++
		summary.ByCategory[f.Category]++
		if f.Applied {
			summary.FixesApplied++
		}
	}

	return summary
}
