package rules

import (
	"context"

	"github.com/hassansallam/Kubernetes-Security-Auditor/pkg/audit"
	"github.com/hassansallam/Kubernetes-Security-Auditor/pkg/client"
)

// Rule defines the interface for security checks
type Rule interface {
	// Evaluate executes the security check and returns findings
	Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding

	// Metadata returns rule information
	Metadata() RuleMetadata
}

// RuleMetadata provides information about a rule
type RuleMetadata struct {
	ID          string
	Name        string
	Description string
	Category    string
	Severity    audit.Severity
	References  []string
}

// EvaluationContext provides rules with necessary data
type EvaluationContext struct {
	ClusterData *client.ClusterData
	Config      audit.Config
}

// GetAllRules returns all registered security rules
func GetAllRules() []Rule {
	var allRules []Rule

	// Workload security rules
	allRules = append(allRules, GetWorkloadRules()...)

	// RBAC rules
	allRules = append(allRules, GetRBACRules()...)

	// Secrets rules
	allRules = append(allRules, GetSecretsRules()...)

	// Network rules
	allRules = append(allRules, GetNetworkRules()...)

	// Control plane rules
	allRules = append(allRules, GetControlPlaneRules()...)

	// Supply chain rules
	allRules = append(allRules, GetSupplyChainRules()...)

	return allRules
}
