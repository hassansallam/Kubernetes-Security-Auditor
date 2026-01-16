package audit

import (
	"fmt"
)

// Severity levels for security findings
type Severity string

const (
	SeverityLow      Severity = "Low"
	SeverityMedium   Severity = "Medium"
	SeverityHigh     Severity = "High"
	SeverityCritical Severity = "Critical"
)

// Finding represents a single security issue discovered during audit
type Finding struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Description     string            `json:"description"`
	Severity        Severity          `json:"severity"`
	Category        string            `json:"category"`
	Resource        ResourceRef       `json:"resource"`
	Evidence        map[string]string `json:"evidence"`
	Impact          string            `json:"impact"`
	ExploitPath     string            `json:"exploit_path"`
	Remediation     string            `json:"remediation"`
	RemediationYAML string            `json:"remediation_yaml,omitempty"`
	Verification    string            `json:"verification"`
	References      []string          `json:"references,omitempty"`
	CanAutoFix      bool              `json:"can_auto_fix"`
	IsRisky         bool              `json:"is_risky"`
	Applied         bool              `json:"applied"`
}

// ResourceRef identifies a Kubernetes resource
type ResourceRef struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

func (r ResourceRef) String() string {
	if r.Namespace != "" {
		return fmt.Sprintf("%s/%s/%s", r.Kind, r.Namespace, r.Name)
	}
	return fmt.Sprintf("%s/%s", r.Kind, r.Name)
}

// Results holds all audit findings
type Results struct {
	Findings       []Finding         `json:"findings"`
	Summary        Summary           `json:"summary"`
	ClusterInfo    string            `json:"cluster_info"`
	ClusterVersion string            `json:"cluster_version"`
	Timestamp      string            `json:"timestamp"`
	AuditConfig    Config            `json:"audit_config"`
}

// Summary provides aggregate statistics
type Summary struct {
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[Severity]int `json:"by_severity"`
	ByCategory    map[string]int `json:"by_category"`
	FixesApplied  int            `json:"fixes_applied"`
}

// HasCriticalOrHigh returns true if any critical or high severity findings exist
func (r *Results) HasCriticalOrHigh() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityCritical || f.Severity == SeverityHigh {
			return true
		}
	}
	return false
}

// Config holds audit configuration
type Config struct {
	Namespace    string `json:"namespace,omitempty"`
	Fix          bool   `json:"fix"`
	ApproveRisky bool   `json:"approve_risky"`
	DryRun       bool   `json:"dry_run"`
	ShowDiff     bool   `json:"show_diff"`
	Verbose      bool   `json:"verbose"`
	PythonPlugin string `json:"python_plugin,omitempty"`
	MCPServer    string `json:"mcp_server,omitempty"`
	Offline      bool   `json:"offline"`
}

// Category constants for organizing findings
const (
	CategoryControlPlane  = "Control Plane"
	CategoryAuthN         = "Authentication"
	CategoryAuthZ         = "Authorization"
	CategoryRBAC          = "RBAC"
	CategoryAdmission     = "Admission Control"
	CategoryWorkload      = "Workload Security"
	CategoryNetwork       = "Network Security"
	CategorySecrets       = "Secrets Management"
	CategorySupplyChain   = "Supply Chain"
	CategoryRuntime       = "Runtime Security"
	CategoryCompliance    = "Compliance"
)
