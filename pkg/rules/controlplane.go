package rules

import (
	"context"

	"github.com/hassansallam/Kubernetes-Security-Auditor/pkg/audit"
)

// GetControlPlaneRules returns all control plane security rules
func GetControlPlaneRules() []Rule {
	return []Rule{
		&APIServerAuditRule{},
		&AdmissionControllersRule{},
		&PodSecurityStandardsRule{},
	}
}

// APIServerAuditRule checks for API server audit logging
type APIServerAuditRule struct{}

func (r *APIServerAuditRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "CP-001",
		Name:        "API Server Audit Logging",
		Description: "Verify API server audit logging is enabled",
		Category:    audit.CategoryControlPlane,
		Severity:    audit.SeverityHigh,
		References: []string{
			"https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/",
		},
	}
}

func (r *APIServerAuditRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	// This check requires access to API server configuration
	return []audit.Finding{
		{
			ID:          r.Metadata().ID,
			Name:        r.Metadata().Name,
			Description: r.Metadata().Description,
			Severity:    r.Metadata().Severity,
			Category:    r.Metadata().Category,
			Resource: audit.ResourceRef{
				Kind: "Cluster",
				Name: "api-server-audit",
			},
			Evidence: map[string]string{
				"note": "Manual verification required - check API server configuration",
			},
			Impact: "Without audit logging, there is no record of API requests, making it impossible to " +
				"detect unauthorized access, track security incidents, or perform forensics.",
			ExploitPath: "1. Attacker gains unauthorized access to cluster\n" +
				"2. Performs malicious actions (data theft, resource creation, etc.)\n" +
				"3. No audit trail exists\n" +
				"4. Incident detection and investigation impossible",
			Remediation: "Enable API server audit logging with appropriate audit policy.",
			RemediationYAML: `# Create audit policy
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
    omitStages:
      - RequestReceived
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets", "configmaps"]
  - level: Request
    resources:
      - group: ""
        resources: ["pods", "services"]
    verbs: ["create", "update", "patch", "delete"]

# Add to API server flags:
# --audit-policy-file=/path/to/audit-policy.yaml
# --audit-log-path=/var/log/kubernetes/audit.log
# --audit-log-maxage=30
# --audit-log-maxbackup=10
# --audit-log-maxsize=100`,
			Verification: "Check API server pod/process for audit flags: " +
				"kubectl get pod -n kube-system -l component=kube-apiserver -o yaml | grep audit",
			References: r.Metadata().References,
			CanAutoFix: false, // Requires control plane access
			IsRisky:    false,
		},
	}
}

// AdmissionControllersRule checks for required admission controllers
type AdmissionControllersRule struct{}

func (r *AdmissionControllersRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "CP-002",
		Name:        "Admission Controllers Configuration",
		Description: "Verify critical admission controllers are enabled",
		Category:    audit.CategoryAdmission,
		Severity:    audit.SeverityHigh,
		References: []string{
			"https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/",
		},
	}
}

func (r *AdmissionControllersRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	requiredControllers := []string{
		"NodeRestriction",
		"PodSecurityPolicy or PodSecurity",
		"LimitRanger",
		"ResourceQuota",
		"ServiceAccount",
		"DefaultStorageClass",
		"MutatingAdmissionWebhook",
		"ValidatingAdmissionWebhook",
	}

	return []audit.Finding{
		{
			ID:          r.Metadata().ID,
			Name:        r.Metadata().Name,
			Description: r.Metadata().Description,
			Severity:    r.Metadata().Severity,
			Category:    r.Metadata().Category,
			Resource: audit.ResourceRef{
				Kind: "Cluster",
				Name: "admission-controllers",
			},
			Evidence: map[string]string{
				"note":                "Manual verification required",
				"required_controllers": "NodeRestriction, PodSecurity, LimitRanger, ResourceQuota, etc.",
			},
			Impact: "Missing admission controllers allow bypassing critical security controls. " +
				"For example, without NodeRestriction, kubelets can modify any node object.",
			ExploitPath: "1. Attacker exploits missing admission controller\n" +
				"2. Bypasses intended security policy\n" +
				"3. Creates privileged workloads or modifies cluster state\n" +
				"4. Escalates privileges or compromises cluster",
			Remediation: "Enable required admission controllers: " + requiredControllers[0],
			RemediationYAML: `# API server configuration - ensure these admission controllers are enabled:
# --enable-admission-plugins=NodeRestriction,PodSecurity,LimitRanger,ResourceQuota,ServiceAccount,DefaultStorageClass,MutatingAdmissionWebhook,ValidatingAdmissionWebhook

# Disable dangerous controllers:
# --disable-admission-plugins=AlwaysAdmit`,
			Verification: "Check API server: kubectl get pod -n kube-system -l component=kube-apiserver -o yaml | grep enable-admission-plugins",
			References:   r.Metadata().References,
			CanAutoFix:   false,
			IsRisky:      false,
		},
	}
}

// PodSecurityStandardsRule checks for Pod Security Standards enforcement
type PodSecurityStandardsRule struct{}

func (r *PodSecurityStandardsRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "CP-003",
		Name:        "Pod Security Standards",
		Description: "Verify Pod Security Standards are enforced",
		Category:    audit.CategoryAdmission,
		Severity:    audit.SeverityHigh,
		References: []string{
			"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
			"https://kubernetes.io/docs/concepts/security/pod-security-admission/",
		},
	}
}

func (r *PodSecurityStandardsRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	systemNamespaces := map[string]bool{
		"kube-system":     true,
		"kube-public":     true,
		"kube-node-lease": true,
	}

	for _, ns := range evalCtx.ClusterData.Namespaces {
		if systemNamespaces[ns.Name] {
			continue
		}

		// Check for Pod Security Standard labels
		hasPSS := false
		enforceLevel := ""

		if ns.Labels != nil {
			if level, ok := ns.Labels["pod-security.kubernetes.io/enforce"]; ok {
				hasPSS = true
				enforceLevel = level
			}
		}

		if !hasPSS {
			findings = append(findings, audit.Finding{
				ID:          meta.ID,
				Name:        meta.Name,
				Description: meta.Description,
				Severity:    meta.Severity,
				Category:    meta.Category,
				Resource: audit.ResourceRef{
					Kind: "Namespace",
					Name: ns.Name,
				},
				Evidence: map[string]string{
					"namespace": ns.Name,
					"pss_label": "not set",
				},
				Impact: "Without Pod Security Standards, the namespace accepts pods with dangerous configurations " +
					"(privileged, hostPath, etc.). PSS provides baseline security enforcement.",
				ExploitPath: "1. Developer or attacker deploys pod with dangerous settings\n" +
					"2. No PSS policy blocks it\n" +
					"3. Privileged pod is created\n" +
					"4. Pod is used for privilege escalation or container escape",
				Remediation: "Add Pod Security Standard labels to namespace. Start with 'baseline', move to 'restricted' when possible.",
				RemediationYAML: `# Add PSS labels to namespace
kubectl label namespace ` + ns.Name + ` \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted

# Levels:
# - privileged: Unrestricted (no restrictions)
# - baseline: Minimally restrictive (blocks most dangerous settings)
# - restricted: Heavily restricted (best practice, may break some workloads)`,
				Verification: "kubectl get namespace " + ns.Name + " -o yaml | grep pod-security",
				References:   meta.References,
				CanAutoFix:   true,  // Can safely add baseline level
				IsRisky:      true,  // May block existing workloads
			})
		} else if enforceLevel == "privileged" {
			findings = append(findings, audit.Finding{
				ID:          meta.ID,
				Name:        "Pod Security Standard Too Permissive",
				Description: "Namespace uses 'privileged' Pod Security Standard",
				Severity:    audit.SeverityMedium,
				Category:    meta.Category,
				Resource: audit.ResourceRef{
					Kind: "Namespace",
					Name: ns.Name,
				},
				Evidence: map[string]string{
					"namespace":    ns.Name,
					"enforce_level": enforceLevel,
				},
				Impact: "'privileged' level provides no security restrictions. Consider 'baseline' or 'restricted'.",
				ExploitPath: "Same as missing PSS - privileged level allows all pod configurations",
				Remediation: "Upgrade to 'baseline' or 'restricted' Pod Security Standard.",
				RemediationYAML: `kubectl label namespace ` + ns.Name + ` \
  pod-security.kubernetes.io/enforce=baseline \
  --overwrite`,
				Verification: "kubectl get namespace " + ns.Name + " -o jsonpath='{.metadata.labels}'",
				References:   meta.References,
				CanAutoFix:   false,
				IsRisky:      true,
			})
		}
	}

	return findings
}
