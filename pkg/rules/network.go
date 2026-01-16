package rules

import (
	"context"
	"fmt"

	"github.com/hassansallam/k8s-security-auditor/pkg/audit"
)

// GetNetworkRules returns all network security rules
func GetNetworkRules() []Rule {
	return []Rule{
		&MissingNetworkPolicyRule{},
		&DefaultDenyPolicyRule{},
	}
}

// MissingNetworkPolicyRule checks for namespaces without network policies
type MissingNetworkPolicyRule struct{}

func (r *MissingNetworkPolicyRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "NET-001",
		Name:        "Missing Network Policy",
		Description: "Namespace has no NetworkPolicy resources",
		Category:    audit.CategoryNetwork,
		Severity:    audit.SeverityMedium,
		References: []string{
			"https://kubernetes.io/docs/concepts/services-networking/network-policies/",
		},
	}
}

func (r *MissingNetworkPolicyRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	// Note: NetworkPolicy type not imported yet - this is a placeholder
	// In production, you would check for NetworkPolicy resources per namespace

	systemNamespaces := map[string]bool{
		"kube-system":  true,
		"kube-public":  true,
		"kube-node-lease": true,
	}

	for _, ns := range evalCtx.ClusterData.Namespaces {
		// Skip system namespaces
		if systemNamespaces[ns.Name] {
			continue
		}

		// Check if namespace has any pods
		hasPods := false
		for _, pod := range evalCtx.ClusterData.Pods {
			if pod.Namespace == ns.Name {
				hasPods = true
				break
			}
		}

		if !hasPods {
			continue // Skip empty namespaces
		}

		// TODO: Check for NetworkPolicy resources in this namespace
		// For now, we'll create a finding for manual verification

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
				"note":      "Manual verification required - check for NetworkPolicy resources",
			},
			Impact: "Without NetworkPolicies, all pods can communicate with all other pods. " +
				"This violates the principle of least privilege and increases lateral movement risk.",
			ExploitPath: "1. Attacker compromises a pod\n" +
				"2. Scans and accesses other pods freely (no network segmentation)\n" +
				"3. Moves laterally to sensitive workloads\n" +
				"4. Accesses databases, services, or other targets",
			Remediation: fmt.Sprintf("Create NetworkPolicy resources in namespace '%s' to restrict pod-to-pod communication.",
				ns.Name),
			RemediationYAML: generateNetworkPolicyFix(ns.Name),
			Verification: fmt.Sprintf("kubectl get networkpolicy -n %s", ns.Name),
			References:   meta.References,
			CanAutoFix:   false, // Requires understanding of legitimate traffic flows
			IsRisky:      false,
		})
	}

	return findings
}

// DefaultDenyPolicyRule checks for default-deny network policies
type DefaultDenyPolicyRule struct{}

func (r *DefaultDenyPolicyRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "NET-002",
		Name:        "Missing Default Deny Policy",
		Description: "Namespace lacks a default-deny NetworkPolicy",
		Category:    audit.CategoryNetwork,
		Severity:    audit.SeverityMedium,
		References: []string{
			"https://kubernetes.io/docs/concepts/services-networking/network-policies/#default-policies",
		},
	}
}

func (r *DefaultDenyPolicyRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
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

		// Check if namespace has pods
		hasPods := false
		for _, pod := range evalCtx.ClusterData.Pods {
			if pod.Namespace == ns.Name {
				hasPods = true
				break
			}
		}

		if !hasPods {
			continue
		}

		// TODO: Check for default-deny NetworkPolicy
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
				"note":      "Manual verification required",
			},
			Impact: "Without a default-deny policy, new pods are allowed all traffic by default. " +
				"Best practice is deny-all by default, then explicitly allow required traffic.",
			ExploitPath: "1. Developer deploys new workload\n" +
				"2. Workload has no NetworkPolicy\n" +
				"3. Workload can access all other services\n" +
				"4. If compromised, attacker has broad network access",
			Remediation: fmt.Sprintf("Create default-deny NetworkPolicy in namespace '%s' as a baseline.",
				ns.Name),
			RemediationYAML: generateDefaultDenyFix(ns.Name),
			Verification: fmt.Sprintf("kubectl get networkpolicy -n %s -o yaml | grep -A 10 'podSelector: {}'",
				ns.Name),
			References:  meta.References,
			CanAutoFix:  true, // Default-deny is usually safe to apply
			IsRisky:     true, // May break existing workloads
		})
	}

	return findings
}

// Remediation generators

func generateNetworkPolicyFix(namespace string) string {
	return fmt.Sprintf(`# Example NetworkPolicy for namespace '%s'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-specific-traffic
  namespace: %s
spec:
  podSelector:
    matchLabels:
      app: myapp
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              role: frontend
      ports:
        - protocol: TCP
          port: 8080
  egress:
    - to:
        - podSelector:
            matchLabels:
              role: database
      ports:
        - protocol: TCP
          port: 5432`, namespace, namespace)
}

func generateDefaultDenyFix(namespace string) string {
	return fmt.Sprintf(`# Default deny all traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: %s
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress

# Then create allow policies for legitimate traffic`, namespace)
}
