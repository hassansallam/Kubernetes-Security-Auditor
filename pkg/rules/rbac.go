package rules

import (
	"context"
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/vibecoding/k8s-security-auditor/pkg/audit"
)

// GetRBACRules returns all RBAC security rules
func GetRBACRules() []Rule {
	return []Rule{
		&ClusterAdminBindingRule{},
		&WildcardPermissionsRule{},
		&SecretsAccessRule{},
		&EscalationPermissionsRule{},
		&DefaultServiceAccountRule{},
		&NodeProxyPermissionsRule{},
		&PodExecPermissionsRule{},
	}
}

// ClusterAdminBindingRule checks for cluster-admin bindings
type ClusterAdminBindingRule struct{}

func (r *ClusterAdminBindingRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "RBAC-001",
		Name:        "Cluster Admin Binding Detected",
		Description: "User or service account has cluster-admin privileges",
		Category:    audit.CategoryRBAC,
		Severity:    audit.SeverityCritical,
		References: []string{
			"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles",
		},
	}
}

func (r *ClusterAdminBindingRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	for _, binding := range evalCtx.ClusterData.ClusterRoleBindings {
		if binding.RoleRef.Name == "cluster-admin" {
			for _, subject := range binding.Subjects {
				// Lower severity for system subjects
				severity := meta.Severity
				if strings.HasPrefix(subject.Name, "system:") {
					continue // Skip system accounts
				}

				findings = append(findings, audit.Finding{
					ID:          meta.ID,
					Name:        meta.Name,
					Description: meta.Description,
					Severity:    severity,
					Category:    meta.Category,
					Resource: audit.ResourceRef{
						Kind: "ClusterRoleBinding",
						Name: binding.Name,
					},
					Evidence: map[string]string{
						"binding":      binding.Name,
						"role":         binding.RoleRef.Name,
						"subjectKind":  subject.Kind,
						"subjectName":  subject.Name,
						"namespace":    subject.Namespace,
					},
					Impact: fmt.Sprintf("%s '%s' has cluster-admin privileges, granting full control over all cluster resources. "+
						"Compromise of this principal equals complete cluster compromise.",
						subject.Kind, subject.Name),
					ExploitPath: "1. Attacker compromises principal with cluster-admin\n" +
						"2. Full read/write access to all namespaces and resources\n" +
						"3. Can create privileged pods, access all secrets\n" +
						"4. Complete cluster takeover",
					Remediation: fmt.Sprintf("Remove cluster-admin binding for %s '%s' and grant least-privilege permissions. "+
						"Create a custom Role/ClusterRole with only required permissions.",
						subject.Kind, subject.Name),
					RemediationYAML: generateClusterAdminFix(binding, subject),
					Verification: fmt.Sprintf("kubectl get clusterrolebinding %s -o yaml",
						binding.Name),
					References: meta.References,
					CanAutoFix: false, // Requires understanding of actual permissions needed
					IsRisky:    false,
				})
			}
		}
	}

	return findings
}

// WildcardPermissionsRule checks for wildcard RBAC rules
type WildcardPermissionsRule struct{}

func (r *WildcardPermissionsRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "RBAC-002",
		Name:        "Wildcard RBAC Permissions",
		Description: "Role or ClusterRole uses wildcard (*) permissions",
		Category:    audit.CategoryRBAC,
		Severity:    audit.SeverityHigh,
		References: []string{
			"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#role-and-clusterrole",
		},
	}
}

func (r *WildcardPermissionsRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	// Check ClusterRoles
	for _, role := range evalCtx.ClusterData.ClusterRoles {
		// Skip system roles
		if strings.HasPrefix(role.Name, "system:") {
			continue
		}

		for _, rule := range role.Rules {
			if hasWildcard(rule) {
				findings = append(findings, audit.Finding{
					ID:          meta.ID,
					Name:        meta.Name,
					Description: meta.Description,
					Severity:    meta.Severity,
					Category:    meta.Category,
					Resource: audit.ResourceRef{
						Kind: "ClusterRole",
						Name: role.Name,
					},
					Evidence: map[string]string{
						"resources": strings.Join(rule.Resources, ", "),
						"verbs":     strings.Join(rule.Verbs, ", "),
						"apiGroups": strings.Join(rule.APIGroups, ", "),
					},
					Impact: "Wildcard permissions grant overly broad access, violating the principle of least privilege. " +
						"This increases the blast radius of a compromise.",
					ExploitPath: "1. Attacker compromises principal with wildcard permissions\n" +
						"2. Access to unintended resources and operations\n" +
						"3. Lateral movement or privilege escalation\n" +
						"4. Broader cluster compromise",
					Remediation: fmt.Sprintf("Replace wildcard (*) in ClusterRole '%s' with specific resources, verbs, and apiGroups. "+
						"Grant only the minimum required permissions.",
						role.Name),
					RemediationYAML: generateWildcardFix(role.Name, rule),
					Verification: fmt.Sprintf("kubectl get clusterrole %s -o yaml",
						role.Name),
					References: meta.References,
					CanAutoFix: false,
					IsRisky:    false,
				})
			}
		}
	}

	// Check Roles
	for _, role := range evalCtx.ClusterData.Roles {
		if strings.HasPrefix(role.Name, "system:") {
			continue
		}

		for _, rule := range role.Rules {
			if hasWildcard(rule) {
				findings = append(findings, audit.Finding{
					ID:          meta.ID,
					Name:        meta.Name,
					Description: meta.Description,
					Severity:    audit.SeverityMedium, // Namespace-scoped is less severe
					Category:    meta.Category,
					Resource: audit.ResourceRef{
						Kind:      "Role",
						Namespace: role.Namespace,
						Name:      role.Name,
					},
					Evidence: map[string]string{
						"resources": strings.Join(rule.Resources, ", "),
						"verbs":     strings.Join(rule.Verbs, ", "),
						"apiGroups": strings.Join(rule.APIGroups, ", "),
					},
					Impact: "Wildcard permissions grant overly broad access within the namespace.",
					ExploitPath: "1. Attacker compromises principal with wildcard permissions\n" +
						"2. Access to unintended resources within namespace\n" +
						"3. Potential for lateral movement within namespace",
					Remediation: fmt.Sprintf("Replace wildcard (*) in Role '%s/%s' with specific permissions.",
						role.Namespace, role.Name),
					RemediationYAML: generateWildcardFix(role.Name, rule),
					Verification: fmt.Sprintf("kubectl get role %s -n %s -o yaml",
						role.Name, role.Namespace),
					References: meta.References,
					CanAutoFix: false,
					IsRisky:    false,
				})
			}
		}
	}

	return findings
}

// SecretsAccessRule checks for broad secrets access
type SecretsAccessRule struct{}

func (r *SecretsAccessRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "RBAC-003",
		Name:        "Broad Secrets Access",
		Description: "Role grants list or get access to secrets",
		Category:    audit.CategoryRBAC,
		Severity:    audit.SeverityHigh,
		References: []string{
			"https://kubernetes.io/docs/concepts/configuration/secret/",
		},
	}
}

func (r *SecretsAccessRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	// Check ClusterRoles
	for _, role := range evalCtx.ClusterData.ClusterRoles {
		if strings.HasPrefix(role.Name, "system:") {
			continue
		}

		for _, rule := range role.Rules {
			if containsResource(rule, "secrets") &&
			   (containsVerb(rule, "get") || containsVerb(rule, "list") || containsVerb(rule, "*")) {

				findings = append(findings, audit.Finding{
					ID:          meta.ID,
					Name:        meta.Name,
					Description: meta.Description,
					Severity:    audit.SeverityCritical, // Cluster-wide secrets access is critical
					Category:    meta.Category,
					Resource: audit.ResourceRef{
						Kind: "ClusterRole",
						Name: role.Name,
					},
					Evidence: map[string]string{
						"resources": strings.Join(rule.Resources, ", "),
						"verbs":     strings.Join(rule.Verbs, ", "),
					},
					Impact: "Cluster-wide secrets access allows reading all secrets in all namespaces, " +
						"including service account tokens, credentials, and sensitive data.",
					ExploitPath: "1. Attacker compromises principal with secrets access\n" +
						"2. Lists and retrieves all secrets cluster-wide\n" +
						"3. Obtains credentials for services, databases, APIs\n" +
						"4. Uses stolen credentials for further attacks",
					Remediation: fmt.Sprintf("Remove or restrict secrets access in ClusterRole '%s'. "+
						"Use namespace-scoped Roles and grant access to specific secrets only.",
						role.Name),
					RemediationYAML: generateSecretsAccessFix(role.Name),
					Verification: fmt.Sprintf("kubectl get clusterrole %s -o yaml",
						role.Name),
					References: meta.References,
					CanAutoFix: false,
					IsRisky:    false,
				})
			}
		}
	}

	// Check Roles (namespace-scoped)
	for _, role := range evalCtx.ClusterData.Roles {
		if strings.HasPrefix(role.Name, "system:") {
			continue
		}

		for _, rule := range role.Rules {
			if containsResource(rule, "secrets") &&
			   (containsVerb(rule, "get") || containsVerb(rule, "list") || containsVerb(rule, "*")) {

				findings = append(findings, audit.Finding{
					ID:          meta.ID,
					Name:        meta.Name,
					Description: meta.Description,
					Severity:    audit.SeverityMedium, // Namespace-scoped is less severe
					Category:    meta.Category,
					Resource: audit.ResourceRef{
						Kind:      "Role",
						Namespace: role.Namespace,
						Name:      role.Name,
					},
					Evidence: map[string]string{
						"resources": strings.Join(rule.Resources, ", "),
						"verbs":     strings.Join(rule.Verbs, ", "),
						"namespace": role.Namespace,
					},
					Impact: fmt.Sprintf("Broad secrets access in namespace '%s' allows reading all secrets in the namespace.",
						role.Namespace),
					ExploitPath: "1. Attacker compromises principal\n" +
						"2. Retrieves secrets in namespace\n" +
						"3. Uses credentials for lateral movement",
					Remediation: fmt.Sprintf("Restrict secrets access in Role '%s/%s' to specific secret names using resourceNames.",
						role.Namespace, role.Name),
					RemediationYAML: generateSecretsAccessFix(role.Name),
					Verification: fmt.Sprintf("kubectl get role %s -n %s -o yaml",
						role.Name, role.Namespace),
					References: meta.References,
					CanAutoFix: false,
					IsRisky:    false,
				})
			}
		}
	}

	return findings
}

// EscalationPermissionsRule checks for privilege escalation permissions
type EscalationPermissionsRule struct{}

func (r *EscalationPermissionsRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "RBAC-004",
		Name:        "Privilege Escalation Permissions",
		Description: "Role has permissions that allow privilege escalation",
		Category:    audit.CategoryRBAC,
		Severity:    audit.SeverityCritical,
		References: []string{
			"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping",
		},
	}
}

func (r *EscalationPermissionsRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	escalationVerbs := map[string]string{
		"escalate":    "can escalate own privileges",
		"bind":        "can bind roles they don't have",
		"impersonate": "can impersonate other users/groups",
	}

	// Check ClusterRoles
	for _, role := range evalCtx.ClusterData.ClusterRoles {
		if strings.HasPrefix(role.Name, "system:") {
			continue
		}

		for _, rule := range role.Rules {
			for verb, description := range escalationVerbs {
				if containsVerb(rule, verb) || containsVerb(rule, "*") {
					findings = append(findings, audit.Finding{
						ID:          meta.ID,
						Name:        fmt.Sprintf("Escalation Permission: %s", verb),
						Description: meta.Description,
						Severity:    meta.Severity,
						Category:    meta.Category,
						Resource: audit.ResourceRef{
							Kind: "ClusterRole",
							Name: role.Name,
						},
						Evidence: map[string]string{
							"verb":        verb,
							"description": description,
							"resources":   strings.Join(rule.Resources, ", "),
						},
						Impact: fmt.Sprintf("The '%s' verb %s, bypassing RBAC restrictions. "+
							"This is a direct path to privilege escalation.",
							verb, description),
						ExploitPath: fmt.Sprintf("1. Attacker compromises principal with '%s' permission\n"+
							"2. Uses permission to escalate privileges\n"+
							"3. Gains unauthorized access to resources\n"+
							"4. Full cluster compromise", verb),
						Remediation: fmt.Sprintf("Remove '%s' permission from ClusterRole '%s'. "+
							"This permission is rarely needed and extremely dangerous.",
							verb, role.Name),
						RemediationYAML: generateEscalationFix(role.Name, verb),
						Verification: fmt.Sprintf("kubectl get clusterrole %s -o yaml",
							role.Name),
						References: meta.References,
						CanAutoFix: false,
						IsRisky:    false,
					})
				}
			}
		}
	}

	return findings
}

// DefaultServiceAccountRule checks for default service account usage
type DefaultServiceAccountRule struct{}

func (r *DefaultServiceAccountRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "RBAC-005",
		Name:        "Using Default Service Account",
		Description: "Pod is using the default service account",
		Category:    audit.CategoryRBAC,
		Severity:    audit.SeverityLow,
		References: []string{
			"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/",
		},
	}
}

func (r *DefaultServiceAccountRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	for _, pod := range evalCtx.ClusterData.Pods {
		if pod.Spec.ServiceAccountName == "" || pod.Spec.ServiceAccountName == "default" {
			findings = append(findings, audit.Finding{
				ID:          meta.ID,
				Name:        meta.Name,
				Description: meta.Description,
				Severity:    meta.Severity,
				Category:    meta.Category,
				Resource: audit.ResourceRef{
					Kind:      "Pod",
					Namespace: pod.Namespace,
					Name:      pod.Name,
				},
				Evidence: map[string]string{
					"serviceAccount": "default or empty",
				},
				Impact: "Using default service account may grant unintended permissions. " +
					"Each workload should use a dedicated service account with least-privilege RBAC.",
				ExploitPath: "1. Attacker compromises pod\n" +
					"2. Uses default service account token\n" +
					"3. Accesses resources based on default SA permissions\n" +
					"4. Potential lateral movement if default SA has permissions",
				Remediation: fmt.Sprintf("Create a dedicated ServiceAccount for pod '%s/%s' and assign it minimal required RBAC permissions.",
					pod.Namespace, pod.Name),
				RemediationYAML: generateServiceAccountFix(pod),
				Verification: fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.serviceAccountName}'",
					pod.Name, pod.Namespace),
				References: meta.References,
				CanAutoFix: false,
				IsRisky:    false,
			})
		}
	}

	return findings
}

// NodeProxyPermissionsRule checks for node proxy permissions
type NodeProxyPermissionsRule struct{}

func (r *NodeProxyPermissionsRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "RBAC-006",
		Name:        "Node Proxy Permissions",
		Description: "Role has permissions to proxy to nodes",
		Category:    audit.CategoryRBAC,
		Severity:    audit.SeverityHigh,
		References: []string{
			"https://kubernetes.io/docs/reference/access-authn-authz/authorization/",
		},
	}
}

func (r *NodeProxyPermissionsRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	for _, role := range evalCtx.ClusterData.ClusterRoles {
		if strings.HasPrefix(role.Name, "system:") {
			continue
		}

		for _, rule := range role.Rules {
			if (containsResource(rule, "nodes/proxy") || containsResource(rule, "nodes")) &&
			   containsVerb(rule, "get") {

				findings = append(findings, audit.Finding{
					ID:          meta.ID,
					Name:        meta.Name,
					Description: meta.Description,
					Severity:    meta.Severity,
					Category:    meta.Category,
					Resource: audit.ResourceRef{
						Kind: "ClusterRole",
						Name: role.Name,
					},
					Evidence: map[string]string{
						"resources": strings.Join(rule.Resources, ", "),
						"verbs":     strings.Join(rule.Verbs, ", "),
					},
					Impact: "Node proxy permissions allow direct access to kubelet APIs on nodes, " +
						"bypassing normal Kubernetes API security controls.",
					ExploitPath: "1. Attacker uses node proxy permission\n" +
						"2. Accesses kubelet API directly\n" +
						"3. Retrieves secrets, executes commands in containers\n" +
						"4. Potential node compromise",
					Remediation: fmt.Sprintf("Remove node proxy permissions from ClusterRole '%s' unless absolutely necessary.",
						role.Name),
					RemediationYAML: generateNodeProxyFix(role.Name),
					Verification: fmt.Sprintf("kubectl get clusterrole %s -o yaml",
						role.Name),
					References: meta.References,
					CanAutoFix: false,
					IsRisky:    false,
				})
			}
		}
	}

	return findings
}

// PodExecPermissionsRule checks for pod exec permissions
type PodExecPermissionsRule struct{}

func (r *PodExecPermissionsRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "RBAC-007",
		Name:        "Pod Exec Permissions",
		Description: "Role has permissions to exec into pods",
		Category:    audit.CategoryRBAC,
		Severity:    audit.SeverityMedium,
		References: []string{
			"https://kubernetes.io/docs/reference/access-authn-authz/authorization/",
		},
	}
}

func (r *PodExecPermissionsRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	for _, role := range evalCtx.ClusterData.ClusterRoles {
		if strings.HasPrefix(role.Name, "system:") {
			continue
		}

		for _, rule := range role.Rules {
			if containsResource(rule, "pods/exec") && containsVerb(rule, "create") {
				findings = append(findings, audit.Finding{
					ID:          meta.ID,
					Name:        meta.Name,
					Description: meta.Description,
					Severity:    meta.Severity,
					Category:    meta.Category,
					Resource: audit.ResourceRef{
						Kind: "ClusterRole",
						Name: role.Name,
					},
					Evidence: map[string]string{
						"resources": strings.Join(rule.Resources, ", "),
						"verbs":     strings.Join(rule.Verbs, ", "),
					},
					Impact: "Pod exec permissions allow executing arbitrary commands in containers, " +
						"potentially accessing secrets, data, or escalating privileges.",
					ExploitPath: "1. Attacker uses exec permission\n" +
						"2. Executes commands in target pods\n" +
						"3. Accesses secrets, environment variables, mounted volumes\n" +
						"4. Uses compromised pod as pivot point",
					Remediation: fmt.Sprintf("Restrict pod exec permissions in ClusterRole '%s' to specific namespaces or service accounts that require it.",
						role.Name),
					RemediationYAML: generatePodExecFix(role.Name),
					Verification: fmt.Sprintf("kubectl get clusterrole %s -o yaml",
						role.Name),
					References: meta.References,
					CanAutoFix: false,
					IsRisky:    false,
				})
			}
		}
	}

	return findings
}

// Helper functions

func hasWildcard(rule rbacv1.PolicyRule) bool {
	for _, verb := range rule.Verbs {
		if verb == "*" {
			return true
		}
	}
	for _, resource := range rule.Resources {
		if resource == "*" {
			return true
		}
	}
	for _, apiGroup := range rule.APIGroups {
		if apiGroup == "*" {
			return true
		}
	}
	return false
}

func containsResource(rule rbacv1.PolicyRule, resource string) bool {
	for _, r := range rule.Resources {
		if r == resource || r == "*" {
			return true
		}
	}
	return false
}

func containsVerb(rule rbacv1.PolicyRule, verb string) bool {
	for _, v := range rule.Verbs {
		if v == verb || v == "*" {
			return true
		}
	}
	return false
}

// Remediation generators

func generateClusterAdminFix(binding rbacv1.ClusterRoleBinding, subject rbacv1.Subject) string {
	return fmt.Sprintf(`# Remove cluster-admin binding and create least-privilege alternative
# 1. Delete existing binding:
# kubectl delete clusterrolebinding %s

# 2. Create custom role with minimal permissions:
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: %s-custom
rules:
# Add only required permissions here
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: %s-custom
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: %s-custom
subjects:
- kind: %s
  name: %s
  namespace: %s`, binding.Name, subject.Name, subject.Name, subject.Name, subject.Kind, subject.Name, subject.Namespace)
}

func generateWildcardFix(roleName string, rule rbacv1.PolicyRule) string {
	return fmt.Sprintf(`# Replace wildcards with specific values
rules:
- apiGroups: [""]  # Replace "*" with specific API groups
  resources: ["pods", "services"]  # Replace "*" with specific resources
  verbs: ["get", "list"]  # Replace "*" with specific verbs`)
}

func generateSecretsAccessFix(roleName string) string {
	return `# Restrict secrets access to specific secrets
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["specific-secret-name"]  # Limit to specific secrets
  verbs: ["get"]  # Remove "list" if not needed`
}

func generateEscalationFix(roleName, verb string) string {
	return fmt.Sprintf(`# Remove dangerous '%s' permission
# This permission should be removed entirely unless there is a very specific reason`, verb)
}

func generateServiceAccountFix(pod corev1.Pod) string {
	return fmt.Sprintf(`# Create dedicated service account
apiVersion: v1
kind: ServiceAccount
metadata:
  name: %s-sa
  namespace: %s
---
# Update pod to use dedicated SA
spec:
  serviceAccountName: %s-sa`, pod.Name, pod.Namespace, pod.Name)
}

func generateNodeProxyFix(roleName string) string {
	return `# Remove node proxy permissions
# Remove rules containing 'nodes/proxy' resource`
}

func generatePodExecFix(roleName string) string {
	return `# Restrict exec permissions
# Use namespace-scoped Roles instead of ClusterRole
# Or add resourceNames to limit to specific pods`
}
