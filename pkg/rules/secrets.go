package rules

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/vibecoding/k8s-security-auditor/pkg/audit"
)

// GetSecretsRules returns all secrets security rules
func GetSecretsRules() []Rule {
	return []Rule{
		&UnencryptedSecretsRule{},
		&SecretInEnvRule{},
		&ServiceAccountTokenRule{},
	}
}

// UnencryptedSecretsRule checks for encryption at rest configuration
type UnencryptedSecretsRule struct{}

func (r *UnencryptedSecretsRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "SEC-001",
		Name:        "Secrets Encryption At Rest",
		Description: "Verify secrets encryption at rest is configured",
		Category:    audit.CategorySecrets,
		Severity:    audit.SeverityHigh,
		References: []string{
			"https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/",
		},
	}
}

func (r *UnencryptedSecretsRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	// This check requires access to API server configuration
	// For now, we provide a manual verification finding
	if len(evalCtx.ClusterData.Secrets) > 0 {
		return []audit.Finding{
			{
				ID:          r.Metadata().ID,
				Name:        r.Metadata().Name,
				Description: r.Metadata().Description,
				Severity:    r.Metadata().Severity,
				Category:    r.Metadata().Category,
				Resource: audit.ResourceRef{
					Kind: "Cluster",
					Name: "encryption-config",
				},
				Evidence: map[string]string{
					"note":          "Manual verification required",
					"secrets_count": fmt.Sprintf("%d", len(evalCtx.ClusterData.Secrets)),
				},
				Impact: "Without encryption at rest, secrets stored in etcd are in base64 encoding (not encrypted). " +
					"An attacker with etcd access or etcd backups can read all secrets in plaintext.",
				ExploitPath: "1. Attacker gains access to etcd (database dumps, backups, or direct access)\n" +
					"2. Extracts secret objects from etcd\n" +
					"3. Base64 decodes secret values\n" +
					"4. Obtains credentials, tokens, and sensitive data",
				Remediation: "Configure encryption at rest using EncryptionConfiguration. " +
					"Use a KMS provider (AWS KMS, Azure Key Vault, GCP KMS) or aescbc/secretbox encryption.",
				RemediationYAML: `# Create EncryptionConfiguration
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-32-byte-key>
      - identity: {}

# Update API server flags:
# --encryption-provider-config=/path/to/encryption-config.yaml`,
				Verification: "Check API server configuration for --encryption-provider-config flag. " +
					"Run: kubectl get secret -n kube-system -o yaml | grep -c 'k8s:enc:aescbc' to verify encrypted secrets.",
				References:  r.Metadata().References,
				CanAutoFix:  false, // Requires API server reconfiguration
				IsRisky:     false,
			},
		}
	}
	return nil
}

// SecretInEnvRule checks for secrets exposed as environment variables
type SecretInEnvRule struct{}

func (r *SecretInEnvRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "SEC-002",
		Name:        "Secret Exposed in Environment Variable",
		Description: "Secret is exposed as environment variable instead of volume mount",
		Category:    audit.CategorySecrets,
		Severity:    audit.SeverityMedium,
		References: []string{
			"https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-files-from-a-pod",
		},
	}
}

func (r *SecretInEnvRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	for _, pod := range evalCtx.ClusterData.Pods {
		for _, container := range getAllContainers(pod) {
			for _, env := range container.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
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
							"container":  container.Name,
							"envVar":     env.Name,
							"secretName": env.ValueFrom.SecretKeyRef.Name,
							"secretKey":  env.ValueFrom.SecretKeyRef.Key,
						},
						Impact: "Secrets in environment variables are visible in pod specs, logs, and crash dumps. " +
							"They may be accidentally leaked via logging or error messages.",
						ExploitPath: "1. Attacker gains access to pod spec or logs\n" +
							"2. Retrieves environment variables\n" +
							"3. Extracts secret values\n" +
							"4. Uses credentials for unauthorized access",
						Remediation: fmt.Sprintf("Mount secret '%s' as a volume instead of environment variable in pod '%s/%s'.",
							env.ValueFrom.SecretKeyRef.Name, pod.Namespace, pod.Name),
						RemediationYAML: generateSecretVolumeFix(pod, container.Name, env.ValueFrom.SecretKeyRef.Name),
						Verification: fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.containers[?(@.name==\"%s\")].env}'",
							pod.Name, pod.Namespace, container.Name),
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

// ServiceAccountTokenRule checks for automatic token mounting
type ServiceAccountTokenRule struct{}

func (r *ServiceAccountTokenRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "SEC-003",
		Name:        "Automatic Service Account Token Mounting",
		Description: "Service account token is automatically mounted but may not be needed",
		Category:    audit.CategorySecrets,
		Severity:    audit.SeverityLow,
		References: []string{
			"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server",
		},
	}
}

func (r *ServiceAccountTokenRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	for _, pod := range evalCtx.ClusterData.Pods {
		autoMount := true // Default is true

		if pod.Spec.AutomountServiceAccountToken != nil {
			autoMount = *pod.Spec.AutomountServiceAccountToken
		}

		if autoMount {
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
					"automountServiceAccountToken": "true or not set",
					"serviceAccount":                pod.Spec.ServiceAccountName,
				},
				Impact: "Automatically mounted service account tokens are available to all processes in the pod. " +
					"If the pod doesn't need Kubernetes API access, this increases attack surface.",
				ExploitPath: "1. Attacker compromises pod\n" +
					"2. Reads service account token from /var/run/secrets/kubernetes.io/serviceaccount/token\n" +
					"3. Uses token to authenticate to Kubernetes API\n" +
					"4. Performs actions based on service account permissions",
				Remediation: fmt.Sprintf("Set automountServiceAccountToken: false for pod '%s/%s' if it doesn't need API access.",
					pod.Namespace, pod.Name),
				RemediationYAML: generateAutoMountFix(pod),
				Verification: fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.automountServiceAccountToken}'",
					pod.Name, pod.Namespace),
				References: meta.References,
				CanAutoFix: false, // Requires knowing if pod needs API access
				IsRisky:    false,
			})
		}
	}

	return findings
}

// Remediation generators

func generateSecretVolumeFix(pod corev1.Pod, containerName, secretName string) string {
	return fmt.Sprintf(`# Mount secret as volume instead of env var
spec:
  containers:
  - name: %s
    # Remove env with secretKeyRef
    volumeMounts:
    - name: %s-volume
      mountPath: /etc/secrets/%s
      readOnly: true
  volumes:
  - name: %s-volume
    secret:
      secretName: %s`, containerName, secretName, secretName, secretName, secretName)
}

func generateAutoMountFix(pod corev1.Pod) string {
	return `# Disable automatic token mounting if not needed
spec:
  automountServiceAccountToken: false`
}
