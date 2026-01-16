package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/hassansallam/k8s-security-auditor/pkg/audit"
)

// GetSupplyChainRules returns all supply chain security rules
func GetSupplyChainRules() []Rule {
	return []Rule{
		&ImageTagRule{},
		&ImageRegistryRule{},
		&ImagePullPolicyRule{},
	}
}

// ImageTagRule checks for latest or mutable image tags
type ImageTagRule struct{}

func (r *ImageTagRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "SC-001",
		Name:        "Mutable Image Tag",
		Description: "Container is using 'latest' or mutable image tag",
		Category:    audit.CategorySupplyChain,
		Severity:    audit.SeverityMedium,
		References: []string{
			"https://kubernetes.io/docs/concepts/containers/images/",
		},
	}
}

func (r *ImageTagRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	for _, pod := range evalCtx.ClusterData.Pods {
		for _, container := range getAllContainers(pod) {
			image := container.Image

			// Check for :latest or no tag
			isMutable := false
			reason := ""

			if strings.HasSuffix(image, ":latest") {
				isMutable = true
				reason = "uses :latest tag"
			} else if !strings.Contains(image, ":") {
				isMutable = true
				reason = "no tag specified (defaults to :latest)"
			} else if !strings.Contains(image, "@sha256:") {
				// Tag is present but not a digest
				parts := strings.Split(image, ":")
				tag := parts[len(parts)-1]
				// Check if tag looks like a version (contains numbers)
				if !strings.ContainsAny(tag, "0123456789") {
					isMutable = true
					reason = "non-versioned tag '" + tag + "'"
				}
			}

			if isMutable {
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
						"container": container.Name,
						"image":     image,
						"reason":    reason,
					},
					Impact: "Mutable image tags can be overwritten, leading to inconsistent deployments or supply chain attacks. " +
						"An attacker who compromises the registry can push malicious images with the same tag.",
					ExploitPath: "1. Attacker compromises container registry or CI/CD\n" +
						"2. Pushes malicious image with same tag (e.g., myapp:latest)\n" +
						"3. Kubernetes pulls 'updated' image on pod restart\n" +
						"4. Malicious code executes in the cluster",
					Remediation: fmt.Sprintf("Use immutable image digest (sha256) or semantic version tags for container '%s' in pod '%s/%s'.",
						container.Name, pod.Namespace, pod.Name),
					RemediationYAML: generateImageTagFix(pod, container.Name, image),
					Verification: fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.containers[?(@.name==\"%s\")].image}'",
						pod.Name, pod.Namespace, container.Name),
					References: meta.References,
					CanAutoFix: false, // Requires knowing the correct image digest/version
					IsRisky:    false,
				})
			}
		}
	}

	return findings
}

// ImageRegistryRule checks for untrusted image registries
type ImageRegistryRule struct{}

func (r *ImageRegistryRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "SC-002",
		Name:        "Untrusted Image Registry",
		Description: "Container image is from an untrusted or public registry",
		Category:    audit.CategorySupplyChain,
		Severity:    audit.SeverityMedium,
		References: []string{
			"https://kubernetes.io/docs/concepts/containers/images/#using-a-private-registry",
		},
	}
}

func (r *ImageRegistryRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	// Public/untrusted registries to flag
	untrustedRegistries := []string{
		"docker.io",
		"index.docker.io",
	}

	for _, pod := range evalCtx.ClusterData.Pods {
		for _, container := range getAllContainers(pod) {
			image := container.Image

			// If image has no registry prefix, it's from Docker Hub
			isUntrusted := !strings.Contains(image, "/") || strings.HasPrefix(image, "library/")

			if !isUntrusted {
				for _, registry := range untrustedRegistries {
					if strings.HasPrefix(image, registry+"/") {
						isUntrusted = true
						break
					}
				}
			}

			if isUntrusted {
				findings = append(findings, audit.Finding{
					ID:          meta.ID,
					Name:        meta.Name,
					Description: meta.Description,
					Severity:    audit.SeverityLow, // Lower severity for public images (common in practice)
					Category:    meta.Category,
					Resource: audit.ResourceRef{
						Kind:      "Pod",
						Namespace: pod.Namespace,
						Name:      pod.Name,
					},
					Evidence: map[string]string{
						"container": container.Name,
						"image":     image,
						"issue":     "using public registry (Docker Hub or no registry specified)",
					},
					Impact: "Public registries have less control over image provenance. " +
						"Consider using a private registry or verified public registries with image scanning.",
					ExploitPath: "1. Attacker publishes malicious image to public registry\n" +
						"2. Image uses similar name to legitimate image (typosquatting)\n" +
						"3. Misconfiguration pulls malicious image\n" +
						"4. Compromised workload runs in cluster",
					Remediation: fmt.Sprintf("Consider using a trusted private registry for container '%s' in pod '%s/%s'. "+
						"If using public images, verify provenance and scan for vulnerabilities.",
						container.Name, pod.Namespace, pod.Name),
					RemediationYAML: generateRegistryFix(pod, container.Name, image),
					Verification: fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.containers[?(@.name==\"%s\")].image}'",
						pod.Name, pod.Namespace, container.Name),
					References: meta.References,
					CanAutoFix: false,
					IsRisky:    false,
				})
			}
		}
	}

	return findings
}

// ImagePullPolicyRule checks for improper image pull policies
type ImagePullPolicyRule struct{}

func (r *ImagePullPolicyRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "SC-003",
		Name:        "Weak Image Pull Policy",
		Description: "Container uses IfNotPresent pull policy with mutable tag",
		Category:    audit.CategorySupplyChain,
		Severity:    audit.SeverityLow,
		References: []string{
			"https://kubernetes.io/docs/concepts/containers/images/#image-pull-policy",
		},
	}
}

func (r *ImagePullPolicyRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	for _, pod := range evalCtx.ClusterData.Pods {
		for _, container := range getAllContainers(pod) {
			image := container.Image
			pullPolicy := container.ImagePullPolicy

			// Check if using mutable tag with IfNotPresent
			isMutable := strings.HasSuffix(image, ":latest") ||
				!strings.Contains(image, ":") ||
				!strings.Contains(image, "@sha256:")

			if isMutable && (pullPolicy == "IfNotPresent" || pullPolicy == "Never") {
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
						"container":       container.Name,
						"image":           image,
						"imagePullPolicy": string(pullPolicy),
					},
					Impact: "Using IfNotPresent/Never with mutable tags means updated images won't be pulled, " +
						"leading to inconsistency across nodes and difficulty deploying security updates.",
					ExploitPath: "1. Security vulnerability discovered in image\n" +
						"2. Updated image pushed with same tag\n" +
						"3. IfNotPresent policy prevents pulling updated image\n" +
						"4. Vulnerable workloads continue running",
					Remediation: fmt.Sprintf("Either use immutable image digests with IfNotPresent, or use Always pull policy with version tags for container '%s' in pod '%s/%s'.",
						container.Name, pod.Namespace, pod.Name),
					RemediationYAML: generatePullPolicyFix(pod, container.Name),
					Verification: fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.containers[?(@.name==\"%s\")].imagePullPolicy}'",
						pod.Name, pod.Namespace, container.Name),
					References: meta.References,
					CanAutoFix: false,
					IsRisky:    false,
				})
			}
		}
	}

	return findings
}

// Remediation generators

func generateImageTagFix(pod corev1.Pod, containerName, currentImage string) string {
	return fmt.Sprintf(`# Use immutable image digest or semantic version
spec:
  containers:
  - name: %s
    # Option 1: Use digest (recommended)
    image: %s@sha256:<full-digest>
    # Option 2: Use semantic version tag
    # image: %s:v1.2.3`, containerName, strings.Split(currentImage, ":")[0], strings.Split(currentImage, ":")[0])
}

func generateRegistryFix(pod corev1.Pod, containerName, currentImage string) string {
	return fmt.Sprintf(`# Use trusted private registry
spec:
  containers:
  - name: %s
    image: myregistry.example.com/%s
  imagePullSecrets:
  - name: registry-credentials`, containerName, currentImage)
}

func generatePullPolicyFix(pod corev1.Pod, containerName string) string {
	return fmt.Sprintf(`# Update pull policy
spec:
  containers:
  - name: %s
    imagePullPolicy: Always  # Or use immutable digest with IfNotPresent`, containerName)
}
