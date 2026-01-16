package rules

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/hassansallam/Kubernetes-Security-Auditor/pkg/audit"
)

// GetWorkloadRules returns all workload security rules
func GetWorkloadRules() []Rule {
	return []Rule{
		&PrivilegedPodRule{},
		&HostNamespaceRule{},
		&HostPathRule{},
		&RootUserRule{},
		&ReadOnlyRootFilesystemRule{},
		&CapabilitiesRule{},
		&PrivilegeEscalationRule{},
		&ResourceLimitsRule{},
		&SeccompProfileRule{},
		&AppArmorProfileRule{},
	}
}

// PrivilegedPodRule checks for privileged containers
type PrivilegedPodRule struct{}

func (r *PrivilegedPodRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "WL-001",
		Name:        "Privileged Container Detected",
		Description: "Containers running in privileged mode have full access to host resources",
		Category:    audit.CategoryWorkload,
		Severity:    audit.SeverityCritical,
		References: []string{
			"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
		},
	}
}

func (r *PrivilegedPodRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	for _, pod := range evalCtx.ClusterData.Pods {
		for _, container := range getAllContainers(pod) {
			if container.SecurityContext != nil &&
			   container.SecurityContext.Privileged != nil &&
			   *container.SecurityContext.Privileged {

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
						"privileged": "true",
						"field":      ".spec.containers[].securityContext.privileged",
					},
					Impact: "Privileged containers can access all host devices, bypass SELinux/AppArmor, " +
						"and have unrestricted access to host resources. This effectively grants root access to the host.",
					ExploitPath: "1. Attacker gains access to privileged container\n" +
						"2. Mount host filesystem via /dev\n" +
						"3. Escape container and gain root on host\n" +
						"4. Pivot to other nodes or access cluster secrets",
					Remediation: fmt.Sprintf("Remove privileged flag from container '%s' in pod '%s/%s'",
						container.Name, pod.Namespace, pod.Name),
					RemediationYAML: generatePrivilegedFix(pod, container.Name),
					Verification: fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.containers[?(@.name==\"%s\")].securityContext.privileged}'",
						pod.Name, pod.Namespace, container.Name),
					References: meta.References,
					CanAutoFix: false, // Requires understanding of workload requirements
					IsRisky:    false,
				})
			}
		}
	}

	return findings
}

// HostNamespaceRule checks for host namespace usage
type HostNamespaceRule struct{}

func (r *HostNamespaceRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "WL-002",
		Name:        "Host Namespace Usage Detected",
		Description: "Pod is using host network, PID, or IPC namespace",
		Category:    audit.CategoryWorkload,
		Severity:    audit.SeverityHigh,
		References: []string{
			"https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted",
		},
	}
}

func (r *HostNamespaceRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	for _, pod := range evalCtx.ClusterData.Pods {
		issues := []string{}
		evidence := make(map[string]string)

		if pod.Spec.HostNetwork {
			issues = append(issues, "hostNetwork")
			evidence["hostNetwork"] = "true"
		}
		if pod.Spec.HostPID {
			issues = append(issues, "hostPID")
			evidence["hostPID"] = "true"
		}
		if pod.Spec.HostIPC {
			issues = append(issues, "hostIPC")
			evidence["hostIPC"] = "true"
		}

		if len(issues) > 0 {
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
				Evidence: evidence,
				Impact: fmt.Sprintf("Pod is using host namespaces (%s). This allows the pod to see and potentially "+
					"interact with all processes and network interfaces on the host, breaking container isolation.",
					strings.Join(issues, ", ")),
				ExploitPath: "1. Attacker compromises pod with host namespace access\n" +
					"2. Access host processes/network/IPC directly\n" +
					"3. Sniff network traffic or inject into host processes\n" +
					"4. Escalate privileges on the host system",
				Remediation: fmt.Sprintf("Remove host namespace settings (%s) from pod '%s/%s'",
					strings.Join(issues, ", "), pod.Namespace, pod.Name),
				RemediationYAML: generateHostNamespaceFix(pod),
				Verification: fmt.Sprintf("kubectl get pod %s -n %s -o yaml | grep -E 'host(Network|PID|IPC)'",
					pod.Name, pod.Namespace),
				References: meta.References,
				CanAutoFix: false,
				IsRisky:    false,
			})
		}
	}

	return findings
}

// HostPathRule checks for hostPath volume usage
type HostPathRule struct{}

func (r *HostPathRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "WL-003",
		Name:        "HostPath Volume Detected",
		Description: "Pod is mounting a path from the host filesystem",
		Category:    audit.CategoryWorkload,
		Severity:    audit.SeverityHigh,
		References: []string{
			"https://kubernetes.io/docs/concepts/storage/volumes/#hostpath",
		},
	}
}

func (r *HostPathRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	for _, pod := range evalCtx.ClusterData.Pods {
		for _, volume := range pod.Spec.Volumes {
			if volume.HostPath != nil {
				severity := meta.Severity
				impact := "Mounting host paths allows direct access to host filesystem. "

				// Critical paths get elevated severity
				criticalPaths := []string{"/", "/etc", "/var/run/docker.sock", "/var/run/crio",
					"/proc", "/sys", "/dev", "/var/lib/kubelet"}
				for _, critPath := range criticalPaths {
					if strings.HasPrefix(volume.HostPath.Path, critPath) {
						severity = audit.SeverityCritical
						impact += fmt.Sprintf("Path '%s' is particularly sensitive and can lead to container escape.",
							volume.HostPath.Path)
						break
					}
				}

				findings = append(findings, audit.Finding{
					ID:          meta.ID,
					Name:        meta.Name,
					Description: meta.Description,
					Severity:    severity,
					Category:    meta.Category,
					Resource: audit.ResourceRef{
						Kind:      "Pod",
						Namespace: pod.Namespace,
						Name:      pod.Name,
					},
					Evidence: map[string]string{
						"volume":   volume.Name,
						"hostPath": volume.HostPath.Path,
						"type":     string(*volume.HostPath.Type),
					},
					Impact: impact,
					ExploitPath: "1. Attacker gains access to pod with hostPath mount\n" +
						"2. Read/write sensitive host files\n" +
						"3. Modify system configuration or binaries\n" +
						"4. Access secrets, SSH keys, or kubeconfig from host",
					Remediation: fmt.Sprintf("Replace hostPath volume '%s' (path: %s) with a Kubernetes-native volume type "+
						"(PersistentVolume, ConfigMap, Secret, or emptyDir) in pod '%s/%s'",
						volume.Name, volume.HostPath.Path, pod.Namespace, pod.Name),
					RemediationYAML: generateHostPathFix(pod, volume.Name),
					Verification: fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.volumes[?(@.name==\"%s\")].hostPath}'",
						pod.Name, pod.Namespace, volume.Name),
					References: meta.References,
					CanAutoFix: false,
					IsRisky:    false,
				})
			}
		}
	}

	return findings
}

// RootUserRule checks for containers running as root
type RootUserRule struct{}

func (r *RootUserRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "WL-004",
		Name:        "Container Running as Root",
		Description: "Container is running as root user (UID 0)",
		Category:    audit.CategoryWorkload,
		Severity:    audit.SeverityMedium,
		References: []string{
			"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
		},
	}
}

func (r *RootUserRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	for _, pod := range evalCtx.ClusterData.Pods {
		for _, container := range getAllContainers(pod) {
			runAsRoot := false

			// Check container-level setting
			if container.SecurityContext != nil {
				if container.SecurityContext.RunAsNonRoot != nil && !*container.SecurityContext.RunAsNonRoot {
					runAsRoot = true
				}
				if container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == 0 {
					runAsRoot = true
				}
			}

			// Check pod-level setting if not set at container level
			if container.SecurityContext == nil ||
			   (container.SecurityContext.RunAsUser == nil && container.SecurityContext.RunAsNonRoot == nil) {
				if pod.Spec.SecurityContext != nil {
					if pod.Spec.SecurityContext.RunAsUser != nil && *pod.Spec.SecurityContext.RunAsUser == 0 {
						runAsRoot = true
					}
					// If neither is set, we flag it as potentially running as root
					if pod.Spec.SecurityContext.RunAsUser == nil &&
					   pod.Spec.SecurityContext.RunAsNonRoot == nil {
						runAsRoot = true
					}
				} else {
					// No security context at all - default may be root
					runAsRoot = true
				}
			}

			if runAsRoot {
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
						"issue":     "runAsNonRoot not enforced or runAsUser is 0",
					},
					Impact: "Running as root increases the impact of a container compromise. If the container is " +
						"breached, the attacker has root privileges within the container, making privilege escalation easier.",
					ExploitPath: "1. Attacker exploits application vulnerability\n" +
						"2. Gains root access inside container\n" +
						"3. Attempts kernel exploits or container escape\n" +
						"4. If escaped, has privileged access to host",
					Remediation: fmt.Sprintf("Set runAsNonRoot: true and specify a non-zero runAsUser for container '%s' in pod '%s/%s'",
						container.Name, pod.Namespace, pod.Name),
					RemediationYAML: generateRunAsNonRootFix(pod, container.Name),
					Verification: fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.containers[?(@.name==\"%s\")].securityContext.runAsNonRoot}'",
						pod.Name, pod.Namespace, container.Name),
					References: meta.References,
					CanAutoFix: false, // Requires knowing appropriate UID
					IsRisky:    false,
				})
			}
		}
	}

	return findings
}

// ReadOnlyRootFilesystemRule checks for writable root filesystems
type ReadOnlyRootFilesystemRule struct{}

func (r *ReadOnlyRootFilesystemRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "WL-005",
		Name:        "Writable Root Filesystem",
		Description: "Container root filesystem is writable",
		Category:    audit.CategoryWorkload,
		Severity:    audit.SeverityLow,
		References: []string{
			"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-container",
		},
	}
}

func (r *ReadOnlyRootFilesystemRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	for _, pod := range evalCtx.ClusterData.Pods {
		for _, container := range getAllContainers(pod) {
			isReadOnly := false

			if container.SecurityContext != nil &&
			   container.SecurityContext.ReadOnlyRootFilesystem != nil {
				isReadOnly = *container.SecurityContext.ReadOnlyRootFilesystem
			}

			if !isReadOnly {
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
						"container":               container.Name,
						"readOnlyRootFilesystem": "false or not set",
					},
					Impact: "Writable root filesystem allows attackers to modify binaries, install tools, or " +
						"persist malware within the container. Read-only filesystem is a defense-in-depth measure.",
					ExploitPath: "1. Attacker compromises application\n" +
						"2. Downloads and installs malicious tools\n" +
						"3. Modifies system binaries for persistence\n" +
						"4. Uses tools for lateral movement or data exfiltration",
					Remediation: fmt.Sprintf("Set readOnlyRootFilesystem: true for container '%s' in pod '%s/%s'. "+
						"Use emptyDir or other volumes for directories that need write access.",
						container.Name, pod.Namespace, pod.Name),
					RemediationYAML: generateReadOnlyRootFix(pod, container.Name),
					Verification: fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.containers[?(@.name==\"%s\")].securityContext.readOnlyRootFilesystem}'",
						pod.Name, pod.Namespace, container.Name),
					References: meta.References,
					CanAutoFix: false, // May break applications needing write access
					IsRisky:    false,
				})
			}
		}
	}

	return findings
}

// CapabilitiesRule checks for excessive Linux capabilities
type CapabilitiesRule struct{}

func (r *CapabilitiesRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "WL-006",
		Name:        "Excessive Linux Capabilities",
		Description: "Container has dangerous Linux capabilities",
		Category:    audit.CategoryWorkload,
		Severity:    audit.SeverityHigh,
		References: []string{
			"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container",
		},
	}
}

func (r *CapabilitiesRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	dangerousCaps := map[string]string{
		"SYS_ADMIN":   "allows mount operations, potentially leading to container escape",
		"NET_ADMIN":   "allows network configuration changes and packet sniffing",
		"SYS_MODULE":  "allows loading kernel modules",
		"SYS_RAWIO":   "allows raw disk I/O operations",
		"SYS_PTRACE":  "allows process tracing and debugging across containers",
		"SYS_BOOT":    "allows system reboot",
		"MAC_ADMIN":   "allows MAC configuration changes (SELinux/AppArmor)",
		"DAC_OVERRIDE": "bypasses file permission checks",
		"DAC_READ_SEARCH": "bypasses file read permission checks",
	}

	for _, pod := range evalCtx.ClusterData.Pods {
		for _, container := range getAllContainers(pod) {
			if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
				addedCaps := container.SecurityContext.Capabilities.Add

				for _, cap := range addedCaps {
					capName := string(cap)
					if reason, isDangerous := dangerousCaps[capName]; isDangerous {
						severity := audit.SeverityHigh
						if capName == "SYS_ADMIN" || capName == "SYS_MODULE" {
							severity = audit.SeverityCritical
						}

						findings = append(findings, audit.Finding{
							ID:          meta.ID,
							Name:        fmt.Sprintf("Dangerous Capability: %s", capName),
							Description: meta.Description,
							Severity:    severity,
							Category:    meta.Category,
							Resource: audit.ResourceRef{
								Kind:      "Pod",
								Namespace: pod.Namespace,
								Name:      pod.Name,
							},
							Evidence: map[string]string{
								"container":  container.Name,
								"capability": capName,
								"reason":     reason,
							},
							Impact: fmt.Sprintf("Capability %s %s. This significantly increases attack surface.",
								capName, reason),
							ExploitPath: fmt.Sprintf("1. Attacker compromises container with %s capability\n"+
								"2. Exploits capability to escalate privileges\n"+
								"3. Escapes container or accesses host resources\n"+
								"4. Compromises other workloads or the node", capName),
							Remediation: fmt.Sprintf("Remove capability '%s' from container '%s' in pod '%s/%s'. "+
								"If required, use a more restrictive alternative or redesign the application.",
								capName, container.Name, pod.Namespace, pod.Name),
							RemediationYAML: generateCapabilitiesFix(pod, container.Name, capName),
							Verification: fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.containers[?(@.name==\"%s\")].securityContext.capabilities}'",
								pod.Name, pod.Namespace, container.Name),
							References: meta.References,
							CanAutoFix: false,
							IsRisky:    false,
						})
					}
				}
			}
		}
	}

	return findings
}

// PrivilegeEscalationRule checks for allowPrivilegeEscalation
type PrivilegeEscalationRule struct{}

func (r *PrivilegeEscalationRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "WL-007",
		Name:        "Privilege Escalation Allowed",
		Description: "Container allows privilege escalation",
		Category:    audit.CategoryWorkload,
		Severity:    audit.SeverityMedium,
		References: []string{
			"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
		},
	}
}

func (r *PrivilegeEscalationRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	for _, pod := range evalCtx.ClusterData.Pods {
		for _, container := range getAllContainers(pod) {
			allowEscalation := true // Default is true if not set

			if container.SecurityContext != nil &&
			   container.SecurityContext.AllowPrivilegeEscalation != nil {
				allowEscalation = *container.SecurityContext.AllowPrivilegeEscalation
			}

			if allowEscalation {
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
						"container":                  container.Name,
						"allowPrivilegeEscalation": "true or not set",
					},
					Impact: "Allowing privilege escalation permits processes to gain more privileges than their parent. " +
						"This can be exploited via setuid binaries or kernel vulnerabilities.",
					ExploitPath: "1. Attacker gains initial access to container\n" +
						"2. Discovers setuid binary or kernel vulnerability\n" +
						"3. Escalates privileges within container\n" +
						"4. Uses elevated privileges for further attacks",
					Remediation: fmt.Sprintf("Set allowPrivilegeEscalation: false for container '%s' in pod '%s/%s'",
						container.Name, pod.Namespace, pod.Name),
					RemediationYAML: generatePrivilegeEscalationFix(pod, container.Name),
					Verification: fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.containers[?(@.name==\"%s\")].securityContext.allowPrivilegeEscalation}'",
						pod.Name, pod.Namespace, container.Name),
					References: meta.References,
					CanAutoFix: true, // Generally safe to disable
					IsRisky:    false,
				})
			}
		}
	}

	return findings
}

// ResourceLimitsRule checks for missing resource limits
type ResourceLimitsRule struct{}

func (r *ResourceLimitsRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "WL-008",
		Name:        "Missing Resource Limits",
		Description: "Container has no CPU or memory limits defined",
		Category:    audit.CategoryWorkload,
		Severity:    audit.SeverityLow,
		References: []string{
			"https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
		},
	}
}

func (r *ResourceLimitsRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	for _, pod := range evalCtx.ClusterData.Pods {
		for _, container := range getAllContainers(pod) {
			hasLimits := container.Resources.Limits != nil &&
				(container.Resources.Limits.Memory().Value() > 0 ||
				 container.Resources.Limits.Cpu().Value() > 0)

			if !hasLimits {
				findings = append(findings, audit.Finding{
					ID:          meta.ID,
					Name:        meta.Name,
					Description: meta.Description,
					Severity:    meta.SeverityLow,
					Category:    audit.CategoryWorkload,
					Resource: audit.ResourceRef{
						Kind:      "Pod",
						Namespace: pod.Namespace,
						Name:      pod.Name,
					},
					Evidence: map[string]string{
						"container": container.Name,
						"issue":     "no resource limits defined",
					},
					Impact: "Without resource limits, a compromised or buggy container can consume all node resources, " +
						"causing denial of service to other workloads on the same node.",
					ExploitPath: "1. Attacker compromises container\n" +
						"2. Launches resource exhaustion attack (CPU/memory bomb)\n" +
						"3. Starves other containers on the node\n" +
						"4. Causes node instability or failure",
					Remediation: fmt.Sprintf("Define resource limits for container '%s' in pod '%s/%s'",
						container.Name, pod.Namespace, pod.Name),
					RemediationYAML: generateResourceLimitsFix(pod, container.Name),
					Verification: fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.containers[?(@.name==\"%s\")].resources.limits}'",
						pod.Name, pod.Namespace, container.Name),
					References: meta.References,
					CanAutoFix: false, // Requires knowledge of appropriate limits
					IsRisky:    false,
				})
			}
		}
	}

	return findings
}

// SeccompProfileRule checks for missing seccomp profiles
type SeccompProfileRule struct{}

func (r *SeccompProfileRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "WL-009",
		Name:        "Missing Seccomp Profile",
		Description: "Container is not using a seccomp profile",
		Category:    audit.CategoryWorkload,
		Severity:    audit.SeverityMedium,
		References: []string{
			"https://kubernetes.io/docs/tutorials/security/seccomp/",
		},
	}
}

func (r *SeccompProfileRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	for _, pod := range evalCtx.ClusterData.Pods {
		hasSeccomp := false

		// Check pod-level seccomp
		if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SeccompProfile != nil {
			hasSeccomp = true
		}

		for _, container := range getAllContainers(pod) {
			containerHasSeccomp := hasSeccomp

			// Check container-level seccomp (overrides pod-level)
			if container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil {
				containerHasSeccomp = true
			}

			if !containerHasSeccomp {
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
						"issue":     "no seccomp profile defined",
					},
					Impact: "Seccomp (Secure Computing Mode) restricts system calls available to containers. " +
						"Without it, containers can make any system call, increasing attack surface.",
					ExploitPath: "1. Attacker compromises container\n" +
						"2. Makes malicious system calls (e.g., process injection, kernel exploits)\n" +
						"3. Attempts container escape or privilege escalation\n" +
						"4. Gains access to host or other containers",
					Remediation: fmt.Sprintf("Add seccomp profile (RuntimeDefault or custom) for container '%s' in pod '%s/%s'",
						container.Name, pod.Namespace, pod.Name),
					RemediationYAML: generateSeccompFix(pod, container.Name),
					Verification: fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.securityContext.seccompProfile}'",
						pod.Name, pod.Namespace),
					References: meta.References,
					CanAutoFix: true, // RuntimeDefault is usually safe
					IsRisky:    false,
				})
			}
		}
	}

	return findings
}

// AppArmorProfileRule checks for missing AppArmor profiles
type AppArmorProfileRule struct{}

func (r *AppArmorProfileRule) Metadata() RuleMetadata {
	return RuleMetadata{
		ID:          "WL-010",
		Name:        "Missing AppArmor Profile",
		Description: "Container is not using an AppArmor profile",
		Category:    audit.CategoryWorkload,
		Severity:    audit.SeverityLow,
		References: []string{
			"https://kubernetes.io/docs/tutorials/security/apparmor/",
		},
	}
}

func (r *AppArmorProfileRule) Evaluate(ctx context.Context, evalCtx *EvaluationContext) []audit.Finding {
	var findings []audit.Finding
	meta := r.Metadata()

	for _, pod := range evalCtx.ClusterData.Pods {
		for _, container := range getAllContainers(pod) {
			hasAppArmor := false

			// Check for AppArmor annotation
			if pod.Annotations != nil {
				annotationKey := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container.Name)
				if profile, exists := pod.Annotations[annotationKey]; exists && profile != "unconfined" {
					hasAppArmor = true
				}
			}

			if !hasAppArmor {
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
						"issue":     "no AppArmor profile annotation",
					},
					Impact: "AppArmor provides mandatory access control to restrict program capabilities. " +
						"Without it, containers have fewer restrictions on file access and system operations.",
					ExploitPath: "1. Attacker compromises container\n" +
						"2. Accesses sensitive files that AppArmor would block\n" +
						"3. Performs unauthorized operations\n" +
						"4. Uses unrestricted access for lateral movement",
					Remediation: fmt.Sprintf("Add AppArmor profile annotation for container '%s' in pod '%s/%s'",
						container.Name, pod.Namespace, pod.Name),
					RemediationYAML: generateAppArmorFix(pod, container.Name),
					Verification: fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.metadata.annotations}'",
						pod.Name, pod.Namespace),
					References: meta.References,
					CanAutoFix: false, // Requires AppArmor to be available on nodes
					IsRisky:    false,
				})
			}
		}
	}

	return findings
}

// Helper functions

func getAllContainers(pod corev1.Pod) []corev1.Container {
	containers := append([]corev1.Container{}, pod.Spec.Containers...)
	containers = append(containers, pod.Spec.InitContainers...)
	containers = append(containers, pod.Spec.EphemeralContainers...)
	return containers
}

// Remediation YAML generators (simplified for now)

func generatePrivilegedFix(pod corev1.Pod, containerName string) string {
	return fmt.Sprintf(`# Remove privileged flag from container '%s'
spec:
  containers:
  - name: %s
    securityContext:
      privileged: false`, containerName, containerName)
}

func generateHostNamespaceFix(pod corev1.Pod) string {
	return `# Remove host namespace settings
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false`
}

func generateHostPathFix(pod corev1.Pod, volumeName string) string {
	return fmt.Sprintf(`# Replace hostPath volume with emptyDir or PersistentVolume
spec:
  volumes:
  - name: %s
    emptyDir: {}  # or use persistentVolumeClaim`, volumeName)
}

func generateRunAsNonRootFix(pod corev1.Pod, containerName string) string {
	return fmt.Sprintf(`# Run container as non-root user
spec:
  containers:
  - name: %s
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000  # Adjust UID as appropriate`, containerName)
}

func generateReadOnlyRootFix(pod corev1.Pod, containerName string) string {
	return fmt.Sprintf(`# Set root filesystem as read-only
spec:
  containers:
  - name: %s
    securityContext:
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: tmp
      mountPath: /tmp  # Add writable volumes as needed
  volumes:
  - name: tmp
    emptyDir: {}`, containerName)
}

func generateCapabilitiesFix(pod corev1.Pod, containerName, capability string) string {
	return fmt.Sprintf(`# Remove dangerous capability
spec:
  containers:
  - name: %s
    securityContext:
      capabilities:
        drop:
        - ALL  # Drop all capabilities by default
        # add: [] # Add only necessary capabilities`, containerName)
}

func generatePrivilegeEscalationFix(pod corev1.Pod, containerName string) string {
	return fmt.Sprintf(`# Disable privilege escalation
spec:
  containers:
  - name: %s
    securityContext:
      allowPrivilegeEscalation: false`, containerName)
}

func generateResourceLimitsFix(pod corev1.Pod, containerName string) string {
	return fmt.Sprintf(`# Add resource limits
spec:
  containers:
  - name: %s
    resources:
      requests:
        memory: "64Mi"
        cpu: "100m"
      limits:
        memory: "128Mi"
        cpu: "200m"`, containerName)
}

func generateSeccompFix(pod corev1.Pod, containerName string) string {
	return fmt.Sprintf(`# Add seccomp profile
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: %s
    # Container inherits pod-level seccomp`, containerName)
}

func generateAppArmorFix(pod corev1.Pod, containerName string) string {
	return fmt.Sprintf(`# Add AppArmor profile annotation
metadata:
  annotations:
    container.apparmor.security.beta.kubernetes.io/%s: runtime/default`, containerName)
}
