#!/usr/bin/env python3
"""
Kubernetes Security Auditor - Agentic Reasoning Plugin

This plugin provides advanced AI-powered analysis of security findings:
- Long-form report narration and executive summaries
- RAG-based explanation using Kubernetes documentation
- Contextual recommendations based on cluster characteristics
- Risk prioritization based on attack patterns

The Go tool remains fully functional without this plugin.
"""

import json
import sys
import argparse
from typing import Dict, List, Any
from dataclasses import dataclass


@dataclass
class Finding:
    """Represents a security finding from the Go auditor"""
    id: str
    name: str
    description: str
    severity: str
    category: str
    resource: Dict[str, str]
    evidence: Dict[str, str]
    impact: str
    exploit_path: str
    remediation: str
    verification: str


class AgenticReasoner:
    """Advanced AI reasoning for security findings"""

    def __init__(self, findings_json: str):
        """Initialize with audit results JSON"""
        self.data = json.loads(findings_json)
        self.findings = [
            Finding(**f) for f in self.data.get('findings', [])
        ]
        self.summary = self.data.get('summary', {})
        self.cluster_info = self.data.get('cluster_info', '')

    def generate_executive_summary(self) -> str:
        """Generate an executive summary with business context"""
        critical_count = self.summary.get('by_severity', {}).get('Critical', 0)
        high_count = self.summary.get('by_severity', {}).get('High', 0)

        summary = f"""
# Executive Summary

## Security Posture Assessment

This Kubernetes cluster has been assessed for security vulnerabilities and
misconfigurations. The audit identified {self.summary.get('total_findings', 0)}
findings across multiple security domains.

## Risk Level

"""

        if critical_count > 0:
            summary += f"""
**CRITICAL RISK**: {critical_count} critical findings require immediate attention.
These vulnerabilities could allow complete cluster compromise if exploited.
"""
        elif high_count > 0:
            summary += f"""
**HIGH RISK**: {high_count} high-severity findings require prompt remediation.
These issues significantly increase the attack surface of the cluster.
"""
        else:
            summary += """
**MODERATE TO LOW RISK**: No critical or high-severity findings detected.
Focus on addressing medium and low severity items to maintain good security posture.
"""

        summary += """

## Key Findings

"""

        # Identify top issues by category
        top_categories = sorted(
            self.summary.get('by_category', {}).items(),
            key=lambda x: x[1],
            reverse=True
        )[:3]

        for category, count in top_categories:
            summary += f"- **{category}**: {count} findings\n"

        summary += """

## Recommended Actions

1. **Immediate**: Address all Critical severity findings
2. **Short-term (1-2 weeks)**: Remediate High severity findings
3. **Medium-term (1-3 months)**: Address Medium severity findings
4. **Long-term**: Implement Low severity recommendations for defense-in-depth

## Next Steps

This report provides detailed remediation guidance for each finding, including:
- Exact YAML configurations to apply
- Verification commands to confirm fixes
- References to official Kubernetes documentation

Begin with the Critical Findings section and work systematically through each issue.
"""

        return summary

    def explain_finding_with_context(self, finding: Finding) -> str:
        """
        Provide detailed explanation of a finding with Kubernetes context.

        In a production version, this would:
        1. Query Context7 MCP server for relevant K8s documentation
        2. Use RAG to provide contextual explanations
        3. Offer examples from real-world incidents
        """

        explanation = f"""
## Deep Dive: {finding.name}

### What This Means

{finding.description}

### Why It Matters

{finding.impact}

### Attack Scenario

An attacker could exploit this misconfiguration through the following attack path:

{finding.exploit_path}

### Technical Details

"""

        # Add category-specific context
        if finding.category == "Workload Security":
            explanation += """
Kubernetes workload security is enforced through Pod SecurityContext and SecurityContext
fields. These settings control Linux kernel security features like capabilities, user IDs,
filesystem access, and namespace isolation. Properly configured security contexts implement
the principle of least privilege at the container level.
"""
        elif finding.category == "RBAC":
            explanation += """
Kubernetes Role-Based Access Control (RBAC) determines who can perform what actions on
which resources. RBAC follows the principle of least privilege: each identity should have
only the minimum permissions required. Overly broad RBAC grants increase the blast radius
of a compromise.
"""
        elif finding.category == "Secrets Management":
            explanation += """
Kubernetes Secrets store sensitive data like credentials, tokens, and certificates. Without
proper protection (encryption at rest, access controls, external secret managers), secrets
can be extracted by attackers who gain access to etcd or compromise workloads with broad
RBAC permissions.
"""
        elif finding.category == "Network Security":
            explanation += """
Kubernetes NetworkPolicies provide layer 3/4 network segmentation between pods. Without
NetworkPolicies, all pods can communicate freely, violating zero-trust principles and
enabling lateral movement after initial compromise.
"""
        elif finding.category == "Supply Chain":
            explanation += """
Container image security is critical for supply chain integrity. Using mutable tags,
untrusted registries, or images without vulnerability scanning can introduce compromised
code into your cluster. Image provenance and verification are key supply chain controls.
"""

        explanation += f"""

### How to Fix

{finding.remediation}

### Verification

After applying the fix, verify it worked:

```bash
{finding.verification}
```

### References

For more information, consult the official Kubernetes documentation:
"""

        for ref in getattr(finding, 'references', []):
            explanation += f"- {ref}\n"

        return explanation

    def prioritize_findings(self) -> List[Dict[str, Any]]:
        """
        Prioritize findings based on exploitability, impact, and context.

        Returns a ranked list with priority scores and justification.
        """

        prioritized = []

        for finding in self.findings:
            priority_score = 0
            reasons = []

            # Severity scoring
            severity_scores = {
                'Critical': 40,
                'High': 30,
                'Medium': 20,
                'Low': 10
            }
            priority_score += severity_scores.get(finding.severity, 0)

            # Privilege escalation paths are highest priority
            if 'escalate' in finding.name.lower() or 'privileged' in finding.name.lower():
                priority_score += 20
                reasons.append("Direct privilege escalation path")

            # Cluster-wide issues are higher priority than namespace-scoped
            if finding.resource.get('kind') in ['ClusterRole', 'ClusterRoleBinding', 'Node']:
                priority_score += 15
                reasons.append("Cluster-wide impact")

            # Issues in kube-system are critical
            if finding.resource.get('namespace') == 'kube-system':
                priority_score += 15
                reasons.append("Affects control plane namespace")

            # Secrets and credentials exposure
            if 'secret' in finding.name.lower() or 'credential' in finding.name.lower():
                priority_score += 10
                reasons.append("Credential exposure risk")

            prioritized.append({
                'finding': finding,
                'priority_score': priority_score,
                'reasons': reasons
            })

        # Sort by priority score descending
        prioritized.sort(key=lambda x: x['priority_score'], reverse=True)

        return prioritized

    def generate_remediation_plan(self) -> str:
        """Generate a prioritized remediation plan"""

        prioritized = self.prioritize_findings()

        plan = """
# Remediation Plan

This plan prioritizes security findings based on severity, exploitability, and impact.

## Phase 1: Critical Security Gaps (Immediate Action)

Address these findings immediately, within 24-48 hours:

"""

        phase1 = [p for p in prioritized if p['priority_score'] >= 50]
        if phase1:
            for i, item in enumerate(phase1, 1):
                f = item['finding']
                plan += f"""
### {i}. {f.name}
- **Resource**: `{f.resource.get('kind')}/{f.resource.get('namespace', '')}/{f.resource.get('name')}`
- **Priority Score**: {item['priority_score']}
- **Why Critical**: {', '.join(item['reasons'])}
- **Quick Fix**: {f.remediation.split('.')[0]}

"""
        else:
            plan += "No findings in this category.\n\n"

        plan += """
## Phase 2: High-Risk Findings (1-2 Weeks)

"""

        phase2 = [p for p in prioritized if 30 <= p['priority_score'] < 50]
        if phase2:
            for i, item in enumerate(phase2, 1):
                f = item['finding']
                plan += f"- [{f.id}] {f.name} - `{f.resource.get('kind')}/{f.resource.get('name')}`\n"
        else:
            plan += "No findings in this category.\n"

        plan += """

## Phase 3: Medium-Risk Findings (1-3 Months)

"""

        phase3 = [p for p in prioritized if p['priority_score'] < 30]
        if phase3:
            plan += f"Total of {len(phase3)} findings. Review detailed findings section.\n"
        else:
            plan += "No findings in this category.\n"

        return plan

    def analyze_cluster_patterns(self) -> str:
        """Identify patterns and systemic issues across findings"""

        patterns = """
# Pattern Analysis

Analyzing the findings reveals the following systemic issues:

"""

        # Count findings by category
        category_counts = self.summary.get('by_category', {})

        # Identify dominant issues
        if category_counts.get('Workload Security', 0) > 10:
            patterns += """
## Pattern: Weak Workload Security Posture

Multiple workloads lack basic security controls (SecurityContext, readOnlyRootFilesystem,
runAsNonRoot). This suggests:

**Root Cause**: No Pod Security Standards or admission policies enforcing baseline security.

**Systemic Fix**:
1. Enable Pod Security Standards with at least 'baseline' level
2. Update Deployment templates to include SecurityContext
3. Use PodSecurityPolicy or OPA Gatekeeper to prevent future violations

"""

        if category_counts.get('RBAC', 0) > 5:
            patterns += """
## Pattern: Overprivileged RBAC

Multiple RBAC roles grant excessive permissions (wildcards, cluster-admin, broad secrets access).

**Root Cause**: RBAC designed for convenience rather than least privilege.

**Systemic Fix**:
1. Audit all ClusterRoles and Roles
2. Replace wildcards with specific resources/verbs
3. Use namespace-scoped Roles instead of ClusterRoles where possible
4. Implement regular RBAC reviews

"""

        if category_counts.get('Supply Chain', 0) > 5:
            patterns += """
## Pattern: Weak Supply Chain Controls

Multiple workloads use mutable image tags or untrusted registries.

**Root Cause**: No image policy enforcement or supply chain security practices.

**Systemic Fix**:
1. Require image digests or semantic version tags
2. Implement image scanning in CI/CD
3. Use admission controller to enforce image policies
4. Migrate to private container registry

"""

        if not any([
            category_counts.get('Workload Security', 0) > 10,
            category_counts.get('RBAC', 0) > 5,
            category_counts.get('Supply Chain', 0) > 5
        ]):
            patterns += "No major systemic patterns detected. Issues appear isolated.\n"

        return patterns


def main():
    parser = argparse.ArgumentParser(
        description='Agentic reasoning plugin for K8s Security Auditor'
    )
    parser.add_argument(
        '--input',
        required=True,
        help='Path to JSON audit results from Go tool'
    )
    parser.add_argument(
        '--output',
        required=True,
        help='Path to write enhanced analysis'
    )
    parser.add_argument(
        '--mode',
        choices=['executive', 'technical', 'remediation', 'patterns', 'all'],
        default='all',
        help='Type of analysis to generate'
    )

    args = parser.parse_args()

    # Read input
    with open(args.input, 'r') as f:
        findings_json = f.read()

    # Initialize reasoner
    reasoner = AgenticReasoner(findings_json)

    # Generate analysis
    output = ""

    if args.mode in ['executive', 'all']:
        output += reasoner.generate_executive_summary()
        output += "\n\n"

    if args.mode in ['patterns', 'all']:
        output += reasoner.analyze_cluster_patterns()
        output += "\n\n"

    if args.mode in ['remediation', 'all']:
        output += reasoner.generate_remediation_plan()
        output += "\n\n"

    if args.mode == 'technical':
        # Deep dive on top 3 findings
        prioritized = reasoner.prioritize_findings()[:3]
        for item in prioritized:
            output += reasoner.explain_finding_with_context(item['finding'])
            output += "\n\n---\n\n"

    # Write output
    with open(args.output, 'w') as f:
        f.write(output)

    print(f"Enhanced analysis written to {args.output}", file=sys.stderr)


if __name__ == '__main__':
    main()
