# Python Agentic Reasoning Plugin

This plugin enhances the Go-based K8s Security Auditor with advanced AI-powered analysis.

## Features

- **Executive Summaries**: Business-friendly reports for management
- **Pattern Analysis**: Identifies systemic security issues across the cluster
- **Remediation Planning**: Prioritized, phased remediation roadmaps
- **Deep Dive Analysis**: Detailed technical explanations with Kubernetes context

## Usage

The Go auditor can optionally invoke this plugin for enhanced analysis:

```bash
# Run audit and generate enhanced report
k8s-security-auditor -o json -f audit-results.json
python3 plugins/agentic_reasoner.py --input audit-results.json --output enhanced-report.md

# Or use the --python-plugin flag (if implemented in Go CLI)
k8s-security-auditor --python-plugin plugins/agentic_reasoner.py -o markdown
```

## Modes

- `executive`: Executive summary for leadership
- `technical`: Deep technical analysis of top findings
- `remediation`: Prioritized remediation plan
- `patterns`: Systemic issue identification
- `all`: Complete enhanced report (default)

## Requirements

```bash
pip install dataclasses  # Python 3.6+
```

## Future Enhancements

In a production version, this plugin would:

1. **RAG Integration**: Query Context7 MCP server for official Kubernetes documentation
2. **LLM Analysis**: Use Claude API for intelligent finding correlation
3. **Threat Intelligence**: Cross-reference findings with CVE databases
4. **Custom Rules**: Allow defining organization-specific security policies
5. **Slack/Email**: Send prioritized alerts to security teams

## Architecture

The plugin is designed to be optional - the Go tool produces complete, actionable
results without Python. This plugin adds narrative and contextual analysis for
human consumers of the report.
