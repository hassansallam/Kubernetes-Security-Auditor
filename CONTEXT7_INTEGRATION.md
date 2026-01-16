# Context7 MCP Integration Guide

## Overview

The K8s Security Auditor integrates with **Context7 MCP (Model Context Protocol) Server** to provide version-specific Kubernetes documentation for security findings. This ensures that all recommendations and remediation steps are accurate for your specific Kubernetes version.

## What is Context7?

Context7 is an MCP server that provides structured access to official Kubernetes documentation across all versions. The K8s Security Auditor uses it to:

1. **Detect Cluster Version**: Automatically identify your Kubernetes version (e.g., v1.28.3)
2. **Fetch Version-Specific Documentation**: Retrieve official docs for your exact version
3. **Ground Security Findings**: Reference documentation that matches your cluster's capabilities
4. **Check Latest Versions**: Compare your cluster against the latest Kubernetes releases
5. **Provide Accurate Recommendations**: Avoid suggesting features not available in your version

## Supported Kubernetes Versions

The auditor supports **Kubernetes 1.24 through 1.35** (latest) with full backward compatibility:

- **K8s 1.24-1.25**: Core security features, Pod Security Standards
- **K8s 1.26-1.28**: Enhanced security contexts, improved seccomp/apparmor
- **K8s 1.29-1.31**: Latest security admission policies
- **K8s 1.32-1.35**: Cutting-edge security features

## Installation

### Option 1: Docker (Recommended)

```bash
# Run Context7 MCP server
docker run -d -p 3000:3000 \
  --name context7-mcp \
  --restart unless-stopped \
  modelcontextprotocol/context7-server:latest

# Verify it's running
curl http://localhost:3000/health
```

### Option 2: NPM Package

```bash
# Install globally
npm install -g @modelcontextprotocol/server-context7

# Run the server
context7-server --port 3000

# Or run directly with npx
npx @modelcontextprotocol/server-context7
```

### Option 3: From Source

```bash
# Clone the MCP servers repository
git clone https://github.com/modelcontextprotocol/servers.git
cd servers/src/context7

# Install dependencies
npm install

# Build
npm run build

# Start the server
npm start
```

### Option 4: Claude Desktop Integration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "context7": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-context7"],
      "env": {
        "CONTEXT7_PORT": "3000"
      }
    }
  }
}
```

## Configuration

### Environment Variables

Context7 MCP server supports these environment variables:

```bash
# Server port (default: 3000)
export CONTEXT7_PORT=3000

# Enable debug logging
export CONTEXT7_DEBUG=true

# Cache directory for documentation
export CONTEXT7_CACHE_DIR=/var/cache/context7
```

### Auditor Configuration

The K8s Security Auditor auto-detects Context7 at `http://localhost:3000`. To customize:

```bash
# Use custom MCP server URL
k8s-security-auditor --mcp-server http://context7.example.com:8080

# Run in offline mode (no Context7 required)
k8s-security-auditor --offline

# Check cluster version
k8s-security-auditor --show-version

# Compare with latest K8s version
k8s-security-auditor --check-latest
```

## Usage Examples

### Basic Audit with Version Detection

```bash
# Auditor automatically connects to Context7 and detects cluster version
k8s-security-auditor -v

# Output:
# Connected to cluster: https://prod-k8s.example.com (server: v1.28.3)
# Cluster version: v1.28.3
# Context7 MCP: Connected at http://localhost:3000
# Fetching Kubernetes 1.28 documentation...
# Starting security audit...
```

### View Cluster Version Information

```bash
k8s-security-auditor --show-version

# Output:
# Cluster: https://prod-k8s.example.com (server: v1.28.3)
# Kubernetes Version: v1.28.3
# Major: 1, Minor: 28
```

### Check Latest Kubernetes Version

```bash
k8s-security-auditor --check-latest

# Output:
# Current cluster version: v1.28.3
# Checking latest Kubernetes version via Context7 MCP...
# Latest stable version: v1.35.0
# Your cluster is 7 minor versions behind
# Note: Kubernetes versions 1.24-1.35 are fully supported by this tool
```

### Custom MCP Server

```bash
# Point to custom Context7 server
k8s-security-auditor --mcp-server https://context7.internal.company.com

# Use with namespace scoping
k8s-security-auditor -n production --mcp-server http://context7-dev:3000
```

### Offline Mode

```bash
# Run without Context7 (uses bundled documentation)
k8s-security-auditor --offline

# Generate report without external dependencies
k8s-security-auditor --offline -o json -f audit.json
```

## How It Works

### 1. Cluster Version Detection

When the auditor starts:

```go
// Connects to Kubernetes cluster
k8sClient, err := client.NewClient(kubeconfig, context)

// Automatically detects version via Discovery API
version := k8sClient.GetClusterVersion() // e.g., "v1.28.3"
```

### 2. Version Parsing

The auditor extracts major.minor version:

```
v1.28.3 -> 1.28
v1.35.0-alpha.1 -> 1.35
v1.27.10+k3s1 -> 1.27
```

### 3. Documentation Fetching

For each security rule, the auditor queries Context7:

```http
POST http://localhost:3000/mcp
Content-Type: application/json

{
  "method": "resources/read",
  "params": {
    "uri": "kubernetes://docs/1.28/pod-security-standards",
    "query": "Kubernetes 1.28 Pod Security Standards"
  }
}
```

### 4. Version-Specific Findings

Security findings include version-aware references:

```markdown
### Pod Security Standards Not Enforced (CP-003)

**Cluster Version**: v1.28.3
**Severity**: High
**Category**: Control Plane

**Documentation**:
- https://kubernetes.io/docs/v1.28/concepts/security/pod-security-standards/
- https://kubernetes.io/docs/v1.28/concepts/security/pod-security-admission/

**Evidence**:
- namespace: production
- pod-security.kubernetes.io/enforce: not set

**Impact**:
Your cluster (v1.28.3) supports Pod Security Standards, which should be enforced...

**Remediation** (for Kubernetes 1.28):
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```
```

## Version-Specific Features

The auditor adjusts checks based on your Kubernetes version:

### Kubernetes 1.23+
- Pod Security Standards (PSS) checks enabled
- Pod Security Admission validation

### Kubernetes 1.25+
- Enhanced PSS enforcement
- Improved service account token projection

### Kubernetes 1.27+
- Seccomp profile validation improvements
- Enhanced security context checks

### Kubernetes 1.28+
- AppArmor profile enhancements
- Additional security admission controls

### Kubernetes 1.30+
- Latest security features
- New admission policy APIs

### Kubernetes 1.32+
- Cutting-edge security features
- Beta security enhancements

### Kubernetes 1.35 (latest)
- All latest security capabilities
- Future-proof recommendations

## Benefits

### Accurate Recommendations
- No suggestions for unavailable features
- Version-appropriate YAML examples
- API references that match your cluster

### Version Awareness
- Different checks for K8s 1.24 vs 1.35
- Progressive enhancement for newer versions
- Graceful degradation for older clusters

### Always Grounded
- Official Kubernetes documentation only
- No third-party or outdated sources
- Links verified for your version

### Stay Up-to-Date
- Compare with latest releases
- Understand version upgrade benefits
- Plan security improvements

## Fallback Behavior

If Context7 MCP is not available:

1. **Bundled Documentation**: Uses embedded documentation references
2. **Generic Links**: Points to latest K8s docs (kubernetes.io/docs)
3. **Best-Effort Checks**: Performs version detection but uses generic guidance
4. **Warning Message**: Notifies that Context7 is unavailable

```bash
# Example with Context7 unavailable
k8s-security-auditor -v

# Output:
# Warning: Context7 MCP server not available at http://localhost:3000
# Falling back to bundled documentation
# Some recommendations may not be version-specific
# Use --offline flag to suppress this warning
```

## Troubleshooting

### Context7 Not Starting

```bash
# Check if port 3000 is in use
lsof -i :3000

# Try different port
docker run -d -p 3001:3000 modelcontextprotocol/context7-server:latest
k8s-security-auditor --mcp-server http://localhost:3001
```

### Connection Refused

```bash
# Verify Context7 is running
curl http://localhost:3000/health

# Check firewall rules
sudo ufw status

# Test with verbose output
k8s-security-auditor -v --mcp-server http://localhost:3000
```

### Version Detection Issues

```bash
# Manually check cluster version
kubectl version --short

# Verify client connection
k8s-security-auditor --show-version

# Check RBAC permissions
kubectl auth can-i get --all-namespaces --as system:serviceaccount:default:auditor
```

### Documentation Not Loading

```bash
# Check Context7 logs
docker logs context7-mcp

# Test MCP endpoint directly
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"method":"resources/list","params":{"uri":"kubernetes://versions"}}'

# Use offline mode as workaround
k8s-security-auditor --offline
```

## Performance Considerations

### Caching

Context7 MCP caches documentation locally:

- **Cache Duration**: 24 hours
- **Cache Location**: `~/.cache/context7/`
- **Cache Size**: ~50MB per K8s version

### Network Latency

- **First Run**: 2-5 seconds (fetching documentation)
- **Subsequent Runs**: <100ms (using cache)
- **Offline Mode**: 0ms (no network calls)

### Resource Usage

Context7 MCP server:
- **Memory**: ~50-100MB
- **CPU**: <5% (idle), <20% (active)
- **Disk**: ~500MB (full documentation cache)

## Security Considerations

### Network Security

```bash
# Run Context7 on localhost only
docker run -d -p 127.0.0.1:3000:3000 modelcontextprotocol/context7-server

# Use TLS in production
docker run -d -p 443:3000 \
  -v /etc/ssl:/etc/ssl \
  -e CONTEXT7_TLS_CERT=/etc/ssl/cert.pem \
  -e CONTEXT7_TLS_KEY=/etc/ssl/key.pem \
  modelcontextprotocol/context7-server
```

### Authentication

For production deployments, consider:

```bash
# Use API key authentication
export CONTEXT7_API_KEY=your-secret-key
k8s-security-auditor --mcp-server https://context7.internal.com \
  --mcp-api-key $CONTEXT7_API_KEY
```

### Data Privacy

- Context7 only stores Kubernetes documentation
- No cluster data sent to Context7
- Only version numbers and topic queries transmitted
- All data flows over HTTP/HTTPS

## Production Deployment

### Docker Compose

```yaml
version: '3.8'
services:
  context7:
    image: modelcontextprotocol/context7-server:latest
    ports:
      - "127.0.0.1:3000:3000"
    environment:
      - CONTEXT7_CACHE_DIR=/var/cache/context7
    volumes:
      - context7-cache:/var/cache/context7
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  context7-cache:
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: context7-mcp
  namespace: security-tools
spec:
  replicas: 1
  selector:
    matchLabels:
      app: context7-mcp
  template:
    metadata:
      labels:
        app: context7-mcp
    spec:
      containers:
      - name: context7
        image: modelcontextprotocol/context7-server:latest
        ports:
        - containerPort: 3000
        env:
        - name: CONTEXT7_CACHE_DIR
          value: /var/cache/context7
        volumeMounts:
        - name: cache
          mountPath: /var/cache/context7
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
      volumes:
      - name: cache
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: context7-mcp
  namespace: security-tools
spec:
  selector:
    app: context7-mcp
  ports:
  - port: 3000
    targetPort: 3000
```

## Integration with CI/CD

### GitHub Actions

```yaml
name: K8s Security Audit with Context7

on:
  push:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 1'

jobs:
  audit:
    runs-on: ubuntu-latest
    services:
      context7:
        image: modelcontextprotocol/context7-server:latest
        ports:
          - 3000:3000
    steps:
      - name: Setup kubeconfig
        run: echo "${{ secrets.KUBECONFIG }}" > ~/.kube/config

      - name: Download auditor
        run: |
          curl -L https://github.com/vibecoding/k8s-security-auditor/releases/latest/download/k8s-security-auditor-linux-amd64 -o k8s-security-auditor
          chmod +x k8s-security-auditor

      - name: Run audit with Context7
        run: |
          ./k8s-security-auditor -o sarif -f results.sarif --mcp-server http://localhost:3000

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
k8s-security-audit:
  image: ubuntu:latest
  services:
    - name: modelcontextprotocol/context7-server:latest
      alias: context7
  script:
    - curl -L https://github.com/vibecoding/k8s-security-auditor/releases/latest/download/k8s-security-auditor-linux-amd64 -o k8s-security-auditor
    - chmod +x k8s-security-auditor
    - ./k8s-security-auditor --mcp-server http://context7:3000 -o json
  artifacts:
    reports:
      sast: results.json
```

## Support

- **GitHub Issues**: https://github.com/vibecoding/k8s-security-auditor/issues
- **MCP Documentation**: https://github.com/modelcontextprotocol/specification
- **Context7 Repository**: https://github.com/modelcontextprotocol/servers

## Future Enhancements

- **Custom Documentation Sources**: Support for private K8s forks
- **Multi-Version Comparison**: Compare security across K8s versions
- **Migration Guides**: Version upgrade security impact analysis
- **Historical Analysis**: Track security posture across version upgrades
