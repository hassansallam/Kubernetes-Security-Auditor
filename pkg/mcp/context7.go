package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Context7Client handles communication with the Context7 MCP server
type Context7Client struct {
	serverURL  string
	httpClient *http.Client
}

// NewContext7Client creates a new Context7 MCP client
func NewContext7Client(serverURL string) *Context7Client {
	if serverURL == "" {
		serverURL = "http://localhost:3000" // Default Context7 MCP server URL
	}

	return &Context7Client{
		serverURL: serverURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// MCPRequest represents a request to the Context7 MCP server
type MCPRequest struct {
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params"`
}

// MCPResponse represents a response from the Context7 MCP server
type MCPResponse struct {
	Result interface{} `json:"result,omitempty"`
	Error  *MCPError   `json:"error,omitempty"`
}

// MCPError represents an error from the MCP server
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// KubernetesDocumentation represents documentation fetched from Context7
type KubernetesDocumentation struct {
	Version string   `json:"version"`
	Title   string   `json:"title"`
	Content string   `json:"content"`
	URL     string   `json:"url"`
	Topics  []string `json:"topics"`
}

// FetchKubernetesDocumentation fetches version-specific Kubernetes documentation via Context7 MCP
func (c *Context7Client) FetchKubernetesDocumentation(ctx context.Context, k8sVersion, topic string) (*KubernetesDocumentation, error) {
	// Parse version to get major.minor (e.g., "v1.28.3" -> "1.28")
	versionParts := parseK8sVersion(k8sVersion)

	// Build query for Context7 MCP
	query := fmt.Sprintf("Kubernetes %s %s", versionParts, topic)

	// Call Context7 MCP server to search Kubernetes documentation
	request := MCPRequest{
		Method: "resources/read",
		Params: map[string]interface{}{
			"uri":   fmt.Sprintf("kubernetes://docs/%s/%s", versionParts, normalizeTopicForURI(topic)),
			"query": query,
		},
	}

	response, err := c.makeRequest(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch documentation from Context7 MCP: %w", err)
	}

	// Parse response
	doc := &KubernetesDocumentation{
		Version: versionParts,
		Title:   topic,
		Topics:  []string{topic},
	}

	if result, ok := response.Result.(map[string]interface{}); ok {
		if content, ok := result["contents"].(string); ok {
			doc.Content = content
		}
		if url, ok := result["uri"].(string); ok {
			doc.URL = url
		}
	}

	return doc, nil
}

// GetLatestK8sVersion fetches the latest Kubernetes version from Context7 MCP
func (c *Context7Client) GetLatestK8sVersion(ctx context.Context) (string, error) {
	request := MCPRequest{
		Method: "resources/list",
		Params: map[string]interface{}{
			"uri": "kubernetes://versions/latest",
		},
	}

	response, err := c.makeRequest(ctx, request)
	if err != nil {
		return "", fmt.Errorf("failed to fetch latest Kubernetes version: %w", err)
	}

	if result, ok := response.Result.(map[string]interface{}); ok {
		if version, ok := result["version"].(string); ok {
			return version, nil
		}
	}

	// Fallback to known latest version if MCP doesn't respond
	return "1.35", nil
}

// GetVersionSpecificDocURLs returns documentation URLs for a specific Kubernetes version
func (c *Context7Client) GetVersionSpecificDocURLs(k8sVersion string) map[string]string {
	versionParts := parseK8sVersion(k8sVersion)

	baseURL := fmt.Sprintf("https://kubernetes.io/docs/v%s", versionParts)

	return map[string]string{
		"pod-security":        fmt.Sprintf("%s/concepts/security/pod-security-standards/", baseURL),
		"rbac":                fmt.Sprintf("%s/reference/access-authn-authz/rbac/", baseURL),
		"network-policies":    fmt.Sprintf("%s/concepts/services-networking/network-policies/", baseURL),
		"secrets":             fmt.Sprintf("%s/concepts/configuration/secret/", baseURL),
		"security-context":    fmt.Sprintf("%s/tasks/configure-pod-container/security-context/", baseURL),
		"admission-control":   fmt.Sprintf("%s/reference/access-authn-authz/admission-controllers/", baseURL),
		"api-server":          fmt.Sprintf("%s/reference/command-line-tools-reference/kube-apiserver/", baseURL),
		"service-accounts":    fmt.Sprintf("%s/concepts/security/service-accounts/", baseURL),
		"capabilities":        fmt.Sprintf("%s/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container", baseURL),
		"seccomp":             fmt.Sprintf("%s/tutorials/security/seccomp/", baseURL),
		"apparmor":            fmt.Sprintf("%s/tutorials/security/apparmor/", baseURL),
	}
}

// makeRequest makes a request to the Context7 MCP server
func (c *Context7Client) makeRequest(ctx context.Context, request MCPRequest) (*MCPResponse, error) {
	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL+"/mcp", strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var mcpResp MCPResponse
	if err := json.Unmarshal(body, &mcpResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if mcpResp.Error != nil {
		return nil, fmt.Errorf("MCP error: %s (code: %d)", mcpResp.Error.Message, mcpResp.Error.Code)
	}

	return &mcpResp, nil
}

// parseK8sVersion extracts major.minor from full version string
// Examples: "v1.28.3" -> "1.28", "v1.35.0-alpha.1" -> "1.35"
func parseK8sVersion(version string) string {
	// Remove "v" prefix if present
	version = strings.TrimPrefix(version, "v")

	// Split by "." and take first two parts
	parts := strings.Split(version, ".")
	if len(parts) >= 2 {
		// Handle versions with suffixes like "1.35.0-alpha.1"
		minorPart := parts[1]
		if idx := strings.Index(minorPart, "-"); idx != -1 {
			minorPart = minorPart[:idx]
		}
		return fmt.Sprintf("%s.%s", parts[0], minorPart)
	}

	return version
}

// normalizeTopicForURI converts a topic string to a URI-safe format
func normalizeTopicForURI(topic string) string {
	return strings.ToLower(strings.ReplaceAll(topic, " ", "-"))
}

// IsContext7Available checks if Context7 MCP server is available
func (c *Context7Client) IsContext7Available(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL+"/health", nil)
	if err != nil {
		return false
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}
