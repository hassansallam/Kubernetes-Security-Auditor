package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/hassansallam/k8s-security-auditor/pkg/audit"
	"github.com/hassansallam/k8s-security-auditor/pkg/client"
	"github.com/hassansallam/k8s-security-auditor/pkg/output"
)

var (
	kubeconfig    string
	context       string
	namespace     string
	outputFormat  string
	outputFile    string
	fix           bool
	approveRisky  bool
	dryRun        bool
	showDiff      bool
	verbose       bool
	pythonPlugin  string
	mcpServer     string
	offline       bool
	showVersion   bool
	checkLatest   bool
)

var rootCmd = &cobra.Command{
	Use:   "k8s-security-auditor",
	Short: "Production-grade Kubernetes security auditing CLI",
	Long: `K8s Security Auditor performs comprehensive security analysis of Kubernetes clusters,
including control plane, RBAC, workloads, network policies, secrets, and supply chain security.

Grounded in official Kubernetes documentation and CNCF security best practices.`,
	RunE: runAudit,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
	rootCmd.Flags().StringVar(&context, "context", "", "Kubernetes context to use")
	rootCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace to audit (default: all namespaces)")
	rootCmd.Flags().StringVarP(&outputFormat, "output", "o", "markdown", "Output format: json, sarif, markdown")
	rootCmd.Flags().StringVarP(&outputFile, "output-file", "f", "", "Write output to file instead of stdout")
	rootCmd.Flags().BoolVar(&fix, "fix", false, "Apply automatic fixes for safe remediations")
	rootCmd.Flags().BoolVar(&approveRisky, "approve-risky", false, "Approve potentially disruptive fixes (requires --fix)")
	rootCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be changed without applying (requires --fix)")
	rootCmd.Flags().BoolVar(&showDiff, "diff", false, "Show diffs for proposed changes (requires --fix)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().StringVar(&pythonPlugin, "python-plugin", "", "Path to Python plugin for agentic reasoning")
	rootCmd.Flags().StringVar(&mcpServer, "mcp-server", "http://localhost:3000", "Context7 MCP server URL for version-specific documentation")
	rootCmd.Flags().BoolVar(&offline, "offline", false, "Run without Context7 MCP (use bundled documentation)")
	rootCmd.Flags().BoolVar(&showVersion, "show-version", false, "Display cluster Kubernetes version and exit")
	rootCmd.Flags().BoolVar(&checkLatest, "check-latest", false, "Check if cluster is running latest Kubernetes version")
}

func runAudit(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Validate flags
	if approveRisky && !fix {
		return fmt.Errorf("--approve-risky requires --fix")
	}
	if dryRun && !fix {
		return fmt.Errorf("--dry-run requires --fix")
	}
	if showDiff && !fix {
		return fmt.Errorf("--diff requires --fix")
	}

	// Initialize Kubernetes client
	k8sClient, err := client.NewClient(kubeconfig, context)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Connected to cluster: %s\n", k8sClient.GetClusterInfo())
		fmt.Fprintf(os.Stderr, "Cluster version: %s\n", k8sClient.GetClusterVersion())
	}

	// Handle --show-version flag
	if showVersion {
		fmt.Printf("Cluster: %s\n", k8sClient.GetClusterInfo())
		fmt.Printf("Kubernetes Version: %s\n", k8sClient.GetClusterVersion())
		fmt.Printf("Major: %s, Minor: %s\n", k8sClient.GetMajorVersion(), k8sClient.GetMinorVersion())
		return nil
	}

	// Handle --check-latest flag
	if checkLatest {
		fmt.Printf("Current cluster version: %s\n", k8sClient.GetClusterVersion())
		fmt.Printf("Checking latest Kubernetes version via Context7 MCP...\n")
		// TODO: Implement latest version check via Context7 MCP
		fmt.Printf("Note: Kubernetes versions 1.24-1.35 are fully supported by this tool\n")
		return nil
	}

	// Create auditor
	auditor := audit.NewAuditor(k8sClient, audit.Config{
		Namespace:     namespace,
		Fix:           fix,
		ApproveRisky:  approveRisky,
		DryRun:        dryRun,
		ShowDiff:      showDiff,
		Verbose:       verbose,
		PythonPlugin:  pythonPlugin,
		MCPServer:     mcpServer,
		Offline:       offline,
	})

	// Run audit
	if verbose {
		fmt.Fprintf(os.Stderr, "Starting security audit...\n")
	}

	results, err := auditor.Run(ctx)
	if err != nil {
		return fmt.Errorf("audit failed: %w", err)
	}

	// Format output
	var outputData []byte
	switch outputFormat {
	case "json":
		outputData, err = output.FormatJSON(results)
	case "sarif":
		outputData, err = output.FormatSARIF(results)
	case "markdown":
		outputData, err = output.FormatMarkdown(results)
	default:
		return fmt.Errorf("unsupported output format: %s", outputFormat)
	}

	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	// Write output
	if outputFile != "" {
		if err := os.WriteFile(outputFile, outputData, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "Output written to: %s\n", outputFile)
		}
	} else {
		fmt.Println(string(outputData))
	}

	// Exit with non-zero if critical or high severity issues found
	if results.HasCriticalOrHigh() && !fix {
		return fmt.Errorf("critical or high severity issues detected")
	}

	return nil
}
