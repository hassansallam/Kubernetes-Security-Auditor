package client

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client wraps Kubernetes client-go with convenience methods
type Client struct {
	clientset      *kubernetes.Clientset
	config         *rest.Config
	clusterInfo    string
	clusterVersion string
	majorVersion   string
	minorVersion   string
}

// ClusterData holds all collected Kubernetes resources for analysis
type ClusterData struct {
	Nodes                 []corev1.Node
	Namespaces            []corev1.Namespace
	Pods                  []corev1.Pod
	Services              []corev1.Service
	ServiceAccounts       []corev1.ServiceAccount
	Secrets               []corev1.Secret
	ConfigMaps            []corev1.ConfigMap
	PersistentVolumes     []corev1.PersistentVolume
	PersistentVolumeClaims []corev1.PersistentVolumeClaim
	Roles                 []rbacv1.Role
	RoleBindings          []rbacv1.RoleBinding
	ClusterRoles          []rbacv1.ClusterRole
	ClusterRoleBindings   []rbacv1.ClusterRoleBinding
	// NetworkPolicies will be added with networking API
}

// NewClient creates a new Kubernetes client
func NewClient(kubeconfigPath, contextName string) (*Client, error) {
	// Determine kubeconfig path
	if kubeconfigPath == "" {
		if env := os.Getenv("KUBECONFIG"); env != "" {
			kubeconfigPath = env
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("cannot determine home directory: %w", err)
			}
			kubeconfigPath = filepath.Join(home, ".kube", "config")
		}
	}

	// Build config
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
		&clientcmd.ConfigOverrides{
			CurrentContext: contextName,
		},
	).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to build config: %w", err)
	}

	// Create clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	// Get cluster info and version
	serverVersion, err := clientset.Discovery().ServerVersion()
	clusterInfo := "unknown"
	clusterVersion := "unknown"
	majorVersion := "1"
	minorVersion := "0"
	if err == nil {
		clusterInfo = fmt.Sprintf("%s (server: %s)", config.Host, serverVersion.GitVersion)
		clusterVersion = serverVersion.GitVersion
		majorVersion = serverVersion.Major
		minorVersion = serverVersion.Minor
	}

	return &Client{
		clientset:      clientset,
		config:         config,
		clusterInfo:    clusterInfo,
		clusterVersion: clusterVersion,
		majorVersion:   majorVersion,
		minorVersion:   minorVersion,
	}, nil
}

// GetClusterInfo returns cluster connection information
func (c *Client) GetClusterInfo() string {
	return c.clusterInfo
}

// GetClusterVersion returns the Kubernetes cluster version
func (c *Client) GetClusterVersion() string {
	return c.clusterVersion
}

// GetMajorVersion returns the major version of the cluster
func (c *Client) GetMajorVersion() string {
	return c.majorVersion
}

// GetMinorVersion returns the minor version of the cluster
func (c *Client) GetMinorVersion() string {
	return c.minorVersion
}

// CollectClusterData gathers all resources needed for security analysis
func (c *Client) CollectClusterData(ctx context.Context, namespace string) (*ClusterData, error) {
	data := &ClusterData{}

	// Determine namespace scope
	nsOption := metav1.ListOptions{}
	allNamespaces := namespace == ""

	// Collect nodes (cluster-wide only)
	nodes, err := c.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}
	data.Nodes = nodes.Items

	// Collect namespaces
	namespaces, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}
	data.Namespaces = namespaces.Items

	// Determine which namespaces to scan
	namespacesToScan := []string{}
	if allNamespaces {
		for _, ns := range data.Namespaces {
			namespacesToScan = append(namespacesToScan, ns.Name)
		}
	} else {
		namespacesToScan = []string{namespace}
	}

	// Collect namespaced resources
	for _, ns := range namespacesToScan {
		// Pods
		pods, err := c.clientset.CoreV1().Pods(ns).List(ctx, nsOption)
		if err != nil {
			return nil, fmt.Errorf("failed to list pods in namespace %s: %w", ns, err)
		}
		data.Pods = append(data.Pods, pods.Items...)

		// Services
		services, err := c.clientset.CoreV1().Services(ns).List(ctx, nsOption)
		if err != nil {
			return nil, fmt.Errorf("failed to list services in namespace %s: %w", ns, err)
		}
		data.Services = append(data.Services, services.Items...)

		// ServiceAccounts
		serviceAccounts, err := c.clientset.CoreV1().ServiceAccounts(ns).List(ctx, nsOption)
		if err != nil {
			return nil, fmt.Errorf("failed to list serviceaccounts in namespace %s: %w", ns, err)
		}
		data.ServiceAccounts = append(data.ServiceAccounts, serviceAccounts.Items...)

		// Secrets
		secrets, err := c.clientset.CoreV1().Secrets(ns).List(ctx, nsOption)
		if err != nil {
			return nil, fmt.Errorf("failed to list secrets in namespace %s: %w", ns, err)
		}
		data.Secrets = append(data.Secrets, secrets.Items...)

		// ConfigMaps
		configMaps, err := c.clientset.CoreV1().ConfigMaps(ns).List(ctx, nsOption)
		if err != nil {
			return nil, fmt.Errorf("failed to list configmaps in namespace %s: %w", ns, err)
		}
		data.ConfigMaps = append(data.ConfigMaps, configMaps.Items...)

		// PersistentVolumeClaims
		pvcs, err := c.clientset.CoreV1().PersistentVolumeClaims(ns).List(ctx, nsOption)
		if err != nil {
			return nil, fmt.Errorf("failed to list pvcs in namespace %s: %w", ns, err)
		}
		data.PersistentVolumeClaims = append(data.PersistentVolumeClaims, pvcs.Items...)

		// Roles
		roles, err := c.clientset.RbacV1().Roles(ns).List(ctx, nsOption)
		if err != nil {
			return nil, fmt.Errorf("failed to list roles in namespace %s: %w", ns, err)
		}
		data.Roles = append(data.Roles, roles.Items...)

		// RoleBindings
		roleBindings, err := c.clientset.RbacV1().RoleBindings(ns).List(ctx, nsOption)
		if err != nil {
			return nil, fmt.Errorf("failed to list rolebindings in namespace %s: %w", ns, err)
		}
		data.RoleBindings = append(data.RoleBindings, roleBindings.Items...)
	}

	// Collect cluster-scoped resources
	// PersistentVolumes
	pvs, err := c.clientset.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list persistent volumes: %w", err)
	}
	data.PersistentVolumes = pvs.Items

	// ClusterRoles
	clusterRoles, err := c.clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list clusterroles: %w", err)
	}
	data.ClusterRoles = clusterRoles.Items

	// ClusterRoleBindings
	clusterRoleBindings, err := c.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list clusterrolebindings: %w", err)
	}
	data.ClusterRoleBindings = clusterRoleBindings.Items

	return data, nil
}

// Clientset returns the underlying Kubernetes clientset for advanced operations
func (c *Client) Clientset() *kubernetes.Clientset {
	return c.clientset
}
