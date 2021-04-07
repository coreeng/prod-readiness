package k8s

import (
	"os"
	"path/filepath"

	logr "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// KubernetesConfig returns k8s client config
func KubernetesConfig(kubeContext string, kubeconfigPath string) *rest.Config {
	var config *rest.Config
	var err error

	if kubeContext != "" {
		config, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: GetOrDefaultKubeConfigPath(kubeconfigPath)},
			&clientcmd.ConfigOverrides{
				CurrentContext: kubeContext,
			}).ClientConfig()
	} else {
		config, err = rest.InClusterConfig()
	}
	if err != nil {
		logr.Fatalf("Unable to obtain kube config: %v", err)
	}
	return config
}

// GetOrDefaultKubeConfigPath returns kubeconifg path
func GetOrDefaultKubeConfigPath(path string) string {
	kubeconfigPath := path
	if kubeconfigPath == "" {
		kubeconfigPath = os.Getenv("KUBECONFIG")
		if kubeconfigPath == "" {
			kubeconfigPath = filepath.Join(os.Getenv("HOME"), ".kube", "config")
		}
	}
	return kubeconfigPath
}

// KubernetesClientset returns kubernetes clientset
func KubernetesClientset(config *rest.Config) *kubernetes.Clientset {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logr.Fatalf("Unable to obtain clientset: %v", err)
	}
	return clientset
}
