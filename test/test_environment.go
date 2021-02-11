package test

import (
	"os"
	"path/filepath"

	logr "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc" // required for connectivity into dev cluster
	"k8s.io/client-go/tools/clientcmd"
)

type Environment struct {
	KubeClientset *kubernetes.Clientset
	KubeContext   string
}

func NewIntegratedEnv() *Environment {
	context := "kind"
	env := &Environment{
		KubeContext:   context,
		KubeClientset: newKubeClientset(context),
	}
	logr.Infof("Test environment. K8 context: %s", env.KubeContext)
	return env
}

func newKubeClientset(context string) *kubernetes.Clientset {
	kubeConfigPath := os.Getenv("KUBECONFIG")
	if kubeConfigPath == "" {
		kubeConfigPath = filepath.Join(os.Getenv("HOME"), ".kube", "config")
	}

	var err error
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{Precedence: []string{kubeConfigPath}},
		&clientcmd.ConfigOverrides{CurrentContext: context},
	).ClientConfig()
	if err != nil {
		logr.Fatalf("Unable to obtain out-of-cluster config: %v", err)
	}
	return kubernetes.NewForConfigOrDie(config)
}
