package k8s

import (
	"fmt"

	logr "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// KubernetesClient is a thin client to access the Kubernetes cluster
type KubernetesClient interface {
	// GetContainersInNamespaces returns the containers for all the pods in the namespaces that matche the labelSelector
	GetContainersInNamespaces(labelSelector string) ([]ContainerSummary, error)
}

// ContainerSummary holds details of the docker container
type ContainerSummary struct {
	Image           string
	ContainerName   string
	PodName         string
	Namespace       string
	NamespaceLabels map[string]string
}

type kubernetesClient struct {
	config    *rest.Config
	clientset *kubernetes.Clientset
}

// NewKubernetesClient creates a new KubernetesClient
func NewKubernetesClient(kubeContext, kubeconfigPath string) KubernetesClient {
	config := KubernetesConfig(kubeContext, kubeconfigPath)
	clientset := KubernetesClientset(config)
	return &kubernetesClient{
		config:    config,
		clientset: clientset,
	}
}

// NewKubernetesClientWith creates a new KubernetesClient using the provides clientset
func NewKubernetesClientWith(clientset *kubernetes.Clientset) KubernetesClient {
	return &kubernetesClient{
		clientset: clientset,
	}
}

func (k *kubernetesClient) GetContainersInNamespaces(labelSelector string) ([]ContainerSummary, error) {
	namespaceList, err := k.getNamespaces(labelSelector)
	if err != nil {
		return nil, fmt.Errorf("unable to list namespaces: %v", err)
	}

	// get all pods running for now
	// then we could get all the deployment and statefulset, job, cronjob, to gather all the images which are not running during the scan
	// pod manifest should be available in the kube-system namespace
	return k.getAllPodContainersInNamespaces(namespaceList)
}

func (k *kubernetesClient) getAllPodContainersInNamespaces(namespaceList *v1.NamespaceList) ([]ContainerSummary, error) {
	var containers []ContainerSummary
	for _, namespace := range namespaceList.Items {
		logr.Infof("Getting pods from namespace %s", namespace.Name)
		podList, err := k.clientset.CoreV1().Pods(namespace.Name).List(metaV1.ListOptions{})
		if err != nil {
			logr.Errorf("unable to find pods in namespace %sL %v", namespace.Namespace, err)
			// TODO continue to the next namespace?
		}
		if len(podList.Items) == 0 {
			logr.Warnf("no pods found in namespace: %s %v", namespace.Namespace, err)
			// continue as some namespaces may have scaled down deployments
		}

		for _, pod := range podList.Items {
			logr.Infof("pod %s in namespace %s", pod.Name, pod.Namespace)
			for _, container := range pod.Spec.Containers {
				containers = append(containers, ContainerSummary{
					Namespace:       pod.Namespace,
					NamespaceLabels: namespace.Labels,
					PodName:         pod.Name,
					ContainerName:   container.Name,
					Image:           container.Image,
				})
			}
		}
	}
	return containers, nil
}

func (k *kubernetesClient) getNamespaces(labelSelector string) (*v1.NamespaceList, error) {
	options := metaV1.ListOptions{}
	if labelSelector != "" {
		options.LabelSelector = labelSelector
	}

	namespaceList, err := k.clientset.CoreV1().Namespaces().List(options)
	if err != nil {
		return nil, fmt.Errorf("unable to find namespaces: %v", err)
	}

	if len(namespaceList.Items) == 0 {
		return nil, fmt.Errorf("no namespaces found")
	}

	return namespaceList, nil
}
