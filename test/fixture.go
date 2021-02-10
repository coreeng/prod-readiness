package test

import (
	"time"

	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type Fixture struct {
	env *Environment
}

func NewFixture(env *Environment) *Fixture {
	return &Fixture{env}
}

func (f *Fixture) CreateNamespace(name string, labels map[string]string) {
	_, err := f.env.KubeClientset.CoreV1().Namespaces().Create(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
	})
	Expect(err).NotTo(HaveOccurred())
}

func (f *Fixture) DeleteNamespaces(namespaces ...string) {
	for _, namespace := range namespaces {
		err := f.env.KubeClientset.CoreV1().Namespaces().Delete(namespace, &metav1.DeleteOptions{})
		if errors.IsNotFound(err) {
			continue
		}
		Expect(err).NotTo(HaveOccurred())
		Eventually(f.NamespaceIsAbsent(namespace), 20*time.Second, time.Second).Should(BeTrue())
	}
}

func (f *Fixture) NamespaceIsAbsent(namespace string) func() (bool, error) {
	return func() (bool, error) {
		_, err := f.env.KubeClientset.CoreV1().Namespaces().Get(namespace, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}
}

func (f *Fixture) PodIsReady(podName types.NamespacedName) func() (bool, error) {
	return func() (bool, error) {
		pod, err := f.env.KubeClientset.CoreV1().Pods(podName.Namespace).Get(podName.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if !podReadyCondition(pod) {
			return false, nil
		}
		return true, nil
	}
}

func podReadyCondition(pod *v1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == v1.PodReady {
			return condition.Status == v1.ConditionTrue
		}
	}
	return false
}
