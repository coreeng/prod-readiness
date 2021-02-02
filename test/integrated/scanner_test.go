package integrated

import (
	"fmt"
	"os"
	"testing"

	"github.com/coreeng/production-readiness/production-readiness/pkg/k8s"
	"github.com/coreeng/production-readiness/production-readiness/pkg/scanner"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestBackupIntegratedTest(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integrated Scanner Suite")
}

var _ = Describe("Scan Images", func() {

	var (
		scan *scanner.Scanner
	)

	BeforeEach(func() {
		kubeContext := "kind-kind-production-readiness"
		kubeconfigPath := fmt.Sprintf("%s/.kube/kind-production-readiness", os.Getenv("HOME"))
		kubeconfig := k8s.KubernetesConfig(kubeContext, kubeconfigPath)
		clientset := k8s.KubernetesClient(kubeconfig)
		scan = scanner.New(kubeconfig, clientset)
	})

	It("should scan images", func() {
		config := &scanner.Config{
			LogLevel:             "info",
			Workers:              5,
			ImageNameReplacement: "",
		}

		// to be finished includes all the function inside ScanImages to test output of each of them
		err := scan.ScanImages(config)
		Expect(err).NotTo(HaveOccurred())
	})
})
