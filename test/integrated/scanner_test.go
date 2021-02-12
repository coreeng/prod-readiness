package integrated

import (
	"testing"

	"github.com/coreeng/production-readiness/production-readiness/pkg/k8s"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/coreeng/production-readiness/production-readiness/pkg/scanner"
	. "github.com/coreeng/production-readiness/production-readiness/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	areaLabel = "area-label"
	teamLabel = "team-label"
)

func TestScannerIntegratedTest(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integrated Scanner Suite")
}

var _ = Describe("Scan Images", func() {

	var (
		terminateImmediately = int64(0)
		scan                 *scanner.Scanner
		env                  *Environment
		f                    *Fixture
	)

	BeforeSuite(func() {
		env = NewIntegratedEnv()
		f = NewFixture(env)
		config := &scanner.Config{
			LogLevel:     "info",
			Workers:      3,
			AreaLabels:   areaLabel,
			TeamsLabels:  teamLabel,
			FilterLabels: areaLabel,
			Severity:     "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
		}
		scan = scanner.New(k8s.NewKubernetesClientWith(env.KubeClientset), config)
		f.DeleteNamespaces("namespace1", "namespace2")
	})

	BeforeEach(func() {
		f.CreateNamespace("namespace1", map[string]string{areaLabel: "area1", teamLabel: "team1"})
		f.CreateNamespace("namespace2", map[string]string{areaLabel: "area1", teamLabel: "team2"})
	})

	It("should produce a vulnerability report for the scanned images", func() {
		// given
		// team-1
		team1Pod, err := env.KubeClientset.CoreV1().Pods("namespace1").Create(&v1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1"},
			Spec: v1.PodSpec{
				Containers: []v1.Container{
					{
						Name:    "container1",
						Image:   "alpine:3.11.0",
						Command: []string{"/bin/sh", "-c", "sleep 600"},
					},
					{
						Name:    "container2",
						Image:   "alpine:3.12.0",
						Command: []string{"/bin/sh", "-c", "sleep 600"},
					},
				},
				TerminationGracePeriodSeconds: &terminateImmediately,
			},
		})
		Expect(err).NotTo(HaveOccurred())

		// team2
		team2Pod, err := env.KubeClientset.CoreV1().Pods("namespace2").Create(&v1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "nginx-pod1"},
			Spec: v1.PodSpec{
				Containers:                    []v1.Container{{Name: "container", Image: "nginx:1.15-alpine"}},
				TerminationGracePeriodSeconds: &terminateImmediately,
			},
		})
		Expect(err).NotTo(HaveOccurred())
		team3Pod, err := env.KubeClientset.CoreV1().Pods("namespace2").Create(&v1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "nginx-pod2"},
			Spec: v1.PodSpec{
				Containers:                    []v1.Container{{Name: "container", Image: "nginx:1.15-alpine"}},
				TerminationGracePeriodSeconds: &terminateImmediately,
			},
		})
		Expect(err).NotTo(HaveOccurred())
		Eventually(f.PodIsReady(types.NamespacedName{Namespace: team1Pod.Namespace, Name: team1Pod.Name}))
		Eventually(f.PodIsReady(types.NamespacedName{Namespace: team2Pod.Namespace, Name: team2Pod.Name}))
		Eventually(f.PodIsReady(types.NamespacedName{Namespace: team3Pod.Namespace, Name: team3Pod.Name}))

		// when
		report, err := scan.ScanImages()
		Expect(err).NotTo(HaveOccurred())

		// then
		Expect(report.ScannedImages).To(HaveLen(3))
		Expect(report.ImageByArea).To(HaveLen(1))
		Expect(report.ImageByArea["area1"].Summary.ImageCount).To(Equal(3))
		Expect(report.ImageByArea["area1"].Summary.ContainerCount).To(Equal(4))
		Expect(vulnerabilityCountOf(report.ImageByArea["area1"].Summary.TotalVulnerabilityBySeverity)).To(BeNumerically(">", 0))
		Expect(report.ImageByArea["area1"].Summary.TotalVulnerabilityBySeverity).To(And(
			HaveKey("CRITICAL"),
			HaveKey("HIGH"),
			HaveKey("MEDIUM"),
			HaveKey("LOW"),
		))
		Expect(report.ImageByArea["area1"].Teams).To(HaveLen(2))

		team1 := report.ImageByArea["area1"].Teams["team1"]
		Expect(team1.ImageCount).To(Equal(2))
		Expect(team1.ContainerCount).To(Equal(2))
		Expect(team1.Summary.ImageVulnerabilitySummary["alpine:3.11.0"].ContainerCount).To(Equal(1))
		Expect(vulnerabilityCountOf(team1.Summary.ImageVulnerabilitySummary["alpine:3.11.0"].TotalVulnerabilityBySeverity)).To(BeNumerically(">", 0))
		Expect(team1.Summary.ImageVulnerabilitySummary["alpine:3.12.0"].ContainerCount).To(Equal(1))
		Expect(vulnerabilityCountOf(team1.Summary.ImageVulnerabilitySummary["alpine:3.12.0"].TotalVulnerabilityBySeverity)).To(BeNumerically(">", 0))

		team2 := report.ImageByArea["area1"].Teams["team2"]
		Expect(team2.ImageCount).To(Equal(1))
		Expect(team2.Images[0].TrivyOutput).To(HaveLen(1))
		Expect(len(team2.Images[0].TrivyOutput[0].Vulnerabilities)).To(BeNumerically(">", 0))
		Expect(team2.Images[0].TrivyOutput[0].Vulnerabilities).To(BeOrderedByHighestSeverity())
		Expect(team2.ContainerCount).To(Equal(2))
		Expect(team2.Summary.ImageVulnerabilitySummary["nginx:1.15-alpine"].ContainerCount).To(Equal(2))
		Expect(vulnerabilityCountOf(team2.Summary.ImageVulnerabilitySummary["nginx:1.15-alpine"].TotalVulnerabilityBySeverity)).To(BeNumerically(">", 0))
	})
})

func vulnerabilityCountOf(severity map[string]int) (int, error) {
	vulnerabilityCount := 0
	for _, count := range severity {
		vulnerabilityCount += count
	}
	return vulnerabilityCount, nil
}
