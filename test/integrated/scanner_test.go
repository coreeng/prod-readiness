package integrated

import (
	"context"
	"time"

	"testing"

	"github.com/coreeng/production-readiness/production-readiness/pkg/k8s"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/coreeng/production-readiness/production-readiness/pkg/scanner"
	. "github.com/coreeng/production-readiness/production-readiness/test"
	. "github.com/onsi/ginkgo/v2"
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

var (
	terminateImmediately = int64(0)
	scan                 *scanner.Scanner
	env                  *Environment
	f                    *Fixture
)
var _ = BeforeSuite(func() {
	env = NewIntegratedEnv()
	f = NewFixture(env)
	config := &scanner.Config{
		LogLevel:         "info",
		Workers:          3,
		AreaLabels:       areaLabel,
		TeamsLabels:      teamLabel,
		FilterLabels:     areaLabel,
		Severity:         "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
		ScanImageTimeout: time.Minute,
	}
	scan = scanner.New(k8s.NewKubernetesClientWith(env.KubeClientset), config)
	f.DeleteNamespaces("namespace1", "namespace2")
	f.CreateNamespace("namespace1", map[string]string{areaLabel: "area1", teamLabel: "team1"})
	f.CreateNamespace("namespace2", map[string]string{areaLabel: "area1", teamLabel: "team2"})
})

var _ = Describe("Scan Images", func() {

	BeforeEach(func() {
		f.DeletePods("namespace1", "namespace2")
	})

	It("should produce a vulnerability report for the scanned images", func() {
		// given
		// team-1
		team1Pod, err := env.KubeClientset.CoreV1().Pods("namespace1").Create(context.Background(), &v1.Pod{
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
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// team2
		team2Pod, err := env.KubeClientset.CoreV1().Pods("namespace2").Create(context.Background(), &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "nginx-pod1"},
			Spec: v1.PodSpec{
				Containers:                    []v1.Container{{Name: "container", Image: "nginx:1.15-alpine"}},
				TerminationGracePeriodSeconds: &terminateImmediately,
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		team3Pod, err := env.KubeClientset.CoreV1().Pods("namespace2").Create(context.Background(), &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "nginx-pod2"},
			Spec: v1.PodSpec{
				Containers:                    []v1.Container{{Name: "container", Image: "nginx:1.15-alpine"}},
				TerminationGracePeriodSeconds: &terminateImmediately,
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		Eventually(f.PodIsReady(types.NamespacedName{Namespace: team1Pod.Namespace, Name: team1Pod.Name}))
		Eventually(f.PodIsReady(types.NamespacedName{Namespace: team2Pod.Namespace, Name: team2Pod.Name}))
		Eventually(f.PodIsReady(types.NamespacedName{Namespace: team3Pod.Namespace, Name: team3Pod.Name}))

		// when
		report, err := scan.ScanImages()
		Expect(err).NotTo(HaveOccurred())

		// then
		Expect(report.ScannedImages).To(HaveLen(3))
		Expect(report.AreaSummary).To(HaveLen(1))
		Expect(report.AreaSummary["area1"].ImageCount).To(Equal(3))
		Expect(report.AreaSummary["area1"].ContainerCount).To(Equal(4))
		Expect(countOf(report.AreaSummary["area1"].TotalVulnerabilityBySeverity)).To(BeNumerically(">", 0))
		Expect(report.AreaSummary["area1"].TotalVulnerabilityBySeverity).To(And(
			HaveKey("CRITICAL"),
			HaveKey("HIGH"),
			HaveKey("MEDIUM"),
			HaveKey("LOW"),
			HaveKey("UNKNOWN"),
		))
		Expect(report.AreaSummary["area1"].Teams).To(HaveLen(2))

		team1 := report.AreaSummary["area1"].Teams["team1"]
		Expect(team1.ImageCount).To(Equal(2))
		Expect(team1.ContainerCount).To(Equal(2))
		Expect(vulnerabilityFor(team1, "alpine:3.11.0").ContainerCount).To(Equal(1))
		Expect(countOf(vulnerabilityFor(team1, "alpine:3.11.0").TotalVulnerabilityBySeverity)).To(BeNumerically(">", 0))
		Expect(vulnerabilityFor(team1, "alpine:3.12.0").ContainerCount).To(Equal(1))
		Expect(countOf(vulnerabilityFor(team1, "alpine:3.12.0").TotalVulnerabilityBySeverity)).To(BeNumerically(">", 0))

		team2 := report.AreaSummary["area1"].Teams["team2"]
		Expect(team2.ImageCount).To(Equal(1))
		Expect(team2.Images[0].TrivyOutputResults).To(HaveLen(1))
		Expect(len(team2.Images[0].TrivyOutputResults[0].Vulnerabilities)).To(BeNumerically(">", 0))
		Expect(team2.Images[0].TrivyOutputResults[0].Vulnerabilities).To(BeOrderedByHighestSeverity())
		Expect(team2.ContainerCount).To(Equal(2))
		Expect(vulnerabilityFor(team2, "nginx:1.15-alpine").ContainerCount).To(Equal(2))
		Expect(countOf(vulnerabilityFor(team2, "nginx:1.15-alpine").TotalVulnerabilityBySeverity)).To(BeNumerically(">", 0))
		Expect(vulnerabilityFor(team2, "nginx:1.15-alpine").TotalVulnerabilityBySeverity).To(And(
			HaveKey("CRITICAL"),
			HaveKey("HIGH"),
			HaveKey("MEDIUM"),
			HaveKey("LOW"),
			HaveKey("UNKNOWN"),
		))
	})

	It("should not report pods in empty namespaces", func() {
		// given
		teamPod, err := env.KubeClientset.CoreV1().Pods("namespace2").Create(context.Background(), &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "nginx-pod1"},
			Spec: v1.PodSpec{
				Containers:                    []v1.Container{{Name: "container", Image: "nginx:1.15-alpine"}},
				TerminationGracePeriodSeconds: &terminateImmediately,
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		Eventually(f.PodIsReady(types.NamespacedName{Namespace: teamPod.Namespace, Name: teamPod.Name}))

		// when
		report, err := scan.ScanImages()
		Expect(err).NotTo(HaveOccurred())

		// then
		Expect(report.ScannedImages).To(HaveLen(1))
		Expect(report.AreaSummary["area1"].ImageCount).To(Equal(1))
		Expect(report.AreaSummary["area1"].ContainerCount).To(Equal(1))
		Expect(report.AreaSummary["area1"].Teams).To(And(HaveLen(1), HaveKey("team2")))
		Expect(report.AreaSummary["area1"].Teams["team2"].ImageCount).To(Equal(1))
		Expect(report.AreaSummary["area1"].Teams["team2"].ContainerCount).To(Equal(1))
	})
})

func vulnerabilityFor(summary *scanner.TeamSummary, image string) scanner.VulnerabilitySummary {
	for _, i := range summary.Images {
		if i.ImageName == image {
			return i.VulnerabilitySummary
		}
	}
	return scanner.VulnerabilitySummary{}
}

func countOf(severity map[string]int) (int, error) {
	vulnerabilityCount := 0
	for _, count := range severity {
		vulnerabilityCount += count
	}
	return vulnerabilityCount, nil
}
