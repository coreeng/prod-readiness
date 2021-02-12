package scanner

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/coreeng/production-readiness/production-readiness/pkg/k8s"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestScanner(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Scanner Suite")
}

var _ = Describe("Scanner", func() {

	Describe("string replacement", func() {
		var (
			scan *Scanner
		)

		BeforeEach(func() {
			scan = &Scanner{}
		})

		It("Can replace string", func() {
			imageName := "registry/test/production-readiness"

			valueAsString, err := scan.stringReplacement(imageName, "registry|registry.com,test|extended-test")

			Expect(err).NotTo(HaveOccurred())
			Expect(valueAsString).To(Equal("registry.com/extended-test/production-readiness"))
		})

		It("Can replace string with empty string", func() {
			imageName := "registry/test/production-readiness"

			valueAsString, err := scan.stringReplacement(imageName, "")

			Expect(err).NotTo(HaveOccurred())
			Expect(valueAsString).To(Equal("registry/test/production-readiness"))
		})

		It("Will not replace string with wrong pattern", func() {
			imageName := "registry/test/production-readiness"

			valueAsString, err := scan.stringReplacement(imageName, "registry|wrong|registry.com,test|extended-test")

			Expect(err).To(HaveOccurred())
			Expect(valueAsString).To(Equal("registry/test/production-readiness"))
		})
	})

	Describe("GroupContainersByImageName", func() {
		var (
			scan *Scanner
		)

		BeforeEach(func() {
			scan = &Scanner{}
		})

		It("GroupContainersByImageName should return an unique map", func() {
			container1 := k8s.ContainerSummary{Image: "ubuntu:latest", PodName: "podName1", ContainerName: "containerName1"}
			container2 := k8s.ContainerSummary{Image: "ubuntu:trusty", PodName: "podName1", ContainerName: "containerName2"}
			container3 := k8s.ContainerSummary{Image: "ubuntu:latest", PodName: "podName2", ContainerName: "containerName3"}
			container4 := k8s.ContainerSummary{Image: "gcr.io:name", PodName: "podName2", ContainerName: "containerName4"}

			// when
			actualMap := scan.groupContainersByImageName([]k8s.ContainerSummary{
				container1, container2, container3, container4,
			})

			// then
			expectedMap := map[string][]k8s.ContainerSummary{
				"ubuntu:latest": {container1, container3},
				"ubuntu:trusty": {container2},
				"gcr.io:name":   {container4},
			}
			Expect(actualMap).To(Equal(expectedMap))
		})
	})

	Describe("Compute vulnerability breakdown", func() {
		It("count the number of vulnerability per severity", func() {
			trivyOutput := []TrivyOutput{
				{
					Vulnerabilities: []Vulnerabilities{
						{Severity: "CRITICAL"},
						{Severity: "MEDIUM"},
					},
				},
				{
					Vulnerabilities: []Vulnerabilities{
						{Severity: "CRITICAL"}, {Severity: "CRITICAL"},
						{Severity: "HIGH"}, {Severity: "HIGH"},
						{Severity: "MEDIUM"}, {Severity: "MEDIUM"},
						{Severity: "LOW"}, {Severity: "LOW"}, {Severity: "LOW"},
						{Severity: "UNKNOWN"}, {Severity: "UNKNOWN"}, {Severity: "UNKNOWN"},
					},
				},
			}
			severityMap := computeTotalVulnerabilityBySeverity(trivyOutput)
			Expect(severityMap).To(Equal(
				map[string]int{"CRITICAL": 3, "HIGH": 2, "MEDIUM": 3, "LOW": 3, "UNKNOWN": 3}),
			)
		})
	})

	Describe("scan processing", func() {
		const (
			areaLabel = "area-label"
		)

		var (
			scan                 *Scanner
			mockKubernetesClient *mockKubernetes
			mockTrivyClient      *mockTrivy
			mockDockerClient     *mockDocker
		)

		BeforeEach(func() {
			mockKubernetesClient = &mockKubernetes{}
			mockTrivyClient = &mockTrivy{}
			mockDockerClient = &mockDocker{}
			scan = &Scanner{
				config: &Config{
					Workers:              3,
					FilterLabels:         areaLabel,
					Severity:             "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
					ImageNameReplacement: "replace-this-registry|registry",
				},
				kubernetesClient: mockKubernetesClient,
				trivyClient:      mockTrivyClient,
				dockerClient:     mockDockerClient,
			}
		})

		It("should delete the pulled docker images once the scan is complete", func() {
			// given
			containers := []k8s.ContainerSummary{
				{
					Image:   "alpine:3.11.0",
					PodName: "pod1",
				},
				{
					Image:   "replace-this-registry/image:0.1",
					PodName: "pod1",
				},
			}
			mockKubernetesClient.On("GetContainersInNamespaces", areaLabel).Return(containers, nil)
			mockTrivyClient.On("DownloadDatabase").Return(nil)
			mockDockerClient.
				On("PullImage", "alpine:3.11.0").Return(nil).
				On("PullImage", "registry/image:0.1").Return(nil)
			mockTrivyClient.
				On("ScanImage", "alpine:3.11.0").Return([]TrivyOutput{}, nil).
				On("ScanImage", "registry/image:0.1").Return([]TrivyOutput{}, nil)
			mockDockerClient.
				On("RmiImage", "alpine:3.11.0").Return(nil).
				On("RmiImage", "registry/image:0.1").Return(nil)

			// when
			_, err := scan.ScanImages()
			Expect(err).NotTo(HaveOccurred())
		})

		It("should carry on processing the next image when error occurs processing the previous image", func() {
			// given
			containers := []k8s.ContainerSummary{
				{
					Image:   "alpine:3.11.0",
					PodName: "pod1",
				},
				{
					Image:   "replace-this-registry/image:0.1",
					PodName: "pod1",
				},
			}
			mockKubernetesClient.On("GetContainersInNamespaces", areaLabel).Return(containers, nil)
			mockTrivyClient.On("DownloadDatabase").Return(nil)
			mockDockerClient.
				On("PullImage", "alpine:3.11.0").Return(fmt.Errorf("some docker error")).
				On("PullImage", "registry/image:0.1").Return(nil)
			mockTrivyClient.
				On("ScanImage", "alpine:3.11.0").Return([]TrivyOutput{}, fmt.Errorf("some trivy error")).
				On("ScanImage", "registry/image:0.1").Return([]TrivyOutput{}, nil)
			mockDockerClient.
				On("RmiImage", "alpine:3.11.0").Return(fmt.Errorf("some docker error")).
				On("RmiImage", "registry/image:0.1").Return(nil)

			// when
			_, err := scan.ScanImages()
			Expect(err).NotTo(HaveOccurred())
		})
	})

})

type mockKubernetes struct {
	mock.Mock
}

// force implementation of k8s.KubernetesClient at compilation time
var _ k8s.KubernetesClient = &mockKubernetes{}

func (k *mockKubernetes) GetContainersInNamespaces(labelSelector string) ([]k8s.ContainerSummary, error) {
	args := k.Called(labelSelector)
	return args.Get(0).([]k8s.ContainerSummary), args.Error(1)
}

type mockTrivy struct {
	mock.Mock
}

// force implementation of TrivyClient at compilation time
var _ TrivyClient = &mockTrivy{}

func (t *mockTrivy) DownloadDatabase() error {
	args := t.Called()
	return args.Error(0)

}
func (t *mockTrivy) ScanImage(image string) ([]TrivyOutput, error) {
	args := t.Called(image)
	return args.Get(0).([]TrivyOutput), args.Error(1)
}

type mockDocker struct {
	mock.Mock
}

var _ DockerClient = &mockDocker{}

func (d *mockDocker) PullImage(image string) error {
	args := d.Called(image)
	return args.Error(0)
}

func (d *mockDocker) RmiImage(image string) error {
	args := d.Called(image)
	return args.Error(0)
}
