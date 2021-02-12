package scanner

import (
	"testing"

	"github.com/coreeng/production-readiness/production-readiness/pkg/k8s"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestScanner(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Scanner Suite")
}

var _ = Describe("Scan Images", func() {

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

	Describe("Trivyoutput sorting", func() {
		It("should sort the vulnerabilility by severity", func() {
			output := []TrivyOutput{
				{
					Target: "allSeverities",
					Vulnerabilities: []Vulnerabilities{
						{Severity: "LOW"}, {Severity: "MEDIUM"}, {Severity: "UNKNOWN"}, {Severity: "HIGH"}, {Severity: "CRITICAL"},
					},
				},
				{
					Target: "multipleSeveritiesNoUnknowns",
					Vulnerabilities: []Vulnerabilities{
						{Severity: "MEDIUM"}, {Severity: "LOW"}, {Severity: "HIGH"}, {Severity: "CRITICAL"}, {Severity: "HIGH"}, {Severity: "CRITICAL"}, {Severity: "LOW"}, {Severity: "MEDIUM"},
					},
				},
			}
			sortedOutput := sortTrivyVulnerabilities(output)
			Expect(sortedOutput).To(HaveLen(2))
			Expect(sortedOutput[0].Target).To(Equal("allSeverities"))
			Expect(sortedOutput[0].Vulnerabilities).To(HaveLen(5))
			Expect(sortedOutput[0].Vulnerabilities).To(Equal(
				[]Vulnerabilities{
					{Severity: "CRITICAL"}, {Severity: "HIGH"}, {Severity: "MEDIUM"}, {Severity: "LOW"}, {Severity: "UNKNOWN"},
				},
			))
			Expect(sortedOutput[1].Target).To(Equal("multipleSeveritiesNoUnknowns"))
			Expect(sortedOutput[1].Vulnerabilities).To(HaveLen(8))
			Expect(sortedOutput[1].Vulnerabilities).To(Equal(
				[]Vulnerabilities{
					{Severity: "CRITICAL"}, {Severity: "CRITICAL"}, {Severity: "HIGH"}, {Severity: "HIGH"}, {Severity: "MEDIUM"}, {Severity: "MEDIUM"}, {Severity: "LOW"}, {Severity: "LOW"},
				},
			))
		})
	})

})
