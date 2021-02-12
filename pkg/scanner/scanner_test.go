package scanner

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/coreeng/production-readiness/production-readiness/pkg/k8s"

	"github.com/onsi/gomega/types"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestManager(t *testing.T) {
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

	Describe("Area grouping", func() {

		var (
			areaLabel, teamLabel string
			scan                 *Scanner
		)

		BeforeEach(func() {
			areaLabel = "areas-label"
			teamLabel = "teams-label"
			scan = &Scanner{config: &Config{
				AreaLabels:  areaLabel,
				TeamsLabels: teamLabel,
			}}
		})

		It("groups images per team and area", func() {
			imageSpecs := []ScannedImage{
				{
					ImageName: "image1",
					Containers: []k8s.ContainerSummary{
						{
							Namespace:       "namespace1",
							NamespaceLabels: map[string]string{areaLabel: "area1", teamLabel: "team1"},
							PodName:         "pod1",
						},
					},
				},
				{
					ImageName: "image2",
					Containers: []k8s.ContainerSummary{
						{
							Namespace:       "namespace1",
							NamespaceLabels: map[string]string{areaLabel: "area1", teamLabel: "team1"},
							PodName:         "pod2",
						},
					},
				},
				{
					ImageName: "image3",
					Containers: []k8s.ContainerSummary{
						{
							Namespace:       "namespace2",
							PodName:         "pod3",
							NamespaceLabels: map[string]string{areaLabel: "area1", teamLabel: "team2"},
						},
					},
				},
				{
					ImageName: "image4",
					Containers: []k8s.ContainerSummary{
						{
							Namespace:       "namespace3",
							PodName:         "pod4",
							NamespaceLabels: map[string]string{areaLabel: "area2", teamLabel: "team3"},
						},
					},
				},
			}

			// when
			imageByArea, err := scan.generateAreaGrouping(imageSpecs)

			// then
			Expect(err).NotTo(HaveOccurred())
			Expect(imageByArea["area1"].Teams).Should(HaveLen(2))
			Expect(imageByArea["area1"].Teams["team1"].Images).Should(HaveImages("image1", "image2"))
			Expect(imageByArea["area1"].Teams["team1"].Containers[0].NamespaceLabels).Should(And(
				HaveKeyWithValue(areaLabel, "area1"),
				HaveKeyWithValue(teamLabel, "team1"),
			))

			Expect(imageByArea["area1"].Teams["team2"].Images).Should(HaveImages("image3"))
			Expect(imageByArea["area1"].Teams["team2"].Containers[0].NamespaceLabels).Should(And(
				HaveKeyWithValue(areaLabel, "area1"),
				HaveKeyWithValue(teamLabel, "team2"),
			))

			Expect(imageByArea["area2"].Teams).Should(HaveLen(1))
			Expect(imageByArea["area2"].Teams["team3"].Images).Should(HaveImages("image4"))
			Expect(imageByArea["area2"].Teams["team3"].Containers[0].NamespaceLabels).Should(And(
				HaveKeyWithValue(areaLabel, "area2"),
				HaveKeyWithValue(teamLabel, "team3"),
			))
		})

		It("list the same image found in multiple pods only once", func() {
			scannedImages := []ScannedImage{
				{
					ImageName: "image1",
					Containers: []k8s.ContainerSummary{
						{
							Namespace:       "namespace1",
							NamespaceLabels: map[string]string{areaLabel: "area1", teamLabel: "team1"},
							PodName:         "pod1",
						},
						{
							Namespace:       "namespace1",
							NamespaceLabels: map[string]string{areaLabel: "area1", teamLabel: "team1"},
							PodName:         "pod2",
						},
						{
							Namespace:       "namespace2",
							NamespaceLabels: map[string]string{areaLabel: "area1", teamLabel: "team2"},
							PodName:         "pod3",
						},
					},
				},
			}
			// when
			imageByArea, err := scan.generateAreaGrouping(scannedImages)

			// then
			Expect(err).NotTo(HaveOccurred())
			Expect(imageByArea["area1"].Teams).Should(HaveLen(2))
			Expect(imageByArea["area1"].Teams["team1"].Images).Should(HaveImages("image1"))
			Expect(imageByArea["area1"].Teams["team1"].ImageCount).Should(Equal(1))
			Expect(imageByArea["area1"].Teams["team1"].Containers).Should(HaveLen(2))
			Expect(imageByArea["area1"].Teams["team1"].ContainerCount).Should(Equal(2))
			Expect(imageByArea["area1"].Teams["team1"].Containers[0].PodName).Should(Equal("pod1"))
			Expect(imageByArea["area1"].Teams["team1"].Containers[1].PodName).Should(Equal("pod2"))

			Expect(imageByArea["area1"].Teams["team2"].Images).Should(HaveImages("image1"))
			Expect(imageByArea["area1"].Teams["team2"].ImageCount).Should(Equal(1))
			Expect(imageByArea["area1"].Teams["team2"].Containers).Should(HaveLen(1))
			Expect(imageByArea["area1"].Teams["team2"].ContainerCount).Should(Equal(1))
			Expect(imageByArea["area1"].Teams["team2"].Containers[0].PodName).Should(Equal("pod3"))
		})

		It("sort teams images by criticality", func() {
			team1Pod := k8s.ContainerSummary{
				Namespace:       "namespace1",
				NamespaceLabels: map[string]string{areaLabel: "area1", teamLabel: "team1"},
				PodName:         "pod1",
			}

			team2Pod := k8s.ContainerSummary{
				Namespace:       "namespace1",
				NamespaceLabels: map[string]string{areaLabel: "area1", teamLabel: "team2"},
				PodName:         "pod1",
			}

			scannedImages := []ScannedImage{
				{
					ImageName:  "mostCriticalTeam2",
					Containers: []k8s.ContainerSummary{team2Pod},
					TotalVulnerabilityBySeverity: map[string]int{
						"CRITICAL": 1,
						"HIGH":     5,
						"MEDIUM":   0,
						"LOW":      0,
					},
				},
				{
					ImageName:  "leastCriticalTeam2",
					Containers: []k8s.ContainerSummary{team2Pod},
					TotalVulnerabilityBySeverity: map[string]int{
						"CRITICAL": 0,
						"HIGH":     6,
						"MEDIUM":   10,
						"LOW":      25,
					},
				},
				{
					ImageName:  "mostCritical",
					Containers: []k8s.ContainerSummary{team1Pod},
					TotalVulnerabilityBySeverity: map[string]int{
						"CRITICAL": 4,
						"HIGH":     5,
						"MEDIUM":   10,
						"LOW":      25,
					},
				},
				{
					ImageName:  "mostHighAfterSameCritical",
					Containers: []k8s.ContainerSummary{team1Pod},
					TotalVulnerabilityBySeverity: map[string]int{
						"CRITICAL": 3,
						"HIGH":     6,
						"MEDIUM":   11,
						"LOW":      26,
					},
				},
				{
					ImageName:  "mostMediumAfterSameCriticalAndHigh",
					Containers: []k8s.ContainerSummary{team1Pod},
					TotalVulnerabilityBySeverity: map[string]int{
						"CRITICAL": 3,
						"HIGH":     5,
						"MEDIUM":   12,
						"LOW":      27,
					},
				},
				{
					ImageName:  "leastCriticalTeam1",
					Containers: []k8s.ContainerSummary{team1Pod},
					TotalVulnerabilityBySeverity: map[string]int{
						"CRITICAL": 3,
						"HIGH":     5,
						"MEDIUM":   11,
						"LOW":      28,
					},
				},
			}

			// when
			imageByArea, err := scan.generateAreaGrouping(scannedImages)

			// then
			Expect(err).NotTo(HaveOccurred())
			Expect(imageByArea["area1"].Teams["team1"].Images).To(HaveLen(4))
			Expect(imageByArea["area1"].Teams["team1"].Images[0].ImageName).To(Equal("mostCritical"))
			Expect(imageByArea["area1"].Teams["team1"].Images[1].ImageName).To(Equal("mostHighAfterSameCritical"))
			Expect(imageByArea["area1"].Teams["team1"].Images[2].ImageName).To(Equal("mostMediumAfterSameCriticalAndHigh"))
			Expect(imageByArea["area1"].Teams["team1"].Images[3].ImageName).To(Equal("leastCriticalTeam1"))

			Expect(imageByArea["area1"].Teams["team2"].Images).To(HaveLen(2))
			Expect(imageByArea["area1"].Teams["team2"].Images[0].ImageName).To(Equal("mostCriticalTeam2"))
			Expect(imageByArea["area1"].Teams["team2"].Images[1].ImageName).To(Equal("leastCriticalTeam2"))
		})

		It("sum up the vulnerabilities per area and criticality", func() {
			team1Pod := k8s.ContainerSummary{
				Namespace:       "namespace1",
				NamespaceLabels: map[string]string{areaLabel: "area1", teamLabel: "team1"},
				PodName:         "pod1",
			}
			team2Pod := k8s.ContainerSummary{
				Namespace:       "namespace1",
				NamespaceLabels: map[string]string{areaLabel: "area1", teamLabel: "team2"},
				PodName:         "pod1",
			}
			team3Pod1 := k8s.ContainerSummary{
				Namespace:       "namespace1",
				NamespaceLabels: map[string]string{areaLabel: "area2", teamLabel: "team3"},
				PodName:         "pod1",
			}
			team3Pod2 := k8s.ContainerSummary{
				Namespace:       "namespace1",
				NamespaceLabels: map[string]string{areaLabel: "area2", teamLabel: "team3"},
				PodName:         "pod2",
			}
			team3Pod3 := k8s.ContainerSummary{
				Namespace:       "namespace2",
				NamespaceLabels: map[string]string{areaLabel: "area2", teamLabel: "team3"},
				PodName:         "pod3",
			}

			scannedImages := []ScannedImage{
				{
					ImageName:  "area1-team1-image1",
					Containers: []k8s.ContainerSummary{team1Pod},
					TotalVulnerabilityBySeverity: map[string]int{
						"CRITICAL": 1,
						"HIGH":     5,
						"MEDIUM":   0,
						"LOW":      2,
						"UNKNOWN":  1,
					},
				},
				{
					ImageName:  "area1-team1-image2",
					Containers: []k8s.ContainerSummary{team1Pod},
					TotalVulnerabilityBySeverity: map[string]int{
						"CRITICAL": 2,
						"HIGH":     12,
						"MEDIUM":   4,
						"LOW":      1,
						"UNKNOWN":  0,
					},
				},
				{
					ImageName:  "area1-team1-image2",
					Containers: []k8s.ContainerSummary{team2Pod},
					TotalVulnerabilityBySeverity: map[string]int{
						"CRITICAL": 1,
						"HIGH":     2,
						"MEDIUM":   4,
						"LOW":      1,
						"UNKNOWN":  0,
					},
				},
				{
					ImageName:  "area2-team3-image1",
					Containers: []k8s.ContainerSummary{team3Pod1, team3Pod2, team3Pod3},
					TotalVulnerabilityBySeverity: map[string]int{
						"CRITICAL": 1,
						"HIGH":     5,
						"MEDIUM":   0,
						"LOW":      0,
						"UNKNOWN":  0,
					},
				},
			}

			// when
			imageByArea, err := scan.generateAreaGrouping(scannedImages)

			// then
			Expect(err).NotTo(HaveOccurred())
			Expect(imageByArea).To(HaveLen(2))
			Expect(imageByArea["area1"].Summary.ImageCount).To(Equal(3))
			Expect(imageByArea["area1"].Summary.ContainerCount).To(Equal(3))
			Expect(imageByArea["area1"].Summary.TotalVulnerabilityBySeverity).To(Equal(
				map[string]int{"CRITICAL": 4, "HIGH": 19, "MEDIUM": 8, "LOW": 4, "UNKNOWN": 1}),
			)
			Expect(imageByArea["area1"].Teams["team1"].Summary.ImageVulnerabilitySummary["area1-team1-image1"].ContainerCount).To(Equal(1))
			Expect(imageByArea["area1"].Teams["team1"].Summary.ImageVulnerabilitySummary["area1-team1-image1"].TotalVulnerabilityBySeverity).To(Equal(
				map[string]int{"CRITICAL": 1, "HIGH": 5, "MEDIUM": 0, "LOW": 2, "UNKNOWN": 1},
			))

			Expect(imageByArea["area2"].Summary.ImageCount).To(Equal(1))
			Expect(imageByArea["area2"].Summary.ContainerCount).To(Equal(3))
			Expect(imageByArea["area2"].Summary.TotalVulnerabilityBySeverity).To(Equal(
				map[string]int{"CRITICAL": 1, "HIGH": 5, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}),
			)
			Expect(imageByArea["area2"].Teams["team3"].Summary.ImageVulnerabilitySummary["area2-team3-image1"].ContainerCount).To(Equal(3))
			Expect(imageByArea["area2"].Teams["team3"].Summary.ImageVulnerabilitySummary["area2-team3-image1"].TotalVulnerabilityBySeverity).To(Equal(
				map[string]int{"CRITICAL": 1, "HIGH": 5, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
			))
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

func HaveImages(images ...string) types.GomegaMatcher {
	return &haveImages{expectedImages: images}
}

type haveImages struct {
	expectedImages []string
}

func (m *haveImages) Match(actual interface{}) (success bool, err error) {
	var actualImages []string
	imagesSpecs := actual.([]ScannedImage)
	for _, imageSpec := range imagesSpecs {
		actualImages = append(actualImages, imageSpec.ImageName)
	}
	sort.Strings(m.expectedImages)
	sort.Strings(actualImages)
	return reflect.DeepEqual(actualImages, m.expectedImages), nil
}

func (m *haveImages) FailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("Expected: %v. \nActual response body: %s", m.expectedImages, actual)
}

func (m *haveImages) NegatedFailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("Expected: %v. \nActual response body: %s", m.expectedImages, actual)
}
