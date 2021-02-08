package scanner

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/onsi/gomega/types"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestManager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Scanner Suite")
}

var _ = Describe("Scan Images", func() {

	Context("string replacement", func() {
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

	Context("GetImagesList", func() {
		var (
			scan *Scanner
		)

		BeforeEach(func() {
			scan = &Scanner{}
		})

		It("GetImagesList should return an unique map", func() {
			podList1 := podDetail{
				Pod: v1.Pod{
					ObjectMeta: metaV1.ObjectMeta{
						Name: "podName1",
						Labels: map[string]string{
							"app.kubernetes.io/component": "test-app",
						},
					},
					Spec: v1.PodSpec{
						Containers: []v1.Container{
							{
								Name:  "containerName1",
								Image: "ubuntu:latest",
							},
							{
								Name:  "containerName2",
								Image: "ubuntu:trusty",
							},
						},
					},
				},
				Namespace: v1.Namespace{
					ObjectMeta: metaV1.ObjectMeta{
						Name: "test-namespace",
						Labels: map[string]string{
							"teams-name": "team-1",
						},
					},
				},
			}

			podList2 := podDetail{
				Pod: v1.Pod{
					ObjectMeta: metaV1.ObjectMeta{
						Name: "podName2",
						Labels: map[string]string{
							"app.kubernetes.io/component": "test-app",
						},
					},
					Spec: v1.PodSpec{
						Containers: []v1.Container{
							{
								Name:  "containerName3",
								Image: "ubuntu:latest",
							},
							{
								Name:  "containerName4",
								Image: "gcr.io:name",
							},
						},
					},
				},
				Namespace: v1.Namespace{
					ObjectMeta: metaV1.ObjectMeta{
						Name: "test-namespace",
						Labels: map[string]string{
							"teams-name": "team-2",
						},
					},
				},
			}

			// when
			imageList, err := scan.getImagesList([]podDetail{podList1, podList2})

			// then
			podSummary1 := PodSummary{Name: podList1.Pod.Name, Namespace: podList1.Namespace.Name, NamespaceLabels: podList1.Namespace.Labels}
			podSummary2 := PodSummary{Name: podList2.Pod.Name, Namespace: podList2.Namespace.Name, NamespaceLabels: podList2.Namespace.Labels}
			imageListExpected := map[string]*ImageSpec{
				"ubuntu:latest": {
					Pods: []PodSummary{podSummary1, podSummary2},
				},
				"ubuntu:trusty": {
					Pods: []PodSummary{podSummary1},
				},
				"gcr.io:name": {
					Pods: []PodSummary{podSummary2},
				},
			}

			Expect(err).NotTo(HaveOccurred())
			Expect(imageList).To(Equal(imageListExpected))
		})
	})

	Context("Area grouping", func() {

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
			imageSpecs := map[string]*ImageSpec{
				"image-1": {
					ImageName: "image-1",
					Pods: []PodSummary{
						{
							Namespace:       "namespace-1",
							NamespaceLabels: map[string]string{areaLabel: "area-1", teamLabel: "team-1"},
							Name:            "pod-1",
						},
					},
				},
				"image-2": {
					ImageName: "image-2",
					Pods: []PodSummary{
						{
							Namespace:       "namespace-1",
							NamespaceLabels: map[string]string{areaLabel: "area-1", teamLabel: "team-1"},
							Name:            "pod-2",
						},
					},
				},
				"image-3": {
					ImageName: "image-3",
					Pods: []PodSummary{
						{
							Namespace:       "namespace-2",
							Name:            "pod-3",
							NamespaceLabels: map[string]string{areaLabel: "area-1", teamLabel: "team-2"},
						},
					},
				},
				"image-4": {
					ImageName: "image-4",
					Pods: []PodSummary{
						{
							Namespace:       "namespace-3",
							Name:            "pod-4",
							NamespaceLabels: map[string]string{areaLabel: "area-2", teamLabel: "team-3"},
						},
					},
				},
			}

			// when
			imageByArea, err := scan.generateAreaGrouping(imageSpecs)

			// then
			Expect(err).NotTo(HaveOccurred())
			Expect(imageByArea["area-1"].Teams).Should(HaveLen(2))
			Expect(imageByArea["area-1"].Teams["team-1"].Images).Should(HaveImages("image-1", "image-2"))
			Expect(imageByArea["area-1"].Teams["team-1"].Pods[0].NamespaceLabels).Should(And(
				HaveKeyWithValue(areaLabel, "area-1"),
				HaveKeyWithValue(teamLabel, "team-1"),
			))

			Expect(imageByArea["area-1"].Teams["team-2"].Images).Should(HaveImages("image-3"))
			Expect(imageByArea["area-1"].Teams["team-2"].Pods[0].NamespaceLabels).Should(And(
				HaveKeyWithValue(areaLabel, "area-1"),
				HaveKeyWithValue(teamLabel, "team-2"),
			))

			Expect(imageByArea["area-2"].Teams).Should(HaveLen(1))
			Expect(imageByArea["area-2"].Teams["team-3"].Images).Should(HaveImages("image-4"))
			Expect(imageByArea["area-2"].Teams["team-3"].Pods[0].NamespaceLabels).Should(And(
				HaveKeyWithValue(areaLabel, "area-2"),
				HaveKeyWithValue(teamLabel, "team-3"),
			))
		})

		It("list the same image found in multiple pods only once", func() {
			imageSpecs := map[string]*ImageSpec{
				"image-1": {
					ImageName: "image-1",
					Pods: []PodSummary{
						{
							Namespace:       "namespace-1",
							NamespaceLabels: map[string]string{areaLabel: "area-1", teamLabel: "team-1"},
							Name:            "pod-1",
						},
						{
							Namespace:       "namespace-1",
							NamespaceLabels: map[string]string{areaLabel: "area-1", teamLabel: "team-1"},
							Name:            "pod-2",
						},
						{
							Namespace:       "namespace-2",
							NamespaceLabels: map[string]string{areaLabel: "area-1", teamLabel: "team-2"},
							Name:            "pod-3",
						},
					},
				},
			}
			// when
			imageByArea, err := scan.generateAreaGrouping(imageSpecs)

			// then
			Expect(err).NotTo(HaveOccurred())
			Expect(imageByArea["area-1"].Teams).Should(HaveLen(2))
			Expect(imageByArea["area-1"].Teams["team-1"].Images).Should(HaveImages("image-1"))
			Expect(imageByArea["area-1"].Teams["team-1"].Pods).Should(HaveLen(2))
			Expect(imageByArea["area-1"].Teams["team-1"].Pods[0].Name).Should(Equal("pod-1"))
			Expect(imageByArea["area-1"].Teams["team-1"].Pods[1].Name).Should(Equal("pod-2"))

			Expect(imageByArea["area-1"].Teams["team-2"].Images).Should(HaveImages("image-1"))
			Expect(imageByArea["area-1"].Teams["team-2"].Pods).Should(HaveLen(1))
			Expect(imageByArea["area-1"].Teams["team-2"].Pods[0].Name).Should(Equal("pod-3"))
		})

		XIt("sort teams images by criticality", func() {
			team1Pod := PodSummary{
				Namespace:       "namespace-1",
				NamespaceLabels: map[string]string{areaLabel: "area-1", teamLabel: "team-1"},
				Name:            "pod-1",
			}

			team2Pod := PodSummary{
				Namespace:       "namespace-1",
				NamespaceLabels: map[string]string{areaLabel: "area-1", teamLabel: "team-2"},
				Name:            "pod-1",
			}

			imageSpecs := map[string]*ImageSpec{
				"mostCriticalTeam2": {
					ImageName: "mostCriticalTeam2",
					Pods:      []PodSummary{team2Pod},
					TotalVulnerabilityPerCriticality: map[string]int{
						"CRITICAL": 1,
						"HIGH":     5,
						"MEDIUM":   0,
						"LOW":      0,
					},
				},
				"leastCriticalTeam2": {
					ImageName: "leastCriticalTeam2",
					Pods:      []PodSummary{team2Pod},
					TotalVulnerabilityPerCriticality: map[string]int{
						"CRITICAL": 0,
						"HIGH":     6,
						"MEDIUM":   10,
						"LOW":      25,
					},
				},
				"mostCritical": {
					ImageName: "mostCritical",
					Pods:      []PodSummary{team1Pod},
					TotalVulnerabilityPerCriticality: map[string]int{
						"CRITICAL": 4,
						"HIGH":     5,
						"MEDIUM":   10,
						"LOW":      25,
					},
				},
				"mostHighAfterSameCritical": {
					ImageName: "mostHighAfterSameCritical",
					Pods:      []PodSummary{team1Pod},
					TotalVulnerabilityPerCriticality: map[string]int{
						"CRITICAL": 3,
						"HIGH":     6,
						"MEDIUM":   11,
						"LOW":      26,
					},
				},
				"mostMediumAfterSameCriticalAndHigh": {
					ImageName: "mostMediumAfterSameCriticalAndHigh",
					Pods:      []PodSummary{team1Pod},
					TotalVulnerabilityPerCriticality: map[string]int{
						"CRITICAL": 3,
						"HIGH":     5,
						"MEDIUM":   12,
						"LOW":      27,
					},
				},
				"leastCriticalTeam1": {
					ImageName: "leastCriticalTeam1",
					Pods:      []PodSummary{team1Pod},
					TotalVulnerabilityPerCriticality: map[string]int{
						"CRITICAL": 3,
						"HIGH":     5,
						"MEDIUM":   11,
						"LOW":      28,
					},
				},
			}

			// when
			imageByArea, err := scan.generateAreaGrouping(imageSpecs)

			// then
			Expect(err).NotTo(HaveOccurred())
			Expect(imageByArea["area-1"].Teams["team-1"].Images).To(HaveLen(4))
			Expect(imageByArea["area-1"].Teams["team-1"].Images[0].ImageName).To(Equal("mostCritical"))
			Expect(imageByArea["area-1"].Teams["team-1"].Images[1].ImageName).To(Equal("mostHighAfterSameCritical"))
			Expect(imageByArea["area-1"].Teams["team-1"].Images[2].ImageName).To(Equal("mostMediumAfterSameCriticalAndHigh"))
			Expect(imageByArea["area-1"].Teams["team-1"].Images[3].ImageName).To(Equal("leastCriticalTeam1"))

			Expect(imageByArea["area-1"].Teams["team-2"].Images).To(HaveLen(2))
			Expect(imageByArea["area-1"].Teams["team-2"].Images[0].ImageName).To(Equal("mostCriticalTeam2"))
			Expect(imageByArea["area-1"].Teams["team-2"].Images[1].ImageName).To(Equal("leastCriticalTeam2"))
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
	imagesSpecs := actual.([]ImageSpec)
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
