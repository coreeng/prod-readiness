package scanner

import (
	"fmt"
	"github.com/onsi/gomega/types"
	"reflect"
	"testing"

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
			podList1 := PodDetail{
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
					},
				},
			}

			podList2 := PodDetail{
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
					},
				},
			}

			podList := []PodDetail{}
			podList = append(podList, podList1)
			podList = append(podList, podList2)

			imageList, err := scan.getImagesList(podList)

			imageListExpected := map[string]*ImageSpec{
				"ubuntu:latest": &ImageSpec{
					Pods: podList,
				},
				"ubuntu:trusty": &ImageSpec{
					Pods: []PodDetail{podList1},
				},
				"gcr.io:name": &ImageSpec{
					Pods: []PodDetail{podList2},
				},
			}

			Expect(err).NotTo(HaveOccurred())
			Expect(imageList).To(Equal(imageListExpected))
		})
	})

	Context("Area grouping", func() {
		It("Image specific teams should be grouped under that team", func() {
			areaLabel := "areas-label"
			teamLabel := "teams-label"
			scan := &Scanner{config: &Config{
				AreaLabels:  areaLabel,
				TeamsLabels: teamLabel,
			}}
			imageSpecs := map[string]*ImageSpec{
				"image-1": {
					ImageName: "image-1",
					Pods: []PodDetail{
						{
							Namespace: v1.Namespace{
								ObjectMeta: metaV1.ObjectMeta{
									Labels: map[string]string{areaLabel: "area-1", teamLabel: "team-1"},
								},
							},
						},
					},
				},
				"image-2": {
					ImageName: "image-2",
					Pods: []PodDetail{
						{
							Namespace: v1.Namespace{
								ObjectMeta: metaV1.ObjectMeta{
									Labels: map[string]string{areaLabel: "area-1", teamLabel: "team-1"},
								},
							},
						},
					},
				},
				"image-3": {
					ImageName: "image-3",
					Pods: []PodDetail{
						{
							Namespace: v1.Namespace{
								ObjectMeta: metaV1.ObjectMeta{
									Labels: map[string]string{areaLabel: "area-1", teamLabel: "team-2"},
								},
							},
						},
					},
				},
			}
			imageByArea, err := scan.generateAreaGrouping(imageSpecs)
			Expect(err).NotTo(HaveOccurred())
			Expect(imageByArea["area-1"].Teams).Should(HaveLen(2))
			Expect(imageByArea["area-1"].Teams["team-1"].Images).Should(HaveLen(2))
			Expect(imageByArea["area-1"].Teams["team-2"].Images).Should(HaveLen(1))
			Expect(imageByArea["area-1"].Teams["team-1"].Images).Should(HaveImages("image-1", "image-2"))
			Expect(imageByArea["area-1"].Teams["team-2"].Images).Should(HaveImages("image-3"))
		})

		It("Common images should be grouped within each team", func() {

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
	return reflect.DeepEqual(actualImages, m.expectedImages), nil
}

func (m *haveImages) FailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("Expected: %v. \nActual response body: %s", m.expectedImages, actual)
}

func (m *haveImages) NegatedFailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("Expected: %v. \nActual response body: %s", m.expectedImages, actual)
}
