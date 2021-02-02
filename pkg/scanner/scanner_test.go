package scanner

import (
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

	var (
		scan *Scanner
	)

	BeforeEach(func() {
		scan = &Scanner{}
	})

	// unc (l *Scanner) saveReport(listScanned map[string]*ImageSpec) error {

	// 	// saving the ouput into a file
	// 	file, _ := json.MarshalIndent(listScanned, "", " ")
	// 	date := time.Now()
	// 	dateFormatted := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d",
	// 		date.Year(), date.Month(), date.Day(),
	// 		date.Hour(), date.Minute(), date.Second())

	// 	filename := fmt.Sprintf("results/imageScan_%s.json", dateFormatted)
	// 	err := ioutil.WriteFile(filename, file, 0644)

	// 	if err != nil {
	// 		logr.Errorf("Error saving report %s", err)
	// 		return err
	// 	}

	// 	logr.Infof("Report saved into: %s", filename)

	// 	return nil
	// }

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
