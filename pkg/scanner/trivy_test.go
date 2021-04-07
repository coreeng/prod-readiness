package scanner

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestTrivy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Trivy Suite")
}

var _ = Describe("Trivy client", func() {

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
