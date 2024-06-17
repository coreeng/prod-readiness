package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("Trivy client", func() {

	Describe("Trivyoutput sorting", func() {

		It("should sort the vulnerabilility by severity", func() {
			output := []TrivyOutputResults{
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

	Describe("Commands", func() {

		const (
			severity = "CRITICAL"
		)

		var (
			mockRunner *mockCommanderRunner
			trivy      *trivyClient
		)

		BeforeEach(func() {
			mockRunner = &mockCommanderRunner{}
			trivy = &trivyClient{severity: severity, timeout: 7 * time.Minute, commandRunner: mockRunner}
		})

		Describe("Scan", func() {

			It("invokes trivy CLI to scan the image and parse the output", func() {
				_, filename, _, _ := runtime.Caller(0)
				testPackage := filepath.Dir(filename)
				testoutput, err := os.ReadFile(filepath.Join(testPackage, "trivy_test_output.json"))
				Expect(err).NotTo(HaveOccurred())

				mockRunner.On("Execute", "trivy", []string{"-q", "image", "-f", "json", "--skip-update", "--no-progress", "--severity", severity, "--timeout", "7m0s", "alpine:3.11.0"}).
					Return(testoutput, []byte{}, nil)

				scanOutput, err := trivy.ScanImage("alpine:3.11.0")
				Expect(err).NotTo(HaveOccurred())
				Expect(scanOutput).Should(HaveLen(2))
				Expect(scanOutput[0].Vulnerabilities).Should(HaveLen(12))
				Expect(scanOutput[1].Vulnerabilities).Should(HaveLen(1))
				Expect(scanOutput[0].Vulnerabilities[0].VulnerabilityID).Should(Equal("CVE-2023-45853"))
				Expect(scanOutput[0].Vulnerabilities[0].Severity).Should(Equal("CRITICAL"))
				Expect(scanOutput[0].Vulnerabilities[0].PkgName).Should(Equal("zlib1g"))
				Expect(scanOutput[0].Vulnerabilities[0].InstalledVersion).Should(Equal("1:1.2.13.dfsg-1"))
				Expect(scanOutput[0].Vulnerabilities[0].Status).Should(Equal("will_not_fix"))
				Expect(scanOutput[0].Vulnerabilities[0].FixedVersion).Should(BeEmpty())

				Expect(scanOutput[1].Vulnerabilities[0].VulnerabilityID).Should(Equal("CVE-2022-40897"))
				Expect(scanOutput[1].Vulnerabilities[0].Severity).Should(Equal("HIGH"))
				Expect(scanOutput[1].Vulnerabilities[0].PkgName).Should(Equal("setuptools"))
				Expect(scanOutput[1].Vulnerabilities[0].Status).Should(Equal("fixed"))
				Expect(scanOutput[1].Vulnerabilities[0].InstalledVersion).Should(Equal("58.1.0"))
				Expect(scanOutput[1].Vulnerabilities[0].FixedVersion).Should(Equal("65.5.1"))
			})

			It("return the error when unable to parse the scan output", func() {
				mockRunner.On("Execute", "trivy", []string{"-q", "image", "-f", "json", "--skip-update", "--no-progress", "--severity", severity, "--timeout", "7m0s", "alpine:3.11.0"}).
					Return([]byte("not json"), []byte{}, nil)
				_, err := trivy.ScanImage("alpine:3.11.0")
				Expect(err).Should(MatchError(ContainSubstring("error while decoding trivy output for image alpine:3.11.0")))
			})

		})

		Describe("CisScan", func() {

			It("invokes trivy CLI to scan the Kubernetes cluster", func() {
				output, jsonerr := json.Marshal(CisOutput{})
				Expect(jsonerr).NotTo(HaveOccurred())
				mockRunner.On("Execute", "trivy", []string{"--cache-dir", ".trivycache/", "--timeout", "7m0s", "--format", "json", "kubernetes", "--exit-code", "0", "--no-progress", "--compliance", "mybenchmark", "--slow", "cluster", "--severity", "CRITICAL"}).
					Return(output, []byte{}, nil)

				scanOutput, err := trivy.CisScan("mybenchmark")
				Expect(err).NotTo(HaveOccurred())
				Expect(scanOutput).Should(Equal(&CisOutput{}))
			})

			It("return the error when unable to parse the trivy output", func() {
				mockRunner.On("Execute", "trivy", []string{"--cache-dir", ".trivycache/", "--timeout", "7m0s", "--format", "json", "kubernetes", "--exit-code", "0", "--no-progress", "--compliance", "mybenchmark", "--slow", "cluster", "--severity", "CRITICAL"}).
					Return([]byte("not json"), []byte{}, nil)
				_, err := trivy.CisScan("mybenchmark")
				Expect(err).Should(MatchError(ContainSubstring("error while decoding CisOutput scan output")))
			})
		})
	})
})

type mockCommanderRunner struct {
	mock.Mock
}

func (r *mockCommanderRunner) Execute(cmd string, arg []string) (output []byte, erroutput []byte, err error) {
	args := r.Called(cmd, arg)
	return args.Get(0).([]byte), args.Get(1).([]byte), args.Error(2)
}
