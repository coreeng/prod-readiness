package report

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/coreeng/production-readiness/production-readiness/pkg/scanner"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestManager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Report Suite")
}

type TestReport struct {
	ImageScan *scanner.Report
}

var _ = Describe("Generating report Images", func() {
	var (
		tmpDir string
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = ioutil.TempDir("", "")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		err := os.RemoveAll(tmpDir)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should generate the report according to the template file", func() {
		debianImageScan := aDebianImageScan(map[string]int{"CRITICAL": 0, "HIGH": 10, "MEDIUM": 5, "LOW": 20, "UNKNOWN": 0})
		ubuntuImageScan := anUbuntuImageScan(map[string]int{"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 10, "UNKNOWN": 0})
		alpineImageScan := anAlpineImageScan(map[string]int{})
		imageReport := &TestReport{
			ImageScan: &scanner.Report{
				ImageSummary: &scanner.ImageSummary{
					NumberPodsScanned:                3,
					NumberImagesScanned:              2,
					NumberImagesFromExternalRegistry: 0,
					ImagePerRegistry:                 map[string]*scanner.ImagePerRegistry{},
					TotalVulnerabilityPerCriticality: map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "UNKNOWN": 0},
				},
				ImageSpecs: map[string]*scanner.ImageSpec{
					"debian:latest": &debianImageScan,
					"alpine:latest": &alpineImageScan,
					"ubuntu:18.04":  &ubuntuImageScan,
				},
				ImageByArea: map[string]*scanner.ImagePerArea{
					"area-1": {
						AreaName: "area-1",
						Teams: map[string]*scanner.ImagePerTeam{
							"team-1": {
								TeamName:   "team-1",
								ImageCount: 2,
								PodCount:   3,
								Images: []scanner.ImageSpec{
									debianImageScan,
									alpineImageScan,
									ubuntuImageScan,
								},
							},
							"team-2": {
								TeamName:   "team-2",
								ImageCount: 1,
								PodCount:   1,
								Images: []scanner.ImageSpec{
									ubuntuImageScan,
								},
							},
						},
					},
					"area-2": {
						AreaName: "area-2",
						Teams: map[string]*scanner.ImagePerTeam{
							"team-3": {
								TeamName:   "team-3",
								ImageCount: 1,
								PodCount:   3,
								Images: []scanner.ImageSpec{
									debianImageScan,
								},
							},
						},
					},
				},
			},
		}
		actualReportFile := filepath.Join(tmpDir, "actual-report.md")
		err := GenerateMarkdown(imageReport, "test-report-imageScan-standard.md.tmpl", actualReportFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(fileContentEqual("expected-test-report-imageScan-standard.md", actualReportFile)).
			To(BeTrue(), "Report diff: \n%s", runDiff("expected-test-report-imageScan-standard.md", actualReportFile))
	})
})

func runDiff(filename1, filename2 string) string {
	command := exec.Command("diff", filename1, filename2)
	output, _ := command.CombinedOutput()
	if output != nil {
		return string(output)
	}
	return ""
}

func fileContentEqual(filename1, filename2 string) (bool, error) {
	file1, err := ioutil.ReadFile(filename1)
	if err != nil {
		return false, err
	}

	file2, err := ioutil.ReadFile(filename2)
	if err != nil {
		return false, err
	}

	return bytes.Equal(file1, file2), nil
}

func anAlpineImageScan(vulnerabilitiesDefinition map[string]int) scanner.ImageSpec {
	return scanner.ImageSpec{
		ImageName: "alpine:latest",
		Pods: []scanner.PodDetail{
			{},
		},
		TotalVulnerabilityPerCriticality: map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
		TrivyOutput: []scanner.TrivyOutput{
			{
				Target:          "alpine (alpine 3.13.1)",
				Type:            "alpine",
				Vulnerabilities: buildVulnerabilities(vulnerabilitiesDefinition),
			},
		},
	}
}

func aDebianImageScan(vulnerabilitiesDefinition map[string]int) scanner.ImageSpec {
	return scanner.ImageSpec{
		ImageName: "debian:latest",
		Pods: []scanner.PodDetail{
			{},
		},
		TotalVulnerabilityPerCriticality: vulnerabilitiesDefinition,
		TrivyOutput: []scanner.TrivyOutput{
			{
				Target:          "debian (debian 10.7)",
				Type:            "debian",
				Vulnerabilities: buildVulnerabilities(vulnerabilitiesDefinition),
			},
		},
	}
}

func anUbuntuImageScan(vulnerabilitiesDefinition map[string]int) scanner.ImageSpec {
	return scanner.ImageSpec{
		ImageName: "ubuntu:18.04",
		Pods: []scanner.PodDetail{
			{},
		},
		TotalVulnerabilityPerCriticality: vulnerabilitiesDefinition,
		TrivyOutput: []scanner.TrivyOutput{
			{
				Target:          "ubuntu (ubuntu 18.04)",
				Type:            "ubuntu",
				Vulnerabilities: buildVulnerabilities(vulnerabilitiesDefinition),
			},
		},
	}
}

func buildVulnerabilities(vulnerabilitiesDefinition map[string]int) []scanner.Vulnerabilities {
	var vulnerabilities []scanner.Vulnerabilities
	for severity, count := range vulnerabilitiesDefinition {
		vulnerabilityFor := func(string) scanner.Vulnerabilities {
			switch severity {
			case "HIGH":
				return aHighVulnerablity()
			case "MEDIUM":
				return aMediumVulnerablity()
			case "LOW":
				return aLowVulnerablity()
			default:
				panic(fmt.Errorf("severity %s not supported", severity))
			}
		}
		if count != 0 {
			vulnerabilities = append(vulnerabilities, repeat(count, vulnerabilityFor(severity))...)
		}
	}
	return vulnerabilities
}

func repeat(count int, vulnerability scanner.Vulnerabilities) []scanner.Vulnerabilities {
	var v []scanner.Vulnerabilities
	for i := 0; i < count; i++ {
		v = append(v, vulnerability)
	}
	return v
}

func aLowVulnerablity() scanner.Vulnerabilities {
	return scanner.Vulnerabilities{
		VulnerabilityID:  "CVE-2011-3374",
		PkgName:          "apt",
		InstalledVersion: "1.8.2.2",
		Layer: &scanner.Layer{
			Digest: "sha256:b9a857cbf04d2c0d2f0f6b73e894b20a977a6d3b6edd9e27d080e03142954950",
			DiffID: "sha256:4762552ad7d851a9901571428078281985074e5ddb806979dd7ad24748db4ca0",
		},
		SeveritySource: "debian",
		Description:    "It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.",
		Severity:       "LOW",
		References: []string{
			"https://access.redhat.com/security/cve/cve-2011-3374",
		},
	}
}

func aHighVulnerablity() scanner.Vulnerabilities {
	return scanner.Vulnerabilities{
		VulnerabilityID:  "CVE-2021-3326",
		PkgName:          "libc-bin",
		InstalledVersion: "2.28-10",
		Layer: &scanner.Layer{
			Digest: "sha256:b9a857cbf04d2c0d2f0f6b73e894b20a977a6d3b6edd9e27d080e03142954950",
			DiffID: "sha256:4762552ad7d851a9901571428078281985074e5ddb806979dd7ad24748db4ca0",
		},
		SeveritySource: "nvd",
		Title:          "glibc: Assertion failure in ISO-2022-JP-3 gconv module related to combining characters",
		Description:    "The iconv function in the GNU C Library (aka glibc or libc6) 2.32 and earlier, when processing invalid input sequences in the ISO-2022-JP-3 encoding, fails an assertion in the code path and aborts the program, potentially resulting in a denial of service.",
		Severity:       "HIGH",
		References: []string{
			"http://www.openwall.com/lists/oss-security/2021/01/28/2",
		},
	}
}

func aMediumVulnerablity() scanner.Vulnerabilities {
	return scanner.Vulnerabilities{
		VulnerabilityID:  "CVE-2020-13844",
		PkgName:          "libstdc++6",
		InstalledVersion: "8.4.0-1ubuntu1~18.04",
		Layer: &scanner.Layer{
			DiffID: "sha256:80580270666742c625aecc56607a806ba343a66a8f5a7fd708e6c4e4c07a3e9b",
		},
		SeveritySource: "ubuntu",
		Title:          "kernel: ARM straight-line speculation vulnerability",
		Description:    "Arm Armv8-A core implementations utilizing speculative execution past unconditional changes in control flow may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis, aka \"straight-line speculation.\"",
		Severity:       "MEDIUM",
		References: []string{
			"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20839",
		},
	}
}
