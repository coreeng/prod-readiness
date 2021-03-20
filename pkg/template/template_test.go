package template

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/coreeng/production-readiness/production-readiness/pkg/k8s"

	logr "github.com/sirupsen/logrus"

	"github.com/coreeng/production-readiness/production-readiness/pkg/scanner"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestManager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Report Suite")
}

type TestReport struct {
	ImageScan *scanner.VulnerabilityReport
}

var _ = Describe("Generating vulnerability report", func() {
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

	It("should generate the report according to the md template file", func() {
		actualReportFile := filepath.Join(tmpDir, "actual-report.md")
		reportTemplate := filepath.Join(findProjectDir(), "report-imageScan.md.tmpl")
		err := GenerateReportFromTemplate(aReport(), reportTemplate, actualReportFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(fileContentEqual("expected-test-report-imageScan.md", actualReportFile)).To(BeTrue())
	})

	It("should generate the report according to the html template file", func() {
		actualReportFile := filepath.Join(tmpDir, "actual-report.html")
		reportTemplate := filepath.Join(findProjectDir(), "report-imageScan.html.tmpl")
		err := GenerateReportFromTemplate(aReport(), reportTemplate, actualReportFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(fileContentEqual("expected-test-report-imageScan.html", actualReportFile, "-w")).To(BeTrue())
	})
})

func aReport() *TestReport {
	debianImageScan := aDebianImageScan(map[string]int{"CRITICAL": 0, "HIGH": 10, "MEDIUM": 5, "LOW": 20, "UNKNOWN": 0})
	ubuntuImageScan := anUbuntuImageScan(map[string]int{"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 10, "UNKNOWN": 0})
	alpineImageScan := anAlpineImageScan(map[string]int{})
	return &TestReport{
		ImageScan: &scanner.VulnerabilityReport{
			ScannedImages: []scanner.ScannedImage{debianImageScan, alpineImageScan, ubuntuImageScan},
			AreaSummary: map[string]*scanner.AreaSummary{
				"area-1": {
					Name:                         "area-1",
					ImageCount:                   7,
					ContainerCount:               10,
					TotalVulnerabilityBySeverity: map[string]int{"CRITICAL": 4, "HIGH": 12, "MEDIUM": 5, "LOW": 26, "UNKNOWN": 1},
					Teams: map[string]*scanner.TeamSummary{
						"team-1": {
							Name: "team-1",
							ImageVulnerabilitySummary: map[string]scanner.VulnerabilitySummary{
								"debian:latest": {
									ContainerCount:               2,
									TotalVulnerabilityBySeverity: map[string]int{"CRITICAL": 0, "HIGH": 10, "MEDIUM": 5, "LOW": 20, "UNKNOWN": 0},
								},
								"alpine:latest": {
									ContainerCount:               1,
									TotalVulnerabilityBySeverity: map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 2, "UNKNOWN": 0},
								},
								"ubuntu:18.04": {
									ContainerCount:               3,
									TotalVulnerabilityBySeverity: map[string]int{"CRITICAL": 2, "HIGH": 1, "MEDIUM": 0, "LOW": 2, "UNKNOWN": 1},
								},
							},
							Images: []scanner.ScannedImage{
								debianImageScan,
								alpineImageScan,
								ubuntuImageScan,
							},
						},
						"team-2": {
							Name: "team-2",
							ImageVulnerabilitySummary: map[string]scanner.VulnerabilitySummary{
								"ubuntu:18.04": {
									ContainerCount:               3,
									TotalVulnerabilityBySeverity: map[string]int{"CRITICAL": 2, "HIGH": 1, "MEDIUM": 0, "LOW": 2, "UNKNOWN": 1},
								},
							},
							Images: []scanner.ScannedImage{
								ubuntuImageScan,
							},
						},
					},
				},
				"area-2": {
					Name:                         "area-2",
					ImageCount:                   10,
					ContainerCount:               10,
					TotalVulnerabilityBySeverity: map[string]int{"CRITICAL": 4, "HIGH": 12, "MEDIUM": 5, "LOW": 26, "UNKNOWN": 1},
					Teams: map[string]*scanner.TeamSummary{
						"team-3": {
							Name: "team-3",
							ImageVulnerabilitySummary: map[string]scanner.VulnerabilitySummary{
								"debian:latest": {
									ContainerCount:               2,
									TotalVulnerabilityBySeverity: map[string]int{"CRITICAL": 10, "HIGH": 10, "MEDIUM": 5, "LOW": 20, "UNKNOWN": 0},
								},
							},
							Images: []scanner.ScannedImage{
								debianImageScan,
							},
						},
					},
				},
			},
		},
	}
}

var _ = Describe("Saving json report", func() {
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

	It("should save the report json representation to the given file", func() {
		testReport := TestReport{
			ImageScan: &scanner.VulnerabilityReport{
				AreaSummary: map[string]*scanner.AreaSummary{
					"area-1": {
						Name:                         "area-1",
						ImageCount:                   7,
						ContainerCount:               10,
						TotalVulnerabilityBySeverity: map[string]int{"CRITICAL": 4, "HIGH": 12, "MEDIUM": 5, "LOW": 26, "UNKNOWN": 1},
					},
				},
			},
		}
		err := SaveReport(&testReport, filepath.Join(tmpDir, "report.json"))
		Expect(err).NotTo(HaveOccurred())

		actualReportSaved := &TestReport{}
		actualReportBytes, err := ioutil.ReadFile(filepath.Join(tmpDir, "report.json"))
		Expect(err).NotTo(HaveOccurred())
		err = json.Unmarshal(actualReportBytes, actualReportSaved)
		Expect(err).NotTo(HaveOccurred())
		Expect(actualReportSaved).Should(Equal(&testReport))
	})
})

func fileContentEqual(filename1, filename2 string, diffOptions ...string) (bool, error) {
	var args []string
	if diffOptions != nil {
		args = append(args, diffOptions...)
	}
	args = append(args, filename1, filename2)
	command := exec.Command("diff", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("File content differs: \n%s", string(output))
	}
	return true, nil
}

func anAlpineImageScan(vulnerabilitiesDefinition map[string]int) scanner.ScannedImage {
	return scanner.ScannedImage{
		ImageName: "alpine:latest",
		Containers: []k8s.ContainerSummary{
			{},
		},
		TotalVulnerabilityBySeverity: map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
		TrivyOutput: []scanner.TrivyOutput{
			{
				Target:          "alpine (alpine 3.13.1)",
				Type:            "alpine",
				Vulnerabilities: buildVulnerabilities(vulnerabilitiesDefinition),
			},
		},
	}
}

func aDebianImageScan(vulnerabilitiesDefinition map[string]int) scanner.ScannedImage {
	return scanner.ScannedImage{
		ImageName: "debian:latest",
		Containers: []k8s.ContainerSummary{
			{},
		},
		TotalVulnerabilityBySeverity: vulnerabilitiesDefinition,
		TrivyOutput: []scanner.TrivyOutput{
			{
				Target:          "debian (debian 10.7)",
				Type:            "debian",
				Vulnerabilities: buildVulnerabilities(vulnerabilitiesDefinition),
			},
		},
	}
}

func anUbuntuImageScan(vulnerabilitiesDefinition map[string]int) scanner.ScannedImage {
	return scanner.ScannedImage{
		ImageName: "ubuntu:18.04",
		Containers: []k8s.ContainerSummary{
			{},
		},
		TotalVulnerabilityBySeverity: vulnerabilitiesDefinition,
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
	vulnerabilityFor := func(severity string) scanner.Vulnerabilities {
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

	var vulnerabilities []scanner.Vulnerabilities
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	for _, severity := range severities {
		if count := vulnerabilitiesDefinition[severity]; count != 0 {
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

func findProjectDir() string {
	workingDir, err := os.Getwd()
	if err != nil {
		logr.Fatalf("Unable to stat current directory: %v", err)
	}

	for {
		parentPath := filepath.Dir(workingDir)
		parentDirName := filepath.Base(parentPath)
		if parentDirName == "prod-readiness" {
			return parentPath
		}
		workingDir = parentPath
	}
}
