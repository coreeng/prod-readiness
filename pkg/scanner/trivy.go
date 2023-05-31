package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"

	execCmd "github.com/coreeng/production-readiness/production-readiness/pkg/cmd"
	"github.com/coreeng/production-readiness/production-readiness/pkg/utils"
	logr "github.com/sirupsen/logrus"
)

// TrivyClient is a thin client for trivy
type TrivyClient interface {
	DownloadDatabase(cmd string) error
	ScanImage(image string) ([]TrivyOutputResults, error)
	CisScan(benchmark string) (*CisOutput, error)
}

type trivyClient struct {
	severity string
}

// NewTrivyClient creates a new TrivyClient
func NewTrivyClient(severity string) TrivyClient {
	return &trivyClient{severity: severity}
}

func (t *trivyClient) DownloadDatabase(cmd string) error {
	logr.Infof("Trivy downloading/updating db")
	command := exec.Command("trivy", "-q", cmd, "--download-db-only")
	_, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error while downloading trivy db: %v", err)
	}
	return nil
}

func (t *trivyClient) ScanImage(image string) ([]TrivyOutputResults, error) {
	cmd := "trivy"
	args := []string{"-q", "image", "-f", "json", "--skip-update", "--no-progress", "--severity", t.severity, image}
	output, errOutput, err := execCmd.Execute(cmd, args)

	errOutputAsString := utils.ConvertByteToString(errOutput)
	if err != nil {
		return nil, fmt.Errorf("error while executing trivy for image %s. Output: %s, Error output: %s, Error: %v", image, utils.ConvertByteToString(output), errOutputAsString, err)
	}

	var trivyOutput TrivyOutput
	err = json.Unmarshal(output, &trivyOutput)
	if err != nil {
		return nil, fmt.Errorf("error while decoding trivy output for image %s: %v", image, err)
	}
	return sortTrivyVulnerabilities(trivyOutput.Results), nil
}

func (t *trivyClient) CisScan(benchmark string) (*CisOutput, error) {
	cmd := "trivy"
	args := []string{"--cache-dir", ".trivycache/", "--timeout", "10m0s", "--format", "json", "kubernetes", "--exit-code", "0", "--no-progress", "--compliance", benchmark, "cluster", "--severity", t.severity}
	output, errOutput, err := execCmd.Execute(cmd, args)

	errOutputAsString := utils.ConvertByteToString(errOutput)
	if err != nil {
		return nil, fmt.Errorf("error while running %s benchmark. Output: %s, Error output: %s, Error: %v", benchmark, output, errOutputAsString, err)
	}

	var cisOutput *CisOutput
	err = json.Unmarshal(output, &cisOutput)
	if err != nil {
		return nil, fmt.Errorf("error while decoding CisOutput scan output: %v", err)
	}
	return cisOutput, nil
}

func sortTrivyVulnerabilities(trivyOuput []TrivyOutputResults) []TrivyOutputResults {
	severityScores := map[string]int{
		"CRITICAL": 100000000, "HIGH": 1000000, "MEDIUM": 10000, "LOW": 100, "UNKNOWN": 1,
	}

	for z := 0; z < len(trivyOuput); z++ {
		sort.Slice(trivyOuput[z].Vulnerabilities, func(i, j int) bool {
			firstItemScore := severityScores[trivyOuput[z].Vulnerabilities[i].Severity]
			secondItemScore := severityScores[trivyOuput[z].Vulnerabilities[j].Severity]
			return firstItemScore > secondItemScore
		})
	}
	return trivyOuput
}
