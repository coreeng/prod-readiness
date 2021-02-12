package scanner

import (
	"fmt"
	"os/exec"
	"sort"

	execCmd "github.com/coreeng/production-readiness/production-readiness/pkg/cmd"
	"github.com/coreeng/production-readiness/production-readiness/pkg/utils"
	"github.com/mitchellh/mapstructure"
	logr "github.com/sirupsen/logrus"
)

// TrivyClient is a thin client for trivy
type TrivyClient interface {
	DownloadDatabase() error
	ScanImage(image string) ([]TrivyOutput, error)
}

type trivyClient struct {
	severity string
}

// NewTrivyClient creates a new TrivyClient
func NewTrivyClient(severity string) TrivyClient {
	return &trivyClient{severity: severity}
}

func (t *trivyClient) DownloadDatabase() error {
	logr.Infof("Trivy downloading db")
	command := exec.Command("trivy", "-q", "image", "--download-db-only")
	_, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error while downloading trivy db: %v", err)
	}
	return nil
}

func (t *trivyClient) ScanImage(image string) ([]TrivyOutput, error) {
	cmd := "trivy"
	args := []string{"-q", "image", "-f", "json", "--skip-update", "--no-progress", "--severity", t.severity, image}
	output, errOutput, err := execCmd.Execute(cmd, args)
	outputAsStruct := utils.ConvertByteToStruct(output)
	errOutputAsString := utils.ConvertByteToString(errOutput)
	if err != nil {
		return nil, fmt.Errorf("error while executing trivy for image %s. Output: %s, Error output: %s, Error: %v", image, outputAsStruct, errOutputAsString, err)
	}

	var trivyOutput []TrivyOutput
	err = mapstructure.Decode(outputAsStruct, &trivyOutput)
	if err != nil {
		return nil, fmt.Errorf("error while decoding trivy output for image %s: %v", image, err)
	}
	return sortTrivyVulnerabilities(trivyOutput), nil
}

func sortTrivyVulnerabilities(trivyOuput []TrivyOutput) []TrivyOutput {
	severityScores := map[string]int{
		"CRITICAL": 100000000, "HIGH": 1000000, "MEDIUM": 10000, "LOW": 100, "UNKNOWN": 1,
	}

	for z := 0; z < len(trivyOuput); z++ {
		sort.Slice(trivyOuput[z].Vulnerabilities, func(i, j int) bool {
			firstItemScore := 0
			secondItemScore := 0

			severityScore := severityScores[trivyOuput[z].Vulnerabilities[i].Severity]
			firstItemScore = firstItemScore + severityScore

			severityScore = severityScores[trivyOuput[z].Vulnerabilities[j].Severity]
			secondItemScore = secondItemScore + severityScore
			return firstItemScore > secondItemScore
		})
	}
	return trivyOuput
}
