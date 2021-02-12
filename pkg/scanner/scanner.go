package scanner

import (
	"fmt"
	"sort"
	"strings"

	"github.com/coreeng/production-readiness/production-readiness/pkg/k8s"

	execCmd "github.com/coreeng/production-readiness/production-readiness/pkg/cmd"
	"github.com/coreeng/production-readiness/production-readiness/pkg/utils"
	"github.com/gammazero/workerpool"
	"github.com/mitchellh/mapstructure"
	logr "github.com/sirupsen/logrus"
)

// Scanner will scan images
type Scanner struct {
	config           *Config
	kubernetesClient k8s.KubernetesClient
}

// ScannedImage define the information of an image
type ScannedImage struct {
	TrivyOutput                  []TrivyOutput          `json:"trivyCommand"`
	Containers                   []k8s.ContainerSummary `json:"pods"`
	TotalVulnerabilityBySeverity map[string]int
	ImageName                    string
}

// Vulnerabilities is the object representation of the trivy vulnerability table for an image
type Vulnerabilities struct {
	Description      string
	Severity         string
	SeveritySource   string
	FixedVersion     string
	InstalledVersion string
	VulnerabilityID  string
	PkgName          string
	Title            string
	References       []string
	Layer            *Layer
}

// TrivyOutput is an object representation of the trivy output for an image scan
type TrivyOutput struct {
	Vulnerabilities []Vulnerabilities
	Type            string
	Target          string
}

// Layer is the object representation of the trivy image layer
type Layer struct {
	DiffID string
	Digest string
}

// Config is the config used for the scanner
type Config struct {
	LogLevel             string
	Workers              int
	ImageNameReplacement string
	AreaLabels           string
	TeamsLabels          string
	FilterLabels         string
	Severity             string
}

// New creates a Scanner to find vulnerabilities in container images
func New(kubernetesClient k8s.KubernetesClient, config *Config) *Scanner {
	return &Scanner{
		config:           config,
		kubernetesClient: kubernetesClient,
	}
}

// ScanImages get all the images available in a cluster and scan them
func (s *Scanner) ScanImages() (*VulnerabilityReport, error) {
	logr.Infof("Running scanner")
	containers, err := s.kubernetesClient.GetContainersInNamespaces(s.config.FilterLabels)
	if err != nil {
		return nil, err
	}
	containersByImageName := s.groupContainersByImageName(containers)
	scannedImages, err := s.scanImages(containersByImageName)
	if err != nil {
		return nil, err
	}

	logr.Infof("Generating vulnerability report")
	reportGenerator := &AreaReport{
		AreaLabelName: s.config.AreaLabels,
		TeamLabelName: s.config.TeamsLabels,
	}
	return reportGenerator.GenerateVulnerabilityReport(scannedImages)
}

func computeTotalVulnerabilityBySeverity(trivyOutput []TrivyOutput) map[string]int {
	severityMap := make(map[string]int)
	for _, target := range trivyOutput {
		for _, vulnerability := range target.Vulnerabilities {
			severityMap[vulnerability.Severity] = severityMap[vulnerability.Severity] + 1
		}
	}
	return severityMap
}

func (s *Scanner) groupContainersByImageName(containers []k8s.ContainerSummary) map[string][]k8s.ContainerSummary {
	images := make(map[string][]k8s.ContainerSummary)
	for _, container := range containers {
		if _, ok := images[container.Image]; !ok {
			images[container.Image] = []k8s.ContainerSummary{}
		}
		images[container.Image] = append(images[container.Image], container)
	}
	return images
}

func (s *Scanner) stringReplacement(imageName string, stringReplacement string) (string, error) {
	if stringReplacement != "" {
		replacementArr := strings.Split(stringReplacement, ",")
		for _, pattern := range replacementArr {

			replacementItems := strings.Split(pattern, "|")
			if len(replacementItems) == 2 {
				logr.Debugf("String replacement from imageName: %s, match: %s, replace %s", imageName, replacementItems[0], replacementItems[1])
				imageName = strings.Replace(imageName, replacementItems[0], replacementItems[1], -1)
			} else {
				return imageName, fmt.Errorf("string Replacement pattern is not in the right format '$matchingString|$replacementString,$matchingString|$replacementString'")
			}

		}
	}
	return imageName, nil
}

func (s *Scanner) scanImages(imageList map[string][]k8s.ContainerSummary) ([]ScannedImage, error) {
	var scannedImages []ScannedImage
	wp := workerpool.New(s.config.Workers)
	err := s.execTrivyDB()
	if err != nil {
		logr.Errorf("Failed to download trivy db: %s", err)
	}

	logr.Infof("Scanning %d images with %d workers", len(imageList), s.config.Workers)
	for imageName, containers := range imageList {
		// allocate var to allow access inside the worker submission
		resolvedContainers := containers
		resolvedImageName, err := s.stringReplacement(imageName, s.config.ImageNameReplacement)
		if err != nil {
			logr.Errorf("Error string replacement failed, image_name : %s, image_replacement_string: %s, error: %s", imageName, s.config.ImageNameReplacement, err)
		}

		wp.Submit(func() {
			logr.Infof("Worker processing image: %s", resolvedImageName)

			// trivy fail to download from quay.io so we need to pull the image first
			err := s.execDockerPull(resolvedImageName)
			if err != nil {
				logr.Errorf("Error executing docker pull for image %s: %v", resolvedImageName, err)
			}

			trivyOutput, err := s.execTrivy(resolvedImageName)
			if err != nil {
				logr.Errorf("Error executing trivy for image %s: %s", resolvedImageName, err)
			}
			scannedImages = append(scannedImages, ScannedImage{
				ImageName:                    resolvedImageName,
				Containers:                   resolvedContainers,
				TrivyOutput:                  sortTrivyVulnerabilities(trivyOutput),
				TotalVulnerabilityBySeverity: computeTotalVulnerabilityBySeverity(trivyOutput),
			})

			err = s.execDockerRmi(imageName)
			if err != nil {
				logr.Errorf("Error executing docker rmi for image %s: %v", resolvedImageName, err)
			}
		})
	}

	wp.StopWait()
	return scannedImages, nil
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

func (s *Scanner) execTrivyDB() error {
	logr.Infof("trivy download db")
	cmd := "trivy"
	args := []string{"-q", "image", "--download-db-only"}

	_, _, err := execCmd.Execute(cmd, args)

	return err
}

func (s *Scanner) execTrivy(imageName string) ([]TrivyOutput, error) {
	cmd := "trivy"
	args := []string{"-q", "image", "-f", "json", "--skip-update", "--no-progress", "--severity", s.config.Severity, imageName}
	output, errOutput, err := execCmd.Execute(cmd, args)
	outputAsStruct := utils.ConvertByteToStruct(output)
	errOutputAsString := utils.ConvertByteToString(errOutput)
	if err != nil {
		return nil, fmt.Errorf("error while executing trivy for image %s. Output: %s, Error output: %s, Error: %v", imageName, outputAsStruct, errOutputAsString, err)
	}

	var trivyOutput []TrivyOutput
	err = mapstructure.Decode(outputAsStruct, &trivyOutput)
	if err != nil {
		return nil, fmt.Errorf("error while decoding trivy output for image %s: %v", imageName, err)
	}
	return sortTrivyVulnerabilities(trivyOutput), nil
}

func (s *Scanner) execDockerPull(imageName string) error {
	cmd := "docker"
	args := []string{"pull", imageName}

	output, errOutput, err := execCmd.Execute(cmd, args)
	outputAsString := utils.ConvertByteToString(output)
	errOutputAsString := utils.ConvertByteToString(errOutput)
	if err != nil {
		return fmt.Errorf("error while executing docker pull for image %s. Output: %s, Error output: %s, Error: %v", imageName, outputAsString, errOutputAsString, err)
	}
	return nil
}

func (s *Scanner) execDockerRmi(imageName string) error {
	cmd := "docker"
	args := []string{"rmi", imageName}

	output, errOutput, err := execCmd.Execute(cmd, args)
	outputAsString := utils.ConvertByteToString(output)
	errOutputAsString := utils.ConvertByteToString(errOutput)
	if err != nil {
		return fmt.Errorf("error while executing docker rmi for image %s. Output: %s, Error output: %s, Error: %v", imageName, outputAsString, errOutputAsString, err)
	}
	return nil
}
