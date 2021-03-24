package scanner

import (
	"fmt"
	"strings"

	"github.com/coreeng/production-readiness/production-readiness/pkg/k8s"

	"github.com/gammazero/workerpool"
	logr "github.com/sirupsen/logrus"
)

// Scanner will scan images
type Scanner struct {
	config           *Config
	kubernetesClient k8s.KubernetesClient
	dockerClient     DockerClient
	trivyClient      TrivyClient
}

// ScannedImage define the information of an image
type ScannedImage struct {
	TrivyOutput []TrivyOutput
	Containers  []k8s.ContainerSummary
	ImageName   string
	ScanError   error
}

// VulnerabilitySummary provides a summary of the vulnerabilities found for an image
type VulnerabilitySummary struct {
	ContainerCount               int
	SeverityScore                int
	TotalVulnerabilityBySeverity map[string]int
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
		dockerClient:     NewDockerClient(),
		trivyClient:      NewTrivyClient(config.Severity),
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

func (s *Scanner) scanImages(imageList map[string][]k8s.ContainerSummary) ([]ScannedImage, error) {
	var scannedImages []ScannedImage
	wp := workerpool.New(s.config.Workers)
	err := s.trivyClient.DownloadDatabase()
	if err != nil {
		return nil, fmt.Errorf("failed to download trivy db: %v", err)
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
			err := s.dockerClient.PullImage(resolvedImageName)
			if err != nil {
				logr.Errorf("Error executing docker pull for image %s: %v", resolvedImageName, err)
			}

			trivyOutput, err := s.trivyClient.ScanImage(resolvedImageName)
			var scanError error
			if err != nil {
				scanError = fmt.Errorf("error executing trivy for image %s: %s", resolvedImageName, err)
				logr.Error(scanError)
			}
			scannedImages = append(scannedImages, ScannedImage{
				ImageName:   resolvedImageName,
				Containers:  resolvedContainers,
				TrivyOutput: trivyOutput,
				ScanError:   scanError,
			})

			err = s.dockerClient.RmiImage(resolvedImageName)
			if err != nil {
				logr.Errorf("Error executing docker rmi for image %s: %v", resolvedImageName, err)
			}
		})
	}

	wp.StopWait()
	return scannedImages, nil
}

const (
	critical = 100000000
	high     = 1000000
	medium   = 10000
	low      = 100
	unknown  = 1
)

var severityScores = map[string]int{
	"CRITICAL": critical, "HIGH": high, "MEDIUM": medium, "LOW": low, "UNKNOWN": unknown,
}

// VulnerabilitySummary computes a summary a the vulnerability for that image
func (i *ScannedImage) VulnerabilitySummary() VulnerabilitySummary {
	severityMap := make(map[string]int)
	for severity := range severityScores {
		severityMap[severity] = 0
	}
	for _, target := range i.TrivyOutput {
		for _, vulnerability := range target.Vulnerabilities {
			severityMap[vulnerability.Severity] = severityMap[vulnerability.Severity] + 1
		}
	}

	severityScore := 0
	for severity, count := range severityMap {
		score := severityScores[severity]
		severityScore = severityScore + count*score
	}
	return VulnerabilitySummary{
		ContainerCount:               len(i.Containers),
		SeverityScore:                severityScore,
		TotalVulnerabilityBySeverity: severityMap,
	}
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
