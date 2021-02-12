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

// Report is top level structure holding the results of the image scan
type Report struct {
	ScannedImages []ScannedImage
	ImageByArea   map[string]*ImagePerArea
}

// AreaSummary defines the summary for an area
type AreaSummary struct {
	ImageCount                   int `json:"number_images_scanned"`
	ContainerCount               int `json:"number_pods_scanned"`
	TotalVulnerabilityBySeverity map[string]int
}

// TeamSummary defines the summary for an team
type TeamSummary struct {
	ImageVulnerabilitySummary map[string]VulnerabilitySummary
}

// VulnerabilitySummary defines
type VulnerabilitySummary struct {
	ContainerCount               int
	TotalVulnerabilityBySeverity map[string]int
}

// ImagePerArea regroups image vulnerabilities for an area/department
type ImagePerArea struct {
	AreaName string
	Summary  *AreaSummary
	Teams    map[string]*ImagePerTeam
}

// ImagePerTeam regroups image vulnerabilities for a team
type ImagePerTeam struct {
	TeamName       string
	Summary        *TeamSummary
	ContainerCount int
	ImageCount     int
	Containers     []k8s.ContainerSummary
	Images         []ScannedImage
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
func (l *Scanner) ScanImages() (*Report, error) {
	logr.Infof("Running scanner")
	containers, err := l.kubernetesClient.GetContainersInNamespaces(l.config.FilterLabels)
	if err != nil {
		return nil, err
	}
	containersByImageName := l.groupContainersByImageName(containers)
	scannedImages, err := l.scanImages(containersByImageName)
	if err != nil {
		return nil, err
	}

	logr.Infof("Generating report")
	return l.generateReport(scannedImages)
}

func (l *Scanner) generateReport(scannedImages []ScannedImage) (*Report, error) {
	imagesByArea, err := l.generateAreaGrouping(scannedImages)
	if err != nil {
		return nil, err
	}
	return &Report{
		ScannedImages: scannedImages,
		ImageByArea:   imagesByArea,
	}, nil
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

type teamKey struct {
	area, team string
}

func (l *Scanner) generateAreaGrouping(scannedImages []ScannedImage) (map[string]*ImagePerArea, error) {
	scannedImagesByTeam, containersByTeam := l.groupImagesAndContainersByTeamAndArea(scannedImages)
	imagesByArea := make(map[string]*ImagePerArea)
	for key := range containersByTeam {
		if _, ok := imagesByArea[key.area]; !ok {
			imagesByArea[key.area] = &ImagePerArea{AreaName: key.area, Teams: map[string]*ImagePerTeam{}}
		}
		if _, ok := imagesByArea[key.area].Teams[key.team]; !ok {
			imagesByArea[key.area].Teams[key.team] = &ImagePerTeam{TeamName: key.team}
		}

		var teamImages []ScannedImage
		for _, scannedImage := range scannedImagesByTeam[key] {
			teamImages = append(teamImages, scannedImage)
		}

		imagesByArea[key.area].Teams[key.team].ContainerCount = len(containersByTeam[key])
		imagesByArea[key.area].Teams[key.team].Containers = containersByTeam[key]
		imagesByArea[key.area].Teams[key.team].Images = sortBySeverity(teamImages)
		imagesByArea[key.area].Teams[key.team].ImageCount = len(teamImages)
		imagesByArea[key.area].Teams[key.team].Summary = buildTeamSummary(teamImages)
	}

	for area, areaImages := range imagesByArea {
		imagesByArea[area].Summary = buildAreaSummary(areaImages)
	}

	return imagesByArea, nil
}

func (l *Scanner) groupImagesAndContainersByTeamAndArea(scannedImages []ScannedImage) (map[teamKey]map[string]ScannedImage, map[teamKey][]k8s.ContainerSummary) {
	scannedImagesByTeam := make(map[teamKey]map[string]ScannedImage)
	containersByTeam := make(map[teamKey][]k8s.ContainerSummary)
	var areaLabel, teamsLabel string
	for _, scannedImage := range scannedImages {
		for _, containerSummary := range scannedImage.Containers {
			areaLabel = containerSummary.NamespaceLabels[l.config.AreaLabels]
			teamsLabel = containerSummary.NamespaceLabels[l.config.TeamsLabels]

			if areaLabel == "" {
				areaLabel = "all"
			}
			if teamsLabel == "" {
				teamsLabel = "all"
			}

			key := teamKey{area: areaLabel, team: teamsLabel}
			containersByTeam[key] = append(containersByTeam[key], containerSummary)

			if _, ok := scannedImagesByTeam[key]; !ok {
				scannedImagesByTeam[key] = make(map[string]ScannedImage)
			}
			scannedImagesByTeam[key][scannedImage.ImageName] = scannedImage
		}
	}
	return scannedImagesByTeam, containersByTeam
}

func buildAreaSummary(areaImages *ImagePerArea) *AreaSummary {
	summary := AreaSummary{}
	for _, teamImages := range areaImages.Teams {
		summary.ImageCount += teamImages.ImageCount
		summary.ContainerCount += teamImages.ContainerCount
		for _, vulnerabilitySummary := range teamImages.Summary.ImageVulnerabilitySummary {
			if summary.TotalVulnerabilityBySeverity == nil {
				summary.TotalVulnerabilityBySeverity = make(map[string]int)
			}
			for severity, count := range vulnerabilitySummary.TotalVulnerabilityBySeverity {
				summary.TotalVulnerabilityBySeverity[severity] += count
			}
		}
	}
	return &summary
}

func buildTeamSummary(teamImages []ScannedImage) *TeamSummary {
	summary := TeamSummary{}
	for _, image := range teamImages {
		if summary.ImageVulnerabilitySummary == nil {
			summary.ImageVulnerabilitySummary = make(map[string]VulnerabilitySummary)
		}
		summary.ImageVulnerabilitySummary[image.ImageName] = VulnerabilitySummary{
			ContainerCount:               len(image.Containers),
			TotalVulnerabilityBySeverity: image.TotalVulnerabilityBySeverity,
		}
	}
	return &summary
}

func sortBySeverity(scannedImages []ScannedImage) []ScannedImage {
	severityScores := map[string]int{
		"CRITICAL": 100000000, "HIGH": 1000000, "MEDIUM": 10000, "LOW": 100, "UNKNOWN": 1,
	}

	sort.Slice(scannedImages, func(i, j int) bool {
		firstItemScore := 0
		secondItemScore := 0

		for severity, count := range scannedImages[i].TotalVulnerabilityBySeverity {
			severityScore := severityScores[severity]
			firstItemScore = firstItemScore + count*severityScore
		}

		for severity, count := range scannedImages[j].TotalVulnerabilityBySeverity {
			severityScore := severityScores[severity]
			secondItemScore = secondItemScore + count*severityScore
		}
		return firstItemScore > secondItemScore
	})
	return scannedImages
}

func (l *Scanner) groupContainersByImageName(containers []k8s.ContainerSummary) map[string][]k8s.ContainerSummary {
	images := make(map[string][]k8s.ContainerSummary)
	for _, container := range containers {
		if _, ok := images[container.Image]; !ok {
			images[container.Image] = []k8s.ContainerSummary{}
		}
		images[container.Image] = append(images[container.Image], container)
	}
	return images
}

func (l *Scanner) stringReplacement(imageName string, stringReplacement string) (string, error) {
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

func (l *Scanner) scanImages(imageList map[string][]k8s.ContainerSummary) ([]ScannedImage, error) {
	var scannedImages []ScannedImage
	wp := workerpool.New(l.config.Workers)
	err := l.execTrivyDB()
	if err != nil {
		logr.Errorf("Failed to download trivy db: %s", err)
	}

	logr.Infof("Scanning %d images with %d workers", len(imageList), l.config.Workers)
	for imageName, containers := range imageList {
		// allocate var to allow access inside the worker submission
		resolvedContainers := containers
		resolvedImageName, err := l.stringReplacement(imageName, l.config.ImageNameReplacement)
		if err != nil {
			logr.Errorf("Error string replacement failed, image_name : %s, image_replacement_string: %s, error: %s", imageName, l.config.ImageNameReplacement, err)
		}

		wp.Submit(func() {
			logr.Infof("Worker processing image: %s", resolvedImageName)

			// trivy fail to download from quay.io so we need to pull the image first
			err := l.execDockerPull(resolvedImageName)
			if err != nil {
				logr.Errorf("Error executing docker pull for image %s: %v", resolvedImageName, err)
			}

			trivyOutput, err := l.execTrivy(resolvedImageName)
			if err != nil {
				logr.Errorf("Error executing trivy for image %s: %s", resolvedImageName, err)
			}
			scannedImages = append(scannedImages, ScannedImage{
				ImageName:                    resolvedImageName,
				Containers:                   resolvedContainers,
				TrivyOutput:                  sortTrivyVulnerabilities(trivyOutput),
				TotalVulnerabilityBySeverity: computeTotalVulnerabilityBySeverity(trivyOutput),
			})

			err = l.execDockerRmi(imageName)
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

func (l *Scanner) execTrivyDB() error {
	logr.Infof("trivy download db")
	cmd := "trivy"
	args := []string{"-q", "image", "--download-db-only"}

	_, _, err := execCmd.Execute(cmd, args)

	return err
}

func (l *Scanner) execTrivy(imageName string) ([]TrivyOutput, error) {
	cmd := "trivy"
	args := []string{"-q", "image", "-f", "json", "--skip-update", "--no-progress", "--severity", l.config.Severity, imageName}
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

func (l *Scanner) execDockerPull(imageName string) error {
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

func (l *Scanner) execDockerRmi(imageName string) error {
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
