package scanner

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gammazero/workerpool"
	"github.com/mitchellh/mapstructure"
	logr "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"

	execCmd "github.com/coreeng/production-readiness/production-readiness/pkg/cmd"
	"github.com/coreeng/production-readiness/production-readiness/pkg/utils"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Scanner will scan images
type Scanner struct {
	kubeconfig *rest.Config
	kubeClient *kubernetes.Clientset
	config     *Config
}

// ImageSpec define the information of an image
type ImageSpec struct {
	TrivyOutput                  []TrivyOutput `json:"trivyCommand"`
	TrivyErrOutput               string        `json:"trivyErrCommand"`
	DockerPullCommand            string        `json:"dockerPullCommand"`
	DockerPullErrCommand         string        `json:"dockerPullErrCommand"`
	DockerRmiCommand             string        `json:"dockerRmiCommand"`
	DockerRmiErrCommand          string        `json:"dockerRmiErrCommand"`
	Pods                         []PodSummary  `json:"pods"`
	TotalVulnerabilityBySeverity map[string]int
	ImageName                    string
}

// Report is top level structure holding the results of the image scan
type Report struct {
	ImageSpecs  map[string]*ImageSpec
	ImageByArea map[string]*ImagePerArea
}

// AreaSummary defines the summary for an area
type AreaSummary struct {
	ImageCount                   int `json:"number_images_scanned"`
	PodCount                     int `json:"number_pods_scanned"`
	TotalVulnerabilityBySeverity map[string]int
}

// TeamSummary defines the summary for an team
type TeamSummary struct {
	ImageVulnerabilitySummary map[string]VulnerabilitySummary
}

// VulnerabilitySummary defines
type VulnerabilitySummary struct {
	PodCount                     int
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
	TeamName   string
	Summary    *TeamSummary
	PodCount   int
	ImageCount int
	Pods       []PodSummary
	Images     []ImageSpec
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
func New(kubeClient *kubernetes.Clientset, config *Config) *Scanner {
	return &Scanner{
		kubeClient: kubeClient,
		config:     config,
	}
}

// ScanImages get all the images available in a cluster and scan them
func (l *Scanner) ScanImages() (*Report, error) {
	logr.Infof("Running scanner")

	// get all pods running for now
	// then we could get all the deployment and statefulset, job, cronjob, to gather all the images which are not running during the scan
	// pod manifest should be available in the kube-system namespace
	podList, err := l.getPods(l.config)
	if err != nil {
		return nil, err
	}

	logr.WithFields(logr.Fields{
		"podList": podList,
	}).Debug("Pod List")

	imageList, err := l.getImagesList(podList)
	if err != nil {
		return nil, err
	}
	scannedImages, err := l.scanList(imageList)
	if err != nil {
		return nil, err
	}

	logr.Infof("Generating report")
	return l.generateReport(scannedImages)
}

func (l *Scanner) generateReport(scannedImages map[string]*ImageSpec) (*Report, error) {
	for _, imageSpec := range scannedImages {
		imageSpec.TotalVulnerabilityBySeverity = computeTotalVulnerabilityBySeverity(imageSpec)
	}
	imagesByArea, err := l.generateAreaGrouping(scannedImages)
	if err != nil {
		return nil, err
	}
	return &Report{
		ImageSpecs:  scannedImages,
		ImageByArea: imagesByArea,
	}, nil
}

func computeTotalVulnerabilityBySeverity(imageSpec *ImageSpec) map[string]int {
	severityMap := make(map[string]int)
	for _, target := range imageSpec.TrivyOutput {
		for _, vulnerability := range target.Vulnerabilities {
			severityMap[vulnerability.Severity] = severityMap[vulnerability.Severity] + 1
		}
	}
	return severityMap
}

type teamKey struct {
	area, team string
}

func (l *Scanner) generateAreaGrouping(imageSpecs map[string]*ImageSpec) (map[string]*ImagePerArea, error) {
	imagesSpecByTeam, podsByTeam := l.groupImagesAndPodsByTeamAndArea(imageSpecs)
	imagesByArea := make(map[string]*ImagePerArea)
	for key := range podsByTeam {
		if _, ok := imagesByArea[key.area]; !ok {
			imagesByArea[key.area] = &ImagePerArea{AreaName: key.area, Teams: map[string]*ImagePerTeam{}}
		}
		if _, ok := imagesByArea[key.area].Teams[key.team]; !ok {
			imagesByArea[key.area].Teams[key.team] = &ImagePerTeam{TeamName: key.team}
		}

		var teamImages []ImageSpec
		for _, imageSpec := range imagesSpecByTeam[key] {
			teamImages = append(teamImages, imageSpec)
		}

		imagesByArea[key.area].Teams[key.team].PodCount = len(podsByTeam[key])
		imagesByArea[key.area].Teams[key.team].Pods = podsByTeam[key]
		imagesByArea[key.area].Teams[key.team].Images = sortBySeverity(teamImages)
		imagesByArea[key.area].Teams[key.team].ImageCount = len(teamImages)
		imagesByArea[key.area].Teams[key.team].Summary = buildTeamSummary(teamImages)
	}

	for area, areaImages := range imagesByArea {
		imagesByArea[area].Summary = buildAreaSummary(areaImages)
	}

	return imagesByArea, nil
}

func (l *Scanner) groupImagesAndPodsByTeamAndArea(imageSpecs map[string]*ImageSpec) (map[teamKey]map[string]ImageSpec, map[teamKey][]PodSummary) {
	imagesSpecByTeam := make(map[teamKey]map[string]ImageSpec)
	podsByTeam := make(map[teamKey][]PodSummary)
	var areaLabel, teamsLabel string
	for _, specs := range imageSpecs {
		for _, podSummary := range specs.Pods {
			areaLabel = podSummary.NamespaceLabels[l.config.AreaLabels]
			teamsLabel = podSummary.NamespaceLabels[l.config.TeamsLabels]

			if areaLabel == "" {
				areaLabel = "all"
			}
			if teamsLabel == "" {
				teamsLabel = "all"
			}

			key := teamKey{area: areaLabel, team: teamsLabel}
			podsByTeam[key] = append(podsByTeam[key], podSummary)

			if _, ok := imagesSpecByTeam[key]; !ok {
				imagesSpecByTeam[key] = make(map[string]ImageSpec)
			}
			imagesSpecByTeam[key][specs.ImageName] = *specs
		}
	}
	return imagesSpecByTeam, podsByTeam
}

func buildAreaSummary(areaImages *ImagePerArea) *AreaSummary {
	summary := AreaSummary{}
	for _, teamImages := range areaImages.Teams {
		summary.ImageCount += teamImages.ImageCount
		summary.PodCount += teamImages.PodCount
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

func buildTeamSummary(teamImages []ImageSpec) *TeamSummary {
	summary := TeamSummary{}
	for _, image := range teamImages {
		if summary.ImageVulnerabilitySummary == nil {
			summary.ImageVulnerabilitySummary = make(map[string]VulnerabilitySummary)
		}
		summary.ImageVulnerabilitySummary[image.ImageName] = VulnerabilitySummary{
			PodCount:                     len(image.Pods),
			TotalVulnerabilityBySeverity: image.TotalVulnerabilityBySeverity,
		}
	}
	return &summary
}

func sortBySeverity(imageArr []ImageSpec) []ImageSpec {
	sort.Slice(imageArr, func(i, j int) bool {

		firstItemScore := 0
		secondItemScore := 0
		if _, ok := imageArr[i].TotalVulnerabilityBySeverity["CRITICAL"]; ok {
			firstItemScore = firstItemScore + imageArr[i].TotalVulnerabilityBySeverity["CRITICAL"]*1000000
		}
		if _, ok := imageArr[i].TotalVulnerabilityBySeverity["HIGH"]; ok {
			firstItemScore = firstItemScore + imageArr[i].TotalVulnerabilityBySeverity["HIGH"]*10000
		}
		if _, ok := imageArr[i].TotalVulnerabilityBySeverity["MEDIUM"]; ok {
			firstItemScore = firstItemScore + imageArr[i].TotalVulnerabilityBySeverity["MEDIUM"]*100
		}
		if _, ok := imageArr[i].TotalVulnerabilityBySeverity["LOW"]; ok {
			firstItemScore = firstItemScore + imageArr[i].TotalVulnerabilityBySeverity["LOW"]
		}

		if _, ok := imageArr[j].TotalVulnerabilityBySeverity["CRITICAL"]; ok {
			secondItemScore = secondItemScore + imageArr[j].TotalVulnerabilityBySeverity["CRITICAL"]*1000000
		}
		if _, ok := imageArr[j].TotalVulnerabilityBySeverity["HIGH"]; ok {
			secondItemScore = secondItemScore + imageArr[j].TotalVulnerabilityBySeverity["HIGH"]*10000
		}
		if _, ok := imageArr[j].TotalVulnerabilityBySeverity["MEDIUM"]; ok {
			secondItemScore = secondItemScore + imageArr[j].TotalVulnerabilityBySeverity["MEDIUM"]*100
		}
		if _, ok := imageArr[j].TotalVulnerabilityBySeverity["LOW"]; ok {
			secondItemScore = secondItemScore + imageArr[j].TotalVulnerabilityBySeverity["LOW"]
		}
		return firstItemScore > secondItemScore
	})
	return imageArr
}

func (l *Scanner) getNamespaces(config *Config) (*v1.NamespaceList, error) {

	options := metaV1.ListOptions{}
	if config.FilterLabels != "" {
		options.LabelSelector = config.FilterLabels
	}

	namespaceList, err := l.kubeClient.CoreV1().Namespaces().List(options)
	if err != nil {
		return nil, fmt.Errorf("unable to find namespaces: %v", err)
	}

	if len(namespaceList.Items) == 0 {
		return nil, fmt.Errorf("no namespaces found")
	}

	return namespaceList, nil
}

type podDetail struct {
	Pod       v1.Pod
	Namespace v1.Namespace
}

// PodSummary - cut down version of the podDetail
type PodSummary struct {
	Name            string
	Namespace       string
	NamespaceLabels map[string]string
}

func (l *Scanner) getPods(config *Config) ([]podDetail, error) {
	var podList *v1.PodList
	var podDetailList []podDetail
	var namespaceList *v1.NamespaceList
	var err error

	namespaceList, err = l.getNamespaces(config)
	if err != nil {
		return nil, fmt.Errorf("unable to list namespaces: %v", err)
	}

	for _, namespace := range namespaceList.Items {

		podList, err = l.kubeClient.CoreV1().Pods(namespace.Name).List(metaV1.ListOptions{})

		for _, pod := range podList.Items {
			podDetailList = append(podDetailList, podDetail{Pod: pod, Namespace: namespace})
		}
		logr.Infof("Get pods from namespace %s", namespace.Name)

		if err != nil {
			logr.Errorf("unable to find pods: %v", err)
		}
	}

	if len(podDetailList) == 0 {
		return nil, fmt.Errorf("no pod found")
	}
	return podDetailList, nil
}

func (l *Scanner) getImagesList(podList []podDetail) (map[string]*ImageSpec, error) {
	imageList := map[string]*ImageSpec{}
	for _, pod := range podList {
		logr.Infof("pod %s in namespace %s", pod.Pod.Name, pod.Namespace.Name)
		podItem := PodSummary{Namespace: pod.Namespace.Name, NamespaceLabels: pod.Namespace.Labels, Name: pod.Pod.Name}
		for _, container := range pod.Pod.Spec.Containers {
			// if key exists
			if image, ok := imageList[container.Image]; ok {
				image.Pods = append(image.Pods, podItem)
			} else {
				imageList[container.Image] = &ImageSpec{Pods: []PodSummary{podItem}}
			}
		}
	}
	return imageList, nil
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

func (l *Scanner) scanList(imageList map[string]*ImageSpec) (map[string]*ImageSpec, error) {
	wp := workerpool.New(l.config.Workers)

	err := l.execTrivyDB()
	if err != nil {
		logr.Errorf("Failed to download trivy db: %s", err)
	}

	logr.Infof("Scanning %d images with %d workers", len(imageList), l.config.Workers)
	for imageName, imageSpec := range imageList {
		// allocate var to allow access inside the worker submission
		imageSpec := imageSpec
		imageName, err := l.stringReplacement(imageName, l.config.ImageNameReplacement)
		if err != nil {
			logr.Errorf("Error string replacement failed, image_name : %s, image_replacement_string: %s, error: %s", imageName, l.config.ImageNameReplacement, err)
		}

		wp.Submit(func() {

			// trivy fail to download from quay.io so we need to pull the image first
			err := l.execDockerPull(imageName, imageSpec)
			if err != nil {
				logr.Errorf("Error docker pull exec: %s, image: %s, output: %s, errOutput: %s", err, imageName, imageSpec.DockerPullCommand, imageSpec.DockerPullErrCommand)
			}

			err = l.execTrivy(imageName, imageSpec)
			if err != nil {
				logr.Errorf("Error trivy exec: %s, image: %s, output: %v, errOutput: %s", err, imageName, imageSpec.TrivyOutput, imageSpec.TrivyErrOutput)
			}

			err = l.sortTrivyVulnerabilities(imageSpec)
			if err != nil {
				logr.Errorf("Error sortTrivyVulnerabilities: %s", err)
			}

			err = l.execDockerRmi(imageName, imageSpec)
			if err != nil {
				logr.Errorf("Error exec: %s, image: %s, output: %s, errOutput: %s", err, imageName, imageSpec.DockerRmiCommand, imageSpec.DockerRmiErrCommand)
			}

		})
	}

	wp.StopWait()
	return imageList, nil
}

func (l *Scanner) sortTrivyVulnerabilities(imageSpec *ImageSpec) error {

	for z := 0; z < len(imageSpec.TrivyOutput); z++ {
		sort.Slice(imageSpec.TrivyOutput[z].Vulnerabilities, func(i, j int) bool {

			firstItemScore := 0
			secondItemScore := 0

			if imageSpec.TrivyOutput[z].Vulnerabilities[i].Severity == "CRITICAL" {
				firstItemScore = firstItemScore + 1000
			}

			if imageSpec.TrivyOutput[z].Vulnerabilities[i].Severity == "HIGH" {
				firstItemScore = firstItemScore + 500
			}

			if imageSpec.TrivyOutput[z].Vulnerabilities[i].Severity == "MEDIUM" {
				firstItemScore = firstItemScore + 100
			}

			if imageSpec.TrivyOutput[z].Vulnerabilities[i].Severity == "LOW" {
				firstItemScore = firstItemScore + 10
			}

			if imageSpec.TrivyOutput[z].Vulnerabilities[i].Severity == "UNKNOWN" {
				firstItemScore = firstItemScore + 1
			}

			if imageSpec.TrivyOutput[z].Vulnerabilities[j].Severity == "CRITICAL" {
				secondItemScore = secondItemScore + 1000
			}

			if imageSpec.TrivyOutput[z].Vulnerabilities[j].Severity == "HIGH" {
				secondItemScore = secondItemScore + 500
			}

			if imageSpec.TrivyOutput[z].Vulnerabilities[j].Severity == "MEDIUM" {
				secondItemScore = secondItemScore + 100
			}

			if imageSpec.TrivyOutput[z].Vulnerabilities[j].Severity == "LOW" {
				secondItemScore = secondItemScore + 10
			}

			if imageSpec.TrivyOutput[z].Vulnerabilities[j].Severity == "UNKNOWN" {
				secondItemScore = secondItemScore + 1
			}

			return firstItemScore > secondItemScore
		})
	}
	return nil
}

func (l *Scanner) execTrivyDB() error {

	logr.Infof("trivy download db")
	cmd := "trivy"
	args := []string{"-q", "image", "--download-db-only"}

	_, _, err := execCmd.Execute(cmd, args)

	return err
}

func (l *Scanner) execTrivy(imageName string, imageSpec *ImageSpec) error {

	logr.Infof("worker image: %s, pod_name: %s", imageName, imageSpec.Pods[0].Name)
	cmd := "trivy"
	args := []string{"-q", "image", "-f", "json", "--skip-update", "--no-progress", "--severity", l.config.Severity, imageName}

	output, errOutput, err := execCmd.Execute(cmd, args)

	outputAsStruct := utils.ConvertByteToStruct(output)
	errOutputAsString := utils.ConvertByteToString(errOutput)

	var trivyOutput []TrivyOutput
	err = mapstructure.Decode(outputAsStruct, &trivyOutput)
	if err != nil {
		// error
	}

	imageSpec.TrivyOutput = trivyOutput

	imageSpec.TrivyErrOutput = errOutputAsString
	imageSpec.ImageName = imageName

	if err != nil {
		return err
	}

	// logr.Debugf("worker image: %s, pod_name: %s, output: %v, errOutput: %s", imageName, imageSpec.Pods[0].Pod.Name, imageSpec.TrivyOutput, imageSpec.TrivyErrOutput)

	return nil
}

func (l *Scanner) execDockerPull(imageName string, imageSpec *ImageSpec) error {

	cmd := "docker"
	args := []string{"pull", imageName}

	output, errOutput, err := execCmd.Execute(cmd, args)

	outputAsString := utils.ConvertByteToString(output)
	errOutputAsString := utils.ConvertByteToString(errOutput)

	imageSpec.DockerPullCommand = outputAsString
	imageSpec.DockerPullErrCommand = errOutputAsString

	if err != nil {
		return err
	}

	// logr.Debugf("worker docker pull image: %s, pod_name: %s, output: %s, errOutput: %s", imageName, imageSpec.Pods[0].Pod.Name, imageSpec.DockerPullCommand, imageSpec.DockerPullErrCommand)

	return nil
}

func (l *Scanner) execDockerRmi(imageName string, imageSpec *ImageSpec) error {

	cmd := "docker"
	args := []string{"rmi", imageName}

	output, errOutput, err := execCmd.Execute(cmd, args)

	outputAsString := utils.ConvertByteToString(output)
	errOutputAsString := utils.ConvertByteToString(errOutput)

	imageSpec.DockerRmiCommand = outputAsString
	imageSpec.DockerRmiErrCommand = errOutputAsString

	if err != nil {
		return err
	}

	// logr.Debugf("worker docker rmi image: %s, pod_name: %s, output: %s, errOutput: %s", imageName, imageSpec.Pods[0].Pod.Name, imageSpec.DockerRmiCommand, imageSpec.DockerRmiErrCommand)

	return nil
}
