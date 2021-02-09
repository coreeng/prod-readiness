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
	TrivyOutput                      []TrivyOutput `json:"trivyCommand"`
	TrivyErrOutput                   string        `json:"trivyErrCommand"`
	DockerPullCommand                string        `json:"dockerPullCommand"`
	DockerPullErrCommand             string        `json:"dockerPullErrCommand"`
	DockerRmiCommand                 string        `json:"dockerRmiCommand"`
	DockerRmiErrCommand              string        `json:"dockerRmiErrCommand"`
	Pods                             []PodSummary  `json:"pods"`
	TotalVulnerabilityPerCriticality map[string]int
	ImageName                        string
}

// ImageSummary define the summary
type ImageSummary struct {
	NumberImagesScanned              int `json:"number_images_scanned"`
	NumberPodsScanned                int `json:"number_pods_scanned"`
	NumberImagesFromExternalRegistry int `json:"number_images_from_external_registry"`
	NumberPodsFromExternalRegistry   int `json:"number_pods_from_external_registry"`
	ImagePerRegistry                 map[string]*ImagePerRegistry
	TotalVulnerabilityPerCriticality map[string]int
}

// Report define report
type Report struct {
	ImageSummary                                 *ImageSummary
	ImageSpecs                                   map[string]*ImageSpec
	ImageSpecsSortByCriticality                  []ImageSpec
	ImageSpecsSortByCriticalityTop20             []ImageSpec
	ImageSpecsSortByCriticalityTop20MostReplicas []ImageSpec
	ImageByArea                                  map[string]*ImagePerArea
}

// ImagePerRegistry define ImagePerRegistry
type ImagePerRegistry struct {
	RegistryName string
	PodCount     int
	ImageCount   int
	Pods         []PodSummary
	Images       []string
}

// Vulnerabilities defines Vulnerabilities
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

// TrivyOutput defines TrivyOutput
type TrivyOutput struct {
	Vulnerabilities []Vulnerabilities
	Type            string
	Target          string
}

// Layer defines layer
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

// New creates a Scanner
func New(kubeconfig *rest.Config, kubeClient *kubernetes.Clientset, config *Config) *Scanner {
	return &Scanner{
		kubeconfig: kubeconfig,
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

	// TODO
	// add integration test with kind
	// create metrics for the worker queue, number of images scanned, number of images gathered from cluster
	// use database to store scan result to avoid lost during restart of the application, also to create async scan and get the report later on from the database
	// do we want to scan non-running pods like job, cronjob, mock scaled down
	imageList, err := l.getImagesList(podList)
	if err != nil {
		return nil, err
	}

	listScanned, err := l.scanList(imageList)
	if err != nil {
		return nil, err
	}

	logr.Infof("All namespaces have been scanned.")

	report := &Report{
		ImageSummary: &ImageSummary{},
		ImageSpecs:   listScanned,
	}

	logr.Infof("calculateKpis")
	_, err = l.calculateKpis(report)
	if err != nil {
		return nil, err
	}

	logr.Infof("generateAreaGrouping")
	imagesByArea, err := l.generateAreaGrouping(listScanned)
	if err != nil {
		return nil, err
	}
	report.ImageByArea = imagesByArea

	return report, nil
}
type teamKey struct {
	area, team string
}

func (l *Scanner) generateAreaGrouping(imageSpecs map[string]*ImageSpec) (map[string]*ImagePerArea, error) {
	imagesSpecByTeam := make(map[teamKey]map[string]ImageSpec)
	podsByTeam := make(map[teamKey][]PodSummary)
	var podAreaLabel, podTeamsLabel string
	for _, specs := range imageSpecs {

		for _, podSummary := range specs.Pods {
			podAreaLabel = podSummary.NamespaceLabels[l.config.AreaLabels]
			podTeamsLabel = podSummary.NamespaceLabels[l.config.TeamsLabels]

			if podAreaLabel == "" {
				podAreaLabel = "all"
			}
			if podTeamsLabel == "" {
				podTeamsLabel = "all"
			}

			key := teamKey{area: podAreaLabel, team: podTeamsLabel}
			podsByTeam[key] = append(podsByTeam[key], podSummary)

			if _, ok := imagesSpecByTeam[key]; !ok {
				imagesSpecByTeam[key] = make(map[string]ImageSpec)
			}
			imagesSpecByTeam[key][specs.ImageName] = *specs
		}
	}

	imagesByArea := make(map[string]*ImagePerArea)
	for key := range podsByTeam {
		if _, ok := imagesByArea[key.area]; !ok {
			imagesByArea[key.area] = &ImagePerArea{AreaName: key.area, Teams: map[string]*ImagePerTeam{}}
		}
		if _, ok := imagesByArea[key.area].Teams[key.team]; !ok {
			imagesByArea[key.area].Teams[key.team] = &ImagePerTeam{TeamName: key.team}
		}
		imagesByArea[key.area].Teams[key.team].PodCount = len(podsByTeam[key])
		imagesByArea[key.area].Teams[key.team].Pods = podsByTeam[key]

		var teamImages []ImageSpec
		for _, imageSpec := range imagesSpecByTeam[key] {
			teamImages = append(teamImages, imageSpec)
		}

		logr.Infof("Sort area %s, teams %s", key.area, key.team)
		imagesByArea[key.area].Teams[key.team].Images = sortByCriticality(teamImages, false)
		imagesByArea[key.area].Teams[key.team].ImageCount = len(teamImages)

		imagesByArea[key.area].Teams[key.team].ImageSummary = kpisImages(teamImages)
		imagesArr := []ImageSpec{}
		for _, specs := range teamImages {
			for _, trivy := range specs.TrivyOutput {
				if len(trivy.Vulnerabilities) > 0 {
					imagesArr = append(imagesArr, specs)
				}
			}
		}

		imagesByArea[key.area].Teams[key.team].ImageSpecsSortByCriticality = sortByCriticality(imagesArr, true)

	}

	return imagesByArea, nil
}

// ImagePerArea - define ImagePerArea
type ImagePerArea struct {
	AreaName string
	Teams    map[string]*ImagePerTeam
}

// ImagePerTeam define ImagePerTeam
type ImagePerTeam struct {
	TeamName                    string
	PodCount                    int
	ImageCount                  int
	Pods                        []PodSummary
	Images                      []ImageSpec
	ImageSummary                *ImageSummary
	ImageSpecsSortByCriticality []ImageSpec
}

func kpisImages(images []ImageSpec) *ImageSummary {

	imageSum := ImageSummary{}

	imageSum.NumberImagesScanned = len(images)

	imageSum.NumberPodsScanned = 0

	imageSum.ImagePerRegistry = map[string]*ImagePerRegistry{}

	imageSum.TotalVulnerabilityPerCriticality = map[string]int{}
	imageSum.TotalVulnerabilityPerCriticality["CRITICAL"] = 0
	imageSum.TotalVulnerabilityPerCriticality["HIGH"] = 0
	imageSum.TotalVulnerabilityPerCriticality["MEDIUM"] = 0
	imageSum.TotalVulnerabilityPerCriticality["LOW"] = 0

	imageSum.ImagePerRegistry["docker.io"] = &ImagePerRegistry{RegistryName: "docker.io", Pods: []PodSummary{}}

	for _, specs := range images {
		specs.TotalVulnerabilityPerCriticality = map[string]int{}
		specs.TotalVulnerabilityPerCriticality["CRITICAL"] = 0
		specs.TotalVulnerabilityPerCriticality["HIGH"] = 0
		specs.TotalVulnerabilityPerCriticality["MEDIUM"] = 0
		specs.TotalVulnerabilityPerCriticality["LOW"] = 0

		imageSum.NumberPodsScanned = imageSum.NumberPodsScanned + len(specs.Pods)

		imageNamWitoutTag := strings.Split(specs.ImageName, ":")
		imageNameArr := strings.Split(imageNamWitoutTag[0], "/")
		// if contains . then it's a domain name, otherwise it's plain image like ubuntu:latest
		if strings.Contains(imageNameArr[0], ".") {
			// if key doesn't exist
			if _, ok := imageSum.ImagePerRegistry[imageNameArr[0]]; !ok {
				imageSum.ImagePerRegistry[imageNameArr[0]] = &ImagePerRegistry{RegistryName: imageNameArr[0], Pods: []PodSummary{}}
			}

			imageSum.ImagePerRegistry[imageNameArr[0]].Pods = append(imageSum.ImagePerRegistry[imageNameArr[0]].Pods, specs.Pods...)
			imageSum.ImagePerRegistry[imageNameArr[0]].Images = append(imageSum.ImagePerRegistry[imageNameArr[0]].Images, specs.ImageName)
		} else {
			imageSum.ImagePerRegistry["docker.io"].Pods = append(imageSum.ImagePerRegistry["docker.io"].Pods, specs.Pods...)
			imageSum.ImagePerRegistry["docker.io"].Images = append(imageSum.ImagePerRegistry["docker.io"].Images, specs.ImageName)
		}

		for _, output := range specs.TrivyOutput {
			for _, vul := range output.Vulnerabilities {

				// if key doesn't exist
				if _, ok := imageSum.TotalVulnerabilityPerCriticality[vul.Severity]; !ok {
					imageSum.TotalVulnerabilityPerCriticality[vul.Severity] = 0
				}
				if _, ok := specs.TotalVulnerabilityPerCriticality[vul.Severity]; !ok {
					specs.TotalVulnerabilityPerCriticality[vul.Severity] = 0
				}
				imageSum.TotalVulnerabilityPerCriticality[vul.Severity]++
				specs.TotalVulnerabilityPerCriticality[vul.Severity]++
			}
		}

	}

	imageSum.NumberImagesFromExternalRegistry = 0
	imageSum.NumberPodsFromExternalRegistry = 0
	extenalRegistryName := []string{"docker.io", "quay.io", "gcr.io"}
	for registryName, specs := range imageSum.ImagePerRegistry {
		// if key exists
		if contains(extenalRegistryName, registryName) {
			imageSum.NumberPodsFromExternalRegistry = imageSum.NumberPodsFromExternalRegistry + len(specs.Pods)
			imageSum.NumberImagesFromExternalRegistry = imageSum.NumberImagesFromExternalRegistry + len(specs.Images)
		}
		specs.PodCount = len(specs.Pods)
		specs.ImageCount = len(specs.Images)
	}

	return &imageSum
}

func (l *Scanner) convertMapToArrayImageSpecs(images map[string]*ImageSpec, keepOnlyImgWithVul bool) []ImageSpec {
	var imagesArr []ImageSpec
	for _, specs := range images {
		for _, trivy := range specs.TrivyOutput {
			if len(trivy.Vulnerabilities) > 0 && keepOnlyImgWithVul {
				imagesArr = append(imagesArr, *specs)
			} else {
				imagesArr = append(imagesArr, *specs)
			}
		}
	}
	return imagesArr
}

func (l *Scanner) calculateKpis(report *Report) (*Report, error) {

	report.ImageSpecsSortByCriticality = l.convertMapToArrayImageSpecs(report.ImageSpecs, true)
	images := l.convertMapToArrayImageSpecs(report.ImageSpecs, false)
	report.ImageSummary = kpisImages(images)

	// TOP 20 IMAGES CONTAINING THE MOST CRITICAL and high VULNERABILITIES
	// - count all vulnerabilities high + critical
	// TOP 20 IMAGES CONTAINING CRITICAL VULNERABILITIES WITH THE MOST REPLICAS:
	// - count all vulnerabilities most replicas

	logr.Infof("Sorted by Criticality and replicas")
	report.ImageSpecsSortByCriticality = sortByCriticality(report.ImageSpecsSortByCriticality, true)

	for index, image := range report.ImageSpecsSortByCriticality {
		if index < 20 {
			report.ImageSpecsSortByCriticalityTop20MostReplicas = append(report.ImageSpecsSortByCriticalityTop20MostReplicas, image)
		} else {
			break
		}
	}

	logr.Infof("Sorted by Criticality")

	report.ImageSpecsSortByCriticality = sortByCriticality(report.ImageSpecsSortByCriticality, false)
	for index, image := range report.ImageSpecsSortByCriticality {
		if index < 20 {
			report.ImageSpecsSortByCriticalityTop20 = append(report.ImageSpecsSortByCriticalityTop20, image)
		} else {
			break
		}
	}

	return report, nil
}

func sortByCriticality(imageArr []ImageSpec, includePodCount bool) []ImageSpec {
	sort.Slice(imageArr, func(i, j int) bool {

		firstItemScore := 0
		secondItemScore := 0
		if _, ok := imageArr[i].TotalVulnerabilityPerCriticality["CRITICAL"]; ok {
			firstItemScore = firstItemScore + imageArr[i].TotalVulnerabilityPerCriticality["CRITICAL"]*1000000
		}
		if _, ok := imageArr[i].TotalVulnerabilityPerCriticality["HIGH"]; ok {
			firstItemScore = firstItemScore + imageArr[i].TotalVulnerabilityPerCriticality["HIGH"]*10000
		}
		if _, ok := imageArr[i].TotalVulnerabilityPerCriticality["MEDIUM"]; ok {
			firstItemScore = firstItemScore + imageArr[i].TotalVulnerabilityPerCriticality["MEDIUM"]*100
		}
		if _, ok := imageArr[i].TotalVulnerabilityPerCriticality["LOW"]; ok {
			firstItemScore = firstItemScore + imageArr[i].TotalVulnerabilityPerCriticality["LOW"]
		}

		if _, ok := imageArr[j].TotalVulnerabilityPerCriticality["CRITICAL"]; ok {
			secondItemScore = secondItemScore + imageArr[j].TotalVulnerabilityPerCriticality["CRITICAL"]*1000000
		}
		if _, ok := imageArr[j].TotalVulnerabilityPerCriticality["HIGH"]; ok {
			secondItemScore = secondItemScore + imageArr[j].TotalVulnerabilityPerCriticality["HIGH"]*10000
		}
		if _, ok := imageArr[j].TotalVulnerabilityPerCriticality["MEDIUM"]; ok {
			secondItemScore = secondItemScore + imageArr[j].TotalVulnerabilityPerCriticality["MEDIUM"]*100
		}
		if _, ok := imageArr[j].TotalVulnerabilityPerCriticality["LOW"]; ok {
			secondItemScore = secondItemScore + imageArr[j].TotalVulnerabilityPerCriticality["LOW"]
		}

		if includePodCount {

			// logr.Infof(" %d, %d", len(imageArr[i].Pods)*10000, len(imageArr[j].Pods)*10000)
			firstItemScore = firstItemScore + len(imageArr[i].Pods)*10000
			secondItemScore = secondItemScore + len(imageArr[j].Pods)*10000
		}

		// logr.Infof("%s, %d, %v", imageArr[i].ImageName, firstItemScore, imageArr[i].TotalVulnerabilityPerCriticality)
		// logr.Infof("%s, %d, %v ", imageArr[j].ImageName, secondItemScore, imageArr[j].TotalVulnerabilityPerCriticality)
		return firstItemScore > secondItemScore
	})
	return imageArr
}

func contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
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
