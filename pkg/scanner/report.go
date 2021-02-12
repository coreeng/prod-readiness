package scanner

import (
	"sort"

	"github.com/coreeng/production-readiness/production-readiness/pkg/k8s"
)

// VulnerabilityReport is top level structure holding the results of the image scan
type VulnerabilityReport struct {
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

// AreaReport generates a report grouped by area and team
type AreaReport struct {
	AreaLabelName string
	TeamLabelName string
}

// GenerateVulnerabilityReport generates a vulnerability report grouping images by
func (r *AreaReport) GenerateVulnerabilityReport(scannedImages []ScannedImage) (*VulnerabilityReport, error) {
	imagesByArea, err := r.generateAreaGrouping(scannedImages)
	if err != nil {
		return nil, err
	}
	return &VulnerabilityReport{
		ScannedImages: scannedImages,
		ImageByArea:   imagesByArea,
	}, nil
}

type teamKey struct {
	area, team string
}

func (r *AreaReport) generateAreaGrouping(scannedImages []ScannedImage) (map[string]*ImagePerArea, error) {
	scannedImagesByTeam, containersByTeam := groupImagesAndContainersByAreaAndTeam(scannedImages, r.AreaLabelName, r.TeamLabelName)
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

func groupImagesAndContainersByAreaAndTeam(scannedImages []ScannedImage, areaLabelName, teamLabelName string) (map[teamKey]map[string]ScannedImage, map[teamKey][]k8s.ContainerSummary) {
	scannedImagesByTeam := make(map[teamKey]map[string]ScannedImage)
	containersByTeam := make(map[teamKey][]k8s.ContainerSummary)
	var areaLabel, teamsLabel string
	for _, scannedImage := range scannedImages {
		for _, containerSummary := range scannedImage.Containers {
			areaLabel = containerSummary.NamespaceLabels[areaLabelName]
			teamsLabel = containerSummary.NamespaceLabels[teamLabelName]

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
