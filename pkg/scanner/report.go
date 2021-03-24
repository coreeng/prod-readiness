package scanner

import (
	"sort"

	"github.com/coreeng/production-readiness/production-readiness/pkg/k8s"
)

// VulnerabilityReport is top level structure holding the results of the image scan
type VulnerabilityReport struct {
	ScannedImages []ScannedImage
	AreaSummary   map[string]*AreaSummary
}

// AreaSummary holds the summary of the vulnerabilities of the teams
type AreaSummary struct {
	Name                         string
	Teams                        map[string]*TeamSummary
	ImageCount                   int
	ContainerCount               int
	TotalVulnerabilityBySeverity map[string]int
}

// TeamSummary defines the summary for an team
type TeamSummary struct {
	Name                      string
	Images                    []ScannedImage
	Containers                []k8s.ContainerSummary
	ImageCount                int
	ContainerCount            int
	ImageVulnerabilitySummary map[string]*VulnerabilitySummary
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
		AreaSummary:   imagesByArea,
	}, nil
}

type teamKey struct {
	area, team string
}

func (r *AreaReport) generateAreaGrouping(scannedImages []ScannedImage) (map[string]*AreaSummary, error) {
	imageByTeam := groupImagesByTeam(scannedImages, r.AreaLabelName, r.TeamLabelName)
	var summaryByArea = make(map[string]*AreaSummary)
	for teamID, teamImageMap := range imageByTeam {
		if _, ok := summaryByArea[teamID.area]; !ok {
			summaryByArea[teamID.area] = &AreaSummary{
				Name:  teamID.area,
				Teams: make(map[string]*TeamSummary),
			}
		}

		teamSummary := buildTeamSummary(teamImageMap, teamID)
		summaryByArea[teamID.area].Teams[teamID.team] = teamSummary
		summaryByArea[teamID.area].aggregate(teamSummary)
	}

	return summaryByArea, nil
}

func (a *AreaSummary) aggregate(teamSummary *TeamSummary) {
	a.ImageCount += teamSummary.ImageCount
	a.ContainerCount += teamSummary.ContainerCount
	if a.TotalVulnerabilityBySeverity == nil {
		a.TotalVulnerabilityBySeverity = make(map[string]int)
	}
	for _, vulnerabilitySummary := range teamSummary.ImageVulnerabilitySummary {
		if vulnerabilitySummary != nil {
			for severity, count := range vulnerabilitySummary.TotalVulnerabilityBySeverity {
				a.TotalVulnerabilityBySeverity[severity] += count
			}
		}
	}
}

func groupImagesByTeam(allImages []ScannedImage, areaLabelName, teamLabelName string) map[teamKey]map[string]*ScannedImage {
	imageByTeam := make(map[teamKey]map[string]*ScannedImage)
	var areaLabel, teamsLabel string
	for _, i := range allImages {
		for _, c := range i.Containers {
			areaLabel = c.NamespaceLabels[areaLabelName]
			teamsLabel = c.NamespaceLabels[teamLabelName]

			if areaLabel == "" {
				areaLabel = "all"
			}
			if teamsLabel == "" {
				teamsLabel = "all"
			}

			teamID := teamKey{area: areaLabel, team: teamsLabel}
			if _, ok := imageByTeam[teamID]; !ok {
				imageByTeam[teamID] = make(map[string]*ScannedImage)
			}
			if _, ok := imageByTeam[teamID][i.ImageName]; !ok {
				imageByTeam[teamID][i.ImageName] = &ScannedImage{
					ImageName:            i.ImageName,
					TrivyOutput:          i.TrivyOutput,
					VulnerabilitySummary: i.VulnerabilitySummary,
					Containers:           nil,
					ScanError:            i.ScanError,
				}
			}
			imageByTeam[teamID][i.ImageName].Containers = append(imageByTeam[teamID][i.ImageName].Containers, c)
		}
	}
	return imageByTeam
}

func buildTeamSummary(teamImageMap map[string]*ScannedImage, teamID teamKey) *TeamSummary {
	var teamContainers []k8s.ContainerSummary
	var teamImages []ScannedImage
	imagesVulnerabilities := make(map[string]*VulnerabilitySummary)
	for _, scannedImage := range teamImageMap {
		teamImages = append(teamImages, *scannedImage)
		teamContainers = append(teamContainers, scannedImage.Containers...)
		imagesVulnerabilities[scannedImage.ImageName] = scannedImage.VulnerabilitySummary
	}

	return &TeamSummary{
		Name:                      teamID.team,
		Images:                    sortBySeverity(teamImages),
		ImageCount:                len(teamImages),
		Containers:                teamContainers,
		ContainerCount:            len(teamContainers),
		ImageVulnerabilitySummary: imagesVulnerabilities,
	}
}

func sortBySeverity(scannedImages []ScannedImage) []ScannedImage {
	sort.Slice(scannedImages, func(i, j int) bool {
		firstItemScore := 0
		secondItemScore := 0

		if scannedImages[i].VulnerabilitySummary != nil {
			firstItemScore = scannedImages[i].VulnerabilitySummary.SeverityScore()
		}
		if scannedImages[j].VulnerabilitySummary != nil {
			secondItemScore = scannedImages[j].VulnerabilitySummary.SeverityScore()
		}
		return firstItemScore > secondItemScore
	})
	return scannedImages
}
