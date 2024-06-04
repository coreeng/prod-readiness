package main

import (
	"time"

	"github.com/coreeng/production-readiness/production-readiness/pkg/k8s"
	"github.com/coreeng/production-readiness/production-readiness/pkg/scanner"
	r "github.com/coreeng/production-readiness/production-readiness/pkg/template"
	logr "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Will gather all the docker images available in a cluster and scan the image to check vulnerabilities",
		Run:   scan,
	}
)

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.PersistentFlags().StringVar(&kubeconfigPath, "kubeconfig", "", "kubeconfig file to use if connecting from outside a cluster")
	scanCmd.PersistentFlags().StringVar(&kubeContext, "context", "", "kubeconfig context to use if connecting from outside a cluster")
	scanCmd.Flags().StringVar(&imageNameReplacement, "image-name-replacement", "", "string replacement to replace name into the image name for ex: registry url, format: 'registry-mirror:5000|registry.com,registry-second:5000|registry-second.com' list separated by comma, matching and replacement string are seperated by a pipe '|'")
	scanCmd.Flags().StringVar(&areaLabel, "area-labels", "", "string allowing to split per area the image scan")
	scanCmd.Flags().StringVar(&teamLabels, "teams-labels", "", "string allowing to split per team the image scan")
	scanCmd.Flags().StringVar(&filterLabels, "filters-labels", "", "string allowing to filter the namespaces string separated by comma")
	scanCmd.Flags().StringVar(&severity, "severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", "severities of vulnerabilities to be reported (comma separated) ")
	scanCmd.Flags().StringVar(&reportTemplate, "report-input-template", "templates/report-imageScan.html.tmpl", "input filename that will be used as report template")
	scanCmd.Flags().StringVar(&reportFile, "report-output-filename", "report-imageScan.html", "output filename where that will contain the generated report based on the report-template")
	scanCmd.Flags().StringVar(&jsonReportFile, "report-output-filename-json", "", "output filename where the json representation of the report will be saved. No json representation will be created unless this option is specified")
	scanCmd.Flags().DurationVar(&scanTimeout, "scan-timeout", 5*time.Minute, "timeout for each container image scan")
	scanCmd.Flags().IntVar(&scanWorkers, "scan-workers", 10, "number of worker to process images scan in parallel")
	scanCmd.Flags().BoolVar(&reportVerbose, "report-output-verbose", false, "enable additional scan output columns (status, installed version, fixed version) in the report")
}

func scan(_ *cobra.Command, _ []string) {
	config := &scanner.Config{
		LogLevel:             logLevel,
		Workers:              scanWorkers,
		ImageNameReplacement: imageNameReplacement,
		AreaLabels:           areaLabel,
		TeamsLabels:          teamLabels,
		FilterLabels:         filterLabels,
		Severity:             severity,
		ScanImageTimeout:     scanTimeout,
	}
	t := scanner.New(k8s.NewKubernetesClient(kubeContext, kubeconfigPath), config)

	imageScanReport, err := t.ScanImages()
	if err != nil {
		logr.Fatalf("Error scanning images with config %v: %v", config, err)
	}

	fullReport := &FullReport{
		ImageScan: imageScanReport,
		VerboseScan: reportVerbose,
	}
	err = r.GenerateReportFromTemplate(fullReport, reportTemplate, reportDir, reportFile)
	if err != nil {
		logr.Fatal(err)
	}

	if jsonReportFile != "" {
		err = r.SaveReport(fullReport, jsonReportFile)
		if err != nil {
			logr.Fatal(err)
		}
	}

}
