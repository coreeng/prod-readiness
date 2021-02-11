package main

import (
	"github.com/coreeng/production-readiness/production-readiness/pkg/k8s"
	r "github.com/coreeng/production-readiness/production-readiness/pkg/report"
	"github.com/coreeng/production-readiness/production-readiness/pkg/scanner"
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
	scanCmd.Flags().IntVar(&workersScan, "workers-scan", 10, "number of worker to process images scan in parallel")
	scanCmd.Flags().StringVar(&reportTemplate, "report-template-filename", "report-imageScan.md.tmpl", "input filename that will be used as report template")
	scanCmd.Flags().StringVar(&reportFile, "report-filename", "report-imageScan.md", "output filename where that will contain the generated report based on the report-template")
	scanCmd.Flags().StringVar(&jsonReportFile, "json-report-filename", "", "output filename where the json representation of the report will be saved. No json representation will be created unless this option is specified")
}

func scan(_ *cobra.Command, _ []string) {
	kubeconfig := k8s.KubernetesConfig(kubeContext, kubeconfigPath)
	clientset := k8s.KubernetesClient(kubeconfig)

	config := &scanner.Config{
		LogLevel:             logLevel,
		Workers:              workersScan,
		ImageNameReplacement: imageNameReplacement,
		AreaLabels:           areaLabel,
		TeamsLabels:          teamLabels,
		FilterLabels:         filterLabels,
		Severity:             severity,
	}
	t := scanner.New(clientset, config)

	imageScanReport, err := t.ScanImages()
	if err != nil {
		logr.Fatalf("Error scanning images with config %v: %v", config, err)
	}

	fullReport := &FullReport{
		ImageScan: imageScanReport,
	}
	err = r.GenerateMarkdown(fullReport, reportTemplate, reportFile)
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
