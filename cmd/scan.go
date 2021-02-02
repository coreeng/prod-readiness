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
	scanCmd.Flags().IntVar(&workersScan, "workers-scan", 10, "number of worker to process images scan in parallel")
}

func scan(_ *cobra.Command, _ []string) {
	kubeconfig := k8s.KubernetesConfig(kubeContext, kubeconfigPath)
	clientset := k8s.KubernetesClient(kubeconfig)
	t := scanner.New(kubeconfig, clientset)

	config := &scanner.Config{
		LogLevel:             logLevel,
		Workers:              workersScan,
		ImageNameReplacement: imageNameReplacement,
		AreaLabels:           areaLabel,
		TeamsLabels:          teamLabels,
		FilterLabels:         filterLabels,
	}

	imageScanReport, err := t.ScanImages(config)
	if err != nil {
		logr.Errorf("Error scanning images with config %v: %v", config, err)
	}
	// logr.Infof("imageScanReport %v, %v", imageScanReport, err)

	fullReport := &FullReport{
		ImageScan: imageScanReport,
	}
	_, err = r.GenerateMarkdown(fullReport, "report-imageScan.md.tmpl", "report-imageScan.md")
	if err != nil {
		// return nil, err
		logr.Error(err)
	}

	err = r.SaveReport(fullReport, "imageScan")
	if err != nil {
		// return nil, err
		logr.Error(err)
	}

}
