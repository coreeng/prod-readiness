package main

import (
	"time"

	"github.com/coreeng/production-readiness/production-readiness/pkg/k8s"
	"github.com/coreeng/production-readiness/production-readiness/pkg/linuxbench"
	"github.com/coreeng/production-readiness/production-readiness/pkg/scanner"
	r "github.com/coreeng/production-readiness/production-readiness/pkg/template"
	logr "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	reportCmd = &cobra.Command{
		Use:   "report",
		Short: "Will create a full audit of a cluster and generate presentation and json output",
		Run:   report,
	}
	kubeContext, kubeconfigPath, imageNameReplacement, areaLabel, teamLabels, filterLabels, severity, jsonReportFile, reportDir, reportFile, reportTemplate string
	scanWorkers, workersLinuxBench                                                                                                                          int
	scanTimeout                                                                                                                                             time.Duration
	reportVerbose                                                                                                                                           bool
)

func init() {
	rootCmd.AddCommand(reportCmd)
	reportCmd.PersistentFlags().StringVar(&kubeconfigPath, "kubeconfig", "", "kubeconfig file to use if connecting from outside a cluster")
	reportCmd.PersistentFlags().StringVar(&kubeContext, "context", "", "kubeconfig context to use if connecting from outside a cluster")
	reportCmd.Flags().StringVar(&imageNameReplacement, "image-name-replacement", "", "string replacement to replace name into the image name for ex: registry url, format: 'registry-mirror:5000|registry.com,registry-second:5000|registry-second.com' list separated by comma, matching and replacement string are seperated by a pipe '|'")
	reportCmd.Flags().IntVar(&scanWorkers, "scan-workers", 10, "number of worker to process images scan in parallel")
	reportCmd.Flags().IntVar(&workersLinuxBench, "workers-linux-bench", 5, "number of worker to process linux-bench in parallel")
	reportCmd.Flags().StringVar(&areaLabel, "area-labels", "", "string allowing to split per area the image scan")
	reportCmd.Flags().StringVar(&teamLabels, "teams-labels", "", "string allowing to split per team the image scan")
	reportCmd.Flags().StringVar(&filterLabels, "filters-labels", "", "string allowing to filter the namespaces string separated by comma")
	reportCmd.Flags().StringVar(&severity, "severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", "severities of vulnerabilities to be reported (comma separated) ")
	reportCmd.Flags().StringVar(&reportTemplate, "report-input-template", "templates/report.md.tmpl", "input filename that will be used as report template")
	reportCmd.Flags().StringVar(&reportDir, "report-output-directory", "audit-report/", "output directory that will contain the generated report")
	reportCmd.Flags().StringVar(&reportFile, "report-output-filename", "report.md", "output filename that will contain the generated report based on the report-template")
	reportCmd.Flags().StringVar(&jsonReportFile, "report-output-filename-json", "", "output filename where the json representation of the report will be saved. No json representation will be created unless this option is specified")
	reportCmd.Flags().DurationVar(&scanTimeout, "scan-timeout", 5*time.Minute, "timeout for the container image scan")
	reportCmd.Flags().BoolVar(&reportVerbose, "report-output-verbose", false, "enable additional scan output columns (status, installed version, fixed version) in the report")
}

// FullReport - FullReport
type FullReport struct {
	ImageScan   *scanner.VulnerabilityReport
	VerboseScan bool
	LinuxCIS    *linuxbench.LinuxReport
	CisScan     *scanner.CisOutput
}

func report(cmd *cobra.Command, str []string) {
	kubeconfig := k8s.KubernetesConfig(kubeContext, kubeconfigPath)
	clientset := k8s.KubernetesClientset(kubeconfig)

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

	t := scanner.New(k8s.NewKubernetesClientWith(clientset), config)
	imageScanReport, err := t.ScanImages()
	if err != nil {
		logr.Errorf("Error scanning images with config %v: %v", config, err)
	}

	cisScan(cmd, str)

	l := linuxbench.New(kubeconfig, clientset)

	configLinux := &linuxbench.Config{
		LogLevel: logLevel,
		Workers:  workersLinuxBench,
		Template: "linux-bench-node.yaml.tmpl",
	}

	linuxReport, err := l.Run(configLinux)
	if err != nil {
		logr.Errorf("Error scanning images with config %v: %v", configLinux, err)
	}
	logr.Infof("linuxReport %v, %v", linuxReport, err)

	fullReport := &FullReport{
		ImageScan: imageScanReport,
		LinuxCIS:  linuxReport,
	}
	err = r.GenerateReportFromTemplate(fullReport, "templates/report-linuxCIS.html.tmpl", reportDir, "report-linuxCIS.html")

	err = r.GenerateReportFromTemplate(fullReport, reportTemplate, reportDir, reportFile)
	if err != nil {
		logr.Error(err)
	}

	if jsonReportFile != "" {
		err = r.SaveReport(fullReport, jsonReportFile)
		if err != nil {
			logr.Error(err)
		}
	}
}
