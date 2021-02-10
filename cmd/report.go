package main

import (
	"github.com/coreeng/production-readiness/production-readiness/pkg/k8s"
	"github.com/coreeng/production-readiness/production-readiness/pkg/kubebench"
	"github.com/coreeng/production-readiness/production-readiness/pkg/linuxbench"
	r "github.com/coreeng/production-readiness/production-readiness/pkg/report"
	"github.com/coreeng/production-readiness/production-readiness/pkg/scanner"
	logr "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	reportCmd = &cobra.Command{
		Use:   "report",
		Short: "Will create a full audit of a cluster and generate presentation and json output",
		Run:   report,
	}
	kubeContext, kubeconfigPath, imageNameReplacement, areaLabel, teamLabels, filterLabels, severity, jsonReportFile string
	workersScan, workersKubeBench, workersLinuxBench                                                                 int
)

func init() {
	rootCmd.AddCommand(reportCmd)
	reportCmd.PersistentFlags().StringVar(&kubeconfigPath, "kubeconfig", "", "kubeconfig file to use if connecting from outside a cluster")
	reportCmd.PersistentFlags().StringVar(&kubeContext, "context", "", "kubeconfig context to use if connecting from outside a cluster")
	reportCmd.Flags().StringVar(&imageNameReplacement, "image-name-replacement", "", "string replacement to replace name into the image name for ex: registry url, format: 'registry-mirror:5000|registry.com,registry-second:5000|registry-second.com' list separated by comma, matching and replacement string are seperated by a pipe '|'")
	reportCmd.Flags().IntVar(&workersScan, "workers-scan", 10, "number of worker to process images scan in parallel")
	reportCmd.Flags().IntVar(&workersKubeBench, "workers-kube-bench", 5, "number of worker to process kube-bench in parallel")
	reportCmd.Flags().IntVar(&workersLinuxBench, "workers-linux-bench", 5, "number of worker to process linux-bench in parallel")
	reportCmd.Flags().StringVar(&areaLabel, "area-labels", "", "string allowing to split per area the image scan")
	reportCmd.Flags().StringVar(&teamLabels, "teams-labels", "", "string allowing to split per team the image scan")
	reportCmd.Flags().StringVar(&filterLabels, "filters-labels", "", "string allowing to filter the namespaces string separated by comma")
	reportCmd.Flags().StringVar(&severity, "severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", "severities of vulnerabilities to be reported (comma separated) ")
	reportCmd.Flags().StringVar(&jsonReportFile, "json-report-filename", "", "optional filename where the json representation of the report will be saved")
}

// FullReport - FullReport
type FullReport struct {
	ImageScan *scanner.Report
	KubeCIS   *kubebench.KubeReport
	LinuxCIS  *linuxbench.LinuxReport
}

func report(_ *cobra.Command, _ []string) {
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
		logr.Errorf("Error scanning images with config %v: %v", config, err)
	}

	k := kubebench.New(kubeconfig, clientset)

	configKubeBench := &kubebench.Config{
		LogLevel: logLevel,
		Workers:  workersKubeBench,
		Template: "job-node.yaml.tmpl",
	}

	kubeReport, err := k.Run(configKubeBench)
	if err != nil {
		logr.Errorf("Error scanning images with config %v: %v", config, err)
	}

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
		KubeCIS:   kubeReport,
		LinuxCIS:  linuxReport,
	}

	err = r.GenerateMarkdown(fullReport, "report.md.tmpl", "report.md")
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
