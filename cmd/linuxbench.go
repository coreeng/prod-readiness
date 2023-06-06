package main

import (
	"github.com/coreeng/production-readiness/production-readiness/pkg/k8s"
	"github.com/coreeng/production-readiness/production-readiness/pkg/linuxbench"
	r "github.com/coreeng/production-readiness/production-readiness/pkg/template"
	logr "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	linuxBenchCmd = &cobra.Command{
		Use:   "linux-bench",
		Short: "Will run linux-bench as k8s job",
		Run:   linuxBench,
	}
)

func init() {
	// TODO register as root command once ready
	//rootCmd.AddCommand(linuxBenchCmd)
	linuxBenchCmd.PersistentFlags().StringVar(&kubeconfigPath, "kubeconfig", "", "kubeconfig file to use if connecting from outside a cluster")
	linuxBenchCmd.PersistentFlags().StringVar(&kubeContext, "context", "", "kubeconfig context to use if connecting from outside a cluster")
	linuxBenchCmd.Flags().IntVar(&workersLinuxBench, "workers-linux-bench", 5, "number of worker to process linux-bench in parallel")
}

func linuxBench(_ *cobra.Command, _ []string) {
	kubeconfig := k8s.KubernetesConfig(kubeContext, kubeconfigPath)
	clientset := k8s.KubernetesClientset(kubeconfig)
	t := linuxbench.New(kubeconfig, clientset)

	config := &linuxbench.Config{
		LogLevel: logLevel,
		Workers:  workersLinuxBench,
		Template: "linux-bench-node.yaml.tmpl",
	}

	linuxReport, err := t.Run(config)
	if err != nil {
		logr.Errorf("Error scanning images with config %v: %v", config, err)
	}
	logr.Infof("linuxReport %v, %v", linuxReport, err)

	fullReport := &FullReport{
		LinuxCIS: linuxReport,
	}
	err = r.GenerateReportFromTemplate(fullReport, "templates/report-linuxCIS.md.tmpl", reportDir, "report-linuxCIS.md")
	if err != nil {
		// return nil, err
		logr.Error(err)
	}

	err = r.SaveReport(fullReport, "linuxCIS")
	if err != nil {
		// return nil, err
		logr.Error(err)
	}
}
