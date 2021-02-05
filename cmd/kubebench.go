package main

import (
	"github.com/coreeng/production-readiness/production-readiness/pkg/k8s"
	"github.com/coreeng/production-readiness/production-readiness/pkg/kubebench"
	r "github.com/coreeng/production-readiness/production-readiness/pkg/report"
	logr "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	kubeBenchCmd = &cobra.Command{
		Use:   "kube-bench",
		Short: "Will run kube-bench as k8s job",
		Run:   kubeBench,
	}
)

func init() {
	rootCmd.AddCommand(kubeBenchCmd)
	kubeBenchCmd.PersistentFlags().StringVar(&kubeconfigPath, "kubeconfig", "", "kubeconfig file to use if connecting from outside a cluster")
	kubeBenchCmd.PersistentFlags().StringVar(&kubeContext, "context", "", "kubeconfig context to use if connecting from outside a cluster")
	kubeBenchCmd.Flags().IntVar(&workersKubeBench, "workers-kube-bench", 5, "number of worker to process kube-bench in parallel")
}

func kubeBench(_ *cobra.Command, _ []string) {
	kubeconfig := k8s.KubernetesConfig(kubeContext, kubeconfigPath)
	clientset := k8s.KubernetesClient(kubeconfig)
	t := kubebench.New(kubeconfig, clientset)

	config := &kubebench.Config{
		LogLevel: logLevel,
		Workers:  workersKubeBench,
		Template: "job-node.yaml.tmpl",
	}

	kubeReport, err := t.Run(config)
	if err != nil {
		logr.Errorf("Error scanning images with config %v: %v", config, err)
	}
	logr.Infof("kubeReport %v, %v", kubeReport, err)

	fullReport := &FullReport{
		KubeCIS: kubeReport,
	}
	err = r.GenerateMarkdown(fullReport, "report-kubeCIS.md.tmpl", "report-kubeCIS.md")
	if err != nil {
		// return nil, err
		logr.Error(err)
	}

	err = r.SaveReport(fullReport, "kubeCIS")
	if err != nil {
		// return nil, err
		logr.Error(err)
	}
}
