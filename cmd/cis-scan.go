package main

import (
	"time"

	"github.com/coreeng/production-readiness/production-readiness/pkg/scanner"
	r "github.com/coreeng/production-readiness/production-readiness/pkg/template"
	logr "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	cisScanCmd = &cobra.Command{
		Use:   "cis-scan",
		Short: "Scan cluster with CIS, NSA and PSS-Restricted security benchmarks",
		Run:   cisScan,
	}
	benchmarks        []string
	defaultBenchmarks = []string{"k8s-cis", "k8s-nsa", "k8s-pss-restricted"}
)

func init() {
	rootCmd.AddCommand(cisScanCmd)
	cisScanCmd.PersistentFlags().StringVar(&kubeconfigPath, "kubeconfig", "", "path to kubeconfig file if connecting from outside a cluster")
	cisScanCmd.PersistentFlags().StringVar(&kubeContext, "context", "", "kubeconfig context to use if connecting from outside a cluster")
	cisScanCmd.Flags().StringVar(&severity, "severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", "severities of vulnerabilities to be reported (comma separated) ")
	cisScanCmd.Flags().StringSliceVar(&benchmarks, "benchmarks", defaultBenchmarks, "List of security benchmarks to run. If not specified all are run (permitted values: k8s-cis,k8s-nsa,k8s-pss-restricted)")
	cisScanCmd.Flags().DurationVar(&scanTimeout, "scan-timeout", 60*time.Minute, "timeout for the Kubernetes cluster scan")
}

func cisScan(_ *cobra.Command, _ []string) {

	t := scanner.NewTrivyClient(severity, scanTimeout)

	for _, benchmark := range benchmarks {
		if !contains(defaultBenchmarks, benchmark) {
			logr.Infof("Unrecognised benchmark: %s. Skipping.... (permitted values: %v))", benchmark, defaultBenchmarks)
			continue
		}

		logr.Infof("Running %s security benchmark. Please wait...", benchmark)
		cisScanReport, err := t.CisScan(benchmark)
		if err != nil {
			logr.Fatalf("Error running %s security benchmark: %v", benchmark, err)
		}

		fullReport := &FullReport{
			CisScan: cisScanReport,
		}
		logr.Infof("Generating %s security benchmark report", benchmark)
		err = r.GenerateReportFromTemplate(fullReport, "templates/report-cisScan.html.tmpl", reportDir, "report-CIS-"+benchmark+".html")
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
}

func contains(elems []string, v string) bool {
	for _, s := range elems {
		if v == s {
			return true
		}
	}
	return false
}
