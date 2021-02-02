package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	logr "github.com/sirupsen/logrus"

	execCmd "github.com/coreeng/production-readiness/production-readiness/pkg/cmd"
	"github.com/spf13/cobra"
)

var signalsCh chan os.Signal

var rootCmd = &cobra.Command{
	Use:   "production-readiness",
	Short: "Utility to analyse an environment/cluster",
	Run:   runCheck,
}

var (
	logLevel            string
	image               string
	enableImageScanning bool
	serverAdminPort     int
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "L", logr.InfoLevel.String(), "should be one of: debug, info, warn, error, fatal, panic.")
	rootCmd.PersistentFlags().IntVar(&serverAdminPort, "admin-port", 18081, "Admin port")
	rootCmd.PersistentFlags().BoolVar(&enableImageScanning, "scan-image", false, "Enable image scanning")
	rootCmd.PersistentFlags().StringVar(&image, "image", "", "Name of the image to scan.")

	// _ = rootCmd.MarkPersistentFlagRequired("admin-port")
	cobra.OnInitialize(onInitialise)
}

func onInitialise() {
	setLogLevel(logLevel)
}

func runCheck(_ *cobra.Command, _ []string) {
	doneCh := make(chan bool, 1)

	startServer(serverAdminPort)
	if enableImageScanning {
		cmd := "trivy"
		args := []string{"image", "-f", "json", image}

		execCmd.Execute(cmd, args)
	}

	handleSignals(doneCh)

	<-doneCh
	logr.Info("Shut down complete")
}

func startServer(adminPort int) *http.Server {
	serverMux := http.NewServeMux()
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", adminPort),
		Handler: serverMux,
	}
	serverMux.Handle("/metrics", promhttp.Handler())
	serverMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	go func() {
		logr.Infof("Starting to listen at: http://0.0.0.0%s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logr.Fatalf("Unexpected failure when starting the server: %v", err)
		}
	}()
	return server
}

func handleSignals(doneCh chan bool) {
	signalsCh = make(chan os.Signal, 1)
	signal.Notify(signalsCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-signalsCh
		logr.Infof("Received signal %s", sig)
		doneCh <- true
	}()
}

func setLogLevel(logLevel string) {
	level, err := logr.ParseLevel(logLevel)
	if err != nil {
		logAndExit("invalid log-level")
	}
	logr.SetLevel(level)
}

func logAndExit(message string, args ...interface{}) {
	logr.Errorf(message, args...)
	os.Exit(1)
}
