package main

import (
	"context"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/agent"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/cloud"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
)

const (
	parentCheckInterval = time.Second
	minPort             = 1024
)

var logger = utils.GetLogger()

// monitorParentProcess monitors the parent process and exits if it is no longer alive or the context is canceled.
func monitorParentProcess(ctx context.Context) {
	parentPID := os.Getppid()
	if parentPID <= 1 {
		return // No valid parent to monitor
	}

	proc, err := os.FindProcess(parentPID)
	if err != nil {
		logger.Errorf("Failed to find parent process: %v", err)
		return
	}

	ticker := time.NewTicker(parentCheckInterval)
	defer ticker.Stop() // Ensure ticker is cleaned up

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check if the parent process is alive
			if err := proc.Signal(syscall.Signal(0)); err != nil {
				logger.Fatal("Parent process exited, shutting down")
			}
		}
	}
}

// initializeServices starts all necessary services based on the configuration.
func initializeServices(ctx context.Context) {
	// REST proxy
	logger.Infof("RestEnabled: %t", config.ConfigData.REST.RestEnabled)
	if config.ConfigData.REST.RestEnabled {
		go func() {
			if err := agent.ListenAndServeREST(); err != nil {
				logger.Fatalf("REST agent failed: %v", err)
			}
		}()
	}

	// Prometheus exporter
	logger.Infof("PrometheusExporterListenPort: %d", config.ConfigData.REST.PrometheusExporterListenPort)
	if port := config.ConfigData.REST.PrometheusExporterListenPort; port > minPort {
		go func() {
			if err := agent.ListenPrometheus(port); err != nil {
				logger.Errorf("Prometheus exporter failed: %v", err)
			}
		}()
		logger.Infof("<Prometheus Exporter> listening at: %d", port)
	}

	// Cloud resource reporting
	go func() {
		c := cloud.NewCloud()
		if err := c.ReportHostMetricsPeriodically(ctx); err != nil {
			logger.Errorf("Host resource reporting failed: %v", err)
		}
	}()
}

// setupGracefulShutdown sets up signal handling for SIGINT and SIGTERM and cancels the context on signal reception.
func setupGracefulShutdown(cancel context.CancelFunc) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		logger.Info("Shutting down gracefully...")
		cancel() // Trigger context cancellation
	}()
}

func changeWorkDir(dir string) {
	if err := os.Chdir(dir); err != nil {
		logger.Fatalf("Failed to change directory to %s : %v", dir, err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		logger.Fatalf("Failed to get working directory: %v", err)
	}
	logger.Infof("Changed working directory to: %s", cwd)
}

func main() {
	cwd, _ := os.Getwd()
	logger.Info("Current working directory:", cwd)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config.AbsConfigPath()

	// Handle graceful shutdown
	setupGracefulShutdown(cancel)

	// HMAC initialization
	if hmac, err := cloud.NewHMACVerify(); err != nil {
		logger.Errorf("HMAC Verifier initialization failed: %v", err)
	} else {
		cloud.HMAC = hmac
	}

	// Start all services
	initializeServices(ctx)
	go monitorParentProcess(ctx)

	changeWorkDir(path.Join(config.GetAppMeshHomeDir(), "work", "tmp"))

	// Wait for shutdown signal
	<-ctx.Done()
	logger.Info("Shutdown complete.")
}
