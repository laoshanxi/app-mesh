package main

import (
	"context"
	"os"
	"os/signal"
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

// monitorParentExit monitors the parent process and exits if it is no longer alive or the context is canceled.
func monitorParentExit(ctx context.Context) {
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

func startServices(ctx context.Context) {
	// REST proxy
	logger.Infof("RestEnabled: %t", config.ConfigData.REST.RestEnabled)
	if config.ConfigData.REST.RestEnabled {
		go func() {
			if err := agent.ListenRest(); err != nil {
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
		if err := c.HostMetricsReportPeriod(ctx); err != nil {
			logger.Errorf("Host resource reporting failed: %v", err)
		}
	}()
}

// handleGracefulShutdown sets up signal handling for SIGINT and SIGTERM and cancels the context on signal reception.
func handleGracefulShutdown(cancel context.CancelFunc) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		logger.Info("Shutting down gracefully...")
		cancel() // Trigger context cancellation
	}()
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	handleGracefulShutdown(cancel)

	// HMAC initialization
	if hmac, err := cloud.NewHMACVerify(); err != nil {
		logger.Errorf("HMAC Verifier initialization failed: %v", err)
	} else {
		cloud.HMAC = hmac
	}

	// Start all services
	startServices(ctx)
	go monitorParentExit(ctx)

	// Wait for shutdown signal
	<-ctx.Done()
	logger.Info("Shutdown complete.")
}
