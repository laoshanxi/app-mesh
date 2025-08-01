package main

import (
	"context"
	"os"
	"os/signal"
	"path"
	"runtime"
	"syscall"
	"time"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/agent"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/cloud"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
)

const (
	parentCheckInterval = time.Second * 2
	minPort             = 1024
)

var logger = utils.GetLogger()
var parentPID = os.Getppid()

// monitorParentProcess monitors the parent process and exits if it is no longer alive or the context is canceled.
func monitorParentProcess(ctx context.Context) {
	if parentPID <= 1 {
		return // No valid parent to monitor
	}

	// Instead of creating a ticker that runs constantly, use a longer interval
	// and efficiently wait using a timer channel
	timer := time.NewTimer(parentCheckInterval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			// Check if parent exists by checking /proc directly instead of using Signal(0)
			if !utils.IsProcessRunning(parentPID) {
				logger.Fatal("Parent process exited, shutting down")
			}
			// Reset the timer with a longer interval
			timer.Reset(parentCheckInterval)
		}
	}
}

// ensureSystemRoot sets the SYSTEMROOT environment variable if it is not already set.
// https://github.com/golang/go/issues/61452
// https://github.com/golang/go/issues/26457
// https://go-review.googlesource.com/c/go/+/124858
func ensureSystemRoot() {
	if runtime.GOOS == "windows" && os.Getenv("SYSTEMROOT") == "" {
		if err := os.Setenv("SYSTEMROOT", `C:\Windows`); err != nil {
			logger.Warnf("Failed to set SYSTEMROOT: %v", err)
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

	ensureSystemRoot()
	//import _ "net/http/pprof"
	//go func() {
	//    log.Println(http.ListenAndServe("localhost:7070", nil))
	//}()
	logger.Info("Starting agent with PID:", os.Getpid())
	cwd, _ := os.Getwd()
	logger.Info("Current working directory:", cwd)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config.ResolveAbsolutePaths()

	// Handle graceful shutdown
	setupGracefulShutdown(cancel)

	// HMAC initialization
	if hmac, err := cloud.NewHMACVerify(); err != nil {
		logger.Fatalf("HMAC Verifier initialization failed: %v", err)
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
