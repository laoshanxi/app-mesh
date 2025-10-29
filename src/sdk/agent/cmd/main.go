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

// monitorParentProcess monitors the parent process and exits gracefully
// when either the parent exits or the context is canceled.
func monitorParentProcess(ctx context.Context, stop context.CancelFunc) {
	if parentPID <= 1 {
		return // No valid parent to monitor
	}

	timer := time.NewTimer(parentCheckInterval)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			// Context canceled — exit loop, timer will be cleaned up by defer
			return
		case <-timer.C:
			// Check if parent still alive
			if !utils.IsProcessRunning(parentPID) {
				logger.Warn("Parent process exited, canceling context...")
				stop() // Gracefully signal upper layers to stop
				return
			}
			// Reset timer for next check
			timer.Reset(parentCheckInterval)
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

// createSignalContext sets up signal handling for exit
func createSignalContext() (context.Context, context.CancelFunc) {
	baseCtx, cancel := context.WithCancel(context.Background())

	signals := []os.Signal{
		os.Interrupt,    // Ctrl+C
		syscall.SIGTERM, // kill cmd
	}

	if runtime.GOOS != "windows" {
		signals = append(signals,
			syscall.SIGQUIT, // Ctrl+\
			syscall.SIGHUP,  // Console
		)
	}

	signalCtx, stop := signal.NotifyContext(baseCtx, signals...)

	return signalCtx, func() {
		stop()
		cancel()
	}
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

	//import _ "net/http/pprof"
	//go func() {
	//    log.Println(http.ListenAndServe("localhost:7070", nil))
	//}()
	logger.Info("Starting agent with PID:", os.Getpid())
	cwd, _ := os.Getwd()
	logger.Info("Current working directory:", cwd)

	ctx, stop := createSignalContext()
	defer stop()

	config.ResolveAbsolutePaths()

	// Read PSK from shared memory
	psk, err := readPSKFromSHM()
	if err != nil || len(psk) == 0 {
		logger.Fatal("failed to read PSK from shared memory")
	}
	cloud.HMAC_AgentToCPP = cloud.NewHMACVerify(string(psk))

	// Initialize HMAC (use configured salt for cluster-shared tokens)
	salt := config.ConfigData.REST.JWT.JWTSalt
	if salt == "" {
		logger.Fatal("JWT salt is missing in configuration")
	}
	cloud.HMAC_SDKToAgent = cloud.NewHMACVerify(salt)

	// Start all services
	initializeServices(ctx)
	go monitorParentProcess(ctx, stop)

	changeWorkDir(path.Join(config.GetAppMeshHomeDir(), "work", "tmp"))

	// Wait for shutdown signal
	<-ctx.Done()
	logger.Info("Received shutdown signal, initiating graceful shutdown...")

	// shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	// defer cancel()
	// Do clean with timeout here
}
