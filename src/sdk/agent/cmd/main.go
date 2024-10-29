package main

import (
	"os"
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

func monitorParentExit(parentPID int) {
	if err := setPDeathSignal(); err != nil {
		logger.Errorf("Failed to set parent death signal: %v", err)
	}

	for {
		if os.Getppid() != parentPID {
			logger.Fatal("Parent process exited, shutting down")
		}
		time.Sleep(parentCheckInterval)
	}
}

func setPDeathSignal() error {
	_, _, errno := syscall.RawSyscall(uintptr(syscall.SYS_PRCTL), uintptr(syscall.PR_SET_PDEATHSIG), uintptr(syscall.SIGKILL), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func startServices() {

	// Start REST proxy if enabled
	logger.Infof("RestEnabled: %t", config.ConfigData.REST.RestEnabled)
	if config.ConfigData.REST.RestEnabled {
		go func() {
			if err := agent.ListenRest(); err != nil {
				logger.Fatalf("REST agent failed: %v", err)
			}
		}()
	}

	// Start Prometheus exporter if port is valid
	logger.Infof("PrometheusExporterListenPort: %d", config.ConfigData.REST.PrometheusExporterListenPort)
	if port := config.ConfigData.REST.PrometheusExporterListenPort; port > minPort {
		go func() {
			if err := agent.ListenPrometheus(port); err != nil {
				logger.Errorf("Prometheus exporter failed: %v", err)
			}
		}()
		logger.Infof("<Prometheus Exporter> listening at: %d", port)
	}

	// Start cloud resource reporting
	go func() {
		c := cloud.NewCloud()
		if err := c.HostMetricsReportPeriod(); err != nil {
			logger.Errorf("Host resource reporting failed: %v", err)
		}
	}()
}

func main() {

	// Initialize HMAC verifier
	var err error
	if cloud.HMAC, err = cloud.NewHMACVerify(); err != nil {
		logger.Errorf("HMAC Verifier initialization failed: %v", err)
	}

	// Start all services
	startServices()

	// Start parent process monitoring
	parentPID := os.Getppid()
	monitorParentExit(parentPID)
}
