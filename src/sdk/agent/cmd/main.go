package main

import (
	"flag"
	"log"
	"os"
	"syscall"
	"time"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/agent"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/cloud"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
)

const (
	parentCheckInterval = time.Second
	minPort             = 1024
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func monitorParentExit(parentPID int) {
	if err := setPDeathSignal(); err != nil {
		log.Printf("Failed to set parent death signal: %v", err)
	}

	for {
		if os.Getppid() != parentPID {
			log.Println("Parent process exited, shutting down")
			os.Exit(0)
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
	// Start Docker proxy if address is provided
	log.Printf("DockerListenAddress: %s, DockerSocketFilePath: %s", agent.DockerListenAddress, agent.DockerSocketFilePath)
	if agent.DockerListenAddress != "" {
		go func() {
			if err := agent.ListenDocker(
				config.ConfigData.REST.SSL.SSLCertificateFile,
				config.ConfigData.REST.SSL.SSLCertificateKeyFile,
				config.ConfigData.REST.SSL.SSLCaPath); err != nil {
				log.Printf("Docker agent failed: %v", err)
			}
		}()
		log.Printf("<Docker Agent> listening at: %s, forwarding to: %s", agent.DockerListenAddress, agent.DockerSocketFilePath)
	}

	// Start REST proxy if enabled
	log.Printf("RestEnabled: %t", config.ConfigData.REST.RestEnabled)
	if config.ConfigData.REST.RestEnabled {
		go func() {
			if err := agent.ListenRest(); err != nil {
				log.Fatalf("REST agent failed: %v", err)
			}
		}()
	}

	// Start Prometheus exporter if port is valid
	log.Printf("PrometheusExporterListenPort: %d", config.ConfigData.REST.PrometheusExporterListenPort)
	if port := config.ConfigData.REST.PrometheusExporterListenPort; port > minPort {
		go func() {
			if err := agent.ListenPrometheus(port); err != nil {
				log.Printf("Prometheus exporter failed: %v", err)
			}
		}()
		log.Printf("<Prometheus Exporter> listening at: %d", port)
	}

	// Start cloud resource reporting
	go func() {
		c := cloud.NewCloud()
		if err := c.HostMetricsReportPeriod(); err != nil {
			log.Printf("Host resource reporting failed: %v", err)
		}
	}()
}

func main() {
	// Parse command line flags
	dockerAddr := flag.String("docker_agent_url", agent.DockerListenAddress, "Host URL for Docker proxy, e.g., https://127.0.0.1:6058")
	socketSock := flag.String("docker_socket_file", agent.DockerSocketFilePath, "Path to Docker's Unix domain socket file")
	flag.Parse()

	// Update configuration based on flags
	if dockerAddr != nil && socketSock != nil {
		agent.DockerListenAddress = *dockerAddr
		agent.DockerSocketFilePath = *socketSock
	}

	// Initialize HMAC verifier
	var err error
	if cloud.HMAC, err = cloud.NewHMACVerify(); err != nil {
		log.Printf("HMAC Verifier initialization failed: %v", err)
	}

	// Start all services
	startServices()

	// Start parent process monitoring
	parentPID := os.Getppid()
	monitorParentExit(parentPID)
}
