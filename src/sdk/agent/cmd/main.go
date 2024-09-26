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

func monitorParentExit(parentProPid int) {
	// 1. Force process exit when parent was exited
	_, _, errno := syscall.RawSyscall(uintptr(syscall.SYS_PRCTL), uintptr(syscall.PR_SET_PDEATHSIG), uintptr(syscall.SIGKILL), 0)
	if errno != 0 {
		log.Println("Failed to call prctl with error:", errno)
	}

	// 2. Period check parent exit and exit itself
	oneSecond := time.Duration(1) * time.Second
	for {
		if os.Getppid() != parentProPid {
			log.Println("Parent exit")
			os.Exit(0)
		}
		time.Sleep(oneSecond)
	}
}

// main
func main() {
	var dockerAgentAddr = "" //"https://127.0.0.1:6058"

	// parse arguments
	dockerAddr := flag.String("docker_agent_url", dockerAgentAddr, "The host URL used to listen docker proxy")
	socket := flag.String("docker_socket_file", agent.DockerSocketFilePath, "Docker unix domain socket file path used to forward docker proxy")
	flag.Parse()

	log.Println("REST Agent enter")

	// read arguments
	if socket != nil {
		agent.DockerSocketFilePath = *socket
	}
	if dockerAddr != nil {
		dockerAgentAddr = *dockerAddr
	}

	// init PSK HMAC
	var err error
	if agent.HMAC, err = agent.NewHMACVerify(); err != nil {
		log.Printf("HMAC Verifier initialization failed: %v", err)
	}

	// exit when parent not exist
	go monitorParentExit(os.Getppid())

	// start listen docker proxy
	if len(dockerAgentAddr) > 0 {
		go agent.ListenDocker(dockerAgentAddr)
		log.Println("<Docker Agent> listening at:", dockerAgentAddr, " forward to:", agent.DockerSocketFilePath)

	}

	// start listen REST proxy
	if config.ConfigData.REST.RestEnabled {
		go agent.ListenRest()
	}

	// start prometheus exporter (without SSL)
	prometheusPort := config.ConfigData.REST.PrometheusExporterListenPort
	if (prometheusPort) > 1024 {
		go agent.ListenPrometheus(prometheusPort)
		log.Println("<Prometheus Exporter> listening at: ", prometheusPort)
	}

	// Report consul after listener setup
	go cloud.NewCloud().ReportHostResource()

	// Wait forever.
	select {}
}
