package main

import (
	"flag"
	"log"
	"os"
	"syscall"
	"time"
)

var restAgentAddr = "" //"https://0.0.0.0:6060"

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
	var restTcpPort = 0      //6059
	var prometheusPort = 0   //6061
	var dockerAgentAddr = "" //"https://127.0.0.1:6058"

	// parse arguments
	restAddr := flag.String("agent_url", restAgentAddr, "The host URL used to listen REST proxy")
	tcpPort := flag.Int("rest_tcp_port", restTcpPort, "The host port used to forward REST proxy")
	promePort := flag.Int("prom_exporter_port", prometheusPort, "The host port used to expose Prometheus metrics")
	dockerAddr := flag.String("docker_agent_url", dockerAgentAddr, "The host URL used to listen docker proxy")
	socket := flag.String("docker_socket_file", dockerSocketFile, "Docker unix domain socket file path used to forward docker proxy")
	flag.Parse()

	log.Println("REST Agent enter")

	// read arguments
	if restAddr != nil {
		restAgentAddr = *restAddr
	}
	if tcpPort != nil {
		restTcpPort = *tcpPort
	}
	if promePort != nil {
		prometheusPort = *promePort
	}
	if socket != nil {
		dockerSocketFile = *socket
	}
	if dockerAddr != nil {
		dockerAgentAddr = *dockerAddr
	}

	// exit when parent not exist
	go monitorParentExit(os.Getppid())

	// start listen docker proxy
	if len(dockerAgentAddr) > 0 {
		go listenDocker(dockerAgentAddr)
		log.Println("Docker agent listening at:", dockerAgentAddr, " forward to:", dockerSocketFile)

	}

	// start listen REST proxy
	if restTcpPort > 1024 {
		go listenRest(restAgentAddr, restTcpPort)
		log.Println("REST agent listening at:", restAgentAddr)
	}

	// start prometheus exporter (without SSL)
	if prometheusPort > 1024 {
		go listenPrometheus(prometheusPort)
		log.Println("Prometheus exporter listening at:", prometheusPort)
	}

	// Wait forever.
	select {}
}
