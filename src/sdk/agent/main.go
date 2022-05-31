package main

import (
	"flag"
	"log"
	"os"
	"syscall"
	"time"
)

var (
	restAgentAddr = "https://0.0.0.0:6060"
	restTcpPort   = 6059

	dockerAgentAddr  = "https://127.0.0.1:6058"
	dockerSocketFile = "/var/run/docker.sock"

	parentProPid = os.Getppid()
)

func monitorParentExit() {
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
	log.Println("Docker Agent enter")

	// parse arguments
	restAddr := flag.String("agent_url", restAgentAddr, "The host URL used to listen REST proxy")
	tcpPort := flag.Int("rest_tcp_port", restTcpPort, "The host port used to forward REST proxy")
	dockerAddr := flag.String("docker_agent_url", dockerAgentAddr, "The host URL used to listen docker proxy")
	socket := flag.String("docker_socket_file", dockerSocketFile, "Docker unix domain socket file path used to forward docker proxy")
	flag.Parse()

	// read arguments
	if restAddr != nil {
		restAgentAddr = *restAddr
	}
	if tcpPort != nil {
		restTcpPort = *tcpPort
	}
	if socket != nil {
		dockerSocketFile = *socket
	}
	if dockerAddr != nil {
		dockerAgentAddr = *dockerAddr
	}
	log.Println("REST agent listening at:", restAgentAddr)
	log.Println("Docker agent listening at:", dockerAgentAddr, " forward to: ", dockerSocketFile)

	// exit when parent not exist
	go monitorParentExit()

	// start listen docker proxy
	go listenDocker()

	// start listen REST proxy
	go listenRest()

	// Wait forever.
	select {}
}
