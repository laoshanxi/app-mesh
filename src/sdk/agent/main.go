package main

import (
	"flag"
	"log"
	"os"
	"strings"
	"syscall"
	"time"
)

var (
	dockerAgentAddr  = "https://127.0.0.1:6058"
	dockerSocketFile = "/var/run/docker.sock"
	parentProPid     = os.Getppid()
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
	addr := flag.String("docker_agent_url", dockerAgentAddr, "The host URL used to listen")
	socket := flag.String("docker_socket", dockerSocketFile, "Unix domain socket file path")
	flag.Parse()

	// exit when parent not exist
	go monitorParentExit()

	// read arguments
	dockerSocketFile = *socket
	dockerAgentAddr = *addr
	log.Println("Docker socket:", dockerSocketFile)
	log.Println("Listening at:", dockerAgentAddr)
	enableTLS := strings.HasPrefix(dockerAgentAddr, "https://")

	// clean schema prefix for Listen
	dockerAgentAddr = strings.Replace(dockerAgentAddr, "https://", "", 1)
	dockerAgentAddr = strings.Replace(dockerAgentAddr, "http://", "", 1)

	// start listen
	if enableTLS {
		go listenDockerAgentTls()
	} else {
		go listenDockerAgent()
	}
	// Wait forever.
	select {}
}
