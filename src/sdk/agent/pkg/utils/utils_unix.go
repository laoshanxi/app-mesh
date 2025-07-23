//go:build !windows

package utils

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
)

// IsProcessRunning checks if a process with the given PID is running.
// It uses /proc on Linux for performance, falling back to Signal(0) on other platforms.
func IsProcessRunning(pid int) bool {
	// Fast check for Linux using /proc
	if runtime.GOOS == "linux" {
		_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
		return err == nil
	}

	// Fallback for non-Linux systems
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Signal 0 does not send a signal but performs error checking
	return proc.Signal(syscall.Signal(0)) == nil
}
