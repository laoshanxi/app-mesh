//go:build windows

package utils

import (
	"golang.org/x/sys/windows"
)

const STILL_ACTIVE = 259

func IsProcessRunning(pid int) bool {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)

	var code uint32
	err = windows.GetExitCodeProcess(handle, &code)
	if err != nil {
		return false
	}
	return code == STILL_ACTIVE
}
