//go:build windows
// +build windows

package appmesh

import (
	"net/http"
	"os"
	"strconv"
)

// fileAttributes returns a fresh map with the file's attribute headers.
// On Windows, only mode is available; UID/GID are not applicable.
func fileAttributes(filePath string) (map[string]string, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}

	// Capture only the permission bits
	return map[string]string{
		"X-File-Mode": strconv.FormatUint(uint64(info.Mode().Perm()), 10),
	}, nil
}

// ApplyFileAttributes applies file mode on Windows.
// Ownership changes are not supported on Windows.
func ApplyFileAttributes(filePath string, headers http.Header) error {
	modeStr := headers.Get("X-File-Mode")
	if modeStr == "" {
		return nil
	}

	modeVal, err := strconv.ParseUint(modeStr, 10, 32)
	if err != nil {
		return err
	}

	// os.Chmod on Windows primarily toggles the read-only attribute
	return os.Chmod(filePath, os.FileMode(modeVal))
}
