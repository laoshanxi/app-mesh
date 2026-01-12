//go:build windows
// +build windows

package appmesh

import (
	"net/http"
	"os"
	"strconv"
)

// GetFileAttributes returns a map with file attributes.
// On Windows, only mode is available; UID/GID are not applicable.
func GetFileAttributes(filePath string, headers ...map[string]string) (map[string]string, error) {
	h := make(map[string]string)
	if len(headers) > 0 && headers[0] != nil {
		h = headers[0]
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return h, err
	}

	// Capture only the permission bits
	h["X-File-Mode"] = strconv.FormatUint(uint64(info.Mode().Perm()), 10)
	return h, nil
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
