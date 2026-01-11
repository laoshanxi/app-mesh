//go:build windows
// +build windows

package appmesh

import (
	"net/http"
	"os"
	"strconv"
)

// GetFileAttributes returns a map with file attributes. The optional second
// parameter allows callers to provide a map to populate. Returns the map and
// any error encountered. Signature: GetFileAttributes(path[, headers]) (map[string]string, error)
func GetFileAttributes(filePath string, headers ...map[string]string) (map[string]string, error) {
	var h map[string]string
	if len(headers) > 0 && headers[0] != nil {
		h = headers[0]
	} else {
		h = make(map[string]string)
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return h, err
	}

	h["X-File-Mode"] = strconv.Itoa(int(fileInfo.Mode().Perm()))
	// Windows has no UID/GID in the same way; omit those headers.
	return h, nil
}

// ApplyFileAttributes is a no-op on Windows; provided to satisfy cross-platform callers.
func ApplyFileAttributes(filePath string, headers http.Header) error {
	// Best effort for ReadOnly bit on Windows
	if modeStr := headers.Get("X-File-Mode"); modeStr != "" {
		modeVal, err := strconv.ParseUint(modeStr, 10, 32)
		if err == nil {
			return os.Chmod(filePath, os.FileMode(modeVal))
		}
		return err
	}
	return nil
}
