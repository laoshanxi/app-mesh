//go:build linux || darwin
// +build linux darwin

package appmesh

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"syscall"
)

// GetFileAttributes returns a map with file attributes: mode, user ID, and group ID.
// The second parameter is optional; if provided, the map will be populated and
// returned. Otherwise a new map is returned. Signature: GetFileAttributes(path[, headers]) (map[string]string, error)
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

	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return h, syscall.EINVAL
	}

	h["X-File-Mode"] = strconv.Itoa(int(fileInfo.Mode().Perm()))
	h["X-File-User"] = strconv.Itoa(int(stat.Uid))
	h["X-File-Group"] = strconv.Itoa(int(stat.Gid))

	return h, nil
}

// ApplyFileAttributes applies file mode and ownership (UID, GID) to a given file
// based on HTTP headers. Implemented for Unix-like systems.
func ApplyFileAttributes(filePath string, headers http.Header) error {
	// http.Header.Get is Case-Insensitive

	// Mode
	if modeStr := headers.Get("X-File-Mode"); modeStr != "" {
		// Parse decimal string "493" -> 493
		modeVal, err := strconv.ParseUint(modeStr, 10, 32)
		if err == nil {
			// Cast to os.FileMode
			if err := os.Chmod(filePath, os.FileMode(modeVal)); err != nil {
				return fmt.Errorf("failed to change file mode: %w", err)
			}
		}
	}

	// Ownership
	uidStr := headers.Get("X-File-User")
	gidStr := headers.Get("X-File-Group")
	if uidStr != "" && gidStr != "" {
		uid, errU := strconv.Atoi(uidStr)
		gid, errG := strconv.Atoi(gidStr)
		if errU == nil && errG == nil {
			if err := os.Chown(filePath, uid, gid); err != nil {
				return fmt.Errorf("failed to change file ownership: %w", err)
			}
		}
	}
	return nil
}
