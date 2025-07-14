//go:build linux || darwin
// +build linux darwin

package appmesh

import (
	"os"
	"strconv"
	"syscall"
)

// GetFileAttributes returns a map with file attributes: mode, user ID, and group ID.
func GetFileAttributes(filePath string) (map[string]string, error) {
	// Initialize the map to store file attributes
	attributes := make(map[string]string)

	// Get the file attributes
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return attributes, err // Return nil map and the error if file stats cannot be retrieved
	}

	// Retrieve syscall.Stat_t from the file info
	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return attributes, syscall.EINVAL // Return nil map and an invalid argument error if Sys() is not *syscall.Stat_t
	}

	// Populate the attributes map
	attributes["X-File-Mode"] = strconv.Itoa(int(fileInfo.Mode().Perm()))
	attributes["X-File-User"] = strconv.Itoa(int(stat.Uid))
	attributes["X-File-Group"] = strconv.Itoa(int(stat.Gid))

	return attributes, nil
}
