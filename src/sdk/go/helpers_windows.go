//go:build windows
// +build windows

package appmesh

import (
	"os"
	"strconv"
)

func GetFileAttributes(filePath string) (map[string]string, error) {
	attributes := make(map[string]string)

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return attributes, err
	}

	attributes["X-File-Mode"] = strconv.Itoa(int(fileInfo.Mode().Perm()))
	// Windows have no UID/GID, ignore
	return attributes, nil
}
