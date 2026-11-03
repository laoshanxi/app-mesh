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
		headerFileMode: strconv.FormatUint(uint64(info.Mode().Perm()), 10),
	}, nil
}

// ApplyFileAttributes applies file mode on Windows.
// Ownership changes are not supported on Windows.
func ApplyFileAttributes(filePath string, headers http.Header) error {
	modeStr := headers.Get(headerFileMode)
	if modeStr == "" {
		return nil
	}

	modeVal, err := strconv.ParseUint(modeStr, 10, 32)
	if err != nil {
		return err
	}
	// Decimal permission bits (493 = 0755), same convention as the daemon and
	// the unix implementation. Out-of-range values are ignored, never masked.
	if modeVal > 0o777 {
		logf("file mode %q is not a decimal value in 0..511; leaving attributes unchanged", modeStr)
		return nil
	}

	// os.Chmod on Windows primarily toggles the read-only attribute
	return os.Chmod(filePath, os.FileMode(modeVal))
}
