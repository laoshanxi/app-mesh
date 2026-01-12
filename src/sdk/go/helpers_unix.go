//go:build linux || darwin
// +build linux darwin

package appmesh

import (
	"fmt"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// GetFileAttributes populates a map with file mode, owner, and group.
func GetFileAttributes(filePath string, headers ...map[string]string) (map[string]string, error) {
	h := make(map[string]string)
	if len(headers) > 0 && headers[0] != nil {
		h = headers[0]
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return h, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return h, fmt.Errorf("unsupported stat type")
	}

	h["X-File-Mode"] = strconv.FormatUint(uint64(info.Mode().Perm()), 10)

	// Resolve User
	if u, err := user.LookupId(strconv.Itoa(int(stat.Uid))); err == nil {
		h["X-File-User"] = u.Username
	} else {
		h["X-File-User"] = strconv.Itoa(int(stat.Uid))
	}

	// Resolve Group
	if g, err := user.LookupGroupId(strconv.Itoa(int(stat.Gid))); err == nil {
		h["X-File-Group"] = g.Name
	} else {
		h["X-File-Group"] = strconv.Itoa(int(stat.Gid))
	}

	return h, nil
}

// ApplyFileAttributes applies ownership and permissions from HTTP headers to a file.
func ApplyFileAttributes(filePath string, headers http.Header) error {
	userStr := headers.Get("X-File-User")
	groupStr := headers.Get("X-File-Group")
	modeStr := headers.Get("X-File-Mode")

	// 1. Handle Ownership (Chown)
	if userStr != "" && groupStr != "" {
		uid := lookupID(userStr, "user")
		gid := lookupID(groupStr, "group")

		if uid == -1 || gid == -1 {
			return fmt.Errorf("failed to resolve user/group: %s:%s", userStr, groupStr)
		}
		if err := os.Chown(filePath, uid, gid); err != nil {
			return err
		}
	}

	// 2. Handle Permissions (Chmod) - Done after Chown to ensure bits aren't reset
	if modeStr != "" {
		if mode, err := strconv.ParseUint(modeStr, 10, 32); err == nil {
			return os.Chmod(filePath, os.FileMode(mode))
		}
	}

	return nil
}

// Helper to resolve string (name or ID) to a numeric UID/GID
func lookupID(val, kind string) int {
	if kind == "user" {
		if u, err := user.Lookup(val); err == nil {
			val = u.Uid
		}
	} else {
		if g, err := user.LookupGroup(val); err == nil {
			val = g.Gid
		}
	}
	id, err := strconv.Atoi(val)
	if err != nil || id < 0 {
		return -1
	}
	return id
}
