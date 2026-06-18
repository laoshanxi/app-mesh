//go:build unix

package budget

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock on the whole file. flock locks are
// tied to the open file description and released by the kernel when the process
// exits, so a crashed worker never leaves a stale lock behind.
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
