//go:build linux || darwin
// +build linux darwin

package cloud

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"
)

func readPSKFromSHM() ([]byte, error) {
	shmName := os.Getenv(pskSHMEnv)
	if shmName == "" {
		return nil, errNoSHMName
	}
	os.Unsetenv(pskSHMEnv)

	var shmPath string
	if runtime.GOOS == "darwin" {
		// macOS POSIX shared memory requires leading slash
		shmPath = path.Join("/tmp", shmName)
	} else {
		// Linux - for POSIX shared memory, use /dev/shm/
		// This assumes ACE uses POSIX shared memory on Linux
		shmPath = path.Join("/dev/shm", shmName)
	}

	logger.Infof("Reading SHM_NAME: %s on %s", shmPath, runtime.GOOS)

	fd, err := syscall.Open(shmPath, syscall.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open shared memory %s: %w", shmPath, err)
	}
	defer func() {
		if closeErr := syscall.Close(fd); closeErr != nil {
			logger.Warnf("Failed to close shared memory fd: %v", closeErr)
		}
	}()

	// Verify file size
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return nil, fmt.Errorf("failed to stat shared memory: %w", err)
	}
	if stat.Size < int64(pskSHMTotalSize) {
		return nil, fmt.Errorf("shared memory size %d < expected %d", stat.Size, pskSHMTotalSize)
	}

	mmap, err := syscall.Mmap(fd, 0, pskSHMTotalSize,
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("failed to map shared memory: %w", err)
	}
	defer func() {
		if unmapErr := syscall.Munmap(mmap); unmapErr != nil {
			logger.Warnf("Failed to unmap shared memory: %v", unmapErr)
		}
	}()

	// Validate offsets
	if pskFlagOffset >= len(mmap) {
		return nil, fmt.Errorf("flag offset %d >= mmap size %d", pskFlagOffset, len(mmap))
	}
	if pskLength > pskFlagOffset {
		return nil, fmt.Errorf("psk length %d > flag offset %d", pskLength, pskFlagOffset)
	}

	// Read PSK data
	psk := make([]byte, pskLength)
	copy(psk, mmap[:pskLength])

	// Atomic flag check and set
	flagPtr := (*uint32)(unsafe.Pointer(&mmap[pskFlagOffset]))
	if !atomic.CompareAndSwapUint32(flagPtr, 0, 1) {
		return nil, errPSKAlreadyRead
	}

	logger.Infof("Read PSK and set flag success")
	return psk, nil
}
