//go:build linux || darwin
// +build linux darwin

package main

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
	shmName := os.Getenv(ENV_PSK_SHM)
	if shmName == "" {
		return nil, errNoSHMName
	}
	// Don't unset the environment variable immediately in case of errors
	defer os.Unsetenv(ENV_PSK_SHM)

	var shmPath string
	if runtime.GOOS == "darwin" {
		// macOS: Match C++ implementation using /tmp for file-backed shared memory
		shmPath = path.Join("/tmp", shmName)
	} else {
		// Linux: Use /dev/shm for tmpfs-based shared memory (fast in-memory)
		shmPath = path.Join("/dev/shm", shmName)
	}

	logger.Infof("Reading SHM_NAME: %s on %s", shmPath, runtime.GOOS)

	// Open with read-write access to match C++ behavior
	fd, err := syscall.Open(shmPath, syscall.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open shared memory %s: %w", shmPath, err)
	}
	defer func() {
		if closeErr := syscall.Close(fd); closeErr != nil {
			logger.Warnf("Failed to close shared memory fd: %v", closeErr)
		}
	}()

	// Verify file size before mapping
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return nil, fmt.Errorf("failed to stat shared memory: %w", err)
	}
	if stat.Size < int64(PSK_SHM_TOTAL_SIZE) {
		return nil, fmt.Errorf("shared memory size %d < expected %d", stat.Size, PSK_SHM_TOTAL_SIZE)
	}

	// Map with read-write permissions to match C++ behavior
	mmap, err := syscall.Mmap(fd, 0, PSK_SHM_TOTAL_SIZE,
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("failed to map shared memory: %w", err)
	}
	defer func() {
		if unmapErr := syscall.Munmap(mmap); unmapErr != nil {
			logger.Warnf("Failed to unmap shared memory: %v", unmapErr)
		}
	}()

	// Validate offsets and alignment
	if PSK_FLAG_OFFSET+4 > len(mmap) { // +4 for uint32_t size
		return nil, fmt.Errorf("flag offset %d + 4 > mmap size %d", PSK_FLAG_OFFSET, len(mmap))
	}
	if PSK_MSG_LENGTH > PSK_FLAG_OFFSET {
		return nil, fmt.Errorf("psk length %d > flag offset %d", PSK_MSG_LENGTH, PSK_FLAG_OFFSET)
	}

	// Check alignment for atomic operations (uint32_t requires 4-byte alignment)
	mmapAddr := uintptr(unsafe.Pointer(&mmap[0]))
	flagAddr := mmapAddr + uintptr(PSK_FLAG_OFFSET)
	if flagAddr%4 != 0 {
		return nil, fmt.Errorf("flag address %x is not 4-byte aligned", flagAddr)
	}

	// Read PSK data first, but ensure we don't read null-terminated string beyond PSK_MSG_LENGTH
	// Find actual string length (if null-terminated)
	actualLen := 0
	for i := 0; i < min(len(mmap), PSK_MSG_LENGTH); i++ {
		if mmap[i] == 0 {
			break
		}
		actualLen++
	}
	psk := make([]byte, actualLen)
	copy(psk, mmap[:actualLen])

	// Atomic flag check and set using proper alignment
	flagPtr := (*uint32)(unsafe.Pointer(&mmap[PSK_FLAG_OFFSET]))

	// Use compare-and-swap to atomically check if flag is 0 and set it to 1
	if !atomic.CompareAndSwapUint32(flagPtr, 0, 1) {
		return nil, errPSKAlreadyRead
	}

	// Force memory sync to ensure flag write is persisted
	// Note: Go's syscall package doesn't expose msync directly on all platforms
	// The atomic operation with proper memory ordering should be sufficient
	// for inter-process synchronization in most cases
	//if err := syscall.Msync(mmap[pskFlagOffset:pskFlagOffset+4], syscall.MS_SYNC); err != nil {
	//	logger.Warnf("Failed to sync flag write: %v", err)
	//}

	logger.Infof("Read PSK (length: %d) and set flag success", len(psk))
	return psk, nil
}
