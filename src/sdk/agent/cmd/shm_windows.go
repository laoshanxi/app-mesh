//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"unsafe"

	"github.com/edsrzf/mmap-go"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
)

func readPSKFromSHM() ([]byte, error) {
	shmName := os.Getenv(ENV_PSK_SHM)
	if shmName == "" {
		return nil, errNoSHMName
	}
	// Don't unset the environment variable immediately in case of errors
	defer os.Unsetenv(ENV_PSK_SHM)

	shmFile := filepath.Join(config.GetAppMeshHomeDir(), "work", "tmp", shmName)
	logger.Infof("Reading SHM file: %s on Windows", shmFile)

	// Open file for read/write
	f, err := os.OpenFile(shmFile, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open shm file: %w", err)
	}
	defer f.Close()

	// Memory-map the file
	mmapData, err := mmap.Map(f, mmap.RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap file: %w", err)
	}
	defer mmapData.Unmap()

	if len(mmapData) < PSK_FLAG_OFFSET+4 {
		return nil, fmt.Errorf("mmap size %d too small for flag offset %d", len(mmapData), PSK_FLAG_OFFSET)
	}
	if PSK_MSG_LENGTH > PSK_FLAG_OFFSET {
		return nil, fmt.Errorf("psk length %d > flag offset %d", PSK_MSG_LENGTH, PSK_FLAG_OFFSET)
	}

	// Read PSK content (null-terminated within limit)
	actualLen := 0
	for i := 0; i < min(len(mmapData), PSK_MSG_LENGTH); i++ {
		if mmapData[i] == 0 {
			break
		}
		actualLen++
	}
	psk := make([]byte, actualLen)
	copy(psk, mmapData[:actualLen])

	// Atomic flag update
	flagPtr := (*uint32)(unsafe.Pointer(&mmapData[PSK_FLAG_OFFSET]))
	if uintptr(unsafe.Pointer(flagPtr))%4 != 0 {
		return nil, fmt.Errorf("flag address not 4-byte aligned")
	}
	if !atomic.CompareAndSwapUint32(flagPtr, 0, 1) {
		return nil, errPSKAlreadyRead
	}

	// Flush memory to file
	if err := mmapData.Flush(); err != nil {
		logger.Warnf("Failed to flush mmap data: %v", err)
	}

	logger.Infof("Read PSK (length: %d) and set flag success", len(psk))
	return psk, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
