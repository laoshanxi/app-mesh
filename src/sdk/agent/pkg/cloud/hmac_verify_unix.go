//go:build linux || darwin
// +build linux darwin

package cloud

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"syscall"
	"unsafe"
)

func readPSKFromSHM() ([]byte, error) {
	shmName := os.Getenv(pskSHMEnv)
	if shmName == "" {
		return nil, errNoSHMName
	}
	os.Unsetenv(pskSHMEnv)

	if runtime.GOOS == "darwin" {
		shmName = path.Join("/private/tmp", shmName)
	} else {
		shmName = path.Join("/dev/shm", shmName)
	}

	logger.Infof("Reading SHM_NAME: %s on %s", shmName, runtime.GOOS)

	fd, err := syscall.Open(shmName, syscall.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open shared memory: %w", err)
	}
	defer syscall.Close(fd)

	mmap, err := syscall.Mmap(fd, 0, pskSHMTotalSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("failed to map shared memory: %w", err)
	}
	defer syscall.Munmap(mmap)

	psk := make([]byte, pskLength)
	copy(psk, mmap[:pskLength])

	flag := (*byte)(unsafe.Pointer(&mmap[pskFlagOffset]))
	if *flag != 0 {
		return nil, errPSKAlreadyRead
	}
	*flag = 1

	logger.Infof("Read PSK and set flag success")
	return psk, nil
}
