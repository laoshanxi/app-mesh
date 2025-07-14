//go:build windows
// +build windows

package cloud

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procOpenFileMappingW = modkernel32.NewProc("OpenFileMappingW")
)

func openFileMapping(desiredAccess uint32, inheritHandle bool, name *uint16) (windows.Handle, error) {
	inherit := uintptr(0)
	if inheritHandle {
		inherit = 1
	}
	handle, _, err := procOpenFileMappingW.Call(
		uintptr(desiredAccess),
		inherit,
		uintptr(unsafe.Pointer(name)),
	)
	if handle == 0 {
		return 0, err
	}
	return windows.Handle(handle), nil
}

func readPSKFromSHM() ([]byte, error) {
	shmName := os.Getenv(pskSHMEnv)
	if shmName == "" {
		return nil, errNoSHMName
	}
	os.Unsetenv(pskSHMEnv)

	shmName = `Global\` + shmName
	logger.Infof("Reading SHM_NAME: %s on Windows", shmName)

	nameUTF16, err := windows.UTF16PtrFromString(shmName)
	if err != nil {
		return nil, fmt.Errorf("invalid shm name: %w", err)
	}

	handle, err := openFileMapping(windows.FILE_MAP_READ|windows.FILE_MAP_WRITE, false, nameUTF16)
	if err != nil {
		return nil, fmt.Errorf("failed to open file mapping: %w", err)
	}
	defer windows.CloseHandle(handle)

	addr, err := windows.MapViewOfFile(handle, windows.FILE_MAP_READ|windows.FILE_MAP_WRITE, 0, 0, uintptr(pskSHMTotalSize))
	if err != nil {
		return nil, fmt.Errorf("map view of file failed: %w", err)
	}
	defer windows.UnmapViewOfFile(addr)

	mmap := unsafe.Slice((*byte)(unsafe.Pointer(addr)), pskSHMTotalSize)

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
