//go:build windows
// +build windows

package cloud

import (
	"fmt"
	"os"
	"sync/atomic"
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
		if err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("OpenFileMapping failed with unknown error")
	}
	return windows.Handle(handle), nil
}

func readPSKFromSHM() ([]byte, error) {
	shmName := os.Getenv(ENV_PSK_SHM)
	if shmName == "" {
		return nil, errNoSHMName
	}
	// Don't unset the environment variable immediately in case of errors
	defer os.Unsetenv(ENV_PSK_SHM)

	// Ensure Global namespace prefix matches C++ implementation
	if len(shmName) < 7 || shmName[:7] != "Global\\" {
		shmName = `Global\` + shmName
	}

	logger.Infof("Reading SHM_NAME: %s on Windows", shmName)

	nameUTF16, err := windows.UTF16PtrFromString(shmName)
	if err != nil {
		return nil, fmt.Errorf("invalid shm name: %w", err)
	}

	// Open with read-write access to match C++ behavior
	handle, err := openFileMapping(windows.FILE_MAP_READ|windows.FILE_MAP_WRITE, false, nameUTF16)
	if err != nil {
		return nil, fmt.Errorf("failed to open file mapping %s: %w", shmName, err)
	}
	defer func() {
		if closeErr := windows.CloseHandle(handle); closeErr != nil {
			logger.Warnf("Failed to close file mapping handle: %v", closeErr)
		}
	}()

	// Map the entire shared memory region with read-write access
	addr, err := windows.MapViewOfFile(handle, windows.FILE_MAP_READ|windows.FILE_MAP_WRITE, 0, 0, uintptr(PSK_SHM_TOTAL_SIZE))
	if err != nil {
		return nil, fmt.Errorf("map view of file failed: %w", err)
	}
	defer func() {
		if unmapErr := windows.UnmapViewOfFile(addr); unmapErr != nil {
			logger.Warnf("Failed to unmap view of file: %v", unmapErr)
		}
	}()

	// Validate mapped address
	if addr == 0 {
		return nil, fmt.Errorf("mapped address is null")
	}

	// Create slice with proper bounds checking
	mmap := unsafe.Slice((*byte)(unsafe.Pointer(addr)), PSK_SHM_TOTAL_SIZE)

	// Validate offsets and alignment
	if PSK_FLAG_OFFSET+4 > len(mmap) { // +4 for uint32_t size
		return nil, fmt.Errorf("flag offset %d + 4 > mmap size %d", PSK_FLAG_OFFSET, len(mmap))
	}
	if PSK_MSG_LENGTH > PSK_FLAG_OFFSET {
		return nil, fmt.Errorf("psk length %d > flag offset %d", PSK_MSG_LENGTH, PSK_FLAG_OFFSET)
	}

	// Check alignment for atomic operations (uint32_t requires 4-byte alignment)
	flagAddr := addr + uintptr(PSK_FLAG_OFFSET)
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

	// Force memory sync on Windows to ensure flag write is persisted
	if err := windows.FlushViewOfFile(addr+uintptr(PSK_FLAG_OFFSET), 4); err != nil {
		logger.Warnf("Failed to flush flag write to disk: %v", err)
	}

	logger.Infof("Read PSK (length: %d) and set flag success", len(psk))
	return psk, nil
}
