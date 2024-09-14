package http

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"
)

const (
	pskLength       = 32
	pskSHMEnv       = "SHM_NAME"
	pskFlagOffset   = pskLength + 1
	pskSHMTotalSize = pskLength + 2
)

var (
	errNoSHMName      = errors.New("no SHM_NAME env found")
	errPSKAlreadyRead = errors.New("PSK has already been read")
)

// Hash-based Message Authentication Code
// HMACVerify handles HMAC operations using a pre-shared key (PSK).
type HMACVerify struct {
	psk []byte
}

// NewHMACVerify creates and initializes a new HMACVerifier.
func NewHMACVerify() (*HMACVerify, error) {
	psk, err := readPSKFromSHM()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize HMACVerifier: %w", err)
	}
	return &HMACVerify{psk: psk}, nil
}

// GenerateHMAC generates an HMAC for the given message.
func (h *HMACVerify) GenerateHMAC(message string) string {
	mac := hmac.New(sha256.New, h.psk)
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyHMAC verifies the HMAC for the given message.
func (h *HMACVerify) VerifyHMAC(message, receivedHMAC string) bool {
	calculatedHMAC := h.GenerateHMAC(message)
	return hmac.Equal([]byte(calculatedHMAC), []byte(receivedHMAC))
}

func readPSKFromSHM() ([]byte, error) {
	shmName := os.Getenv(pskSHMEnv)
	if shmName == "" {
		return nil, errNoSHMName
	}
	os.Unsetenv(pskSHMEnv)
	log.Printf("Reading SHM_NAME: %s", shmName)

	fd, err := syscall.Open("/dev/shm"+shmName, syscall.O_RDWR, 0666)
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

	log.Println("Read PSK and set flag success")
	return psk, nil
}
