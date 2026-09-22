package appmesh

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"unsafe"

	"github.com/edsrzf/mmap-go"
)

// Managed-process proof wire layout, mirrored from the Engine's
// src/daemon/security/SharedMemory.h.
const (
	// EnvPSKShmName carries the absolute path of the shared memory segment that
	// holds the pre-shared key, from the Engine to a managed system process it
	// spawns.
	EnvPSKShmName = "PSK_SHM_NAME"
	pskMsgLength  = 32
	// pskFlagOffset is the byte offset of the single-consumer flag in the segment.
	pskFlagOffset   = 64
	pskShmTotalSize = 128
)

// HeaderProcessProof marks a request that must carry a process proof. The
// transport replaces the marker with headerRequestHMAC, so the marker itself
// never reaches the wire.
const HeaderProcessProof = "X-AppMesh-Process-Proof"

// headerRequestHMAC carries the per-request proof signature: hex HMAC-SHA256
// of the request UUID under the pre-shared key.
const headerRequestHMAC = "X-Request-HMAC"

var (
	errNoSHMName      = errors.New("no PSK_SHM_NAME env found")
	errPSKAlreadyRead = errors.New("PSK has already been read")
)

// ReadPSKFromSHM reads the one-time pre-shared key the Engine prepared for this
// process in shared memory and marks the segment as consumed so the Engine
// removes it. Must be called once at process start.
func ReadPSKFromSHM() ([]byte, error) {
	shmPath := os.Getenv(EnvPSKShmName)
	if shmPath == "" {
		return nil, errNoSHMName
	}
	// Don't unset the environment variable immediately in case of errors
	defer os.Unsetenv(EnvPSKShmName)

	f, err := os.OpenFile(shmPath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open shm file: %w", err)
	}
	defer f.Close()

	mmapData, err := mmap.Map(f, mmap.RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap file: %w", err)
	}
	defer mmapData.Unmap()

	if len(mmapData) < pskShmTotalSize {
		return nil, fmt.Errorf("shm segment has an unexpected size %d", len(mmapData))
	}
	if pskMsgLength > pskFlagOffset {
		return nil, fmt.Errorf("psk length %d > flag offset %d", pskMsgLength, pskFlagOffset)
	}

	// Read the null-terminated key within the message area.
	actualLen := 0
	for i := 0; i < min(len(mmapData), pskMsgLength); i++ {
		if mmapData[i] == 0 {
			break
		}
		actualLen++
	}
	psk := make([]byte, actualLen)
	copy(psk, mmapData[:actualLen])

	// Single-consumer: only the first reader may claim the key.
	flagPtr := (*uint32)(unsafe.Pointer(&mmapData[pskFlagOffset]))
	if uintptr(unsafe.Pointer(flagPtr))%4 != 0 {
		return nil, fmt.Errorf("flag address not 4-byte aligned")
	}
	if !atomic.CompareAndSwapUint32(flagPtr, 0, 1) {
		return nil, errPSKAlreadyRead
	}

	if err := mmapData.Flush(); err != nil {
		logf("failed to flush shared memory: %v", err)
	}

	logf("read PSK (length: %d) from shared memory", len(psk))
	return psk, nil
}

// signRequestPSK returns the hex HMAC-SHA256 of message under psk.
func signRequestPSK(psk []byte, message string) string {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// applyProcessProof replaces the proof marker with a signature over the request
// UUID. A forwarded request is never signed: a proof must not travel through
// another party.
func applyProcessProof(request *Request, psk []byte) error {
	// The message headers come from http.Header, whose keys are canonical, so the
	// marker must be looked up in its canonical form. A raw constant would silently
	// match nothing and look exactly like a missing key.
	marker := http.CanonicalHeaderKey(HeaderProcessProof)
	if _, marked := request.Headers[marker]; !marked {
		return nil
	}
	delete(request.Headers, marker)

	if _, forwarded := request.Headers[headerTargetHost]; forwarded {
		return errors.New("a process proof cannot be forwarded")
	}
	if len(psk) == 0 {
		return errors.New("process proof requested but no pre-shared key is available")
	}
	request.Headers[headerRequestHMAC] = signRequestPSK(psk, request.UUID)
	return nil
}
