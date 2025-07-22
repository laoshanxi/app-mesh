package cloud

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	HTTP_HEADER_HMAC = "X-Request-HMAC"
	ENV_PSK_SHM      = "PSK_SHM_NAME"

	PSK_MSG_LENGTH     = 32
	PSK_FLAG_OFFSET    = 64
	PSK_SHM_TOTAL_SIZE = 128
)

var (
	errNoSHMName      = errors.New("no PSK_SHM_NAME env found")
	errPSKAlreadyRead = errors.New("PSK has already been read")
	HMAC              *HMACVerify
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
	// Use constant-time comparison to prevent timing attacks
	return hmac.Equal([]byte(calculatedHMAC), []byte(receivedHMAC))
}
