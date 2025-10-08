package cloud

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

const HTTP_HEADER_HMAC = "X-Request-HMAC"

var (
	HMAC_SDKToAgent *HMACVerify // HMAC key for SDK-to-agent (CSRF) communication; derived from config to ensure CSRF token validity
	HMAC_AgentToCPP *HMACVerify // HMAC key for agent-to-C++-service communication; inherited from parent C++ process
)

// Hash-based Message Authentication Code
// HMACVerify handles HMAC operations using a pre-shared key (PSK).
type HMACVerify struct {
	psk []byte
}

// NewHMACVerify creates and initializes a new HMACVerifier.
func NewHMACVerify(key string) *HMACVerify {
	return &HMACVerify{psk: []byte(key)}
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
