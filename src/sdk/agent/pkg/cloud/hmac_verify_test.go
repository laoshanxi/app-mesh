package cloud

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVeriry(t *testing.T) {
	msg := "Message-For-Generate-HMAC"
	psk := "PRE_SHARED_KEY"
	hmacVerify := &HMACVerify{psk: []byte(psk)}
	hmac := hmacVerify.GenerateHMAC(msg)
	require.True(t, hmacVerify.VerifyHMAC(msg, hmac))

	msg = msg + "modify"
	require.False(t, hmacVerify.VerifyHMAC(msg, hmac))
	psk = psk + "modify"
	hmacVerify = &HMACVerify{psk: []byte(psk)}
	require.False(t, hmacVerify.VerifyHMAC(msg, hmac))
}
