package appmesh

import (
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestSignRequestPSK(t *testing.T) {
	// RFC 4231-style known answer: HMAC-SHA256("key", quick-brown-fox).
	got := signRequestPSK([]byte("key"), "The quick brown fox jumps over the lazy dog")
	require.Equal(t, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8", got)

	// Distinct messages produce distinct signatures.
	require.NotEqual(t, got, signRequestPSK([]byte("key"), "another message"))
}

// createTestSegment materializes a fake Engine segment: key at offset 0 and a
// zeroed single-consumer flag at pskFlagOffset. Returns the absolute path.
func createTestSegment(t *testing.T, key string) string {
	t.Helper()
	data := make([]byte, pskShmTotalSize)
	copy(data, key)
	shmPath := filepath.Join(t.TempDir(), "appmesh_shm_test")
	require.NoError(t, os.WriteFile(shmPath, data, 0600))
	return shmPath
}

func readTestSegmentFlag(t *testing.T, shmPath string) uint32 {
	t.Helper()
	data, err := os.ReadFile(shmPath)
	require.NoError(t, err)
	return atomic.LoadUint32((*uint32)(unsafe.Pointer(&data[pskFlagOffset])))
}

func TestReadPSKFromSHM(t *testing.T) {
	shmPath := createTestSegment(t, "0123456789abcdef0123456789abcdef")
	t.Setenv(EnvPSKShmName, shmPath)

	psk, err := ReadPSKFromSHM()
	require.NoError(t, err)
	require.Equal(t, "0123456789abcdef0123456789abcdef", string(psk))
	require.Equal(t, uint32(1), readTestSegmentFlag(t, shmPath))
	// The path is cleared once the key is in memory.
	require.Empty(t, os.Getenv(EnvPSKShmName))

	// The segment is single-consumer: a second read is rejected.
	t.Setenv(EnvPSKShmName, shmPath)
	_, err = ReadPSKFromSHM()
	require.ErrorIs(t, err, errPSKAlreadyRead)
}

func TestReadPSKFromSHMNoEnv(t *testing.T) {
	t.Setenv(EnvPSKShmName, "")
	_, err := ReadPSKFromSHM()
	require.ErrorIs(t, err, errNoSHMName)
}

func TestApplyProcessProofReplacesTheMarker(t *testing.T) {
	request := NewRequest()
	request.Headers[http.CanonicalHeaderKey(HeaderProcessProof)] = "1"

	require.NoError(t, applyProcessProof(request, []byte("key")))

	_, marked := request.Headers[http.CanonicalHeaderKey(HeaderProcessProof)]
	require.False(t, marked, "the marker must never reach the wire")
	require.Equal(t, signRequestPSK([]byte("key"), request.UUID), request.Headers[headerRequestHMAC])
}

func TestApplyProcessProofLeavesUnmarkedRequestsAlone(t *testing.T) {
	request := NewRequest()

	require.NoError(t, applyProcessProof(request, []byte("key")))
	_, signed := request.Headers[headerRequestHMAC]
	require.False(t, signed)
}

func TestApplyProcessProofRefusesForwardedRequests(t *testing.T) {
	request := NewRequest()
	request.Headers[http.CanonicalHeaderKey(HeaderProcessProof)] = "1"
	request.Headers[headerTargetHost] = "other-host:6060"

	require.Error(t, applyProcessProof(request, []byte("key")))
	_, signed := request.Headers[headerRequestHMAC]
	require.False(t, signed, "a refused request must not carry a signature")
}

func TestApplyProcessProofRequiresAKey(t *testing.T) {
	request := NewRequest()
	request.Headers[http.CanonicalHeaderKey(HeaderProcessProof)] = "1"

	require.Error(t, applyProcessProof(request, nil))
	_, signed := request.Headers[headerRequestHMAC]
	require.False(t, signed)
}
