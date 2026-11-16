package agent

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// Pins the streaming allowlist: listed endpoints pass through unbuffered,
// everything else is buffered and Content-Length framed for the daemon.
func TestIsStreamingDockerEndpoint(t *testing.T) {
	streaming := []string{
		// Original suffix allowlist.
		"/containers/abc123/logs",
		"/containers/abc123/attach",
		"/events",
		"/containers/abc123/stats",
		"/images/foo/pull",
		"/images/foo/push",
		"/images/foo/get",
		"/images/load",
		"/containers/abc123/archive",
		// Endpoints the suffix list missed.
		"/build",
		"/exec/abc123/start",
	}
	follow := url.Values{"follow": {"1"}}
	for _, path := range streaming {
		require.Truef(t, isStreamingDockerEndpoint(path, follow), "%s must stay unbuffered", path)
	}
	// A live log follow stays a stream even without other query flags.
	require.True(t, isStreamingDockerEndpoint("/containers/abc123/logs", url.Values{"follow": {"true"}}))

	buffered := []string{
		// Daemon control plane; must stay buffered for Content-Length framing.
		"/containers/json",
		"/containers/create",
		"/containers/abc123/json",
		"/containers/abc123",
		"/containers/abc123/wait",
		"/images/json",
		"/images/busybox/json",
		"/networks/create",
		"/volumes/create",
		"/exec/abc123/json",
		"/version",
		"/info",
	}
	noFollow := url.Values{}
	for _, path := range buffered {
		require.Falsef(t, isStreamingDockerEndpoint(path, noFollow), "%s must stay buffered", path)
	}
	// Non-following logs and one-shot stats are finite documents: they must be
	// buffered and length-framed for buffered HTTP clients.
	require.False(t, isStreamingDockerEndpoint("/containers/abc123/logs", noFollow))
	// A pull reply is one finite NDJSON document: buffered like non-follow logs.
	require.False(t, isStreamingDockerEndpoint("/images/create", noFollow))
	require.False(t, isStreamingDockerEndpoint("/containers/abc123/stats", url.Values{"stream": {"0"}}))
}
