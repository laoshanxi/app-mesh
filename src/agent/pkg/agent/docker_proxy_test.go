package agent

import (
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
		"/images/create", // the actual pull endpoint
		"/build",
		"/exec/abc123/start",
	}
	for _, path := range streaming {
		require.Truef(t, isStreamingDockerEndpoint(path), "%s must stay unbuffered", path)
	}

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
	for _, path := range buffered {
		require.Falsef(t, isStreamingDockerEndpoint(path), "%s must stay buffered", path)
	}
}
