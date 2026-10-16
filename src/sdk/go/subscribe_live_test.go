package appmesh

// Live-daemon tests for the sub/pub fixes (guarded by APPMESH_BEARER_TOKEN, like
// the other integration tests). They verify against a real daemon:
//   - subscribe-based WaitForAsyncRun streams STDOUT and returns the exit code
//   - the atomic AddApp(subscribe_events) + RegisterEventCallback flush
//   - the F1 file-transfer guard: download is rejected while the demuxer owns
//     the read side, and works again after Unsubscribe

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func liveTCPClient(t *testing.T) *AppMeshClientTCP {
	t.Helper()
	// Skip before dialing so offline runs skip instead of failing on connect.
	token := requireBearerToken(t)
	client, err := NewTCPClient(Option{InsecureSkipVerify: true})
	require.NoError(t, err)
	client.SetToken(token)
	return client
}

// Conformance: S6 + STDOUT streaming over a live TCP transport.
func TestLiveTCPWaitForAsyncRunStreams(t *testing.T) {
	client := liveTCPClient(t)
	defer client.CloseConnection()

	name := fmt.Sprintf("live-wait-%d", time.Now().UnixNano()%1e6)
	shell := true
	run, err := client.RunAppAsync(Application{
		Name:      name,
		Command:   strPtr("echo live-stdout-line-1; echo live-stdout-line-2"),
		ShellMode: &shell,
	}, 10, 0)
	require.NoError(t, err)

	var output strings.Builder
	code, err := client.WaitForAsyncRun(context.Background(), run, func(chunk string, pos int64) {
		output.WriteString(chunk)
	}, 20*time.Second)
	require.NoError(t, err)
	require.NotNil(t, code)
	assert.Equal(t, 0, *code)
	assert.Contains(t, output.String(), "live-stdout-line-1")
	assert.Contains(t, output.String(), "live-stdout-line-2")
}

// The daemon installs an atomic subscription before the add-app response, so the
// START event can precede it; the demuxer must deliver it to the callback
// registered afterwards (pre-registration buffer flush).
func TestLiveTCPAtomicAddAppDeliversStartEvent(t *testing.T) {
	client := liveTCPClient(t)
	defer client.CloseConnection()

	events := make(chan AppEvent, 8)
	name := fmt.Sprintf("live-atomic-%d", time.Now().UnixNano()%1e6)
	shell := true
	added, err := client.AddApp(Application{
		Name:      name,
		Command:   strPtr("echo atomic-start-ok"),
		ShellMode: &shell,
	}, "START", "EXIT")
	require.NoError(t, err)
	require.NotEmpty(t, added.SubscriptionID)
	require.NoError(t, client.RegisterEventCallback(added.SubscriptionID, func(e AppEvent) {
		events <- e
	}))

	_, err = client.EnableApp(name)
	require.NoError(t, err)

	seen := map[string]bool{}
	timeout := time.After(15 * time.Second)
	for len(seen) < 2 {
		select {
		case e := <-events:
			seen[e.EventType] = true
		case <-timeout:
			t.Fatalf("timed out waiting for START+EXIT, got %v", seen)
		}
	}
	assert.True(t, seen["START"])
	assert.True(t, seen["EXIT"])

	_, _ = client.DeleteApp(name)
}

// F1: a TCP file transfer must be rejected while the event demuxer owns the read
// side, and must succeed again once the subscription is gone.
func TestLiveTCPFileTransferGuard(t *testing.T) {
	client := liveTCPClient(t)
	defer client.CloseConnection()

	sub, err := client.Subscribe(SubscribeOption{AppName: "*", Events: []string{"START"}}, func(AppEvent) {})
	require.NoError(t, err)

	err = client.DownloadFile("/opt/appmesh/bin/appmesh", t.TempDir()+"/guarded", false)
	require.Error(t, err, "download must be rejected while a subscription is active")
	assert.Contains(t, err.Error(), "not supported")

	err = client.UploadFile("/etc/hosts", "/tmp/e2e-upload-guarded", false)
	require.Error(t, err, "upload must be rejected while a subscription is active")
	assert.Contains(t, err.Error(), "not supported")

	// Unsubscribe only removes the callback — the demuxer keeps owning the read
	// side (Python semantics), so the guard still applies on this connection...
	require.NoError(t, client.Unsubscribe(sub.SubscriptionID))
	err = client.DownloadFile("/opt/appmesh/bin/appmesh", t.TempDir()+"/still-guarded", false)
	require.Error(t, err, "the demuxer owns the read side until close")
	assert.Contains(t, err.Error(), "not supported")

	// ...and a separate client instance (its own connection) transfers fine.
	plain, err := NewTCPClient(Option{InsecureSkipVerify: true})
	require.NoError(t, err)
	plain.SetToken(requireBearerToken(t))
	defer plain.CloseConnection()
	require.NoError(t, plain.DownloadFile("/opt/appmesh/bin/appmesh", t.TempDir()+"/separate-client", false))
}

// WSS variant of the subscribe-based wait.
func TestLiveWSSWaitForAsyncRun(t *testing.T) {
	// Skip before dialing so offline runs skip instead of failing on connect.
	bearer := requireBearerToken(t)
	client, err := NewWSSClient(Option{InsecureSkipVerify: true})
	require.NoError(t, err)
	defer client.Close()
	client.SetToken(bearer)

	shell := true
	run, err := client.RunAppAsync(Application{
		Name:      fmt.Sprintf("live-wss-wait-%d", time.Now().UnixNano()%1e6),
		Command:   strPtr("echo wss-stdout-line"),
		ShellMode: &shell,
	}, 10, 0)
	require.NoError(t, err)

	var output strings.Builder
	code, err := client.WaitForAsyncRun(context.Background(), run, func(chunk string, pos int64) {
		output.WriteString(chunk)
	}, 20*time.Second)
	require.NoError(t, err)
	require.NotNil(t, code)
	assert.Equal(t, 0, *code)
	assert.Contains(t, output.String(), "wss-stdout-line")
}

// 401 over TCP replays once with a refreshed bearer: a deliberately stale token
// is rejected, the provider rotates it, and the replayed request succeeds.
func TestLiveTCP401RefreshRetry(t *testing.T) {
	valid := requireBearerToken(t)
	client, err := NewTCPClient(Option{InsecureSkipVerify: true})
	require.NoError(t, err)
	defer client.CloseConnection()

	provider := &liveStaleThenFreshProvider{valid: valid}
	client.SetTokenProvider(provider)

	apps, err := client.ListApps()
	require.NoError(t, err, "the replay with the refreshed token must succeed")
	assert.NotEmpty(t, apps)
	assert.Equal(t, 1, provider.refreshCount, "exactly one refresh must happen")
}

type liveStaleThenFreshProvider struct {
	valid        string
	refreshCount int
}

func (p *liveStaleThenFreshProvider) AccessToken() (string, error) {
	if p.refreshCount == 0 {
		return "definitely-stale-token", nil
	}
	return p.valid, nil
}

func (p *liveStaleThenFreshProvider) RefreshAccessToken(string) (string, error) {
	p.refreshCount++
	return p.valid, nil
}

func (p *liveStaleThenFreshProvider) CanRefresh() bool { return true }

func (p *liveStaleThenFreshProvider) Clear() {}

var _ TokenProvider = (*liveStaleThenFreshProvider)(nil)

func strPtr(s string) *string { return &s }
