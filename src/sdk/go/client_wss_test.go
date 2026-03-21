package appmesh

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppmeshWSSLogin(t *testing.T) {
	noVerify := ""
	client, err := NewWSSClient(Option{
		AppMeshUri:   "https://127.0.0.1:6058",
		SslTrustedCA: &noVerify,
	})
	require.NoError(t, err)
	defer client.CloseConnection()

	_, err = client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS, "")
	require.NoError(t, err)

	apps, err := client.ListApps()
	require.NoError(t, err)
	t.Logf("WSS ListApps count: %d", len(apps))

	tags, err := client.GetLabels()
	require.NoError(t, err)
	t.Logf("WSS labels: %v", tags)

	metrics, err := client.GetMetrics()
	require.NoError(t, err)
	require.NotEmpty(t, metrics)
	t.Logf("WSS metrics length: %d", len(metrics))

	res, err := client.GetHostResources()
	require.NoError(t, err)
	require.NotEmpty(t, res)

	_, err = client.Logout()
	require.NoError(t, err)
}

func TestAppmeshWSSOperations(t *testing.T) {
	noVerify := ""
	client, err := NewWSSClient(Option{
		AppMeshUri:   "https://127.0.0.1:6058",
		SslTrustedCA: &noVerify,
	})
	require.NoError(t, err)
	defer client.CloseConnection()

	// 1. Login
	_, err = client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS, "")
	require.NoError(t, err, "WSS login should succeed")

	// 2. RunAppSync - echo command, verify exit code 0
	cmd := "echo hello_wss"
	shellMode := true
	runApp := Application{
		Name:      "go-wss-sync-test",
		Command:   &cmd,
		ShellMode: &shellMode,
	}
	exitCode, output, err := client.RunAppSync(runApp, false, 10, 15)
	require.NoError(t, err, "WSS RunAppSync should succeed")
	require.Equal(t, 0, exitCode, "WSS RunAppSync exit code should be 0")
	require.Contains(t, output, "hello_wss", "WSS RunAppSync output should contain echoed text")
	t.Logf("WSS RunAppSync output: %q, exit: %d", output, exitCode)

	// 3. AddApp + DisableApp + EnableApp + DeleteApp
	const testAppName = "go-wss-lifecycle-test"
	appCmd := fmt.Sprintf("echo wss-lifecycle-%s", testAppName)
	newApp := Application{
		Name:    testAppName,
		Command: &appCmd,
	}
	// ensure clean state at the start and on any exit
	_, _ = client.RemoveApp(testAppName)
	defer func() {
		_, _ = client.RemoveApp(testAppName)
	}()

	addedApp, err := client.AddApp(newApp)
	require.NoError(t, err, "WSS AddApp should succeed")
	require.NotNil(t, addedApp, "WSS AddApp should return the created app")
	require.Equal(t, testAppName, addedApp.Name, "WSS AddApp returned app should have correct name")
	t.Logf("WSS AddApp: %s status=%d", addedApp.Name, addedApp.Status)

	disabled, err := client.DisableApp(testAppName)
	require.NoError(t, err, "WSS DisableApp should succeed")
	require.True(t, disabled, "WSS DisableApp should return true")

	enabled, err := client.EnableApp(testAppName)
	require.NoError(t, err, "WSS EnableApp should succeed")
	require.True(t, enabled, "WSS EnableApp should return true")

	removed, err := client.RemoveApp(testAppName)
	require.NoError(t, err, "WSS RemoveApp should succeed")
	require.True(t, removed, "WSS RemoveApp should return true")

	// 4. GetConfig
	cfg, err := client.GetConfig()
	require.NoError(t, err, "WSS GetConfig should succeed")
	require.NotEmpty(t, cfg, "WSS GetConfig should return non-empty data")
	t.Logf("WSS GetConfig keys: %d", len(cfg))

	// 5. ListUsers / GetCurrentUser
	users, err := client.ListUsers()
	require.NoError(t, err, "WSS ListUsers should succeed")
	require.NotEmpty(t, users, "WSS ListUsers should return at least one user")
	t.Logf("WSS ListUsers count: %d", len(users))

	self, err := client.GetCurrentUser()
	require.NoError(t, err, "WSS GetCurrentUser should succeed")
	require.NotEmpty(t, self, "WSS GetCurrentUser should return non-empty data")
	t.Logf("WSS GetCurrentUser: %v", self)

	// 6. Logout
	ok, err := client.Logout()
	require.NoError(t, err, "WSS Logout should succeed")
	require.True(t, ok, "WSS Logout should return true")
}
