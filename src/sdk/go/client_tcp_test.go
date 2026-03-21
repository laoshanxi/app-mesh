package appmesh

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppmeshTCPFile(t *testing.T) {
	noVerify := ""
	client, err := NewTCPClient(Option{SslTrustedCA: &noVerify})
	fmt.Println(err)
	require.Nil(t, err)

	_, err = client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS, "")
	require.NoError(t, err)

	var remotePath, localFile, tempFile string
	if runtime.GOOS == "windows" {
		remotePath = `C:\local\appmesh\bin\appsvc.exe`
		localFile = "appsvc.exe"
		tempFile = filepath.Join(os.TempDir(), "appsvc.exe")
	} else {
		remotePath = "/opt/appmesh/bin/appsvc"
		localFile = "appsvc"
		tempFile = "/tmp/appsvc"
	}

	_ = os.Remove(localFile)
	_ = os.Remove(tempFile)

	require.Nil(t, client.FileDownload(remotePath, localFile, true))
	// require.Nil(t, client.FileUpload(localFile, tempFile, true))

	_ = os.Remove(localFile)
	_ = os.Remove(tempFile)
}

func TestAppmeshTCPOperations(t *testing.T) {
	noVerify := ""
	client, err := NewTCPClient(Option{SslTrustedCA: &noVerify})
	require.NoError(t, err)
	defer client.CloseConnection()

	// 1. Login
	_, err = client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS, "")
	require.NoError(t, err, "TCP login should succeed")

	// 2. ListApps - verify count > 0
	apps, err := client.ListApps()
	require.NoError(t, err, "TCP ListApps should succeed")
	require.Greater(t, len(apps), 0, "TCP ListApps should return at least one app")
	t.Logf("TCP ListApps count: %d", len(apps))

	// 3. RunAppSync - echo command, verify exit code 0
	cmd := "echo hello_tcp"
	shellMode := true
	runApp := Application{
		Name:      "go-tcp-sync-test",
		Command:   &cmd,
		ShellMode: &shellMode,
	}
	exitCode, output, err := client.RunAppSync(runApp, false, 10, 15)
	require.NoError(t, err, "TCP RunAppSync should succeed")
	require.Equal(t, 0, exitCode, "TCP RunAppSync exit code should be 0")
	require.Contains(t, output, "hello_tcp", "TCP RunAppSync output should contain echoed text")
	t.Logf("TCP RunAppSync output: %q, exit: %d", output, exitCode)

	// 4. GetHostResources - verify non-empty
	res, err := client.GetHostResources()
	require.NoError(t, err, "TCP GetHostResources should succeed")
	require.NotEmpty(t, res, "TCP GetHostResources should return non-empty data")
	t.Logf("TCP GetHostResources keys: %d", len(res))

	// 5. GetConfig - verify non-empty
	cfg, err := client.GetConfig()
	require.NoError(t, err, "TCP GetConfig should succeed")
	require.NotEmpty(t, cfg, "TCP GetConfig should return non-empty data")
	t.Logf("TCP GetConfig keys: %d", len(cfg))

	// 6. AddLabel / GetLabels / DeleteLabel
	const tagName = "go-tcp-test-tag"
	const tagValue = "tcp-test-value"

	added, err := client.AddLabel(tagName, tagValue)
	require.NoError(t, err, "TCP AddLabel should succeed")
	require.True(t, added, "TCP AddLabel should return true")

	tags, err := client.GetLabels()
	require.NoError(t, err, "TCP GetLabels should succeed")
	require.Equal(t, tagValue, tags[tagName], "TCP GetLabels should contain the added label with correct value")
	t.Logf("TCP GetLabels: %v", tags)

	deleted, err := client.DeleteLabel(tagName)
	require.NoError(t, err, "TCP DeleteLabel should succeed")
	require.True(t, deleted, "TCP DeleteLabel should return true")

	tagsAfter, err := client.GetLabels()
	require.NoError(t, err, "TCP GetLabels after delete should succeed")
	_, stillPresent := tagsAfter[tagName]
	require.False(t, stillPresent, "TCP label should be absent after deletion")

	// 7. Logout
	ok, err := client.Logout()
	require.NoError(t, err, "TCP Logout should succeed")
	require.True(t, ok, "TCP Logout should return true")
}
