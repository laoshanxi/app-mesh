package appmesh

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppmeshTCPFile(t *testing.T) {
	client, err := NewTCPClient(Option{InsecureSkipVerify: true})
	require.Nil(t, err)

	client.SetToken(requireBearerToken(t))

	// With FileAllowedBaseDir unset the file API jails transfers to the daemon
	// work tree, and inside it only work/tmp is exchangeable: upload to that
	// scratch, then download back and compare.
	var scratch string
	if runtime.GOOS == "windows" {
		scratch = `C:\local\appmesh\work\tmp`
	} else {
		scratch = "/opt/appmesh/work/tmp"
	}
	localFile := "go_file_test"
	tempFile := filepath.Join(os.TempDir(), "go_file_test.copy")
	remotePath := filepath.Join(scratch, "go_file_test.txt")

	_ = os.Remove(localFile)
	_ = os.Remove(tempFile)
	require.Nil(t, os.WriteFile(localFile, []byte("go_file_roundtrip"), 0o644))

	require.Nil(t, client.UploadFile(localFile, remotePath, true))
	require.Nil(t, client.DownloadFile(remotePath, tempFile, true))
	content, err := os.ReadFile(tempFile)
	require.Nil(t, err)
	require.Equal(t, "go_file_roundtrip", string(content))

	_ = os.Remove(localFile)
	_ = os.Remove(tempFile)
}

func TestAppmeshTCPOperations(t *testing.T) {
	client, err := NewTCPClient(Option{InsecureSkipVerify: true})
	require.NoError(t, err)
	defer client.CloseConnection()

	client.SetToken(requireBearerToken(t))

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
	exitCode, output, err := client.RunAppSync(runApp, 10, 15)
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

	// 6. AddLabel / ListLabels / DeleteLabel
	const tagName = "go-tcp-test-tag"
	const tagValue = "tcp-test-value"

	added, err := client.AddLabel(tagName, tagValue)
	require.NoError(t, err, "TCP AddLabel should succeed")
	require.True(t, added, "TCP AddLabel should return true")

	tags, err := client.ListLabels()
	require.NoError(t, err, "TCP ListLabels should succeed")
	require.Equal(t, tagValue, tags[tagName], "TCP ListLabels should contain the added label with correct value")
	t.Logf("TCP ListLabels: %v", tags)

	deleted, err := client.DeleteLabel(tagName)
	require.NoError(t, err, "TCP DeleteLabel should succeed")
	require.True(t, deleted, "TCP DeleteLabel should return true")

	tagsAfter, err := client.ListLabels()
	require.NoError(t, err, "TCP ListLabels after delete should succeed")
	_, stillPresent := tagsAfter[tagName]
	require.False(t, stillPresent, "TCP label should be absent after deletion")

}
