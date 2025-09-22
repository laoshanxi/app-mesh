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
	client, err := NewTcpClient(Option{})
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
	require.Nil(t, client.FileUpload(localFile, tempFile, true))

	_ = os.Remove(localFile)
	_ = os.Remove(tempFile)
}
