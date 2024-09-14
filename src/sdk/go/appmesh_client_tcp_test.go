package appmesh

import (
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppmeshTCPFile(t *testing.T) {

	client, err := NewTcpClient(Option{})
	log.Print(err)
	require.Nil(t, err)

	success, _, _ := client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS)
	require.True(t, success)

	os.Remove("appsvc")
	os.Remove("/tmp/appsvc")

	require.Nil(t, client.FileDownload("/opt/appmesh/bin/appsvc", "appsvc"))
	require.Nil(t, client.FileUpload("appsvc", "/tmp/appsvc"))
	os.Remove("appsvc")
}
