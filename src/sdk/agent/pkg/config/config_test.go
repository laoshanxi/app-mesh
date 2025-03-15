package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {

	os.Setenv("APPMESH_ABC", "DEF")
	os.Setenv("APPMESH_REST_RestEnabled", "false")
	os.Setenv("APPMESH_REST_RestListenAddress", "ABC")
	os.Setenv("APPMESH_REST_RestListenPort", "999")
	os.Setenv("APPMESH_REST_SSL_SSLCaPath", "DEF")
	readConfig()
	require.Equal(t, ConfigData.REST.RestListenAddress, "ABC")
	require.Equal(t, ConfigData.REST.RestEnabled, false)
	require.Equal(t, ConfigData.REST.RestListenPort, 999)
	require.Equal(t, ConfigData.REST.SSL.SSLCaPath, "DEF")
}
