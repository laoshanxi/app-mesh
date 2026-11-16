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
	require.Equal(t, ConfigData.REST.RESTListenAddress, "ABC")
	require.Equal(t, ConfigData.REST.RESTEnabled, false)
	require.Equal(t, ConfigData.REST.RESTListenPort, 999)
	require.Equal(t, ConfigData.REST.SSL.SSLCAPath, "DEF")

	os.Setenv("APPMESH_REST_TcpApiPort", "777")
	readConfig()
	require.Equal(t, ConfigData.REST.TCPAPIPort, 777)

	// The CORS allowlist defaults to empty (the agent then sends no CORS
	// headers at all, like the daemon), also when the local config file
	// predates the REST.CorsAllowOrigins key.
	require.Empty(t, ConfigData.REST.CorsAllowOrigins)

	// The environment override for the allowlist is a comma-separated list.
	// Set directly (not via APPMESH_REST_CorsAllowOrigins) because the env
	// override path only applies to keys the config file already defines, and
	// installed files may predate the key.
	err := setConfigValue(&ConfigData, []string{"rest", "corsalloworigins"},
		"https://ui.example.com, https://alt.example.com")
	require.NoError(t, err)
	require.Equal(t, ConfigData.REST.CorsAllowOrigins,
		[]string{"https://ui.example.com", "https://alt.example.com"})
}
