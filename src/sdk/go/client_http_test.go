package appmesh

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func requireBearerToken(t *testing.T) string {
	t.Helper()
	token := os.Getenv("APPMESH_BEARER_TOKEN")
	if token == "" {
		t.Skip("APPMESH_BEARER_TOKEN is required for live integration tests")
	}
	return token
}

func TestBearerTokenIsInMemoryOnly(t *testing.T) {
	client, err := NewHTTPClient(Option{InsecureSkipVerify: true})
	require.NoError(t, err)
	defer client.Close()

	require.Empty(t, client.GetToken())
	client.SetToken("test-only-placeholder")
	require.Equal(t, "test-only-placeholder", client.GetToken())
	client.ClearToken()
	require.Empty(t, client.GetToken())

	httpRequester, ok := client.req.(*HTTPRequester)
	require.True(t, ok)
	require.Nil(t, httpRequester.httpClient.Jar, "bearer-only clients must not retain cookies")
}
