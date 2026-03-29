package appmesh

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
)

type mockAuthRequester struct {
	storedToken string
	lastHeaders map[string]string
	updateCalls []string
}

func (m *mockAuthRequester) Send(method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	m.lastHeaders = make(map[string]string, len(headers))
	for k, v := range headers {
		m.lastHeaders[k] = v
	}
	resp := []byte(`{"access_token":"verified-token","expires_in":3600,"expire_time":999999999}`)
	code := http.StatusOK
	// Simulate transport-level token sync (as real requesters do)
	syncTransportToken(code, resp, apiPath, headers, m)
	return code, resp, http.Header{}, nil
}

func (m *mockAuthRequester) Close() {}
func (m *mockAuthRequester) handleTokenUpdate(token string) {
	m.updateCalls = append(m.updateCalls, token)
	if token != "" {
		m.storedToken = token
	}
}
func (m *mockAuthRequester) setToken(token string)         { m.storedToken = token }
func (m *mockAuthRequester) getAccessToken() string        { return m.storedToken }
func (m *mockAuthRequester) setForwardTo(forwardTo string) {}
func (m *mockAuthRequester) getForwardTo() string          { return "" }

func TestAuthenticateApplyFalseDoesNotMutateHTTPState(t *testing.T) {
	req := &mockAuthRequester{storedToken: "existing-token"}
	client, err := newHTTPClientWithRequester(Option{}, req)
	require.NoError(t, err)

	ok, err := client.Authenticate("provided-token", "", "", false)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "Bearer provided-token", req.lastHeaders["Authorization"])
	require.Empty(t, req.lastHeaders[HTTP_HEADER_JWT_SET_COOKIE])
	require.Equal(t, "existing-token", req.getAccessToken())
	require.Empty(t, req.updateCalls)
}

func TestAuthenticateApplyTrueUpdatesHTTPState(t *testing.T) {
	req := &mockAuthRequester{}
	client, err := newHTTPClientWithRequester(Option{}, req)
	require.NoError(t, err)

	ok, err := client.Authenticate("provided-token", "", "", true)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "Bearer provided-token", req.lastHeaders["Authorization"])
	require.Equal(t, "true", req.lastHeaders[HTTP_HEADER_JWT_SET_COOKIE])
	require.Equal(t, "verified-token", req.getAccessToken())
	require.Equal(t, []string{"verified-token"}, req.updateCalls)
}

// mockTransportRequester simulates a TCP/WSS transport for syncTransportToken tests.
// Unlike mockAuthRequester (which simulates HTTP), this one records handleTokenUpdate calls
// and lets tests verify the path-based token extraction logic.
type mockTransportRequester struct {
	storedToken string
	lastHeaders map[string]string
	updateCalls []string
	respCode    int    // response status code, default 200
	respBody    string // response body JSON, default with access_token
}

func (m *mockTransportRequester) Send(method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	m.lastHeaders = make(map[string]string, len(headers))
	for k, v := range headers {
		m.lastHeaders[k] = v
	}
	code := m.respCode
	if code == 0 {
		code = http.StatusOK
	}
	respBody := m.respBody
	if respBody == "" {
		respBody = `{"access_token":"new-token","expires_in":3600}`
	}
	raw := []byte(respBody)
	// Simulate transport-level token sync (as TCP/WSS requesters do)
	syncTransportToken(code, raw, apiPath, headers, m)
	return code, raw, http.Header{}, nil
}

func (m *mockTransportRequester) Close() {}
func (m *mockTransportRequester) handleTokenUpdate(token string) {
	m.updateCalls = append(m.updateCalls, token)
	m.storedToken = token
}
func (m *mockTransportRequester) setToken(token string)         { m.storedToken = token }
func (m *mockTransportRequester) getAccessToken() string        { return m.storedToken }
func (m *mockTransportRequester) setForwardTo(forwardTo string) {}
func (m *mockTransportRequester) getForwardTo() string          { return "" }

func TestSyncTransportToken_LoginWithSetCookie(t *testing.T) {
	req := &mockTransportRequester{}
	client, err := newHTTPClientWithRequester(Option{}, req)
	require.NoError(t, err)

	_, err = client.Login("user", "pass", "", 3600, "")
	require.NoError(t, err)
	require.Equal(t, "new-token", req.storedToken)
	require.Contains(t, req.updateCalls, "new-token")
}

func TestSyncTransportToken_LoginWithoutSetCookie(t *testing.T) {
	// Login always sends X-Set-Cookie: true, so token should be applied
	req := &mockTransportRequester{}
	client, err := newHTTPClientWithRequester(Option{}, req)
	require.NoError(t, err)

	_, err = client.Login("user", "pass", "", 3600, "")
	require.NoError(t, err)
	require.Equal(t, "true", req.lastHeaders[HTTP_HEADER_JWT_SET_COOKIE])
	require.Equal(t, "new-token", req.storedToken)
}

func TestSyncTransportToken_ValidateTotp(t *testing.T) {
	req := &mockTransportRequester{}
	client, err := newHTTPClientWithRequester(Option{}, req)
	require.NoError(t, err)

	err = client.ValidateTotp("user", "challenge", "123456", 3600)
	require.NoError(t, err)
	// ValidateTotp sends X-Set-Cookie: true
	require.Equal(t, "true", req.lastHeaders[HTTP_HEADER_JWT_SET_COOKIE])
	require.Equal(t, "new-token", req.storedToken)
}

func TestSyncTransportToken_Logout(t *testing.T) {
	req := &mockTransportRequester{storedToken: "old-token"}
	client, err := newHTTPClientWithRequester(Option{}, req)
	require.NoError(t, err)

	ok, err := client.Logout()
	require.NoError(t, err)
	require.True(t, ok)
	// Token should be cleared
	require.Equal(t, "", req.storedToken)
	require.Contains(t, req.updateCalls, "")
}

func TestSyncTransportToken_LogoutFailure(t *testing.T) {
	req := &mockTransportRequester{storedToken: "old-token", respCode: http.StatusInternalServerError}
	client, err := newHTTPClientWithRequester(Option{}, req)
	require.NoError(t, err)

	ok, _ := client.Logout()
	require.False(t, ok)
	// Token should NOT be cleared on failure
	require.Equal(t, "old-token", req.storedToken)
	require.Empty(t, req.updateCalls)
}

func TestSyncTransportToken_RenewToken(t *testing.T) {
	req := &mockTransportRequester{storedToken: "old-token"}
	client, err := newHTTPClientWithRequester(Option{}, req)
	require.NoError(t, err)

	ok, err := client.RenewToken()
	require.NoError(t, err)
	require.True(t, ok)
	// Token should be updated (renew path always applies)
	require.Equal(t, "new-token", req.storedToken)
}

func TestSyncTransportToken_EnableTotp(t *testing.T) {
	req := &mockTransportRequester{storedToken: "old-token"}
	client, err := newHTTPClientWithRequester(Option{}, req)
	require.NoError(t, err)

	token, err := client.EnableTotp("123456")
	require.NoError(t, err)
	require.Equal(t, "new-token", token)
	// Token should be updated (setup path always applies)
	require.Equal(t, "new-token", req.storedToken)
}

func TestSyncTransportToken_NonAuthPath(t *testing.T) {
	req := &mockTransportRequester{storedToken: "old-token"}
	// Call syncTransportToken directly with a non-auth path
	raw := []byte(`{"access_token":"should-not-apply"}`)
	syncTransportToken(http.StatusOK, raw, "/appmesh/applications", nil, req)
	// Token should NOT change
	require.Equal(t, "old-token", req.storedToken)
	require.Empty(t, req.updateCalls)
}

// Integration tests: verify cookie/token state against the live server.
// These tests require the updated appsvc daemon with Set-Cookie support for renew/logoff.

func TestIntegration_HTTP_RenewToken_UpdatesCookie(t *testing.T) {
	cookiePath := filepath.Join(os.TempDir(), fmt.Sprintf("appmesh_go_test_%s.cookie", xid.New().String()))
	defer os.Remove(cookiePath)

	emptyStr := ""
	client, err := NewHTTPClient(Option{SslTrustedCA: &emptyStr, CookieFile: cookiePath})
	require.NoError(t, err)
	defer client.Close()

	_, err = client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS, "")
	require.NoError(t, err)

	tokenAfterLogin := client.req.getAccessToken()
	require.NotEmpty(t, tokenAfterLogin, "should have token after login")

	// Cookie file should contain the token
	data, err := os.ReadFile(cookiePath)
	require.NoError(t, err)
	require.Contains(t, string(data), tokenAfterLogin, "cookie file should contain login token")

	// Renew token
	ok, err := client.RenewToken()
	require.NoError(t, err)
	require.True(t, ok)

	tokenAfterRenew := client.req.getAccessToken()
	require.NotEmpty(t, tokenAfterRenew, "should have token after renew")

	// Cookie file should be updated with renewed token
	data, err = os.ReadFile(cookiePath)
	require.NoError(t, err)
	require.Contains(t, string(data), tokenAfterRenew, "cookie file should contain renewed token")
}

func TestIntegration_HTTP_Logout_ClearsCookie(t *testing.T) {
	cookiePath := filepath.Join(os.TempDir(), fmt.Sprintf("appmesh_go_test_%s.cookie", xid.New().String()))
	defer os.Remove(cookiePath)

	emptyStr := ""
	client, err := NewHTTPClient(Option{SslTrustedCA: &emptyStr, CookieFile: cookiePath})
	require.NoError(t, err)
	defer client.Close()

	_, err = client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS, "")
	require.NoError(t, err)
	tokenBeforeLogout := client.req.getAccessToken()
	require.NotEmpty(t, tokenBeforeLogout)

	// Logout
	ok, err := client.Logout()
	require.NoError(t, err)
	require.True(t, ok)

	// Token should be cleared from cookie jar
	require.Empty(t, client.req.getAccessToken(), "token should be empty after logout")

	// Cookie file should not contain the old token value
	data, err := os.ReadFile(cookiePath)
	require.NoError(t, err)
	require.NotContains(t, string(data), tokenBeforeLogout, "cookie file should not contain the old token after logout")
}

func TestIntegration_TCP_Logout_ClearsToken(t *testing.T) {
	emptyStr := ""
	client, err := NewTCPClient(Option{SslTrustedCA: &emptyStr})
	require.NoError(t, err)
	defer client.Close()

	_, err = client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS, "")
	require.NoError(t, err)
	require.NotEmpty(t, client.req.getAccessToken(), "should have token after TCP login")

	ok, err := client.Logout()
	require.NoError(t, err)
	require.True(t, ok)
	require.Empty(t, client.req.getAccessToken(), "TCP token should be empty after logout")
}

func TestIntegration_WSS_Logout_ClearsToken(t *testing.T) {
	emptyStr := ""
	client, err := NewWSSClient(Option{SslTrustedCA: &emptyStr})
	require.NoError(t, err)
	defer client.Close()

	_, err = client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS, "")
	require.NoError(t, err)
	require.NotEmpty(t, client.req.getAccessToken(), "should have token after WSS login")

	ok, err := client.Logout()
	require.NoError(t, err)
	require.True(t, ok)
	require.Empty(t, client.req.getAccessToken(), "WSS token should be empty after logout")
}

func TestIntegration_HTTP_Authenticate_ApplyTrue(t *testing.T) {
	emptyStr := ""
	client, err := NewHTTPClient(Option{SslTrustedCA: &emptyStr})
	require.NoError(t, err)
	defer client.Close()

	// Login to get a token
	_, err = client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS, "")
	require.NoError(t, err)
	token := client.req.getAccessToken()

	// Create a new client and use authenticate to apply the token
	client2, err := NewHTTPClient(Option{SslTrustedCA: &emptyStr})
	require.NoError(t, err)
	defer client2.Close()
	require.Empty(t, client2.req.getAccessToken())

	ok, err := client2.Authenticate(token, "", "", true)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotEmpty(t, client2.req.getAccessToken(), "token should be applied after authenticate(apply=true)")
}

func TestIntegration_HTTP_Authenticate_ApplyFalse(t *testing.T) {
	emptyStr := ""
	client, err := NewHTTPClient(Option{SslTrustedCA: &emptyStr})
	require.NoError(t, err)
	defer client.Close()

	_, err = client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS, "")
	require.NoError(t, err)
	token := client.req.getAccessToken()

	// New client: authenticate(apply=false) should NOT store the token
	client2, err := NewHTTPClient(Option{SslTrustedCA: &emptyStr})
	require.NoError(t, err)
	defer client2.Close()

	ok, err := client2.Authenticate(token, "", "", false)
	require.NoError(t, err)
	require.True(t, ok)
	require.Empty(t, client2.req.getAccessToken(), "token should NOT be applied after authenticate(apply=false)")
}

func TestAppmeshLogin(t *testing.T) {

	emptyStr := ""
	client, _ := NewHTTPClient(Option{SslTrustedCA: &emptyStr})

	client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS, "")
	res, _ := client.GetHostResources()
	t.Log(res)
	labels, _ := client.GetLabels()
	t.Log(labels)
	apps, _ := client.ListApps()
	t.Log(apps)

	app, _ := client.GetApp("test")
	t.Log(app)

	runApp := Application{}
	cmd := "ping cloudflare.com -w 3"
	runApp.Command = &cmd
	client.RunAppSync(runApp, true, 5, 10)
	client.RunAppAsync(runApp, 5, 10)
}

func TestAppmeshSetToken(t *testing.T) {
	emptyStr := ""
	// 1. Login to get a valid token
	client, _ := NewHTTPClient(Option{SslTrustedCA: &emptyStr})
	_, err := client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS, "")
	require.NoError(t, err)
	token := client.req.getAccessToken()
	require.NotEmpty(t, token)
	t.Log("Got token from login")

	// 2. SetToken without cookie file (in-memory)
	client2, _ := NewHTTPClient(Option{SslTrustedCA: &emptyStr})
	client2.SetToken(token)
	apps, err := client2.ListApps()
	require.NoError(t, err)
	require.NotEmpty(t, apps)
	t.Logf("SetToken in-memory: got %d apps", len(apps))

	// 3. JwtToken constructor param without cookie file
	client3, _ := NewHTTPClient(Option{SslTrustedCA: &emptyStr, JwtToken: token})
	apps3, err := client3.ListApps()
	require.NoError(t, err)
	require.Equal(t, len(apps), len(apps3))
	t.Log("JwtToken constructor: list_apps ok")

	// 4. SetToken with cookie file
	cookiePath := filepath.Join(os.TempDir(), fmt.Sprintf("appmesh_go_test_%s.cookie", xid.New().String()))
	defer os.Remove(cookiePath)
	client4, _ := NewHTTPClient(Option{SslTrustedCA: &emptyStr, CookieFile: cookiePath})
	client4.SetToken(token)
	apps4, err := client4.ListApps()
	require.NoError(t, err)
	require.Equal(t, len(apps), len(apps4))
	t.Log("SetToken with cookie file: list_apps ok")

	// 5. JwtToken + CookieFile constructor
	cookiePath2 := filepath.Join(os.TempDir(), fmt.Sprintf("appmesh_go_test_%s.cookie", xid.New().String()))
	defer os.Remove(cookiePath2)
	client5, _ := NewHTTPClient(Option{SslTrustedCA: &emptyStr, JwtToken: token, CookieFile: cookiePath2})
	apps5, err := client5.ListApps()
	require.NoError(t, err)
	require.Equal(t, len(apps), len(apps5))
	t.Log("JwtToken + CookieFile constructor: list_apps ok")

	client.Close()
	client2.Close()
	client3.Close()
	client4.Close()
	client5.Close()
}

func TestAppmeshFile(t *testing.T) {
	client, _ := NewHTTPClient(Option{})

	_, err := client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS, DEFAULT_JWT_AUDIENCE)
	require.NoError(t, err)

	var remotePath, localFile, tempFile string
	if runtime.GOOS == "windows" {
		remotePath = `C:\local\appmesh\bin\appsvc.exe`
		localFile = "appsvc.exe"
		tempFile = filepath.Join(os.TempDir(), fmt.Sprintf("appsvc_%d.exe", os.Getpid()))
	} else {
		remotePath = "/opt/appmesh/bin/appsvc"
		localFile = "appsvc"
		tempFile = fmt.Sprintf("/tmp/appsvc_%d", os.Getpid())
	}

	_ = os.Remove(localFile)
	_ = os.Remove(tempFile)
	require.Nil(t, client.DownloadFile(remotePath, localFile, true))
	require.Nil(t, client.UploadFile(localFile, tempFile, true))
	_ = os.Remove(localFile)
	_ = os.Remove(tempFile)
	client.updateForwardTo("localhost:6059")
	require.Nil(t, client.DownloadFile(remotePath, localFile, true))
	// require.Nil(t, client.UploadFile(localFile, tempFile, true))

	_ = os.Remove(localFile)
	_ = os.Remove(tempFile)
}

func TestAppmeshTotp(t *testing.T) {

	client, _ := NewHTTPClient(Option{})

	_, err := client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS, DEFAULT_JWT_AUDIENCE)
	require.NoError(t, err, "Login failed")

	/*
		secret, err := client.TotpSecret()
		require.NoError(t, err, "TotpSecret failed")

		code, _ := totp.GenerateCode(secret, time.Now().UTC())
		success, err = client.TotpSetup(code)
		require.True(t, success, "TotpSetup failed")
		require.NoError(t, err, "TotpSetup failed")

		code, _ = totp.GenerateCode(secret, time.Now().UTC())
		success, _, err = client.Login("admin", "admin123", code, DEFAULT_TOKEN_EXPIRE_SECONDS)
		require.True(t, success, "Login with TOTP code failed")
		require.NoError(t, err, "Login with TOTP code failed")

		success, err = client.TotpDisable()
		require.True(t, success, "TotpDisable failed")
		require.NoError(t, err, "TotpDisable failed")
	*/
}

func TestMessagePack(t *testing.T) {
	type Response struct {
		Uuid        string            `msg:"uuid" msgpack:"uuid"`
		RequestUri  string            `msg:"request_uri" msgpack:"request_uri"`
		HttpStatus  int               `msg:"http_status" msgpack:"http_status"`
		BodyMsgType string            `msg:"body_msg_type" msgpack:"body_msg_type"`
		Body        string            `msg:"body" msgpack:"body"`
		Headers     map[string]string `msg:"headers" msgpack:"headers"`
	}

	data := new(Response)
	data.Uuid = xid.New().String()
	data.RequestUri = "123"
	data.HttpStatus = 1
	content, _ := os.ReadFile("/root/app-mesh/1.log")
	data.Body = string(content)
	data.Headers = make(map[string]string)
	data.Headers[string("key")] = string("value")

	buf, err := msgpack.Marshal(*data)
	require.NoError(t, err, "msgpack Marshal failed")

	t.Log(len(buf))
	protocResponse := new(Response)
	err = msgpack.Unmarshal(buf, protocResponse)
	require.NoError(t, err, "msgpack Unmarshal failed")

	require.Equal(t, data.Body, protocResponse.Body)
}

func TestAppmeshAppManagement(t *testing.T) {
	noVerify := ""
	client, err := NewHTTPClient(Option{SslTrustedCA: &noVerify})
	require.NoError(t, err)

	_, err = client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS, "")
	require.NoError(t, err, "Login failed")

	// --- AddApp ---
	appName := "go-test-app"
	cmd := "echo hello"
	shellMode := true
	app := Application{
		Name:      appName,
		Command:   &cmd,
		ShellMode: &shellMode,
	}
	added, err := client.AddApp(app)
	require.NoError(t, err, "AddApp failed")
	require.NotNil(t, added, "AddApp returned nil")
	require.Equal(t, appName, added.Name)
	t.Logf("AddApp: %s (status=%d)", added.Name, added.Status)

	// Ensure cleanup regardless of test outcome.
	defer func() {
		ok, err := client.RemoveApp(appName)
		require.NoError(t, err, "RemoveApp (cleanup) failed")
		require.True(t, ok, "RemoveApp (cleanup) returned false")
		t.Logf("RemoveApp: %s removed", appName)
	}()

	// --- EnableApp ---
	ok, err := client.EnableApp(appName)
	require.NoError(t, err, "EnableApp failed")
	require.True(t, ok, "EnableApp returned false")
	t.Logf("EnableApp: %s enabled", appName)

	// --- DisableApp ---
	ok, err = client.DisableApp(appName)
	require.NoError(t, err, "DisableApp failed")
	require.True(t, ok, "DisableApp returned false")
	t.Logf("DisableApp: %s disabled", appName)

	// --- GetAppOutput ---
	out := client.GetAppOutput(appName, 0, 0, 4096, "", 3)
	// Output may be empty for a disabled/stopped app; check no transport error.
	require.NoError(t, out.Error, "GetAppOutput returned error")
	t.Logf("GetAppOutput: success=%v body=%q", out.HttpSuccess, out.HttpBody)

	// --- GetConfig / SetConfig ---
	cfg, err := client.GetConfig()
	require.NoError(t, err, "GetConfig failed")
	require.NotEmpty(t, cfg, "GetConfig returned empty config")
	t.Logf("GetConfig: keys=%d", len(cfg))

	// Set a description field inside BaseConfig to verify round-trip.
	// We only mutate a safe, low-risk field (Description) and restore it.
	baseCfg, _ := cfg["BaseConfig"].(map[string]interface{})
	var origDescription interface{}
	if baseCfg != nil {
		origDescription = baseCfg["Description"]
	}

	patchCfg := map[string]interface{}{
		"BaseConfig": map[string]interface{}{
			"Description": "go-sdk-test",
		},
	}
	updatedCfg, err := client.SetConfig(patchCfg)
	require.NoError(t, err, "SetConfig failed")
	require.NotEmpty(t, updatedCfg, "SetConfig returned empty config")
	t.Logf("SetConfig: keys=%d", len(updatedCfg))

	// Restore original description.
	restoreVal := ""
	if origDescription != nil {
		if s, ok := origDescription.(string); ok {
			restoreVal = s
		}
	}
	restoreCfg := map[string]interface{}{
		"BaseConfig": map[string]interface{}{
			"Description": restoreVal,
		},
	}
	_, err = client.SetConfig(restoreCfg)
	require.NoError(t, err, "SetConfig restore failed")

	// --- AddLabel / DeleteLabel ---
	tagName := "go-sdk-test-tag"
	tagValue := "test-value-123"
	ok, err = client.AddLabel(tagName, tagValue)
	require.NoError(t, err, "AddLabel failed")
	require.True(t, ok, "AddLabel returned false")
	t.Logf("AddLabel: %s=%s", tagName, tagValue)

	tags, err := client.GetLabels()
	require.NoError(t, err, "GetLabels after AddLabel failed")
	require.Equal(t, tagValue, tags[tagName], "label value mismatch after AddLabel")

	ok, err = client.DeleteLabel(tagName)
	require.NoError(t, err, "DeleteLabel failed")
	require.True(t, ok, "DeleteLabel returned false")
	t.Logf("DeleteLabel: %s deleted", tagName)

	tags, err = client.GetLabels()
	require.NoError(t, err, "GetLabels after DeleteLabel failed")
	_, exists := tags[tagName]
	require.False(t, exists, "label should be absent after DeleteLabel")

	// --- ListUsers ---
	users, err := client.ListUsers()
	require.NoError(t, err, "ListUsers failed")
	require.NotEmpty(t, users, "ListUsers returned empty map")
	t.Logf("ListUsers: count=%d", len(users))

	// --- GetCurrentUser ---
	currentUser, err := client.GetCurrentUser()
	require.NoError(t, err, "GetCurrentUser failed")
	require.NotEmpty(t, currentUser, "GetCurrentUser returned empty map")
	t.Logf("GetCurrentUser: %v", currentUser)

	// --- ListRoles ---
	roles, err := client.ListRoles()
	require.NoError(t, err, "ListRoles failed")
	require.NotEmpty(t, roles, "ListRoles returned empty slice")
	t.Logf("ListRoles: count=%d", len(roles))

	// --- ListPermissions (ViewPermissions) ---
	perms, err := client.ViewPermissions()
	require.NoError(t, err, "ViewPermissions failed")
	require.NotEmpty(t, perms, "ViewPermissions returned empty list")
	t.Logf("ViewPermissions: count=%d", len(perms))

	// --- GetUserPermissions ---
	userPerms, err := client.GetUserPermissions()
	require.NoError(t, err, "GetUserPermissions failed")
	require.NotEmpty(t, userPerms, "GetUserPermissions returned empty list")
	t.Logf("GetUserPermissions: count=%d", len(userPerms))
}

func TestParseDuration(t *testing.T) {
	// Integer seconds
	secs, err := ParseDuration("3600")
	require.NoError(t, err)
	require.Equal(t, 3600, secs)

	// ISO 8601: P1W = 7 days
	secs, err = ParseDuration("P1W")
	require.NoError(t, err)
	require.Equal(t, 604800, secs)

	// ISO 8601: P2DT12H = 2 days + 12 hours
	secs, err = ParseDuration("P2DT12H")
	require.NoError(t, err)
	require.Equal(t, 216000, secs)

	// ISO 8601: PT5M30S = 5 min + 30 sec
	secs, err = ParseDuration("PT5M30S")
	require.NoError(t, err)
	require.Equal(t, 330, secs)

	// ISO 8601: P1Y2M3DT4H5M6S
	secs, err = ParseDuration("P1Y2M3DT4H5M6S")
	require.NoError(t, err)
	expected := 365*86400 + 2*30*86400 + 3*86400 + 4*3600 + 5*60 + 6
	require.Equal(t, expected, secs)

	// Invalid
	_, err = ParseDuration("invalid")
	require.Error(t, err)
}
