package appmesh

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// emptyBodySha256 is the SHA-256 of the empty string, the documented
// known-answer vector for the body-hash field.
const emptyBodySha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

const (
	testKeyID  = "ak-3f9c2a81b0d4"
	testSecret = "unit-test-secret"
)

func TestSha256HexKnownAnswer(t *testing.T) {
	assert.Equal(t, emptyBodySha256, sha256Hex(nil), "sha256 of no body must hash the empty string")
	assert.Equal(t, emptyBodySha256, sha256Hex([]byte{}))
	// Lowercase hex, stable second vector.
	assert.Equal(t, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", sha256Hex([]byte("test")))
}

func TestSignCanonicalKnownAnswer(t *testing.T) {
	// Same independent vector as the PSK test: HMAC-SHA256("key", quick-brown-fox).
	assert.Equal(t, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
		signCanonical([]byte("key"), "The quick brown fox jumps over the lazy dog"))
}

func TestCanonicalRequestStringLayout(t *testing.T) {
	got := canonicalRequestString("POST", "/appmesh/app/run", "lifecycle=0&timeout=6", emptyBodySha256,
		"1700000000", "nonce-1")
	assert.Equal(t, "POST\n/appmesh/app/run\nlifecycle=0&timeout=6\n"+emptyBodySha256+"\n1700000000\nnonce-1", got)
}

func TestCanonicalQuerySortsByKeyThenValue(t *testing.T) {
	query := map[string]string{"timeout": "6", "lifecycle": "0", "app": "demo"}
	assert.Equal(t, "app=demo&lifecycle=0&timeout=6", canonicalQuery(query))

	// An empty query is an empty string, never a dangling separator.
	assert.Equal(t, "", canonicalQuery(map[string]string{}))
}

func TestCanonicalQueryValuesKeepsFirstValueOfRepeatedKey(t *testing.T) {
	// The daemon's query map is first-wins; a repeated key must canonicalize
	// to its first value only.
	values := url.Values{"b": []string{"2", "1"}, "a": []string{"x"}}
	assert.Equal(t, map[string]string{"a": "x", "b": "2"}, canonicalQueryValues(values))
	assert.Equal(t, "a=x&b=2", canonicalQuery(canonicalQueryValues(values)))
}

func TestEncodeQueryPercentOnlyNeverUsesPlusForSpace(t *testing.T) {
	values := url.Values{}
	values.Set("value", "hello world")
	values.Set("name", "a&b=c")
	encoded := encodeQueryPercentOnly(values)
	assert.NotContains(t, encoded, "+", "the daemon decodes '+' literally")
	assert.Equal(t, "name=a%26b%3Dc&value=hello%20world", encoded)

	// Round trip: the %-only decode the daemon performs must return the exact
	// decoded values that get signed.
	decoded, err := url.ParseQuery(encoded)
	require.NoError(t, err)
	assert.Equal(t, url.Values{"name": []string{"a&b=c"}, "value": []string{"hello world"}}, decoded)

	assert.Equal(t, "", encodeQueryPercentOnly(nil))
}

// signFramedRequest builds and signs one framed request, returning it.
func signFramedRequest(t *testing.T) *Request {
	t.Helper()
	request := NewRequest()
	request.HTTPMethod = http.MethodPost
	request.RequestURI = "/appmesh/app/run"
	request.Body = []byte(`{"name":"demo"}`)
	request.Query = map[string]string{"timeout": "6", "lifecycle": "0"}

	applyRequestSignature(request, newRequestSigner(testKeyID, testSecret))
	return request
}

func TestApplyRequestSignatureFramedRequest(t *testing.T) {
	request := signFramedRequest(t)

	require.Equal(t, testKeyID, request.Headers[headerRequestKey])
	timestamp := request.Headers[headerTimestamp]
	require.False(t, timestamp == "", "timestamp header must be set")
	// Unix seconds, within the acceptance window of "now".
	claimed, err := strconv.ParseInt(timestamp, 10, 64)
	require.NoError(t, err)
	assert.InDelta(t, time.Now().Unix(), claimed, 120)

	// The framed uuid serves as the nonce.
	assert.Equal(t, request.UUID, request.Headers[headerNonce])

	// Verify the signature against an independently built canonical string.
	expected := signCanonical([]byte(testSecret), canonicalRequestString(http.MethodPost, "/appmesh/app/run",
		"lifecycle=0&timeout=6", sha256Hex([]byte(`{"name":"demo"}`)), timestamp, request.UUID))
	assert.Equal(t, expected, request.Headers[headerSignature])

	// A tampered body no longer matches: the signature binds the body bytes.
	request.Headers[headerSignature] = expected
	tampered := *request
	tampered.Body = []byte(`{"name":"other"}`)
	recomputed := signCanonical([]byte(testSecret), canonicalRequestString(http.MethodPost, "/appmesh/app/run",
		"lifecycle=0&timeout=6", sha256Hex(tampered.Body), timestamp, request.UUID))
	assert.NotEqual(t, recomputed, tampered.Headers[headerSignature])
}

func TestApplyRequestSignatureSignsEmptyBodyOnFileEndpoints(t *testing.T) {
	for _, tc := range []struct{ path, signPath string }{
		{"/appmesh/file/upload", "/appmesh/file/upload"},
		{"/appmesh/file/download", "/appmesh/file/download"},
		{"/appmesh/file/delete", "/appmesh/file/delete"},
		// The trailing "/ws" selects the WSS transfer channel, not the signed
		// resource: the canonical path is the stripped route (daemon
		// canonicalFileRoute, docs/source/Security.md).
		{"/appmesh/file/upload/ws", "/appmesh/file/upload"},
		{"/appmesh/file/download/ws", "/appmesh/file/download"},
	} {
		request := NewRequest()
		request.HTTPMethod = http.MethodPost
		request.RequestURI = tc.path
		request.Body = []byte("file bytes must not be hashed")
		applyRequestSignature(request, newRequestSigner(testKeyID, testSecret))

		expected := signCanonical([]byte(testSecret), canonicalRequestString(http.MethodPost, tc.signPath, "",
			emptyBodySha256, request.Headers[headerTimestamp], request.UUID))
		assert.Equal(t, expected, request.Headers[headerSignature],
			"path %s must sign as %s with the empty-string body hash", tc.path, tc.signPath)
	}
}

func TestCanonicalSigningPathPassesOtherPathsThrough(t *testing.T) {
	assert.Equal(t, "/appmesh/app/demo", canonicalSigningPath("/appmesh/app/demo"))
	assert.Equal(t, "/appmesh/file/delete", canonicalSigningPath("/appmesh/file/delete"))
	// Only the two exact data-channel routes are rewritten.
	assert.Equal(t, "/appmesh/file/download/ws/other", canonicalSigningPath("/appmesh/file/download/ws/other"))
}

func TestApplyRequestSignatureWithoutSignerIsANoOp(t *testing.T) {
	request := NewRequest()
	applyRequestSignature(request, nil)
	for _, header := range []string{headerRequestKey, headerTimestamp, headerNonce, headerSignature} {
		_, present := request.Headers[header]
		assert.False(t, present, "%s must not be set without a signer", header)
	}
}

func TestSignHTTPRequestHashesBodyAndSetsHeaders(t *testing.T) {
	body := []byte(`{"config":true}`)
	req, err := http.NewRequest(http.MethodPut, "https://127.0.0.1:6060/appmesh/app/demo?timeout=6",
		bytes.NewReader(body))
	require.NoError(t, err)
	query := url.Values{"timeout": []string{"6"}}

	require.NoError(t, signHTTPRequest(req, query, newRequestSigner(testKeyID, testSecret)))

	assert.Equal(t, testKeyID, req.Header.Get(headerRequestKey))
	nonce := req.Header.Get(headerNonce)
	assert.NotEmpty(t, nonce)
	assert.NotContains(t, nonce, " ", "nonce must not contain whitespace")

	expected := signCanonical([]byte(testSecret), canonicalRequestString(http.MethodPut, "/appmesh/app/demo",
		"timeout=6", sha256Hex(body), req.Header.Get(headerTimestamp), nonce))
	assert.Equal(t, expected, req.Header.Get(headerSignature))

	// The body stays readable after hashing and the length is preserved.
	sent, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, body, sent)
	assert.Equal(t, int64(len(body)), req.ContentLength)
}

func TestSignHTTPRequestKeepsStreamedFileBodiesUntouched(t *testing.T) {
	fileBody := io.NopCloser(bytes.NewReader([]byte("streamed file content")))
	req, err := http.NewRequest(http.MethodPost, "https://127.0.0.1:6060/appmesh/file/upload", fileBody)
	require.NoError(t, err)

	require.NoError(t, signHTTPRequest(req, nil, newRequestSigner(testKeyID, testSecret)))

	expected := signCanonical([]byte(testSecret), canonicalRequestString(http.MethodPost, "/appmesh/file/upload",
		"", emptyBodySha256, req.Header.Get(headerTimestamp), req.Header.Get(headerNonce)))
	assert.Equal(t, expected, req.Header.Get(headerSignature))

	// The stream was not consumed by the signing step.
	sent, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, []byte("streamed file content"), sent)
}

func TestSignHTTPRequestSignsWsRouteAsStrippedPath(t *testing.T) {
	// The WSS data-channel route signs the route without the trailing "/ws"
	// (daemon canonicalFileRoute) with the empty-string body hash.
	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:6060/appmesh/file/download/ws", nil)
	require.NoError(t, err)

	require.NoError(t, signHTTPRequest(req, nil, newRequestSigner(testKeyID, testSecret)))

	expected := signCanonical([]byte(testSecret), canonicalRequestString(http.MethodGet, "/appmesh/file/download",
		"", emptyBodySha256, req.Header.Get(headerTimestamp), req.Header.Get(headerNonce)))
	assert.Equal(t, expected, req.Header.Get(headerSignature),
		"the /ws route must sign the stripped path with the empty-body hash")
}

// percentOnlyDecode mirrors the daemon's query decoding: %XX decodes, '+'
// stays literal, a malformed escape keeps its raw value.
func percentOnlyDecode(t *testing.T, value string) string {
	t.Helper()
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '%' && i+2 < len(value) {
			hi := strings.IndexByte("0123456789abcdef", lowerByte(value[i+1]))
			lo := strings.IndexByte("0123456789abcdef", lowerByte(value[i+2]))
			if hi >= 0 && lo >= 0 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 2
				continue
			}
		}
		b.WriteByte(value[i])
	}
	return b.String()
}

func lowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// verifySignedRequest recomputes the canonical string daemon-side (percent-only
// query decode, raw path before '?', first value per key) and compares the
// HMAC in constant time, exactly like RequestSignature::verifyWithSecret.
func verifySignedRequest(t *testing.T, r *http.Request, body []byte) {
	t.Helper()
	keyID := r.Header.Get(headerRequestKey)
	timestamp := r.Header.Get(headerTimestamp)
	nonce := r.Header.Get(headerNonce)
	signature := r.Header.Get(headerSignature)
	require.NotEmpty(t, keyID)
	require.NotEmpty(t, timestamp)
	require.NotEmpty(t, nonce)
	require.NotEmpty(t, signature)
	assert.Equal(t, testKeyID, keyID)

	claimed, err := strconv.ParseInt(timestamp, 10, 64)
	require.NoError(t, err)
	assert.InDelta(t, time.Now().Unix(), claimed, 120)

	raw := r.RequestURI
	path := raw
	if q := strings.IndexByte(raw, '?'); q >= 0 {
		path = raw[:q]
	}
	query := map[string]string{}
	for _, pair := range strings.Split(r.URL.RawQuery, "&") {
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		decodedKey := percentOnlyDecode(t, key)
		if _, exists := query[decodedKey]; exists {
			continue // first value wins, like the daemon's map emplace
		}
		query[decodedKey] = percentOnlyDecode(t, value)
	}

	canonical := canonicalRequestString(r.Method, path, canonicalQuery(query), sha256Hex(body), timestamp, nonce)
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(canonical))
	assert.Equal(t, hex.EncodeToString(mac.Sum(nil)), signature,
		"signature must verify against the daemon-side canonical string")
}

func TestHTTPRequesterAttachesSignatureHeaders(t *testing.T) {
	var mu sync.Mutex
	nonces := map[string]bool{}
	var rawQueries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		verifySignedRequest(t, r, body)

		mu.Lock()
		nonces[r.Header.Get(headerNonce)] = true
		rawQueries = append(rawQueries, r.URL.RawQuery)
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"BaseConfig":{"LogLevel":"DEBUG"}}`))
	}))
	defer server.Close()

	client, err := NewHTTPClient(Option{
		AppMeshURI:             server.URL,
		RequestSignatureKeyID:  testKeyID,
		RequestSignatureSecret: testSecret,
	})
	require.NoError(t, err)
	defer client.Close()

	// POST with a JSON body: the signature must bind the body bytes.
	level, err := client.SetLogLevel("DEBUG")
	require.NoError(t, err)
	assert.Equal(t, "DEBUG", level)

	// GET with a query that contains a space: the wire query is percent-only
	// encoded, so the daemon-side decoded value matches the signed value.
	ok, err := client.AddLabel("team label", "hello world")
	require.NoError(t, err)
	assert.True(t, ok)

	require.Len(t, rawQueries, 2)
	// The space-valued query reaches the wire as %20, never '+': the daemon
	// decodes %XX only and keeps a literal '+' untouched, so a '+'-for-space
	// wire form would not verify.
	assert.NotContains(t, rawQueries[1], "+", "wire query: %s", rawQueries[1])
	assert.Contains(t, rawQueries[1], "value=hello%20world", "wire query: %s", rawQueries[1])

	assert.Len(t, nonces, 2, "every request must carry a unique nonce")
}

func TestWithRequestSignatureTogglesSigningAtRuntime(t *testing.T) {
	signed := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerRequestKey) != "" {
			signed++
			verifySignedRequest(t, r, nil)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewHTTPClient(Option{AppMeshURI: server.URL})
	require.NoError(t, err)
	defer client.Close()

	// Off by default: no signature headers.
	_, err = client.GetMetrics()
	require.NoError(t, err)
	assert.Equal(t, 0, signed)

	client.WithRequestSignature(testKeyID, testSecret)
	_, err = client.GetMetrics()
	require.NoError(t, err)
	assert.Equal(t, 1, signed)

	// An empty key ID disables signing again.
	client.WithRequestSignature("", "")
	_, err = client.GetMetrics()
	require.NoError(t, err)
	assert.Equal(t, 1, signed)
}
