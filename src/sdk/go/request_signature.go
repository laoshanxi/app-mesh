// request_signature.go
package appmesh

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rs/xid"
)

// Opt-in HMAC request signing (docs/source/Security.md, "Request replay
// protection and signatures"). The signature is an integrity layer on top of
// bearer authentication, produced with a per-principal API key; it does not
// replace the bearer token. Mirrors the daemon's
// src/daemon/security/RequestSignature.cpp byte-for-byte.
const (
	headerRequestKey = "X-Request-Key"
	headerTimestamp  = "X-Timestamp"
	headerNonce      = "X-Nonce"
	headerSignature  = "X-Signature"
)

// emptyBodySignedPaths are the streamed file endpoints: their body crosses the
// wire as a stream (or a socket side channel), so they sign the empty-string
// body hash instead of the file content. Documented exemption, same list the
// daemon enforces hardening on.
var emptyBodySignedPaths = map[string]bool{
	"/appmesh/file/upload":      true,
	"/appmesh/file/download":    true,
	"/appmesh/file/delete":      true,
	"/appmesh/file/upload/ws":   true,
	"/appmesh/file/download/ws": true,
}

// requestSigner holds the per-principal API key used for opt-in HMAC request
// signing. The secret is never logged and never crosses the wire; only its
// HMAC does.
type requestSigner struct {
	keyID  string
	secret []byte
}

// newRequestSigner builds a signer from an API key id and its secret (the
// POST /appmesh/security/apikeys response returns the secret exactly once).
func newRequestSigner(keyID, secret string) *requestSigner {
	return &requestSigner{keyID: keyID, secret: []byte(secret)}
}

// sha256Hex returns the lowercase hex SHA-256 of data; an empty or nil input
// hashes the empty string.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// signCanonical returns the lowercase hex HMAC-SHA256 of canonical under secret.
func signCanonical(secret []byte, canonical string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// canonicalRequestString mirrors RequestSignature::canonicalString byte-for-byte:
// METHOD + "\n" + path + "\n" + sortedQuery + "\n" + bodySha256Hex + "\n" + timestamp + "\n" + nonce
func canonicalRequestString(method, path, sortedQuery, bodySha256Hex, timestamp, nonce string) string {
	return method + "\n" + path + "\n" + sortedQuery + "\n" + bodySha256Hex + "\n" + timestamp + "\n" + nonce
}

// canonicalQuery joins the decoded query parameters as "k=v" pairs with '&',
// sorted by key then value — the exact form of RequestSignature::canonicalQuery.
// A repeated key keeps only its first value, mirroring the daemon's query map.
func canonicalQuery(query map[string]string) string {
	pairs := make([][2]string, 0, len(query))
	for key, value := range query {
		pairs = append(pairs, [2]string{key, value})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i][0] != pairs[j][0] {
			return pairs[i][0] < pairs[j][0]
		}
		return pairs[i][1] < pairs[j][1]
	})
	var b strings.Builder
	for i, pair := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(pair[0])
		b.WriteByte('=')
		b.WriteString(pair[1])
	}
	return b.String()
}

// canonicalQueryValues adapts url.Values to the daemon's first-value-per-key
// query map (decoded values).
func canonicalQueryValues(query url.Values) map[string]string {
	m := make(map[string]string, len(query))
	for key, values := range query {
		if len(values) > 0 {
			m[key] = values[0]
		}
	}
	return m
}

// encodeQueryPercentOnly encodes query like url.Values.Encode but escapes a
// space as %20 instead of '+'. The daemon percent-decodes the query with '+'
// kept literal, so a signed request must never rely on '+'-for-space: the
// daemon-visible decoded values must equal the values the client signed.
func encodeQueryPercentOnly(query url.Values) string {
	if len(query) == 0 {
		return ""
	}
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		encodedKey := strings.ReplaceAll(url.QueryEscape(key), "+", "%20")
		for _, value := range query[key] {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			b.WriteString(encodedKey)
			b.WriteByte('=')
			b.WriteString(strings.ReplaceAll(url.QueryEscape(value), "+", "%20"))
		}
	}
	return b.String()
}

// canonicalSigningPath returns the path the daemon signs: the trailing "/ws"
// of the WSS HTTPS data-channel file routes selects the transfer channel, not
// the signed resource, so it is dropped (the daemon's
// RequestHardening::canonicalFileRoute; docs/source/Security.md, "Request
// replay protection and signatures"). Every other path passes through.
func canonicalSigningPath(path string) string {
	switch path {
	case "/appmesh/file/download/ws":
		return "/appmesh/file/download"
	case "/appmesh/file/upload/ws":
		return "/appmesh/file/upload"
	default:
		return path
	}
}

// sign computes the timestamp and signature header values for one request.
// nonce must be unique per request; the caller owns its generation.
func (s *requestSigner) sign(method, path, sortedQuery, bodySha256Hex, nonce string) (timestamp, signature string) {
	timestamp = strconv.FormatInt(time.Now().Unix(), 10)
	return timestamp, signCanonical(s.secret,
		canonicalRequestString(method, path, sortedQuery, bodySha256Hex, timestamp, nonce))
}

// applyRequestSignature signs a framed TCP/WSS request: the four signature
// headers go into the request header map and the framed uuid serves as the
// nonce. Called after the uuid, headers, query and body are final and before
// the request is serialized, next to applyProcessProof.
func applyRequestSignature(request *Request, signer *requestSigner) {
	if signer == nil {
		return
	}
	// The WSS data-channel "/ws" routes sign the stripped route (the suffix is
	// the channel selector, not the signed resource). Streamed file endpoints
	// sign the empty-string body hash (documented exemption); everything else
	// hashes the raw body bytes.
	signPath := canonicalSigningPath(request.RequestURI)
	bodyHash := sha256Hex(request.Body)
	if emptyBodySignedPaths[signPath] {
		bodyHash = sha256Hex(nil)
	}
	timestamp, signature := signer.sign(request.HTTPMethod, signPath, canonicalQuery(request.Query),
		bodyHash, request.UUID)
	request.Headers[headerRequestKey] = signer.keyID
	request.Headers[headerTimestamp] = timestamp
	request.Headers[headerNonce] = request.UUID
	request.Headers[headerSignature] = signature
}

// signHTTPRequest attaches the four signature headers to a plain HTTP request.
// query carries the decoded parameter values the daemon will see (the caller
// must have encoded the wire query with encodeQueryPercentOnly). The request
// path is taken exactly as sent (still percent-encoded), not decoded — except
// the WSS data-channel "/ws" routes, which sign the route without the trailing
// "/ws" (canonicalSigningPath, mirroring the daemon). The body is consumed to
// compute its hash and replaced with an equivalent reader; streamed file
// endpoints keep their body untouched and sign the empty-string hash instead.
func signHTTPRequest(req *http.Request, query url.Values, signer *requestSigner) error {
	if signer == nil {
		return nil
	}
	signPath := canonicalSigningPath(req.URL.EscapedPath())
	bodyHash := sha256Hex(nil)
	if !emptyBodySignedPaths[signPath] && req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("failed to buffer request body for signing: %w", err)
		}
		bodyHash = sha256Hex(bodyBytes)
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
	}
	nonce := xid.New().String()
	timestamp, signature := signer.sign(req.Method, signPath,
		canonicalQuery(canonicalQueryValues(query)), bodyHash, nonce)
	req.Header.Set(headerRequestKey, signer.keyID)
	req.Header.Set(headerTimestamp, timestamp)
	req.Header.Set(headerNonce, nonce)
	req.Header.Set(headerSignature, signature)
	return nil
}
