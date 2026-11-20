package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"

	"github.com/laoshanxi/app-mesh/src/agent/pkg/cloud"
	"github.com/laoshanxi/app-mesh/src/agent/pkg/config"
	"github.com/laoshanxi/app-mesh/src/agent/pkg/grafana"
	"github.com/laoshanxi/app-mesh/src/agent/pkg/utils"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

// Constants for REST paths and headers
const (
	RestPathUpload          = "/appmesh/file/upload"
	RestPathDownload        = "/appmesh/file/download"
	HTTPUserAgentHeaderName = "User-Agent"
	UserAgentAppmeshSDK     = "appmesh/sdk"
	UserAgentAppmeshTCP     = "appmesh/sdk/tcp"

	HTTPHeaderKeyXTargetHost      = "X-Target-Host"
	HTTPHeaderKeyAuthorization    = "Authorization"
	HTTPHeaderKeyAppmeshForwarded = "X-AppMesh-Forwarded"
	HTTPHeaderKeyAppmeshRoute     = "X-AppMesh-Forward-Route"
	HTTPHeaderKeyAppmeshProcess   = "X-AppMesh-Process-Key"
	// Marks the bearer-only precheck the daemon exempts from signature enforcement.
	HTTPHeaderKeyAgentPrecheck   = "X-Appmesh-Agent-Precheck"
	HTTPHeaderKeyXSendFileSocket = "X-Send-File-Socket"
	HTTPHeaderKeyXRecvFileSocket = "X-Recv-File-Socket"
	HTTPHeaderKeyFilePath        = "X-File-Path"

	// PermissionHostForward gates X-Target-Host forwarding on the engine; the
	// agent enforces the same grant before it opens the outbound connection.
	PermissionHostForward = "host-forward"

	TCPChunkBlockSize = appmesh.TCPChunkBlockSize
)

func isSubscriptionRequest(r *http.Request) bool {
	return r.URL.Path == "/appmesh/subscribe" || strings.HasSuffix(r.URL.Path, "/subscribe") ||
		r.URL.Query().Get("subscribe_events") != ""
}

func stripInternalClientProof(r *http.Request) {
	r.Header.Del(HTTPHeaderKeyAppmeshProcess)
	r.Header.Del(cloud.HeaderHMAC)
	r.Header.Del(HTTPHeaderKeyAppmeshForwarded)
	r.Header.Del(HTTPHeaderKeyAppmeshRoute)
	query := r.URL.Query()
	if _, supplied := query["process_key"]; supplied {
		query.Del("process_key")
		r.URL.RawQuery = query.Encode()
	}
}

// newForwardPrecheckRequest builds the bearer-only /appmesh/principal/self probe
// gating X-Target-Host forwarding; the precheck marker exempts it from the
// daemon's mandatory signature enforcement.
func newForwardPrecheckRequest(authorization string) *Request {
	request := &Request{appmesh.NewRequest()}
	request.HTTPMethod = http.MethodGet
	request.RequestURI = "/appmesh/principal/self"
	request.ClientAddress = "agent-forward-check"
	request.Headers[HTTPUserAgentHeaderName] = UserAgentAppmeshSDK
	request.Headers[HTTPHeaderKeyAuthorization] = authorization
	request.Headers[HTTPHeaderKeyAgentPrecheck] = "1"
	return request
}

func validateForwardBearer(ctx context.Context, localConn *Connection, authorization string) (*Response, error) {
	return localConn.sendRequestDataWithContext(ctx, newForwardPrecheckRequest(authorization))
}

func writeForwardValidationResponse(w http.ResponseWriter, response *Response) {
	for key, value := range response.Headers {
		w.Header().Set(key, value)
	}
	if response.BodyMsgType != "" {
		w.Header().Set("Content-Type", response.BodyMsgType)
	}
	w.WriteHeader(response.HTTPStatus)
	if len(response.Body) > 0 {
		if _, err := w.Write(response.Body); err != nil {
			logger.Warnf("Failed to write forwarding authentication response: %v", err)
		}
	}
}

// forwardPermissionGranted reads the /appmesh/principal/self validation answer
// and reports whether the principal holds the host-forward permission. The
// outbound connection itself is a capability: without this gate any
// authenticated principal could probe the network through open/closed/timeout
// answers (blind port-scan oracle).
func forwardPermissionGranted(validation *Response) bool {
	var self struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(validation.Body, &self); err != nil {
		return false
	}
	for _, permission := range self.Permissions {
		if permission == PermissionHostForward {
			return true
		}
	}
	return false
}

var (
	logger       = utils.GetLogger()
	localTCPAddr net.Addr // local daemon TCP address, set by ListenAndServeREST
	localWSSAddr string   // local daemon WSS address, set by ListenAndServeREST

	delegateClient     *http.Client
	delegateClientOnce sync.Once
)

// getLocalConnection returns the pooled connection to the local daemon,
// re-establishing it if a read error removed it from the pool.
// TCP is preferred: WSS is used only when the TCP dial fails, and is then reclaimed.
func getLocalConnection() (*Connection, error) {
	if localTCPAddr == nil {
		return nil, fmt.Errorf("local daemon address not initialized")
	}
	conn, err := getOrCreateConnection(localTCPAddr, config.ConfigData.REST.SSL.VerifyServer, false)
	if err == nil {
		reclaimWSSFallback(localWSSAddr)
		return conn, nil
	}
	// A daemon without the TCP port fails every dial: warn once per minute,
	// keep the repeated failures at debug level.
	if last := lastTCPDialWarnNs.Load(); last == 0 || time.Since(time.Unix(0, last)) > time.Minute {
		lastTCPDialWarnNs.Store(time.Now().UnixNano())
		logger.Warnf("TCP connect to local daemon <%s> failed (%v), trying WSS <%s>", localTCPAddr, err, localWSSAddr)
	} else {
		logger.Debugf("TCP connect to local daemon <%s> failed (%v), using WSS <%s>", localTCPAddr, err, localWSSAddr)
	}
	return getOrCreateWSSConnection(localWSSAddr, config.ConfigData.REST.SSL.VerifyServer)
}

// getDelegateClient lazily builds the shared HTTP client for forwarding requests
// (http.Client is concurrency-safe and pools connections, so one instance suffices).
func getDelegateClient() *http.Client {
	delegateClientOnce.Do(func() {
		// Load custom CA if server verification is enabled
		var serverCA *x509.CertPool
		if config.ConfigData.REST.SSL.VerifyServer {
			var err error
			if serverCA, err = appmesh.LoadCA(config.ConfigData.REST.SSL.SSLCAPath); err != nil {
				logger.Warnf("Failed to load delegate CA from %q: %v", config.ConfigData.REST.SSL.SSLCAPath, err)
			}
		}

		delegateClient = &http.Client{
			// No overall/header timeout: the async backend may legitimately delay the
			// response (long-poll, async run/wait, large transfers); only connect is bounded.
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: !config.ConfigData.REST.SSL.VerifyServer,
					RootCAs:            serverCA, // Use the custom CA if available
				},
				DialContext:     (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
				IdleConnTimeout: 90 * time.Second,
			},
		}
	})
	return delegateClient
}

// MonitorConnectionResponse continuously reads messages from a connection and forwards responses
// to their corresponding channels. It handles connection cleanup on errors.
// allowError is retained for API compatibility; read errors only drop the dead
// connection from the pool, and the next request reconnects.
func MonitorConnectionResponse(conn *Connection, allowError bool) {
	// deleteConnection skips unpooled one-shot connections, so close here too
	// (once-guarded) or the in-flight waiter hangs and the fd leaks.
	defer conn.close()
	defer deleteConnection(conn)

	for {
		response, err := readResponseFromConn(conn)
		if err != nil {
			logger.Errorf("Failed to parse response from host %s: %v", conn, err)
			return
		}

		conn.onResponse(response)
	}
}

// watchCorsAllowlist reloads config.yaml when its mtime changes and swaps the
// CORS allowlist, mirroring the daemon's hot reload without an agent restart.
func watchCorsAllowlist(ctx context.Context, allowlist *utils.CORSAllowlist) {
	latestMtime := func() time.Time {
		var latest time.Time
		for _, path := range config.ConfigFileCandidates() {
			if info, err := os.Stat(path); err == nil && info.ModTime().After(latest) {
				latest = info.ModTime()
			}
		}
		return latest
	}
	lastMod := latestMtime()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := latestMtime()
			if !current.After(lastMod) {
				continue
			}
			lastMod = current
			if err := config.Reload(); err != nil {
				logger.Warnf("Config reload for the CORS allowlist failed: %v", err)
				continue
			}
			origins := config.ConfigData.REST.CorsAllowOrigins
			allowlist.Set(origins)
			logger.Infof("CORS allowlist reloaded from config: %d origin(s)", len(origins))
		}
	}
}

// ListenAndServeREST starts the REST API server
func ListenAndServeREST(ctx context.Context) error {
	var listenAddr = config.ConfigData.REST.RESTListenAddress + ":" + strconv.Itoa(config.ConfigData.REST.RESTListenPort)
	var hostPort = config.ConfigData.REST.RESTListenAddress + ":" + strconv.Itoa(config.ConfigData.REST.TCPAPIPort)
	var wssHostPort = config.ConfigData.REST.RESTListenAddress + ":" + strconv.Itoa(config.ConfigData.REST.WebSocketPort)

	hostPort = strings.Replace(hostPort, "0.0.0.0", "127.0.0.1", 1)
	wssHostPort = strings.Replace(wssHostPort, "0.0.0.0", "127.0.0.1", 1)
	connectAddr, err := net.ResolveTCPAddr("tcp", hostPort)
	if err != nil {
		return fmt.Errorf("failed to resolve address %s: %w", hostPort, err)
	}
	localTCPAddr = connectAddr
	localWSSAddr = wssHostPort

	// Eager connect so a misconfigured/unreachable daemon fails at startup.
	localConn, err := getLocalConnection()
	if err != nil {
		return fmt.Errorf("failed to connect to daemon (TCP <%s>, WSS <%s>): %w", connectAddr, wssHostPort, err)
	}
	logger.Infof("Established REST connection to daemon via <%s>", localConn)

	// CORS is opt-in by allowlist, the daemon semantics: with the default empty
	// REST.CorsAllowOrigins no CORS header is sent at all. CorsDisabled is kept
	// as the explicit off switch for older configurations; an empty allowlist
	// already implies the same zero-header behavior.
	corsDisabled := config.ConfigData.REST.CORSDisabled
	utils.EnableGlobalCORS(!corsDisabled)
	corsConfig := utils.DefaultCORSConfig
	corsAllowlist := utils.NewCORSAllowlist(config.ConfigData.REST.CorsAllowOrigins)
	corsConfig.LiveOrigins = corsAllowlist
	logger.Infof("CORS enabled: %v, allowlisted origins: %d", !corsDisabled, len(config.ConfigData.REST.CorsAllowOrigins))

	// HTTP router using gorilla/mux
	router := mux.NewRouter()

	// Every agent response opts out of MIME sniffing. Proxied HTML surfaces
	// (Grafana, docker, the authentication service, the relay page) get no
	// further restriction here: a restrictive default-src would break their UI.
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			next.ServeHTTP(w, r)
		})
	})

	// Apply CORS globally
	if !corsDisabled {
		router.Use(utils.Cors(corsConfig))
		// Follow daemon-side CORS hot reloads (PUT /appmesh/config, SIGHUP): a stale
		// startup snapshot would keep serving the old allowlist until an agent restart.
		go watchCorsAllowlist(ctx, corsAllowlist)
	}

	// Grafana
	grafana.RegisterGrafanaRESTHandler(router)

	// Container lifecycle service (absent when no Docker endpoint exists)
	if err := RegisterContainerRoutes(router); err != nil {
		logger.Infof("Docker container service disabled: %v", err)
	}

	// Static relay page for the browser OAuth callback on this entry origin.
	// Must stay ahead of the catch-all forward to the daemon.
	RegisterAuthRelayRoutes(router)

	// Route only the configured authentication surface. Upstream identity providers
	// stay behind that service and are never routed by the agent.
	authProxy, authPath, err := newAuthReverseProxy()
	if err != nil {
		return err
	}
	if authPath != "" {
		RegisterAuthLogoRoutes(router, authPath)
		router.Path(authPath).Handler(authProxy)
		router.PathPrefix(authPath + "/").Handler(authProxy)
	} else {
		logger.Infof("The OIDC issuer has no path. The authentication service is reached directly at <%s>.",
			config.OIDCData.Issuer)
	}

	// Forward all remaining requests, including static content, to the daemon.
	router.PathPrefix("/").HandlerFunc(HandleAppMeshRequest)

	return StartHTTPSServer(ctx, listenAddr, router)
}

func newAuthReverseProxy() (http.Handler, string, error) {
	issuer, err := url.Parse(config.OIDCData.Issuer)
	if err != nil || (issuer.Scheme != "http" && issuer.Scheme != "https") || issuer.Host == "" ||
		issuer.Hostname() == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.ForceQuery ||
		issuer.Fragment != "" {
		return nil, "", fmt.Errorf("invalid OIDC issuer")
	}
	target, err := url.Parse(config.OIDCData.AccessURL)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" ||
		target.Hostname() == "" || target.User != nil || target.RawQuery != "" || target.ForceQuery ||
		target.Fragment != "" {
		return nil, "", fmt.Errorf("invalid OIDC access URL")
	}
	issuerPath := strings.TrimSuffix(issuer.Path, "/")
	// An issuer without a path uses the target's
	// root: the director below forwards request paths unchanged. Such an issuer
	// cannot be mounted under the agent's "/" catch-all (which serves the local
	// daemon), so callers reach it directly and no sub-path is registered.
	targetPath := strings.TrimSuffix(target.Path, "/")
	proxy := httputil.NewSingleHostReverseProxy(target)
	var authRoots *x509.CertPool
	if config.OIDCData.CAPath != "" {
		authRoots, err = appmesh.LoadCA(config.OIDCData.CAPath)
		if err != nil {
			return nil, "", fmt.Errorf("failed to load the authentication-service CA: %w", err)
		}
	}
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: !config.OIDCData.TLSVerify,
			RootCAs:            authRoots,
		},
		DialContext:     (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		IdleConnTimeout: 90 * time.Second,
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, proxyErr error) {
		logger.Warnf("Authentication-service reverse proxy failed: %v", proxyErr)
		utils.HTTPError(w, "Authentication service is unavailable", http.StatusBadGateway)
	}
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		incomingPath := req.URL.Path
		originalDirector(req)
		suffix := strings.TrimPrefix(incomingPath, issuerPath)
		if suffix != "" && !strings.HasPrefix(suffix, "/") {
			suffix = "/" + suffix
		}
		req.URL.Path = targetPath + suffix
		if req.URL.Path == "" {
			req.URL.Path = "/"
		}
		req.URL.RawPath = ""
		req.Host = target.Host
	}
	return proxy, issuerPath, nil
}

// StartHTTPSServer starts the REST server; plaintext when SSL.SSLEnabled=false.
func StartHTTPSServer(ctx context.Context, restAgentAddr string, router *mux.Router) error {
	if !config.ConfigData.REST.SSL.Enabled() {
		logger.Warnf("<App Mesh Agent> SSL is disabled: serving PLAINTEXT on %s (TLS terminates upstream)", restAgentAddr)
		server := &http.Server{
			Addr:              restAgentAddr,
			Handler:           router,
			ReadHeaderTimeout: 15 * time.Second,
			IdleTimeout:       2 * time.Minute,
			MaxHeaderBytes:    64 << 10,
		}
		return servePlain(ctx, restAgentAddr, server)
	}
	// Load server certificate and key
	serverCA, err := appmesh.LoadCertificatePair(config.ConfigData.REST.SSL.SSLCertificateFile,
		config.ConfigData.REST.SSL.SSLCertificateKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load server certificate and key: %w", err)
	}

	// Client authentication
	clientAuth := tls.NoClientCert
	var clientCA *x509.CertPool
	if config.ConfigData.REST.SSL.VerifyClient {
		clientAuth = tls.RequireAndVerifyClientCert
		clientCA, err = appmesh.LoadCA(config.ConfigData.REST.SSL.SSLCAPath)
		if err != nil {
			return fmt.Errorf("failed to load client CA: %w", err)
		}
	}

	// TLS configuration
	tlsConfig := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		Certificates:     []tls.Certificate{serverCA},
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384}, // Remove P521 for performance
		// CipherSuites only applies to TLS 1.2; TLS 1.3 suites are not configurable in Go.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},

		// Client authentication
		ClientAuth: clientAuth,
		ClientCAs:  clientCA,

		// Server-side session resumption via session tickets (enabled by default).
		SessionTicketsDisabled: false,

		// Enable HTTP/2 and HTTP/1.1
		// NextProtos: []string{"h2", "http/1.1"},
		// NOTE:HTTP/2 protocol requires all headers to be in lowercase
	}

	// HTTP server configuration
	server := &http.Server{
		Addr:      restAgentAddr,
		Handler:   router,
		TLSConfig: tlsConfig,
		// No Read/WriteTimeout: large file transfers must not be capped. Slowloris is
		// bounded by ReadHeaderTimeout, idle keep-alive by IdleTimeout.
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10, // 64 KB (max header size)
	}

	// Start HTTPS server
	return serveTLS(ctx, restAgentAddr, server)
}

// servePlain serves the server without TLS and shuts it down gracefully on ctx cancel.
func servePlain(ctx context.Context, address string, server *http.Server) error {
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", address, err)
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Warnf("Graceful shutdown failed: %v", err)
		}
	}()
	logger.Infof("<App Mesh Agent> Listening on %s", address)
	if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("plain server error: %w", err)
	}
	return nil
}

// serveTLS serves the server over TLS and shuts it down gracefully on ctx cancel.
// (Not named ListenAndServeTLS to avoid the stdlib method's cert-path contract.)
func serveTLS(ctx context.Context, address string, server *http.Server) error {
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", address, err)
	}

	// Gracefully drain in-flight requests when the context is canceled.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Warnf("Graceful shutdown failed: %v", err)
		}
	}()

	logger.Infof("<App Mesh Agent> Listening on %s", address)
	tlsListener := tls.NewListener(ln, server.TLSConfig)
	if err := server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

// HandleAppMeshRequest processes AppMesh requests
func HandleAppMeshRequest(w http.ResponseWriter, r *http.Request) {
	// The App Mesh API serves JSON and files, never active content, so the
	// daemon's lock-down CSP applies with no functional side effects. Proxied
	// surfaces (Grafana, docker, the authentication service) do not pass here
	// and keep only the global nosniff header. Daemon replies overwrite this
	// with their identical value.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

	stripInternalClientProof(r)

	localConn, err := getLocalConnection()
	if err != nil {
		logger.Errorf("Failed to connect to local daemon: %v", err)
		utils.HTTPError(w, "failed to connect to local service", http.StatusBadGateway)
		return
	}
	targetConnection := localConn

	// Handle forward request
	forwardingHost := string(r.Header.Get(HTTPHeaderKeyXTargetHost))
	if forwardingHost != "" {
		r.Header.Del(HTTPHeaderKeyXTargetHost)
		// Forwarding is a capability regardless of target path: a public discovery
		// path must not hand an anonymous caller a port-scan oracle.
		authorization := strings.TrimSpace(r.Header.Get(HTTPHeaderKeyAuthorization))
		if authorization == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="appmesh"`)
			utils.HTTPError(w, "Forwarded requests require bearer authentication", http.StatusUnauthorized)
			return
		}
		validation, validationErr := validateForwardBearer(r.Context(), localConn, authorization)
		if validationErr != nil {
			logger.Errorf("Failed to validate forwarding authentication: %v", validationErr)
			utils.HTTPError(w, "authentication service is unavailable", http.StatusServiceUnavailable)
			return
		}
		if validation.HTTPStatus < http.StatusOK || validation.HTTPStatus >= http.StatusMultipleChoices {
			writeForwardValidationResponse(w, validation)
			return
		}
		if !forwardPermissionGranted(validation) {
			utils.HTTPError(w, "forwarding requires the "+PermissionHostForward+" permission", http.StatusForbidden)
			return
		}
		if isSubscriptionRequest(r) {
			utils.HTTPError(w, "Forwarded subscriptions require TCP or WebSocket", http.StatusMethodNotAllowed)
			return
		}

		logger.Debugf("Forward request to %s", forwardingHost)

		forwardingURL, err := appmesh.ParseURL(forwardingHost)
		if err != nil || (forwardingURL.Scheme != "http" && forwardingURL.Scheme != "https") ||
			forwardingURL.Hostname() == "" || forwardingURL.User != nil ||
			(forwardingURL.Path != "" && forwardingURL.Path != "/") || forwardingURL.RawQuery != "" ||
			forwardingURL.Fragment != "" {
			logger.Errorf("Failed to parse target host %q: %v", forwardingHost, err)
			utils.HTTPError(w, "invalid target host", http.StatusBadRequest)
			return
		}
		r.Header.Set(HTTPHeaderKeyAppmeshForwarded, "1")

		// If no port is provided, use HTTP forwarding
		if forwardingURL.Port() == "" || forwardingURL.Port() == strconv.Itoa(config.ConfigData.REST.RESTListenPort) {
			// Forward with HTTP protocol
			ForwardAppMeshRequest(w, r, forwardingURL)
			return
		} else {
			// Forward with TCP protocol over a pooled connection
			forwardingAddr, resolveErr := net.ResolveTCPAddr("tcp", net.JoinHostPort(forwardingURL.Hostname(),
				forwardingURL.Port()))
			if resolveErr != nil {
				logger.Errorf("Failed to resolve target host %q: %v", forwardingHost, resolveErr)
				utils.HTTPError(w, "invalid target host", http.StatusBadRequest)
				return
			}
			targetConnection, err = getOrCreateConnection(forwardingAddr, config.ConfigData.REST.SSL.VerifyServer, true)
			if err != nil {
				logger.Errorf("Failed to connect TCP to target host %s with error: %v", forwardingHost, err)
				utils.HTTPError(w, "failed to connect to target host", http.StatusBadGateway)
				return
			}
		}
	}

	// A plain HTTP client behind this agent ends its connection with the response,
	// so pushed events can never reach it. The daemon sees only this agent's pooled
	// TCP connection (always "persistent") and would bind subscriptions to it whose
	// event responses are then dropped here. Mirror the daemon's direct-HTTP
	// behavior: reject subscribe endpoints (POST only; DELETE unsubscribes) and
	// drop subscribe_events on app registration.
	if forwardingHost == "" {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/subscribe") {
			utils.HTTPError(w, "Subscribe requires a persistent connection (TCP or WebSocket)", http.StatusMethodNotAllowed)
			return
		}
		query := r.URL.Query()
		if _, supplied := query["subscribe_events"]; supplied {
			query.Del("subscribe_events")
			r.URL.RawQuery = query.Encode()
		}
	}

	request, err := newRequestFromHTTP(r)
	if err != nil {
		utils.HTTPError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	request.Headers[HTTPUserAgentHeaderName] = UserAgentAppmeshSDK
	if targetConnection != localConn {
		request.Headers[HTTPUserAgentHeaderName] = UserAgentAppmeshTCP
		// File download & upload
		switch request.RequestURI {
		case RestPathDownload:
			request.Headers[HTTPHeaderKeyXRecvFileSocket] = "true"
		case RestPathUpload:
			request.Headers[HTTPHeaderKeyXSendFileSocket] = "true"
		}
	} else if request.RequestURI == RestPathDownload || request.RequestURI == RestPathUpload {
		// TOCTOU: the daemon precheck validates the path and pins the file with
		// open-then-verify; re-opening the client-supplied path on this side
		// would race a swapped symlink component and bypass the jail. Route
		// local file transfers through the daemon's socket file channel on a
		// dedicated connection instead, so the bytes come from (download) or
		// land in (upload) the daemon's verified fd. This side then only ever
		// touches its own uuid-named temp file.
		transferConn, dialErr := openLocalFileTransferConnection()
		if dialErr != nil {
			logger.Errorf("Failed to open a file transfer connection to the local daemon: %v", dialErr)
			utils.HTTPError(w, "failed to connect to local service", http.StatusBadGateway)
			return
		}
		defer transferConn.close()
		targetConnection = transferConn
		request.Headers[HTTPUserAgentHeaderName] = UserAgentAppmeshTCP
		switch request.RequestURI {
		case RestPathDownload:
			request.Headers[HTTPHeaderKeyXRecvFileSocket] = "true"
		case RestPathUpload:
			request.Headers[HTTPHeaderKeyXSendFileSocket] = "true"
		}
	}

	resp, sendErr := targetConnection.sendRequestDataWithContext(r.Context(), request)
	if sendErr != nil {
		logger.Errorf("Failed to send request to server with error: %v", sendErr)

		// Only delete remote connections on error, not local connection
		if targetConnection != localConn {
			deleteConnection(targetConnection)
		}

		utils.HTTPError(w, "failed to process request", http.StatusBadGateway)
		return
	}

	// Reply to client
	resp.writeToHTTPResponse(w, r)

	// Handle file upload after response to client
	if resp.TempUploadFilePath != "" {
		defer os.Remove(resp.TempUploadFilePath)
		sendErr = targetConnection.sendFileDataWithContext(r.Context(), resp.TempUploadFilePath)
		if sendErr != nil {
			logger.Errorf("Failed to send file data: %v", sendErr)
			// Only delete connection on file send error
			if targetConnection != localConn {
				deleteConnection(targetConnection)
			}
			// Don't return error to client since response was already sent
		}
	}
}

// ForwardAppMeshRequest forwards the incoming request to another host and copies the response back.
func ForwardAppMeshRequest(w http.ResponseWriter, r *http.Request, forwardingHost *url.URL) {
	// A bare host must not fall back to the scheme default port (443): use the configured REST listen port
	targetHost := forwardingHost.Host
	if forwardingHost.Port() == "" {
		targetHost = net.JoinHostPort(forwardingHost.Hostname(), strconv.Itoa(config.ConfigData.REST.RESTListenPort))
	}
	// Keep the percent-encoded path (RawPath); the target verifies signatures
	// over the encoded bytes the client sent.
	targetURL := &url.URL{
		Scheme:   forwardingHost.Scheme,
		Host:     targetHost,
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
	}
	logger.Debugf("Forwarding request: %s %s", r.Method, targetURL)
	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), r.Body)
	if err != nil {
		logger.Errorf("Failed to create forward request: %v", err)
		utils.HTTPError(w, "failed to create forward request", http.StatusInternalServerError)
		return
	}
	req.Header = r.Header.Clone() // Copy headers from the original request

	// Forward the request to the target server using the shared HTTP client
	resp, err := getDelegateClient().Do(req)
	if err != nil {
		logger.Errorf("Forward request failed with error: %v", err)
		utils.HTTPError(w, "failed to forward request", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close() // Ensure the response body is closed after use

	// Copy response headers from the forwarded response
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Set(key, value)
		}
	}

	// Copy the status code from the forwarded response
	w.WriteHeader(resp.StatusCode)

	// Copy the response body to the original response
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		utils.HTTPError(w, "Failed to copy response body", http.StatusInternalServerError)
	}
}

// decodeFilePathHeader decodes the percent-encoded X-File-Path header into the
// local path. The daemon decodes the same header and authorizes that path; the
// agent forwards the header unchanged and uses the decoded value only for the
// download's display filename, never to open a file (transfers stream through
// the daemon's verified fd). Path semantics apply: a '+' stays literal, and an
// invalid escape keeps the raw value so an unencoded path still works.
func decodeFilePathHeader(value string) string {
	if !strings.Contains(value, "%") {
		return value
	}
	decoded, err := url.PathUnescape(value)
	if err != nil {
		logger.Warnf("Invalid X-File-Path escape in %q, using the raw value: %v", value, err)
		return value
	}
	return decoded
}

// HandleRESTFile processes file upload and download requests
func HandleRESTFile(w http.ResponseWriter, r *http.Request, data *Response) error {
	logger.Debugf("Requesting path: %s", r.URL.Path)

	filePath := decodeFilePathHeader(r.Header.Get(HTTPHeaderKeyFilePath))

	switch {
	case r.Method == http.MethodGet && r.URL.Path == RestPathDownload && data.HTTPStatus == http.StatusOK:
		return HandleDownload(w, r, data, filePath)
	case r.Method == http.MethodPost && r.URL.Path == RestPathUpload && data.HTTPStatus == http.StatusOK:
		return HandleUpload(w, r, data, filePath)
	default:
		return errors.New(string(data.Body))
	}
}

// Rejected upload/download paths that are not plain I/O failures.
var errInvalidFileName = errors.New("file path is not allowed")

// errNoArmedTransfer: the daemon precheck answered OK without arming the
// socket file transfer, so no verified fd backs this transfer. This side never
// falls back to opening the client-supplied path (TOCTOU on a swapped
// component); the request fails closed instead.
var errNoArmedTransfer = errors.New("the service did not arm a verified file transfer")

// HandleDownload processes file download requests. The bytes can only come
// from the daemon-armed temp file — the agent's uuid-named copy of what the
// daemon streamed from its open-then-verify fd — never from a path this side
// re-opens. The client-supplied path survives only as the display filename.
func HandleDownload(w http.ResponseWriter, r *http.Request, data *Response, requestedPath string) error {
	if data.TempDownloadFilePath == "" {
		return errNoArmedTransfer
	}
	defer os.Remove(data.TempDownloadFilePath)

	_, fileName := filepath.Split(requestedPath)
	if fileName == "" || strings.ContainsAny(fileName, "\x00") {
		return errInvalidFileName
	}
	SetDownloadHeaders(w, fileName)

	logger.Debugf("Serving file: %s", fileName)
	http.ServeFile(w, r, data.TempDownloadFilePath)
	logger.Infof("Download file %s finished", requestedPath)
	return nil
}

// HandleUpload processes file upload requests. The client body is staged into
// the agent's uuid-named temp file and streamed to the daemon's verified fd;
// the destination path is opened only by the daemon (open-then-verify), never
// on this side.
func HandleUpload(w http.ResponseWriter, r *http.Request, data *Response, requestedPath string) error {
	if data.TempUploadFilePath == "" {
		return errNoArmedTransfer
	}
	logger.Debugf("Uploading file: %s", requestedPath)

	if err := SaveUploadedFile(w, r, data.TempUploadFilePath); err != nil {
		return fmt.Errorf("save file failed with error: %w", err)
	}

	// File attributes (X-File-Mode/User/Group) ride on the request headers:
	// the daemon applies them when committing its verified destination.
	return nil
}

// SetDownloadHeaders sets the headers for file download responses
func SetDownloadHeaders(w http.ResponseWriter, fileName string) {
	w.Header().Set("Content-Disposition", "attachment; filename="+url.QueryEscape(fileName))
	w.Header().Set("Content-Description", "File Transfer")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Transfer-Encoding", "binary")
	w.Header().Set("Expires", "0")
	w.Header().Set("Cache-Control", "must-revalidate")
	w.Header().Set("Pragma", "public")
}

// SaveUploadedFile saves an uploaded file directly to the specified path without creating temp files.
// It supports both multipart/form-data and direct body uploads.
func SaveUploadedFile(w http.ResponseWriter, r *http.Request, filePath string) error {
	if filePath == "" {
		return errors.New("file path cannot be empty")
	}

	maxFileSize := int64(2) << 30 // 2GB in bytes
	bufferSize := 32 * 1024       // 32KB chunks for buffered copying

	// Create the destination file with proper permissions
	dst, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dst.Close()

	// Limit the size of the incoming request body
	r.Body = http.MaxBytesReader(w, r.Body, maxFileSize)

	var src io.ReadCloser

	if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data") {
		// Handle multipart upload without creating a temp file
		mr, err := r.MultipartReader()
		if err != nil {
			return fmt.Errorf("failed to create multipart reader: %w", err)
		}

		// Find the file part
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				return errors.New("file part not found in multipart form")
			}
			if err != nil {
				return fmt.Errorf("failed to read multipart form: %w", err)
			}

			if part.FormName() == "file" {
				src = part
				break
			}
			part.Close()
		}
	} else {
		// Handle direct body upload
		src = r.Body
	}
	defer src.Close()

	// Use io.CopyBuffer for efficient streaming with a fixed-size buffer
	buf := make([]byte, bufferSize)
	if _, err := io.CopyBuffer(dst, src, buf); err != nil {
		// In case of error, attempt to remove the partially written file
		dst.Close()
		os.Remove(filePath)
		return fmt.Errorf("failed to copy file data: %w", err)
	}

	return nil
}
