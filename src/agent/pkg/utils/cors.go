package utils

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
)

var globalCORSEnabled = true

func EnableGlobalCORS(enabled bool) {
	globalCORSEnabled = enabled
}

/*
To use this middleware, you can do something like this:
	http.HandleFunc("/api", Cors(corsConfig)(yourHandlerFunc))

With the origins allowed by the allowlist:
	corsConfig := CORSConfig{
		AllowedOrigins: []string{"https://example.com", "https://api.example.com"},
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
		MaxAge:         3600,
		AllowCredentials: true,
	}
	http.HandleFunc("/api", Cors(corsConfig)(yourHandlerFunc))
*/

// allowedHeaders defines the list of allowed headers for CORS preflight
// answers. Agent-internal headers (X-Target-Host forwarding and the pooled
// file-socket proof headers) are deliberately absent: browsers never send
// them, so advertising them would only widen the preflight surface.
var allowedHeaders = []string{
	// Standard Headers
	"Content-Type",
	"Accept",
	"Origin",
	"User-Agent",
	"DNT",
	"Cache-Control",
	"Authorization",
	// File headers
	"X-File-Path",
	"X-File-Mode",
	"X-File-User",
	"X-File-Group",
	"X-File-Overwrite",
}

// CORSConfig holds the configuration for CORS
type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	MaxAge           int
	AllowCredentials bool
	// LiveOrigins replaces the static AllowedOrigins snapshot so a caller holding
	// the allowlist can hot-reload it (daemon PUT /appmesh/config, SIGHUP).
	LiveOrigins *CORSAllowlist
}

// CORSAllowlist is an atomically swappable origin allowlist for Cors.
type CORSAllowlist struct {
	mu      sync.RWMutex
	origins map[string]struct{}
}

// NewCORSAllowlist builds a live allowlist seeded with `origins`.
func NewCORSAllowlist(origins []string) *CORSAllowlist {
	l := &CORSAllowlist{}
	l.Set(origins)
	return l
}

// Set swaps the whole allowlist.
func (l *CORSAllowlist) Set(origins []string) {
	next := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		next[origin] = struct{}{}
	}
	l.mu.Lock()
	l.origins = next
	l.mu.Unlock()
}

// Allowed reports whether `origin` is allowlisted.
func (l *CORSAllowlist) Allowed(origin string) bool {
	l.mu.RLock()
	_, ok := l.origins[origin]
	l.mu.RUnlock()
	return ok
}

// DefaultCORSConfig provides a default configuration for CORS. The origin
// allowlist starts empty, matching the daemon (REST.CorsAllowOrigins): with no
// matching entry no CORS header is ever sent, because the UI is a same-origin
// proxy and needs none.
var DefaultCORSConfig = CORSConfig{
	AllowedOrigins: []string{},
	AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
	AllowedHeaders: allowedHeaders,
	ExposedHeaders: []string{"X-Exit-Code", "X-Output-Position", "X-File-Mode", "X-File-User", "X-File-Group",
		"Content-Type"},
	MaxAge:           86400, // 24 hours
	AllowCredentials: false,
}

// Cors returns a middleware that applies the daemon's CORS semantics to every
// response: opt-in by allowlist, never a wildcard. A request without an Origin
// header (plain API clients) and a request whose Origin is not listed both get
// no CORS headers at all; only a listed Origin is echoed back. A "*" entry in
// the allowlist matches only a literal "*" Origin, which browsers never send,
// so wildcard configurations fail closed.
// The returned middleware is compatible with http.Handler (and thus mux.Router.Use).
func Cors(config CORSConfig) func(http.Handler) http.Handler {
	if !globalCORSEnabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	// Preprocess the allowlist to improve performance
	originsMap := make(map[string]struct{}, len(config.AllowedOrigins))
	for _, origin := range config.AllowedOrigins {
		originsMap[origin] = struct{}{}
	}
	originAllowed := func(origin string) bool {
		if config.LiveOrigins != nil {
			return config.LiveOrigins.Allowed(origin)
		}
		_, ok := originsMap[origin]
		return ok
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Without a matching allowlist entry no CORS header is sent at all;
			// the request simply proceeds like a same-origin one.
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}
			if !originAllowed(origin) {
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("Access-Control-Allow-Origin", origin)
			// Vary on Origin so shared caches never cross-serve origins (Add keeps existing Vary).
			w.Header().Add("Vary", "Origin")
			if config.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			// A preflight is an OPTIONS request that announces the real request
			// with Access-Control-Request-Method; only it gets the 204 answer
			// with the preflight headers. A plain OPTIONS request falls through
			// to the routed handler.
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
				if config.MaxAge > 0 {
					w.Header().Set("Access-Control-Max-Age", strconv.Itoa(config.MaxAge))
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// Actual (non-preflight) cross-origin response: echo the origin and,
			// when configured, expose the non-simple response headers to the
			// browser. Allow-Methods/Allow-Headers/Max-Age are preflight-only.
			if len(config.ExposedHeaders) > 0 {
				w.Header().Set("Access-Control-Expose-Headers", strings.Join(config.ExposedHeaders, ", "))
			}

			// Call the next handler
			next.ServeHTTP(w, r)
		})
	}
}
