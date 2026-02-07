package utils

import (
	"net/http"
	"strconv"
	"strings"
)

var globalCORSEnabled = true

func EnableGlobalCORS(enabled bool) {
	globalCORSEnabled = enabled
}

/*
To use this middleware, you can do something like this:
	http.HandleFunc("/api", Cors(DefaultCORSConfig)(yourHandlerFunc))

Or with custom config:
	customConfig := CORSConfig{
		AllowedOrigins: []string{"https://example.com", "https://api.example.com"},
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
		MaxAge:         3600,
		AllowCredentials: true,
	}
	http.HandleFunc("/api", Cors(customConfig)(yourHandlerFunc))
*/

// allowedHeaders defines the list of allowed headers for CORS
var allowedHeaders = []string{
	// Standard Headers
	"Content-Type",
	"Accept",
	"Origin",
	"User-Agent",
	"DNT",
	"Cache-Control",
	"Authorization",
	// Security headers
	"X-Audience",
	"X-Permission",
	"X-Totp-Code",
	"X-Expire-Seconds",
	"X-Set-Cookie",
	// Proxy header
	"X-Target-Host",
	// File headers
	"X-Send-File-Socket",
	"X-Recv-File-Socket",
	"X-File-Path",
	"X-File-Mode",
	"X-File-User",
	"X-File-Group",
}

// CORSConfig holds the configuration for CORS
type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	MaxAge           int
	AllowCredentials bool
}

// DefaultCORSConfig provides a default configuration for CORS
var DefaultCORSConfig = CORSConfig{
	AllowedOrigins:   []string{"*"},
	AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"},
	AllowedHeaders:   allowedHeaders,
	ExposedHeaders:   []string{"X-Exit-Code", "X-Output-Position", "X-File-Mode", "X-File-User", "X-File-Group", "Content-Type"},
	MaxAge:           86400, // 24 hours
	AllowCredentials: false,
}

// Cors is a middleware that handles CORS for HTTP requests
// Cors returns a middleware compatible with http.Handler (and thus mux.Router.Use).
func Cors(config CORSConfig) func(http.Handler) http.Handler {
	if !globalCORSEnabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	// Preprocess the configuration to improve performance
	allowAllOrigins := false
	originsMap := make(map[string]struct{}, len(config.AllowedOrigins))
	for _, origin := range config.AllowedOrigins {
		if origin == "*" {
			allowAllOrigins = true
			break
		}
		originsMap[origin] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set CORS headers
			origin := r.Header.Get("Origin")
			if origin != "" {
				if allowAllOrigins {
					// When allowing all origins, respond with the actual origin rather than the wildcard
					// This is safer and complies with the standard
					w.Header().Set("Access-Control-Allow-Origin", origin)
				} else if _, exists := originsMap[origin]; exists {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}
			}

			w.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))

			if len(config.ExposedHeaders) > 0 {
				w.Header().Set("Access-Control-Expose-Headers", strings.Join(config.ExposedHeaders, ", "))
			}

			w.Header().Set("Access-Control-Max-Age", strconv.Itoa(config.MaxAge))

			// Only add credentials support when enabled in config
			if config.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// Call the next handler
			next.ServeHTTP(w, r)
		})
	}
}
