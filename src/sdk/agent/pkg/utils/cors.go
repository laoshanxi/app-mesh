package utils

import (
	"net/http"
	"strconv"
	"strings"
)

var globalCORSEnabled = true

func EnableGlobalCORS() {
	globalCORSEnabled = true
}

func DisableGlobalCORS() {
	globalCORSEnabled = false
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
	}
	http.HandleFunc("/api", Cors(customConfig)(yourHandlerFunc))
*/

// allowedHeaders defines the list of allowed headers for CORS
var allowedHeaders = []string{
	"Content-Type",
	"Accept",
	"Origin",
	"User-Agent",
	"DNT",
	"Cache-Control",
	"Authorization",
	"Audience",
	"Auth-Permission",
	"Expire-Seconds",
	"X-Send-File-Socket",
	"X-Recv-File-Socket",
	"X-Target-Host",
	"Username",
	"Totp-Challenge",
	"Totp",
	"New-Password",
	"File-Path",
	"File-Mode",
	"File-User",
	"File-Group",
}

// CORSConfig holds the configuration for CORS
type CORSConfig struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
	ExposedHeaders []string
	MaxAge         int
}

// DefaultCORSConfig provides a default configuration for CORS
var DefaultCORSConfig = CORSConfig{
	AllowedOrigins: []string{"*"},
	AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"},
	AllowedHeaders: allowedHeaders,
	ExposedHeaders: []string{"Exit-Code", "Output-Position", "File-Mode", "File-User", "File-Group", "Content-Type"},
	MaxAge:         86400, // 24 hours
}

// Cors is a middleware that handles CORS for HTTP requests
func Cors(config CORSConfig) func(http.HandlerFunc) http.HandlerFunc {
	if !globalCORSEnabled {
		return func(next http.HandlerFunc) http.HandlerFunc {
			return next
		}
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Set CORS headers
			origin := r.Header.Get("Origin")
			if origin != "" && contains(config.AllowedOrigins, origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			} else if contains(config.AllowedOrigins, "*") {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
			w.Header().Set("Access-Control-Expose-Headers", strings.Join(config.ExposedHeaders, ", "))
			w.Header().Set("Access-Control-Max-Age", strconv.Itoa(config.MaxAge))
			// w.Header().Set("Access-Control-Allow-Credentials", "true")

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// Call the next handler
			next.ServeHTTP(w, r)
		}
	}
}

// contains checks if a string is present in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
