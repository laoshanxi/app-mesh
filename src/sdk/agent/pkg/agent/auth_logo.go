package agent

import (
	"net/http"

	"github.com/gorilla/mux"
)

// The login page of the authentication service references its logo with an
// issuer-path relative URL (frontend.logoURL in dex.yaml), so the browser
// loads it from the address it reached this agent on. Dex serves no asset, so
// this exact route, registered before the authentication reverse proxy, hands
// the request to the daemon's public /appmesh/logo.svg route, the engine's
// single copy of the asset.
func RegisterAuthLogoRoutes(router *mux.Router, authPath string) {
	router.Path(authPath + "/logo.svg").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/appmesh/logo.svg", http.StatusMovedPermanently)
	}))
}
