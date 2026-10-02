package agent

import (
	"net/http"

	"github.com/gorilla/mux"
)

// Byte-identical copy of the daemon relay page (RestHandler.cpp,
// OAUTH_CALLBACK_RELAY_HTML); change both together.
const authRelayHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex">
<title>App Mesh sign-in</title>
</head>
<body>
<p id="message">Completing the sign-in.</p>
<script>
(function () {
  "use strict";
  var fail = function () {
    document.getElementById("message").textContent =
      "The sign-in link is not valid. Start the sign-in again from the App Mesh page.";
  };
  var query = new URLSearchParams(window.location.search);
  var state = query.get("state");
  var code = query.get("code");
  if (!state || !code) {
    fail();
    return;
  }
  var decoded = state.replace(/-/g, "+").replace(/_/g, "/");
  while (decoded.length % 4 !== 0) {
    decoded += "=";
  }
  var payload;
  try {
    payload = JSON.parse(atob(decoded));
  } catch (error) {
    fail();
    return;
  }
  var target;
  try {
    target = new URL(payload && typeof payload.o === "string" ? payload.o : "");
  } catch (error) {
    target = null;
  }
  if (!target || (target.protocol !== "https:" && target.protocol !== "http:") || !target.host) {
    fail();
    return;
  }
  window.location.replace(target.origin + "/oauth/callback" + window.location.search);
})();
</script>
</body>
</html>
`

// The browser lands on /oauth/callback on this entry origin after the
// authorization-code flow. The page is static and needs no server state: it
// hands the unchanged query string to the web UI origin carried in the state
// parameter, and only to the fixed /oauth/callback path on that origin.
// Registered before the catch-all that forwards the rest to the daemon.
func RegisterAuthRelayRoutes(router *mux.Router) {
	router.Path("/oauth/callback").Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(authRelayHTML))
	}))
}
