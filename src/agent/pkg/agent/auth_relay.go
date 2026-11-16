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

// authRelayScriptHash pins the page's inline script (SHA-256, base64) in the
// CSP below. It is the hash of the exact 982-byte text node between <script>
// and </script> (leading and trailing newlines included, as the browser hashes
// it) in authRelayHTML — which is byte-identical to the daemon copy
// (OAUTH_CALLBACK_RELAY_HTML in RestHandler.cpp). The daemon side owns the
// value; keep both sides identical when the page changes:
//
//	python3 -c "import hashlib,base64,re;s=open('auth_relay.go','rb').read();\
//	  m=re.search(rb'<script>(.*?)</script>',s,re.S);\
//	  print(base64.b64encode(hashlib.sha256(m.group(1)).digest()).decode())"
const authRelayScriptHash = "WJHBkicVdWDq2OxtXiYCx4BCaK7EV2KyjwBP8/UzM6Q="

// The browser lands on /oauth/callback on this entry origin after the
// authorization-code flow. The page is static and needs no server state: it
// hands the unchanged query string to the web UI origin carried in the state
// parameter, and only to the fixed /oauth/callback path on that origin.
// Registered before the catch all that forwards the rest to the daemon.
func RegisterAuthRelayRoutes(router *mux.Router) {
	router.Path("/oauth/callback").Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// The page is HTML with one inline script: everything else is denied.
		// The script hash lets exactly the relay logic run, so the query string
		// (code/state) can never reach injected content.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'sha256-"+authRelayScriptHash+"'; frame-ancestors 'none'")
		_, _ = w.Write([]byte(authRelayHTML))
	}))
}
