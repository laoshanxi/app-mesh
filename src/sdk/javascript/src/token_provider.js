// token_provider.js
//
// Access-token provider contract for App Mesh SDK clients.
//
// Providers own token acquisition and refresh. Engine clients consume only the
// resulting access token and never receive passwords, refresh tokens, or OAuth
// authorization responses.
//
// A provider is duck-typed (no base class required):
//   {
//     async getAccessToken()             -> string|null  // current access token
//     canRefresh()                       -> boolean      // optional, default false
//     async refreshAccessToken(rejected) -> string|null  // called at most once per 401
//     clear()                            -> void         // optional
//   }
//
// `refreshAccessToken(rejectedToken)` is called at most once after Engine rejects
// a provider-managed token with HTTP 401. Implementations should use
// `rejectedToken` to avoid duplicate refreshes when requests race.

/**
 * In-memory provider for a caller-supplied access token. Cannot refresh.
 */
class StaticAccessTokenProvider {
  /**
   * @param {string} token - Non-empty access token
   * @throws {TypeError} If the token is not a non-empty string
   */
  constructor(token) {
    this._token = StaticAccessTokenProvider._validate(token);
  }

  static _validate(token) {
    if (typeof token !== 'string' || !token.trim()) {
      throw new TypeError('bearer token must be a non-empty string');
    }
    return token.trim();
  }

  /** Return the current access token. */
  async getAccessToken() {
    return this._token;
  }

  /** A static token cannot replace a rejected or expiring token. */
  canRefresh() {
    return false;
  }

  /** Forget the in-memory token. */
  clear() {
    this._token = null;
  }
}

export { StaticAccessTokenProvider };
