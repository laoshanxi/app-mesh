// refresh_token_provider.js
//
// Built-in OAuth2 refresh-token provider for App Mesh SDK clients.
//
// The caller hands the provider an access_token + refresh_token pair (e.g. from
// an earlier `appmesh-cli login`) and the provider keeps the access token fresh:
// it refreshes proactively before expiry and reactively when Engine rejects a
// token with HTTP 401. Implements the duck-typed provider contract documented
// in token_provider.js.

import axios from 'axios';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);
const MIN_REFRESH_MARGIN_MS = 30000;

/**
 * Validate the token endpoint URL: https is always allowed; http is allowed
 * only for loopback hosts (local development and tests).
 * @param {string} tokenUrl - Token endpoint URL
 * @returns {string} The validated URL
 * @throws {TypeError} If the URL is invalid or uses insecure transport
 */
function validateTokenUrl(tokenUrl) {
  let url;
  try {
    url = new URL(tokenUrl);
  } catch (_) {
    throw new TypeError('tokenUrl must be a valid URL');
  }
  if (url.protocol === 'https:') {
    return tokenUrl;
  }
  if (url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname.toLowerCase())) {
    return tokenUrl;
  }
  throw new TypeError('tokenUrl must use https, or http only for loopback hosts (127.0.0.1, localhost, ::1)');
}

/**
 * Token provider that owns an access_token + refresh_token pair and refreshes
 * the access token through the OAuth2 refresh_token grant.
 */
class RefreshTokenProvider {
  /**
   * @param {Object} options
   * @param {string} options.tokenUrl - Token endpoint URL (https, or http on loopback only)
   * @param {string} [options.clientId='appmesh-cli'] - OAuth2 client id sent with the grant
   * @param {string} [options.accessToken] - Current access token
   * @param {string} [options.refreshToken] - Refresh token used to obtain new access tokens
   * @param {number} [options.expiresIn=0] - Access token lifetime in seconds; 0/unknown means refresh only on 401
   * @param {Object} [options.httpClient] - Axios instance override (TLS configuration, tests)
   * @throws {TypeError} If tokenUrl is not https and not a loopback http URL
   */
  constructor({ tokenUrl, clientId = 'appmesh-cli', accessToken, refreshToken, expiresIn = 0, httpClient } = {}) {
    this._tokenUrl = validateTokenUrl(tokenUrl);
    this._clientId = clientId;
    this._accessToken = accessToken || null;
    this._refreshToken = refreshToken || null;
    this._http = httpClient || axios.create({ timeout: 30000 });
    this._inflightRefresh = null;
    this._expiresAtMs = 0;
    this._lifetimeMs = 0;
    this._setExpiry(expiresIn);
  }

  /**
   * Return the current access token, refreshing it first when none is stored
   * or it is inside the expiry margin (max of 30s and 10% of the token
   * lifetime). Concurrent refreshes are serialized through a shared in-flight
   * promise.
   * @returns {Promise<string|null>} The current access token
   * @throws {Error} If the provider holds neither an access token nor a refresh token
   */
  async getAccessToken() {
    if ((this._accessToken === null && this._refreshToken) || this._isExpiringSoon()) {
      await this._refresh();
    }
    if (this._accessToken === null && !this._refreshToken) {
      throw new Error('no access token available: the provider holds no credentials');
    }
    return this._accessToken;
  }

  /** A refresh is possible while a refresh token is stored. */
  canRefresh() {
    return !!this._refreshToken;
  }

  /**
   * Refresh after Engine rejected a token with HTTP 401. If `rejectedToken`
   * does not match the current access token, a racing caller already refreshed
   * and the current token is returned without a new grant.
   * @param {string|null} rejectedToken - The access token Engine rejected
   * @returns {Promise<string|null>} The (possibly refreshed) access token
   */
  async refreshAccessToken(rejectedToken) {
    if (rejectedToken && rejectedToken !== this._accessToken) {
      return this._accessToken;
    }
    await this._refresh();
    return this._accessToken;
  }

  /** Forget both tokens; canRefresh() reports false afterwards. */
  clear() {
    this._accessToken = null;
    this._refreshToken = null;
    this._expiresAtMs = 0;
    this._lifetimeMs = 0;
  }

  _setExpiry(expiresIn) {
    const seconds = Number(expiresIn);
    if (Number.isFinite(seconds) && seconds > 0) {
      this._lifetimeMs = seconds * 1000;
      this._expiresAtMs = Date.now() + this._lifetimeMs;
    } else {
      this._lifetimeMs = 0;
      this._expiresAtMs = 0;
    }
  }

  _isExpiringSoon() {
    if (!this._expiresAtMs || !this._refreshToken) {
      return false;
    }
    const margin = Math.max(MIN_REFRESH_MARGIN_MS, this._lifetimeMs * 0.1);
    return Date.now() >= this._expiresAtMs - margin;
  }

  /**
   * Single-flight refresh: the first caller starts the grant, concurrent
   * callers join the same in-flight promise.
   */
  async _refresh() {
    if (!this._inflightRefresh) {
      this._inflightRefresh = this._performRefresh().finally(() => {
        this._inflightRefresh = null;
      });
    }
    return this._inflightRefresh;
  }

  async _performRefresh() {
    if (!this._refreshToken) {
      throw new Error('cannot refresh: no refresh token available');
    }
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: this._refreshToken,
      client_id: this._clientId
    });

    let response;
    try {
      response = await this._http.post(this._tokenUrl, body.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        validateStatus: () => true
      });
    } catch (error) {
      // Network-level failure: keep the stored tokens so a later call can retry.
      throw new Error(`token refresh request failed: ${error.message || 'unknown error'}`);
    }

    const status = response.status;
    const data = response.data && typeof response.data === 'object' ? response.data : {};
    if (data.error === 'invalid_grant') {
      // The refresh token is dead (revoked, expired, reused): drop both tokens.
      this.clear();
      throw new Error('token refresh rejected by the server (invalid_grant)');
    }
    if (status < 200 || status >= 300 || data.error) {
      throw new Error(`token refresh failed with status ${status}${data.error ? `: ${data.error}` : ''}`);
    }
    if (typeof data.access_token !== 'string' || !data.access_token) {
      throw new Error('token refresh response did not include an access_token');
    }

    this._accessToken = data.access_token;
    // Rotate the refresh token only when the server issues a new one; servers
    // with a reuse interval (e.g. Dex) omit it and the old one stays valid.
    if (typeof data.refresh_token === 'string' && data.refresh_token) {
      this._refreshToken = data.refresh_token;
    }
    this._setExpiry(data.expires_in);
  }
}

export { RefreshTokenProvider };
