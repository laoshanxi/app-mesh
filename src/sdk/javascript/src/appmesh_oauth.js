// appmesh_oauth.js - App Mesh client with Keycloak OAuth2 authentication support.
// Mirrors the Python SDK's AppMeshClientOAuth (client_http_oauth.py): tokens are obtained
// directly from Keycloak and the access token is used as the Bearer token for daemon calls.
import axios from "axios";
import AppMeshClient, { AppMeshError } from "./appmesh.js";

// OAuth2 scopes requesting identity claims so userinfo returns preferred_username/email
const DEFAULT_OAUTH_SCOPE = "openid profile email";

/**
 * AppMeshClient with Keycloak as the identity provider.
 *
 * Authentication (login, token renewal, logout, userinfo) is performed directly against
 * Keycloak's OpenID Connect endpoints; the Keycloak access token is then used as this
 * client's token for App Mesh daemon API calls (RBAC is enforced by the daemon).
 */
class AppMeshClientOAuth extends AppMeshClient {
  /**
   * Initialize an App Mesh client with Keycloak support.
   * @param {Object} oauth2 - Keycloak configuration for oauth2 authentication:
   *   - authServerUrl: Keycloak server URL (e.g. "https://keycloak.example.com/auth")
   *   - realm: Keycloak realm
   *   - clientId: Keycloak client ID
   *   - clientSecret: Keycloak client secret (optional, confidential clients only)
   * @param {string} [baseURL] - App Mesh daemon URL (see AppMeshClient)
   * @param {Object|false|null} [sslConfig] - SSL tri-state for the daemon connection (see AppMeshClient)
   */
  constructor(oauth2, baseURL = undefined, sslConfig = null) {
    super(baseURL, sslConfig);

    if (!oauth2 || !oauth2.authServerUrl || !oauth2.realm || !oauth2.clientId) {
      throw new AppMeshError(
        "oauth2 config requires authServerUrl, realm and clientId",
        400,
        null,
        "INVALID_OAUTH_CONFIG",
      );
    }

    /** @type {Object} Keycloak configuration @private */
    this._oauth2 = {
      authServerUrl: String(oauth2.authServerUrl).replace(/\/+$/, ""),
      realm: oauth2.realm,
      clientId: oauth2.clientId,
      clientSecret: oauth2.clientSecret || null,
    };

    /** @type {Object} Complete Keycloak token response (access_token, refresh_token, ...) @private */
    this._oauthToken = {};

    // Dedicated axios instance for Keycloak endpoints (the inherited this._client
    // targets the App Mesh daemon and injects daemon-specific headers/cookies)
    /** @private */
    this._oauthClient = axios.create({
      timeout: 60000,
      validateStatus: () => true,
    });
  }

  /**
   * Build a Keycloak OpenID Connect endpoint URL for the configured realm.
   * @param {string} name - Endpoint name (e.g. "token", "auth/device", "logout", "userinfo")
   * @returns {string} Full endpoint URL
   * @private
   */
  _oauthEndpoint(name) {
    return `${this._oauth2.authServerUrl}/realms/${encodeURIComponent(this._oauth2.realm)}/protocol/openid-connect/${name}`;
  }

  /**
   * POST x-www-form-urlencoded params to a Keycloak endpoint, adding client credentials.
   * @param {string} endpoint - Endpoint name for _oauthEndpoint()
   * @param {Object} params - Form fields (null/undefined values are skipped)
   * @returns {Promise<any>} Raw axios response (any status)
   * @private
   */
  async _oauthPost(endpoint, params) {
    const form = new URLSearchParams();
    form.append("client_id", this._oauth2.clientId);
    if (this._oauth2.clientSecret)
      form.append("client_secret", this._oauth2.clientSecret);
    for (const [key, value] of Object.entries(params)) {
      // Values are appended as-is (strings): TOTP codes keep leading zeros
      if (value !== null && value !== undefined)
        form.append(key, String(value));
    }
    return this._oauthClient.post(this._oauthEndpoint(endpoint), form);
  }

  /**
   * Extract the OAuth2 "error" code from a Keycloak error response body.
   * @param {any} data - Response body
   * @returns {string} OAuth2 error code or ""
   * @private
   */
  static _oauthErrorCode(data) {
    if (typeof data === "string") {
      try {
        data = JSON.parse(data);
      } catch (_) {
        return "";
      }
    }
    return data && typeof data === "object" && typeof data.error === "string"
      ? data.error
      : "";
  }

  /**
   * Store a full Keycloak token response and propagate the access token to the base client.
   * @param {Object} tokenResponse - Complete Keycloak token endpoint response
   * @private
   */
  _storeOauthToken(tokenResponse) {
    this._oauthToken = tokenResponse || {};
    this._handleTokenUpdate(this._oauthToken.access_token || null);
  }

  /**
   * Login with username and password using the OAuth2 Direct Access Grant (Resource
   * Owner Password Credentials) against Keycloak.
   * @param {string} username - The name of the user
   * @param {string} password - The password of the user
   * @param {string} [totpCode] - TOTP code if enabled for the user. Passed verbatim as a
   *   string: leading zeros matter (e.g. "012345")
   * @param {string|number} [tokenExpire] - Ignored by the Keycloak login flow
   * @param {string} [audience] - Ignored by the Keycloak login flow
   * @returns {Promise<void>} Resolves when login succeeds
   * @throws {AppMeshError} If authentication fails
   */
  async login(
    username,
    password,
    totpCode = null,
    tokenExpire = null,
    audience = null,
  ) {
    if (tokenExpire || audience) {
      console.warn(
        "tokenExpire and audience are ignored by the Keycloak login flow",
      );
    }
    if (!username || !password) {
      throw new AppMeshError(
        "Username and password are required",
        400,
        null,
        "INVALID_CREDENTIALS",
      );
    }

    const response = await this._oauthPost("token", {
      grant_type: "password",
      username,
      password,
      scope: DEFAULT_OAUTH_SCOPE,
      // Pass TOTP as-is (string): a numeric conversion would strip leading zeros
      totp: totpCode ? String(totpCode) : null,
    });
    if (response.status !== 200) {
      throw new AppMeshError(
        `Keycloak login failed: ${this._extractErrorMessage(response.data)}`,
        response.status,
        response.data,
        "OAUTH_LOGIN_FAILED",
      );
    }
    this._storeOauthToken(response.data);
  }

  /**
   * Login via the OAuth 2.0 Device Authorization Grant (RFC 8628).
   *
   * For browserless/input-constrained environments: the user opens
   * `verification_uri_complete` (or `verification_uri` + `user_code`) on another device,
   * and this call polls the token endpoint until approval, denial, or expiry.
   *
   * Requires "OAuth 2.0 Device Authorization Grant" enabled on the Keycloak client.
   *
   * @param {Function} [onPrompt] - Callback receiving the device authorization response
   *   (keys per RFC 8628 §3.2: `user_code`, `verification_uri`, `verification_uri_complete`,
   *   `expires_in`, `interval`) to present the instructions to the user. Defaults to
   *   printing them to the console.
   * @param {string} [scope] - OAuth2 scopes to request
   * @returns {Promise<void>} Resolves once the user approved the request
   * @throws {AppMeshError} When the user denies the request, the device code expires,
   *   or the token request fails for any other reason
   */
  async login_device_flow(onPrompt = null, scope = DEFAULT_OAUTH_SCOPE) {
    const deviceResponse = await this._oauthPost("auth/device", { scope });
    if (deviceResponse.status !== 200) {
      throw new AppMeshError(
        `Device authorization request failed: ${this._extractErrorMessage(deviceResponse.data)}`,
        deviceResponse.status,
        deviceResponse.data,
        "OAUTH_DEVICE_FLOW_FAILED",
      );
    }
    const device = deviceResponse.data;

    if (onPrompt) {
      onPrompt(device);
    } else {
      const uri = device.verification_uri_complete || device.verification_uri;
      console.log(
        `To sign in, open ${uri} and enter code: ${device.user_code}`,
      );
    }

    // RFC 8628 §3.5: poll no faster than "interval", stop once the device code expires
    let interval = parseInt(device.interval, 10) || 5;
    const deadline =
      Date.now() + (parseInt(device.expires_in, 10) || 600) * 1000;

    for (;;) {
      const remaining = (deadline - Date.now()) / 1000;
      if (remaining <= 0) {
        throw new AppMeshError(
          "Device authorization expired before the user approved the request",
          null,
          null,
          "OAUTH_DEVICE_FLOW_EXPIRED",
        );
      }
      await this._sleep(Math.min(interval, remaining));

      const response = await this._oauthPost("token", {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: device.device_code,
      });
      if (response.status === 200) {
        this._storeOauthToken(response.data);
        return;
      }
      const error = AppMeshClientOAuth._oauthErrorCode(response.data);
      if (error === "authorization_pending") {
        continue;
      }
      if (error === "slow_down") {
        interval += 5; // RFC 8628 §3.5: back off by 5 seconds
        continue;
      }
      throw new AppMeshError(
        `Device authorization failed: ${error || this._extractErrorMessage(response.data)}`,
        response.status,
        response.data,
        "OAUTH_DEVICE_FLOW_FAILED",
      );
    }
  }

  /**
   * Sleep helper used by the device-flow polling loop.
   * @param {number} seconds - Duration in seconds
   * @returns {Promise<void>}
   * @protected
   */
  _sleep(seconds) {
    return new Promise((resolve) => setTimeout(resolve, seconds * 1000));
  }

  /**
   * Renew the current Keycloak token using the refresh token.
   * Keycloak rotates the refresh token: the complete new token response is stored.
   * @param {string|number} [tokenExpire] - Ignored by the Keycloak refresh flow
   * @returns {Promise<void>}
   * @throws {AppMeshError} If no refresh token is available or the renewal fails
   */
  async renew_token(tokenExpire = null) {
    // eslint-disable-line no-unused-vars
    const refreshToken = this._oauthToken && this._oauthToken.refresh_token;
    if (!refreshToken) {
      throw new AppMeshError(
        "No Keycloak refresh token available to renew",
        null,
        null,
        "OAUTH_NO_REFRESH_TOKEN",
      );
    }

    const response = await this._oauthPost("token", {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    });
    if (response.status !== 200) {
      throw new AppMeshError(
        `Keycloak token renewal failed: ${this._extractErrorMessage(response.data)}`,
        response.status,
        response.data,
        "OAUTH_RENEW_FAILED",
      );
    }
    // Keycloak rotates refresh tokens: replace the whole stored token response
    this._storeOauthToken(response.data);
  }

  /**
   * Log out of the current session from Keycloak and the App Mesh daemon.
   * The daemon logoff (super.logout) runs BEFORE the local token is cleared so it can
   * still authenticate; the Keycloak session is revoked via the refresh token.
   * @returns {Promise<boolean>} true when the Keycloak session was revoked
   */
  async logout() {
    let result = false;
    const refreshToken = this._oauthToken && this._oauthToken.refresh_token;
    if (refreshToken) {
      try {
        const response = await this._oauthPost("logout", {
          refresh_token: refreshToken,
        });
        if (response.status >= 200 && response.status < 300) {
          result = true;
        } else {
          console.warn(
            `Failed to logout from Keycloak: ${this._extractErrorMessage(response.data)}`,
          );
        }
      } catch (error) {
        console.warn(`Failed to logout from Keycloak: ${error.message}`);
      }
    }

    // Daemon-side logoff before clearing the local token (it still needs the token)
    await super.logout();
    this._oauthToken = {};

    return result;
  }

  /**
   * Get Keycloak OIDC userinfo for the current access token, directly from Keycloak.
   * Unlike get_current_user() (inherited), which asks the App Mesh daemon
   * /appmesh/user/self, this queries the Keycloak userinfo endpoint without the daemon.
   * @returns {Promise<Object>} Keycloak userinfo (OIDC claims such as `sub`,
   *   `preferred_username`, `email`)
   * @throws {AppMeshError} If no access token is available or the request fails
   */
  async get_oauth_userinfo() {
    const accessToken = this._oauthToken && this._oauthToken.access_token;
    if (!accessToken) {
      throw new AppMeshError(
        "No Keycloak access token available",
        null,
        null,
        "OAUTH_NO_ACCESS_TOKEN",
      );
    }
    const response = await this._oauthClient.get(
      this._oauthEndpoint("userinfo"),
      {
        headers: { Authorization: `Bearer ${accessToken}` },
      },
    );
    if (response.status !== 200) {
      throw new AppMeshError(
        `Keycloak userinfo request failed: ${this._extractErrorMessage(response.data)}`,
        response.status,
        response.data,
        "OAUTH_USERINFO_FAILED",
      );
    }
    return response.data;
  }
}

export { AppMeshClientOAuth };
export default AppMeshClientOAuth;
