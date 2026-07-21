// src/sdk/cpp/ClientHttpOAuth.h
#pragma once

#include <functional>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

#include "ClientHttp.h"

/// Authentication failure in the Keycloak OAuth2 flow (derives from std::runtime_error).
class AppMeshAuthError : public std::runtime_error
{
public:
    explicit AppMeshAuthError(const std::string &message) : std::runtime_error(message) {}
};

/// Keycloak connection settings for AppMeshClientOAuth.
struct ClientOAuthConfig
{
    /// Keycloak server URL (e.g. "https://keycloak.example.com/" or legacy ".../auth/").
    std::string authServerUrl;
    /// Keycloak realm name.
    std::string realm;
    /// Keycloak client ID.
    std::string clientId;
    /// Keycloak client secret; empty for public clients.
    std::string clientSecret;
};

/// Callback presenting the device authorization prompt to the user. Receives the
/// device authorization response (RFC 8628 §3.2 keys: user_code, verification_uri,
/// verification_uri_complete, expires_in, interval).
using DeviceAuthPromptHandler = std::function<void(const nlohmann::json &deviceAuth)>;

/// AppMeshClient with Keycloak as the identity provider: tokens are obtained directly
/// from Keycloak and the access token is attached as the Bearer authorization header
/// on every daemon request (the daemon verifies it via its Keycloak security backend).
/// NOTE: Keycloak requests share the process-global RestClient session/SSL
/// configuration with daemon requests (see AppMeshClient class note), so the
/// configured CA must also cover the Keycloak server certificate.
class AppMeshClientOAuth : public AppMeshClient
{
public:
    explicit AppMeshClientOAuth(const ClientOAuthConfig &oauth, const ClientHttpConfig &config = ClientHttpConfig());

    /// Login with username/password via the Direct Access Grant (grant_type=password).
    /// totpCode is sent as-is when non-empty (kept as a string: leading zeros matter).
    /// Stores the full Keycloak token response. Throws AppMeshHttpError on failure.
    /// (Hides AppMeshClient::login: tokenExpire/audience and the TOTP challenge flow
    /// do not apply to Keycloak.)
    void login(const std::string &username, const std::string &password, const std::string &totpCode = "");

    /// Login via the OAuth 2.0 Device Authorization Grant (RFC 8628) for
    /// browserless/input-constrained environments: the user opens
    /// verification_uri_complete (or verification_uri + user_code) on another device
    /// while this call polls the token endpoint until approval, denial, or expiry.
    /// Requires "OAuth 2.0 Device Authorization Grant" enabled on the Keycloak client.
    /// onPrompt defaults to printing the sign-in instructions to stdout.
    /// Throws AppMeshAuthError when the user denies the request, the device code
    /// expires, or the token request fails for any other reason.
    void loginDeviceFlow(DeviceAuthPromptHandler onPrompt = nullptr, const std::string &scope = "openid profile email");

    /// Log out the Keycloak session with the refresh token (best-effort), then log out
    /// of the daemon session and clear the locally stored token.
    /// (Hides AppMeshClient::logout.)
    void logout();

    /// Renew the current token with the Keycloak refresh token. Keycloak ROTATES
    /// refresh tokens, so the complete new token response is stored.
    /// Throws AppMeshAuthError when no refresh token is available or renewal fails.
    /// (Hides AppMeshClient::renewToken: expiry is controlled by Keycloak.)
    void renewToken();

    /// Get Keycloak OIDC userinfo (claims such as sub, preferred_username, email) for
    /// the current access token, directly from Keycloak. Unlike getCurrentUser()
    /// (inherited), the daemon is not involved. Throws AppMeshHttpError on failure.
    nlohmann::json getOauthUserinfo() const;

protected:
    /// Attach the Keycloak access token as the Bearer authorization on daemon requests.
    void addCommonHeaders(std::map<std::string, std::string> &header) const override;

private:
    /// Build the Keycloak OIDC endpoint path: /realms/{realm}/protocol/openid-connect/{name}.
    std::string oauthEndpoint(const std::string &name) const;
    /// POST an x-www-form-urlencoded request (with client credentials added) to a
    /// Keycloak OIDC endpoint; the raw response is returned for caller-side status handling.
    std::shared_ptr<CurlResponse> requestOauth(const std::string &endpoint, std::map<std::string, std::string> formData) const;
    /// Get a string field from the stored token response; empty when absent.
    std::string tokenField(const std::string &key) const;
    /// Extract the OAuth2 "error" code from a Keycloak error response body.
    static std::string oauthErrorCode(const std::string &responseBody);

    ClientOAuthConfig m_oauth;
    nlohmann::json m_token; ///< Full Keycloak token response (access_token, refresh_token, ...)
};
