// src/daemon/security/SecurityKeycloak.h
#pragma once
#include "SecurityJson.h"
#include "../../common/JwtHelper.h"
#include <jwt-cpp/traits/nlohmann-json/defaults.h>

class SecurityKeycloak : public SecurityJson
{
    struct JsonKeycloak
    {
        static std::shared_ptr<JsonKeycloak> FromJson(const nlohmann::json &jsonObj);
        nlohmann::json AsJson() const;

        std::string m_keycloakUrl;
        std::string m_keycloakRealm;
        std::string m_keycloakClientId;
        std::string m_keycloakClientSecret;
    };

public:
    SecurityKeycloak();
    virtual ~SecurityKeycloak() = default;
    virtual void init() override;
    virtual void save() NOT_APPLICABLE_THROW;

    // Resolve a user profile from Keycloak (admin API) instead of the local JSON store.
    // A locally-defined user still wins (preserves exec-user overrides); otherwise the profile
    // is fetched from Keycloak and cached, so a Keycloak-only identity no longer requires a
    // matching local entry. A genuinely absent user throws NotFound; only an unavailable admin
    // API (no secret / 403 / network) falls back to a name-only user.
    virtual std::shared_ptr<User> getUserInfo(const std::string &userName) override;

public:
    // Keycloak
    const std::tuple<std::string, std::string, std::set<std::string>> extractUserInfo(const jwt::decoded_jwt<jwt::traits::nlohmann_json> &decoded);
    const std::tuple<std::string, std::string, std::set<std::string>> verifyKeycloakToken(const jwt::decoded_jwt<jwt::traits::nlohmann_json> &decoded, const std::string &audience);
    const JwtHelper::TokenResponse getKeycloakToken(const std::string &userName, const std::string &password, const std::string &totp, int timeout);
    const JwtHelper::TokenResponse refreshKeycloakToken(const std::string &refreshToken, int timeout);
    void logoutKeycloak(const std::string &refreshToken);
    const nlohmann::json getKeycloakUser(const std::string &accessToken);

private:
    // Keycloak
    const std::string formatCertificateToPem(const std::string &cert_base64);
    const std::string extractCertificate(const std::string &keysJson, const std::string &kid);
    const std::string fetchKeycloakPublicKeys(const std::string &kid);

    // Admin API: client-credentials token (cached until expiry) and user-profile lookup by name.
    const std::string getAdminAccessToken();
    std::shared_ptr<User> fetchKeycloakUserProfile(const std::string &userName);
    // Internal (UUID) id of m_keycloakClientId, cached per process; "" if not resolvable.
    const std::string resolveClientUuid(const std::map<std::string, std::string> &headers);

private:
    std::shared_ptr<JsonKeycloak> m_config;
};
