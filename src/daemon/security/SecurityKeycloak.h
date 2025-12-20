// src/daemon/security/SecurityKeycloak.h
#pragma once
#include "SecurityJson.h"
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

public:
    // Keycloak
    const std::tuple<std::string, std::string, std::set<std::string>> extractUserInfo(const jwt::decoded_jwt<jwt::traits::nlohmann_json> &decoded);
    const std::tuple<std::string, std::string, std::set<std::string>> verifyKeycloakToken(const jwt::decoded_jwt<jwt::traits::nlohmann_json> &decoded);
    const std::string getKeycloakToken(const std::string &userName, const std::string &password, const std::string &totp, int timeout);
    const nlohmann::json getKeycloakUser(const std::string &accessToken);

private:
    // Keycloak
    const std::string formatCertificateToPem(const std::string &cert_base64);
    const std::string extractCertificate(const std::string &keysJson, const std::string &kid);
    const std::string fetchKeycloakPublicKeys(const std::string &kid);

private:
    std::shared_ptr<JsonKeycloak> m_config;
};