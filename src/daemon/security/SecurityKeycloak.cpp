#include "SecurityKeycloak.h"
#include "../../common/RestClient.h"
#include "../../common/Utility.h"
#include "../Configuration.h"

#include "ConsulConnection.h"
#include <fstream>
#include <iostream>
#include <jwt-cpp/traits/nlohmann-json/defaults.h>
#include <nlohmann/json.hpp>

SecurityKeycloak::SecurityKeycloak()
{
    m_config = std::make_shared<JsonKeycloak>();
}

void SecurityKeycloak::init()
{
    const static char fname[] = "SecurityKeycloak::init() ";

    // TODO: Keycloak integration requires an admin token for user management operations
    // such as retrieving detailed user information via Security::instance()->getUserInfo(ownerStr)
    // Using local JSON user configuration as an interim solution until full integration
    SecurityJson::init();

    const auto securityYamlFile = Utility::getConfigFilePath(APPMESH_OAUTH2_CONFIG_FILE);
    auto jsonObj = Utility::yamlToJson(YAML::LoadFile(securityYamlFile)).at(JSON_KEY_JWT_Keycloak);

    // Accept ENV override
    Configuration::overrideConfigWithEnv(jsonObj);

    m_config->m_keycloakUrl = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_JWT_Keycloak_URL);
    m_config->m_keycloakRealm = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_JWT_Keycloak_Realm);
    m_config->m_keycloakClientId = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_JWT_Keycloak_ClientID);
    m_config->m_keycloakClientSecret = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_JWT_Keycloak_ClientSecret);

    LOG_DBG << fname << "Keycloak URL: " << m_config->m_keycloakUrl;
    LOG_DBG << fname << "Keycloak Realm: " << m_config->m_keycloakRealm;
    LOG_DBG << fname << "Keycloak Client ID: " << m_config->m_keycloakClientId;
    LOG_DBG << fname << "Keycloak Client Secret: " << Utility::maskSecret(m_config->m_keycloakClientSecret);

    if (m_config->m_keycloakUrl.empty())
    {
        throw std::invalid_argument("Keycloak URL is not configured");
    }
}

const std::string SecurityKeycloak::formatCertificateToPem(const std::string &cert_base64)
{
    std::string cert_pem = "-----BEGIN CERTIFICATE-----\n";
    cert_pem += cert_base64;
    cert_pem += "\n-----END CERTIFICATE-----";
    return cert_pem;
}

const std::string SecurityKeycloak::extractCertificate(const std::string &keysJson, const std::string &kid)
{
    const static char fname[] = "SecurityKeycloak::extractCertificate() ";
    try
    {
        nlohmann::json j = nlohmann::json::parse(keysJson);
        for (const auto &key : j["keys"])
        {
            if (key["kid"] == kid)
            {
                return key["x5c"][0];
            }
        }
        LOG_WAR << fname << "Key ID not found: " << kid;
        throw std::invalid_argument(Utility::stringFormat("Key ID <%s> not found", kid.c_str()));
    }
    catch (const nlohmann::json::exception &e)
    {
        LOG_ERR << fname << "JSON parsing error: " << e.what();
        throw std::invalid_argument(Utility::stringFormat("Failed to parse keys JSON: %s", e.what()));
    }
}

const std::string SecurityKeycloak::fetchKeycloakPublicKeys(const std::string &kid)
{
    const static char fname[] = "SecurityKeycloak::fetchKeycloakPublicKeys() ";

    try
    {
        const auto path = "/realms/" + m_config->m_keycloakRealm + "/protocol/openid-connect/certs";
        LOG_DBG << fname << "Fetching public keys from " << m_config->m_keycloakUrl << path;

        auto response = RestClient::request(m_config->m_keycloakUrl, web::http::methods::GET, path, "", {}, {});
        response->raise_for_status();

        // Extract the certificate and convert to PEM format
        const std::string cert_base64 = extractCertificate(response->text, kid);
        const std::string pem = formatCertificateToPem(cert_base64);
        return pem;
    }
    catch (const std::exception &e)
    {
        LOG_ERR << fname << "Failed to fetch Keycloak public keys: " << e.what();
        throw std::runtime_error(Utility::stringFormat("Failed to fetch Keycloak public keys: %s", e.what()));
    }
}

const std::string SecurityKeycloak::getKeycloakToken(const std::string &userName, const std::string &password, const std::string &totp, int timeout)
{
    const static char fname[] = "SecurityKeycloak::getKeycloakToken() ";

    try
    {
        const auto path = "/realms/" + m_config->m_keycloakRealm + "/protocol/openid-connect/token";
        LOG_DBG << fname << "Get user token from " << m_config->m_keycloakUrl << path;

        std::map<std::string, std::string> formData;
        formData["client_id"] = m_config->m_keycloakClientId;
        formData["grant_type"] = "password";
        formData["scope"] = "openid";
        formData["username"] = userName;
        formData["password"] = password;
        if (m_config->m_keycloakClientSecret.length())
            formData["client_secret"] = m_config->m_keycloakClientSecret;
        if (!totp.empty())
            formData["totp"] = totp;
        if (timeout)
            formData["requested_token_lifespan"] = std::to_string(timeout);

        auto response = RestClient::request(m_config->m_keycloakUrl, web::http::methods::POST, path, "", {}, {}, std::move(formData));
        response->raise_for_status();

        // Extract the tokens
        auto result = nlohmann::json::parse(response->text);
        const std::string accessToken = result.at("access_token").get<std::string>();
        const std::string refreshToken = result.at("refresh_token").get<std::string>();
        return accessToken;
    }
    catch (const std::exception &e)
    {
        LOG_ERR << fname << "Failed to fetch Keycloak token: " << e.what();
        throw std::runtime_error(Utility::stringFormat("Failed to fetch Keycloak token: %s", e.what()));
    }
}

const nlohmann::json SecurityKeycloak::getKeycloakUser(const std::string &accessToken)
{
    const static char fname[] = "SecurityKeycloak::getKeycloakUser() ";

    try
    {
        const auto path = "/realms/" + m_config->m_keycloakRealm + "/protocol/openid-connect/userinfo";
        LOG_DBG << fname << "Get user info from " << m_config->m_keycloakUrl << path;

        std::map<std::string, std::string> headers;
        headers["Authorization"] = "Bearer " + accessToken;

        auto response = RestClient::request(m_config->m_keycloakUrl, web::http::methods::GET, path, "", std::move(headers), {});
        response->raise_for_status();

        return nlohmann::json::parse(response->text);
    }
    catch (const std::exception &e)
    {
        LOG_ERR << fname << "Failed to fetch Keycloak user info: " << e.what();
        throw std::runtime_error(Utility::stringFormat("Failed to fetch Keycloak user info: %s", e.what()));
    }
}

const std::tuple<std::string, std::string, std::set<std::string>> SecurityKeycloak::extractUserInfo(const jwt::decoded_jwt<jwt::traits::nlohmann_json> &decoded)
{
    const static char fname[] = "SecurityKeycloak::extractUserInfo() ";
    std::string userName, groupName;
    std::set<std::string> roles;

    // Extract username - could be in different claims depending on Keycloak configuration
    if (decoded.has_payload_claim("preferred_username"))
    {
        userName = decoded.get_payload_claim("preferred_username").as_string();
    }
    else if (decoded.has_payload_claim("username"))
    {
        userName = decoded.get_payload_claim("username").as_string();
    }
    else if (decoded.has_payload_claim("sub"))
    {
        userName = decoded.get_payload_claim("sub").as_string();
    }
    else
    {
        LOG_WAR << fname << "No username found in token";
        throw std::invalid_argument("No username could be extracted from the token");
    }

    // Extract groups - they can be in different claims based on Keycloak configuration
    if (decoded.has_payload_claim("groups"))
    {
        auto groups = decoded.get_payload_claim("groups");
        if (groups.get_type() == jwt::json::type::array && !groups.as_array().empty())
        {
            // Just use the first group for now
            groupName = groups.as_array()[0].get<std::string>();
        }
    }

    // Extract roles from resource_access
    if (decoded.has_payload_claim("resource_access"))
    {
        auto resource_access = decoded.get_payload_claim("resource_access").to_json();
        for (const auto &item : resource_access.items())
        {
            const auto &client_data = item.value();
            if (client_data.contains("roles") && client_data["roles"].is_array())
            {
                for (const auto &role : client_data["roles"])
                {
                    // Add client-prefixed role for better context
                    roles.insert(role.get<std::string>());
                }
            }
        }
    }

    LOG_DBG << fname << "Extracted user info - User: " << userName << ", Group: " << groupName << ", Roles: " << roles.size();
    return std::make_tuple(userName, groupName, roles);
}

// Main function to verify a Keycloak token
const std::tuple<std::string, std::string, std::set<std::string>> SecurityKeycloak::verifyKeycloakToken(
    const jwt::decoded_jwt<jwt::traits::nlohmann_json> &decoded)
{
    const static char fname[] = "SecurityKeycloak::verifyKeycloakToken() ";

    try
    {
        LOG_DBG << fname << "Verifying token for realm: " << m_config->m_keycloakRealm;

        // Get the key ID from the token header
        std::string kid = decoded.get_header_claim("kid").as_string();
        LOG_DBG << fname << "Token key ID: " << kid;

        // Fetch Keycloak public keys
        // Use a static mutex for thread safety and static map to cache keys
        static std::mutex keysLock;
        static std::unordered_map<std::string, std::string> keyCache;

        std::string pem;
        {
            // Thread-safe access to the key cache
            std::lock_guard<std::mutex> lock(keysLock);
            auto it = keyCache.find(kid);
            if (it != keyCache.end())
            {
                LOG_DBG << fname << "Using cached public key for kid: " << kid;
                pem = it->second;
            }
            else
            {
                LOG_DBG << fname << "Fetching new public key for kid: " << kid;
                keyCache.clear();
                pem = fetchKeycloakPublicKeys(kid);
                keyCache[kid] = pem;
            }
        }

        // Construct issuer URL
        std::string issuer = (fs::path(m_config->m_keycloakUrl) / "realms" / m_config->m_keycloakRealm).string();
        issuer = Utility::stringReplace(issuer, "\\", "/"); // fix windows path issue

        // Verify the token
        const auto verifier = jwt::verify()
                                  .allow_algorithm(jwt::algorithm::rs256{pem})
                                  .with_issuer(issuer);

        // Verify client-id; TODO: check aud instead of azp
        if (decoded.has_payload_claim("azp"))
        {
            if (m_config->m_keycloakClientId != decoded.get_payload_claim("azp").as_string())
            {
                throw std::domain_error("JWT 'azp' claim does not match the expected client ID");
            }
        }

        verifier.verify(decoded);

        // Additional checks for token expiration and not-before time
        auto currentTime = std::chrono::system_clock::now();
        auto exp = decoded.get_payload_claim("exp").as_integer();
        auto expTime = std::chrono::system_clock::from_time_t(exp);

        if (currentTime > expTime)
        {
            LOG_WAR << fname << "Token has expired";
            throw std::domain_error("Token has expired");
        }

        // Check if token is not yet valid (if nbf claim exists)
        if (decoded.has_payload_claim("nbf"))
        {
            auto nbf = decoded.get_payload_claim("nbf").as_integer();
            auto nbfTime = std::chrono::system_clock::from_time_t(nbf);
            if (currentTime < nbfTime)
            {
                LOG_WAR << fname << "Token not yet valid";
                throw std::domain_error("Token not yet valid");
            }
        }

        // Success - parse user info from token
        LOG_DBG << fname << "Token verification successful";
        return extractUserInfo(decoded);
    }
    catch (const std::exception &e)
    {
        LOG_WAR << fname << "Token verification failed: " << e.what();
        throw std::domain_error(Utility::stringFormat("Token verification failed: %s", e.what()));
    }
}
