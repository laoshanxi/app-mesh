// src/daemon/security/SecurityKeycloak.cpp
#include "SecurityKeycloak.h"
#include "../../common/JwtHelper.h"
#include "../../common/RestClient.h"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "User.h"

#include <chrono>
#include <cstdlib>
#include <mutex>
#include <unordered_map>
#include <utility>

#include <jwt-cpp/traits/nlohmann-json/defaults.h>
#include <nlohmann/json.hpp>

SecurityKeycloak::SecurityKeycloak()
{
    m_config = std::make_shared<JsonKeycloak>();
}

void SecurityKeycloak::init()
{
    const static char fname[] = "SecurityKeycloak::init() ";

    // Local JSON still backs locally-defined users (a local entry overrides Keycloak in
    // getUserInfo); Keycloak-only identities are now resolved via the admin API in getUserInfo().
    SecurityJson::init();

    const auto securityYamlFile = Utility::getConfigFilePath(APPMESH_OAUTH2_CONFIG_FILE);
    auto jsonObj = Utility::yamlToJson(YAML::LoadFile(securityYamlFile)).at(JSON_KEY_JWT_Keycloak);

    // Accept ENV override
    Configuration::overrideConfigWithEnv(jsonObj);

    m_config->m_keycloakUrl = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_JWT_Keycloak_URL);
    m_config->m_keycloakRealm = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_JWT_Keycloak_Realm);
    m_config->m_keycloakClientId = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_JWT_Keycloak_ClientID);
    m_config->m_keycloakClientSecret = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_JWT_Keycloak_ClientSecret);

    // The generic APPMESH_<Section>_<Key> override splits on '_' and walks from the top config,
    // so it cannot target this nested key whose name also contains '_'. Honor the documented
    // secret env var explicitly so the secret can be injected without committing it to YAML.
    if (const char *secretEnv = ::getenv(ENV_APPMESH_Keycloak_client_secret))
    {
        if (secretEnv[0] != '\0')
            m_config->m_keycloakClientSecret = secretEnv;
    }

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
        throw std::invalid_argument(Utility::stringFormat("Key ID <%s> not found", kid.c_str()));
    }
    catch (const nlohmann::json::exception &e)
    {
        LOG_ERR << fname << "Failed to parse Keycloak keys JSON: " << e.what();
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

const JwtHelper::TokenResponse SecurityKeycloak::getKeycloakToken(const std::string &userName, const std::string &password, const std::string &totp, int timeout)
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

        JwtHelper::TokenResponse tokenResponse;
        if (!JwtHelper::extractTokenResponse(response->text, tokenResponse))
        {
            throw std::runtime_error("Keycloak token response missing access_token");
        }

        return tokenResponse;
    }
    catch (const std::exception &e)
    {
        LOG_ERR << fname << "Failed to fetch Keycloak token: " << e.what();
        throw std::runtime_error(Utility::stringFormat("Failed to fetch Keycloak token: %s", e.what()));
    }
}

const JwtHelper::TokenResponse SecurityKeycloak::refreshKeycloakToken(const std::string &refreshToken, int timeout)
{
    const static char fname[] = "SecurityKeycloak::refreshKeycloakToken() ";

    try
    {
        const auto path = "/realms/" + m_config->m_keycloakRealm + "/protocol/openid-connect/token";
        LOG_DBG << fname << "Refresh user token from " << m_config->m_keycloakUrl << path;

        std::map<std::string, std::string> formData;
        formData["client_id"] = m_config->m_keycloakClientId;
        formData["grant_type"] = "refresh_token";
        formData["refresh_token"] = refreshToken;
        if (m_config->m_keycloakClientSecret.length())
            formData["client_secret"] = m_config->m_keycloakClientSecret;
        if (timeout)
            formData["requested_token_lifespan"] = std::to_string(timeout);

        auto response = RestClient::request(m_config->m_keycloakUrl, web::http::methods::POST, path, "", {}, {}, std::move(formData));
        response->raise_for_status();

        JwtHelper::TokenResponse tokenResponse;
        if (!JwtHelper::extractTokenResponse(response->text, tokenResponse))
        {
            throw std::runtime_error("Keycloak refresh response missing access_token");
        }

        return tokenResponse;
    }
    catch (const std::exception &e)
    {
        LOG_ERR << fname << "Failed to refresh Keycloak token: " << e.what();
        throw std::runtime_error(Utility::stringFormat("Failed to refresh Keycloak token: %s", e.what()));
    }
}

void SecurityKeycloak::logoutKeycloak(const std::string &refreshToken)
{
    const static char fname[] = "SecurityKeycloak::logoutKeycloak() ";

    try
    {
        const auto path = "/realms/" + m_config->m_keycloakRealm + "/protocol/openid-connect/logout";
        LOG_DBG << fname << "Logout user from " << m_config->m_keycloakUrl << path;

        std::map<std::string, std::string> formData;
        formData["client_id"] = m_config->m_keycloakClientId;
        formData["refresh_token"] = refreshToken;
        if (m_config->m_keycloakClientSecret.length())
            formData["client_secret"] = m_config->m_keycloakClientSecret;

        auto response = RestClient::request(m_config->m_keycloakUrl, web::http::methods::POST, path, "", {}, {}, std::move(formData));
        response->raise_for_status();
    }
    catch (const std::exception &e)
    {
        LOG_ERR << fname << "Failed to logout from Keycloak: " << e.what();
        throw std::runtime_error(Utility::stringFormat("Failed to logout from Keycloak: %s", e.what()));
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
        headers["Authorization"] = JwtHelper::buildBearerAuthorization(accessToken);

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

    // Extract roles only from THIS client's resource_access entry.
    // Iterating all clients would mix in roles granted on unrelated clients in the
    // same realm, which could be mapped to local permissions and cause privilege bleed.
    if (decoded.has_payload_claim("resource_access"))
    {
        auto resource_access = decoded.get_payload_claim("resource_access").to_json();
        if (resource_access.contains(m_config->m_keycloakClientId))
        {
            const auto &client_data = resource_access[m_config->m_keycloakClientId];
            if (client_data.contains("roles") && client_data["roles"].is_array())
            {
                for (const auto &role : client_data["roles"])
                {
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
    const jwt::decoded_jwt<jwt::traits::nlohmann_json> &decoded, const std::string &audience)
{
    const static char fname[] = "SecurityKeycloak::verifyKeycloakToken() ";

    try
    {
        LOG_DBG << fname << "Verifying token for realm: " << m_config->m_keycloakRealm;

        // appmesh audience semantics encode a target host (e.g. remote run isolation).
        // A Keycloak access token cannot carry that claim, so any request that asks for a
        // specific non-default audience cannot be honored under OAuth2 - reject explicitly
        // instead of silently passing, which would bypass host-level isolation.
        if (!audience.empty() && audience != HTTP_HEADER_JWT_Audience_appmesh)
        {
            throw std::domain_error(Utility::stringFormat("Audience <%s> isolation is not supported in OAuth2 mode", audience.c_str()));
        }

        // Get the key ID from the token header
        std::string kid = decoded.get_header_claim("kid").as_string();
        LOG_DBG << fname << "Token key ID: " << kid;

        // Fetch Keycloak public keys with a thread-safe, time-bounded cache.
        // Positive entries expire so realm key rotation is eventually picked up; a short
        // negative cache prevents forged/unknown kids from triggering a network fetch on
        // every request (DoS amplification toward the Keycloak server).
        struct KeyEntry
        {
            std::string pem;
            std::chrono::steady_clock::time_point fetchedAt;
        };
        static std::mutex keysLock;
        static std::unordered_map<std::string, KeyEntry> keyCache;
        static std::unordered_map<std::string, std::chrono::steady_clock::time_point> negativeCache;
        const auto POSITIVE_TTL = std::chrono::hours(1);
        const auto NEGATIVE_TTL = std::chrono::seconds(30);

        std::string pem;
        {
            // Thread-safe access to the key cache
            std::lock_guard<std::mutex> lock(keysLock);
            const auto now = std::chrono::steady_clock::now();

            auto neg = negativeCache.find(kid);
            if (neg != negativeCache.end())
            {
                if (now - neg->second < NEGATIVE_TTL)
                {
                    throw std::domain_error(Utility::stringFormat("Key ID <%s> recently failed to resolve", kid.c_str()));
                }
                negativeCache.erase(neg);
            }

            auto it = keyCache.find(kid);
            if (it != keyCache.end() && (now - it->second.fetchedAt) < POSITIVE_TTL)
            {
                LOG_DBG << fname << "Using cached public key for kid: " << kid;
                pem = it->second.pem;
            }
            else
            {
                LOG_DBG << fname << "Fetching new public key for kid: " << kid;
                try
                {
                    pem = fetchKeycloakPublicKeys(kid);
                }
                catch (const std::exception &)
                {
                    negativeCache[kid] = now;
                    throw;
                }
                keyCache[kid] = KeyEntry{pem, now};
            }
        }

        // Construct issuer URL
        std::string issuer = (fs::path(m_config->m_keycloakUrl) / "realms" / m_config->m_keycloakRealm).string();
        issuer = Utility::stringReplace(issuer, "\\", "/"); // fix windows path issue

        // Verify signature, issuer, and (by default) exp/nbf claims.
        // Select the algorithm from the token header but restrict to asymmetric families
        // only (RS/ES/PS). Never accept HS* here: the verification key is a public key, so
        // allowing HMAC would enable the classic "alg confusion" forgery.
        const std::string alg = decoded.get_algorithm();
        auto verifier = jwt::verify().with_issuer(issuer).leeway(JWT_CLOCK_LEEWAY_SECONDS); // tolerate clock skew vs Keycloak
        if (alg == "RS256")
            verifier.allow_algorithm(jwt::algorithm::rs256{pem});
        else if (alg == "RS384")
            verifier.allow_algorithm(jwt::algorithm::rs384{pem});
        else if (alg == "RS512")
            verifier.allow_algorithm(jwt::algorithm::rs512{pem});
        else if (alg == "ES256")
            verifier.allow_algorithm(jwt::algorithm::es256{pem});
        else if (alg == "ES384")
            verifier.allow_algorithm(jwt::algorithm::es384{pem});
        else if (alg == "ES512")
            verifier.allow_algorithm(jwt::algorithm::es512{pem});
        else if (alg == "PS256")
            verifier.allow_algorithm(jwt::algorithm::ps256{pem});
        else if (alg == "PS384")
            verifier.allow_algorithm(jwt::algorithm::ps384{pem});
        else if (alg == "PS512")
            verifier.allow_algorithm(jwt::algorithm::ps512{pem});
        else
            throw std::domain_error(Utility::stringFormat("Unsupported or insecure JWT algorithm: %s", alg.c_str()));
        verifier.verify(decoded);

        // Mandatory client binding: the token must be issued for / target this client.
        // Accept a match in either 'azp' (authorized party) or 'aud' (audience, string or
        // array). A token from another client in the same realm must NOT be accepted.
        bool clientMatched = false;
        if (decoded.has_payload_claim("azp"))
        {
            clientMatched = (m_config->m_keycloakClientId == decoded.get_payload_claim("azp").as_string());
        }
        if (!clientMatched && decoded.has_audience())
        {
            // get_audience() normalizes both the string and array forms into a set
            const auto auds = decoded.get_audience();
            clientMatched = (auds.count(m_config->m_keycloakClientId) > 0);
        }
        if (!clientMatched)
        {
            throw std::domain_error("JWT client binding (azp/aud) does not match the expected client ID");
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

const std::string SecurityKeycloak::getAdminAccessToken()
{
    const static char fname[] = "SecurityKeycloak::getAdminAccessToken() ";

    // Cache the client-credentials token until shortly before it expires.
    static std::mutex tokenLock;
    static std::string cachedToken;
    static std::chrono::steady_clock::time_point expiresAt;
    {
        std::lock_guard<std::mutex> lock(tokenLock);
        if (!cachedToken.empty() && std::chrono::steady_clock::now() < expiresAt)
            return cachedToken;
    }

    if (m_config->m_keycloakClientSecret.empty())
        throw std::runtime_error("Keycloak admin API requires a confidential client secret");

    const auto path = "/realms/" + m_config->m_keycloakRealm + "/protocol/openid-connect/token";
    std::map<std::string, std::string> formData;
    formData["client_id"] = m_config->m_keycloakClientId;
    formData["client_secret"] = m_config->m_keycloakClientSecret;
    formData["grant_type"] = "client_credentials";

    auto response = RestClient::request(m_config->m_keycloakUrl, web::http::methods::POST, path, "", {}, {}, std::move(formData));
    response->raise_for_status();

    JwtHelper::TokenResponse tokenResponse;
    if (!JwtHelper::extractTokenResponse(response->text, tokenResponse))
        throw std::runtime_error("Keycloak admin token response missing access_token");

    // Cache below the real expiry: omitted expires_in => conservative 60s; short-lived token =>
    // half its life so we never serve it past expiry; otherwise refresh 30s early.
    long long ttl;
    if (tokenResponse.expiresIn <= 0)
        ttl = 60;
    else if (tokenResponse.expiresIn > 60)
        ttl = tokenResponse.expiresIn - 30;
    else
        ttl = tokenResponse.expiresIn / 2;
    {
        std::lock_guard<std::mutex> lock(tokenLock);
        cachedToken = tokenResponse.accessToken;
        expiresAt = std::chrono::steady_clock::now() + std::chrono::seconds(ttl);
    }
    LOG_DBG << fname << "obtained Keycloak admin token";
    return tokenResponse.accessToken;
}

std::shared_ptr<User> SecurityKeycloak::fetchKeycloakUserProfile(const std::string &userName)
{
    const static char fname[] = "SecurityKeycloak::fetchKeycloakUserProfile() ";

    std::map<std::string, std::string> headers;
    headers["Authorization"] = JwtHelper::buildBearerAuthorization(getAdminAccessToken());

    // Exact-match lookup by username.
    std::map<std::string, std::string> query;
    query["username"] = userName;
    query["exact"] = "true";
    const auto usersPath = "/admin/realms/" + m_config->m_keycloakRealm + "/users";

    auto response = RestClient::request(m_config->m_keycloakUrl, web::http::methods::GET, usersPath, "", headers, std::move(query));
    response->raise_for_status();

    auto users = nlohmann::json::parse(response->text);
    if (!users.is_array() || users.empty())
        throw NotFoundException(Utility::stringFormat("Keycloak user <%s> not found", userName.c_str()).c_str());
    const auto &kcUser = users.front();
    const auto userId = GET_JSON_STR_VALUE(kcUser, "id");

    // Build a runtime profile: authentication/authorization still come from the verified token,
    // not this object; roles/group here are for display (e.g. the user-self endpoint).
    nlohmann::json userJson = nlohmann::json::object();
    userJson[JSON_KEY_USER_email] = GET_JSON_STR_VALUE(kcUser, "email");

    // Group: best-effort first Keycloak group (leading '/' stripped). Failure is non-fatal.
    try
    {
        if (!userId.empty())
        {
            const auto groupsPath = "/admin/realms/" + m_config->m_keycloakRealm + "/users/" + userId + "/groups";
            auto groupsResp = RestClient::request(m_config->m_keycloakUrl, web::http::methods::GET, groupsPath, "", headers, {});
            groupsResp->raise_for_status();
            auto groups = nlohmann::json::parse(groupsResp->text);
            if (groups.is_array() && !groups.empty())
                userJson[JSON_KEY_USER_group] = Utility::stdStringTrim(GET_JSON_STR_VALUE(groups.front(), "name"), '/', true, false);
        }
    }
    catch (const std::exception &e)
    {
        LOG_WAR << fname << "group lookup failed for <" << userName << ">: " << e.what();
    }

    // Roles: this client's role-mappings for the user (the same permission keys the token carries).
    // Display-only; per-request authorization uses the token's resource_access. Non-fatal.
    try
    {
        const auto clientUuid = resolveClientUuid(headers);
        if (!userId.empty() && !clientUuid.empty())
        {
            const auto rolesPath = "/admin/realms/" + m_config->m_keycloakRealm + "/users/" + userId + "/role-mappings/clients/" + clientUuid;
            auto rolesResp = RestClient::request(m_config->m_keycloakUrl, web::http::methods::GET, rolesPath, "", headers, {});
            rolesResp->raise_for_status();
            auto roles = nlohmann::json::parse(rolesResp->text);
            if (roles.is_array())
            {
                auto roleNames = nlohmann::json::array();
                for (const auto &role : roles)
                {
                    const auto roleName = GET_JSON_STR_VALUE(role, "name");
                    if (!roleName.empty())
                        roleNames.push_back(roleName);
                }
                if (!roleNames.empty())
                    userJson[JSON_KEY_USER_roles] = std::move(roleNames);
            }
        }
    }
    catch (const std::exception &e)
    {
        LOG_WAR << fname << "role lookup failed for <" << userName << ">: " << e.what();
    }

    LOG_DBG << fname << "resolved Keycloak user profile: " << userName;
    return User::FromJson(userName, userJson, m_jsonSecurity->m_roles);
}

const std::string SecurityKeycloak::resolveClientUuid(const std::map<std::string, std::string> &headers)
{
    // The clientId -> internal UUID mapping is stable for a process lifetime; cache it.
    static std::mutex lock;
    static std::string cached;
    {
        std::lock_guard<std::mutex> guard(lock);
        if (!cached.empty())
            return cached;
    }

    std::map<std::string, std::string> query;
    query["clientId"] = m_config->m_keycloakClientId;
    const auto path = "/admin/realms/" + m_config->m_keycloakRealm + "/clients";
    auto response = RestClient::request(m_config->m_keycloakUrl, web::http::methods::GET, path, "", headers, std::move(query));
    response->raise_for_status();

    auto clients = nlohmann::json::parse(response->text);
    if (clients.is_array() && !clients.empty())
    {
        const auto uuid = GET_JSON_STR_VALUE(clients.front(), "id");
        std::lock_guard<std::mutex> guard(lock);
        cached = uuid;
        return uuid;
    }
    return "";
}

std::shared_ptr<User> SecurityKeycloak::getUserInfo(const std::string &userName)
{
    const static char fname[] = "SecurityKeycloak::getUserInfo() ";

    // 1) A locally-defined user wins (preserves admin-configured exec-user / group overrides).
    try
    {
        auto localUser = SecurityJson::getUserInfo(userName);
        if (localUser)
            return localUser;
    }
    catch (const NotFoundException &)
    {
        // not defined locally — resolve from Keycloak below
    }

    // 2) Short-lived cache to avoid an admin round-trip on every lookup.
    static std::mutex cacheLock;
    static std::unordered_map<std::string, std::pair<std::shared_ptr<User>, std::chrono::steady_clock::time_point>> cache;
    const auto CACHE_TTL = std::chrono::minutes(5);
    {
        std::lock_guard<std::mutex> lock(cacheLock);
        auto it = cache.find(userName);
        if (it != cache.end() && (std::chrono::steady_clock::now() - it->second.second) < CACHE_TTL)
            return it->second.first;
    }

    // 3) Resolve from Keycloak. A genuinely absent user propagates as NotFound (callers still get
    // a 404); only an unavailable admin API (no secret / 403 / network) degrades to a name-only
    // profile so an authenticated identity never breaks owner / exec-user resolution.
    std::shared_ptr<User> user;
    try
    {
        user = fetchKeycloakUserProfile(userName);
    }
    catch (const NotFoundException &)
    {
        throw;
    }
    catch (const std::exception &e)
    {
        LOG_WAR << fname << "admin API unavailable for <" << userName << "> (" << e.what() << "); using name-only profile";
        user = std::make_shared<User>(userName);
    }

    {
        std::lock_guard<std::mutex> lock(cacheLock);
        cache[userName] = std::make_pair(user, std::chrono::steady_clock::now());
    }
    return user;
}
