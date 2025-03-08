#include <functional>

#include <boost/algorithm/string_regex.hpp>
#include <jwt-cpp/traits/nlohmann-json/defaults.h>

#include "../../common/RestClient.h"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "../ResourceCollection.h"
#include "../security/Security.h"
#include "../security/TokenBlacklist.h"
#include "HttpRequest.h"
#include "RestBase.h"

RestBase::RestBase()
{
}

RestBase::~RestBase()
{
}

nlohmann::json RestBase::convertText2Json(const std::string &msg)
{
    nlohmann::json result;
    result[REST_TEXT_MESSAGE_JSON_KEY] = std::string(msg);
    return result;
}

void RestBase::handle_get(const HttpRequest &message)
{
    handleRest(message, m_restGetFunctions);
}

void RestBase::handle_put(const HttpRequest &message)
{
    handleRest(message, m_restPutFunctions);
}

void RestBase::handle_post(const HttpRequest &message)
{
    handleRest(message, m_restPstFunctions);
}

void RestBase::handle_delete(const HttpRequest &message)
{
    handleRest(message, m_restDelFunctions);
}

void RestBase::handle_options(const HttpRequest &message)
{
    message.reply(web::http::status_codes::OK);
}

void RestBase::handle_head(const HttpRequest &message)
{
    message.reply(web::http::status_codes::OK);
}

void RestBase::handleRest(const HttpRequest &message, const std::map<std::string, std::function<void(const HttpRequest &)>> &restFunctions)
{
    const static char fname[] = "RestHandler::handleRest() ";
    REST_INFO_PRINT;
    std::function<void(const HttpRequest &)> stdFunction;
    const auto path = Utility::stringReplace(message.m_relative_uri, "//", "/");

    if (path == "/" || path.empty())
    {
        static auto body = std::string(REST_ROOT_TEXT_MESSAGE);
        static auto contentType = std::string("text/html; charset=utf-8");
        message.reply(web::http::status_codes::OK, body, contentType);
        return;
    }

    bool findRest = false;
    for (const auto &kvp : restFunctions)
    {
        if (path == kvp.first || boost::regex_match(path, boost::regex(kvp.first)))
        {
            findRest = true;
            stdFunction = kvp.second;
            break;
        }
    }
    if (!findRest)
    {
        message.reply(web::http::status_codes::NotFound, convertText2Json(Utility::stringFormat("Path not found %s:%s", message.m_method.c_str(), path.c_str())));
        return;
    }

    try
    {
        // this is REST handler service, defend XSS attach before enter to REST handler
        const_cast<HttpRequest *>(&message)->m_relative_uri = replaceXssRiskChars(message.m_relative_uri);
        if (message.m_body.length())
        {
            auto body = nlohmann::json::parse(message.m_body);
            if (body.is_string())
            {
                body = nlohmann::json::parse(body.get<std::string>());
            }
            // tranverseJsonTree(body);
            const_cast<HttpRequest *>(&message)->m_body = body.dump();
        }

        stdFunction(message);
    }
    catch (const NotFoundException &e)
    {
        LOG_WAR << fname << web::http::status_codes::NotFound << " : " << e.what();
        message.reply(web::http::status_codes::NotFound, convertText2Json(e.what()));
    }
    catch (const std::underflow_error &e)
    {
        LOG_WAR << fname << "rest " << path << " authentication failed with error: " << e.what();
        message.reply(web::http::status_codes::Unauthorized, convertText2Json(e.what()));
    }
    catch (const std::exception &e)
    {
        // message.dump();
        LOG_WAR << fname << "rest " << path << " failed with error: " << e.what();
        message.reply(web::http::status_codes::BadRequest, convertText2Json(e.what()));
    }
    catch (...)
    {
        // message.dump();
        LOG_WAR << fname << "rest " << path << " failed";
        message.reply(web::http::status_codes::BadRequest, convertText2Json("unknow exception"));
    }
}

void RestBase::bindRestMethod(const web::http::method &method, const std::string &path, std::function<void(const HttpRequest &)> func)
{
    const static char fname[] = "RestHandler::bindRest() ";

    LOG_DBG << fname << "bind " << method << " for " << path;

    // bind to map
    if (method == web::http::methods::GET)
        m_restGetFunctions[path] = std::move(func);
    else if (method == web::http::methods::PUT)
        m_restPutFunctions[path] = std::move(func);
    else if (method == web::http::methods::POST)
        m_restPstFunctions[path] = std::move(func);
    else if (method == web::http::methods::DEL)
        m_restDelFunctions[path] = std::move(func);
    else
        LOG_ERR << fname << method << " not supported.";
}

const std::string RestBase::getJwtToken(const HttpRequest &message)
{
    std::string token;
    if (message.m_headers.count(HTTP_HEADER_JWT_Authorization))
    {
        token = Utility::stdStringTrim(message.m_headers.find(HTTP_HEADER_JWT_Authorization)->second);
        token = Utility::stdStringTrim(token, HTTP_HEADER_JWT_BearerSpace, true, false);
        token = Utility::stdStringTrim(token);
    }
    else
    {
        throw std::underflow_error("No authentication token provided");
    }
    return token;
}

const jwt::decoded_jwt<jwt::traits::nlohmann_json> RestBase::decodeJwtToken(const std::string &token)
{
    return jwt::decode(token);
}

const std::string RestBase::generateJwtToken(const std::string &userName, const std::string &userGroup, const std::string &audience, int timeoutSeconds)
{
    // Input validation
    if (userName.empty())
    {
        throw std::invalid_argument("must provide name to generate token");
    }

    // Validate audience
    std::string targetAudience = audience.empty() ? HTTP_HEADER_JWT_Audience_appmesh : audience;
    if (Configuration::instance()->getJwt()->m_jwtAudience.count(targetAudience) == 0)
    {
        throw std::invalid_argument(Utility::stringFormat("Audience <%s> verification failed", targetAudience.c_str()));
    }

    // Get user permissions and prepare resource access claim
    auto userRoles = Security::instance()->getUserInfo(userName);
    nlohmann::json resourceAccess;
    for (const auto &role : userRoles->getRoles())
    {
        resourceAccess[HTTP_HEADER_JWT_Audience_appmesh][JSON_KEY_USER_roles].push_back(role->getName());
    }

    // Load signing keys (done once due to static variables)
    const static std::string rsPub = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / APPMESH_JWT_RS256_PUBLIC_KEY_FILE).string());
    const static std::string rsPri = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / APPMESH_JWT_RS256_PRIVATE_KEY_FILE).string());
    const static std::string ecPub = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / APPMESH_JWT_ES256_PUBLIC_KEY_FILE).string());
    const static std::string ecPri = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / APPMESH_JWT_ES256_PRIVATE_KEY_FILE).string());

    // Create token with standard claims
    const auto jwt = jwt::create()
                         .set_issuer(Configuration::instance()->getRestJwtIssuer()) // Issuer: identifies token creator
                         .set_subject(userName)                                     // Subject: user ID
                         .set_audience(std::move(targetAudience))                   // Audience: intended recipient
                         .set_issued_at(jwt::date(std::chrono::system_clock::now()))
                         .set_expires_at(jwt::date(std::chrono::system_clock::now() + std::chrono::seconds{timeoutSeconds}))
                         .set_payload_claim("resource_access", jwt::claim(resourceAccess)); // Custom claim for permissions

    // Sign token with appropriate algorithm
    std::string token;
    const auto &algo = Configuration::instance()->getJwt()->m_jwtAlgorithm;
    if (algo == APPMESH_JWT_ALGORITHM_HS256)
    {
        token = jwt.sign(jwt::algorithm::hs256{Configuration::instance()->getJwt()->m_jwtSalt});
    }
    else if (algo == APPMESH_JWT_ALGORITHM_RS256)
    {
        token = jwt.sign(jwt::algorithm::rs256{rsPub, rsPri});
    }
    else if (algo == APPMESH_JWT_ALGORITHM_ES256)
    {
        token = jwt.sign(jwt::algorithm::es256{ecPub, ecPri});
    }
    else
    {
        throw std::invalid_argument("JWT algorithm not supported");
    }

    // Ensure token is not blacklisted
    TOKEN_BLACK_LIST::instance()->tryRemoveFromList(token);

    return token;
}

const std::string RestBase::replaceXssRiskChars(const std::string &source)
{
    static const std::map<std::string, std::string> xssRiskChars =
        {{"<", "&lt;"},
         {">", "&gt;"},
         {"\\(", "&#40;"},
         {"\\)", "&#41;"},
         {"'", "&#39;"},
         {"\"", "&quot;"},
         {"%", "&#37;"}};

    auto result = source;
    if (source.length())
    {
        for (const auto &kvp : xssRiskChars)
        {
            boost::replace_all_regex(result, boost::regex(kvp.first, boost::regex::icase), kvp.second, boost::match_flag_type::match_default);
        }
    }
    return result;
}

void RestBase::tranverseJsonTree(nlohmann::json &val)
{
    if (val.is_array() || val.is_object())
    {
        for (auto &item : val.items())
        {
            tranverseJsonTree(item.value());
        }
    }
    else if (val.is_string())
    {
        // handle string now
        val = std::string(RestBase::replaceXssRiskChars((val.get<std::string>())));
    }
}

const std::tuple<std::string, std::string, std::set<std::string>> RestBase::verifyToken(const std::string &token, const std::string &audience)
{
    const static char fname[] = "RestBase::verifyToken() ";
    LOG_DBG << fname << "Verifying token for audience: " << audience;

    const auto decodedToken = decodeJwtToken(token);

    // Check if we're using OAuth2/Keycloak or internal authentication
    if (Configuration::instance()->getJwt()->getJwtInterface() == JSON_KEY_USER_key_method_oauth2)
    {
        // For OAuth2/Keycloak tokens, delegate to the Keycloak verification method
        return verifyKeycloakToken(
            decodedToken,
            Configuration::instance()->getJwt()->m_jwtKeycloak->m_keycloakUrl,
            Configuration::instance()->getJwt()->m_jwtKeycloak->m_keycloakRealm,
            Configuration::instance()->getJwt()->m_jwtKeycloak->m_keycloakClientId);
    }

    // Internal token validation flow

    // First check if token is blacklisted
    if (TOKEN_BLACK_LIST::instance()->isTokenBlacklisted(token))
    {
        LOG_WAR << fname << "Token is blacklisted";
        throw std::underflow_error("Token has been revoked");
    }

    // Verify subject claim exists (contains username)
    if (!decodedToken.has_subject())
    {
        LOG_WAR << fname << "Token missing subject claim";
        throw std::underflow_error("No user info in token");
    }

    // Extract user information
    const auto userName = decodedToken.get_subject();
    LOG_DBG << fname << "Verifying token for user: " << userName;

    // Get user details from security system
    const auto userObj = Security::instance()->getUserInfo(userName);

    // Check if user account is locked
    if (userObj->locked())
    {
        LOG_WAR << fname << "User account is locked: " << userName;
        throw std::underflow_error(Utility::stringFormat("User <%s> was locked", userName.c_str()));
    }

    // Load crypto keys for verification (done once due to static variables)
    const static std::string rsPub = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / APPMESH_JWT_RS256_PUBLIC_KEY_FILE).string());
    const static std::string rsPri = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / APPMESH_JWT_RS256_PRIVATE_KEY_FILE).string());
    const static std::string ecPub = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / APPMESH_JWT_ES256_PUBLIC_KEY_FILE).string());
    const static std::string ecPri = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / APPMESH_JWT_ES256_PRIVATE_KEY_FILE).string());

    // Verify token signature and claims
    try
    {
        // Set up token verifier with required claims
        auto verifier = jwt::verify()
                            .with_issuer(Configuration::instance()->getRestJwtIssuer())
                            .with_audience(audience)
                            .with_subject(userName);

        // Configure algorithm based on configuration
        const auto &algo = Configuration::instance()->getJwt()->m_jwtAlgorithm;
        if (algo == APPMESH_JWT_ALGORITHM_HS256)
        {
            verifier.allow_algorithm(jwt::algorithm::hs256{Configuration::instance()->getJwt()->m_jwtSalt});
        }
        else if (algo == APPMESH_JWT_ALGORITHM_RS256)
        {
            verifier.allow_algorithm(jwt::algorithm::rs256{rsPub, rsPri});
        }
        else if (algo == APPMESH_JWT_ALGORITHM_ES256)
        {
            verifier.allow_algorithm(jwt::algorithm::es256{ecPub, ecPri});
        }
        else
        {
            LOG_ERR << fname << "Unsupported JWT algorithm: " << algo;
            throw std::underflow_error("JWT algorithm not supported");
        }

        // Perform verification
        verifier.verify(decodedToken);
        LOG_DBG << fname << "Token verified successfully";
    }
    catch (const std::exception &e)
    {
        LOG_WAR << fname << "User <" << userName << "> token verification failed: " << e.what();
        throw std::underflow_error(Utility::stringFormat("Authentication failed: %s", e.what()));
    }

    // Extract roles from resource_access
    std::set<std::string> roles;
    if (decodedToken.has_payload_claim("resource_access"))
    {
        auto resource_access = decodedToken.get_payload_claim("resource_access").to_json();
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

    // Return tuple of username, group, and roles
    return std::make_tuple(userName, userObj->getGroup(), roles);
}

const std::string RestBase::getJwtUserName(const HttpRequest &message)
{
    const auto decodedToken = decodeJwtToken(getJwtToken(message));

    if (Configuration::instance()->getJwt()->getJwtInterface() == JSON_KEY_USER_key_method_oauth2)
    {
        return std::get<0>(this->extractUserInfo(decodedToken));
    }

    if (decodedToken.has_subject())
    {
        // get user info
        return decodedToken.get_subject();
    }
    else
    {
        throw std::invalid_argument("No user name info in token");
    }
}

const std::set<std::string> RestBase::getJwtUserAudience(const HttpRequest &message)
{
    const auto decodedToken = decodeJwtToken(getJwtToken(message));

    if (decodedToken.has_audience())
    {
        return decodedToken.get_audience();
    }
    else
    {
        throw std::invalid_argument("No audience info in token");
    }
}

const std::string RestBase::permissionCheck(const HttpRequest &message, const std::string &permission, const std::string &audience)
{
    const static char fname[] = "RestBase::permissionCheck() ";

    // Extract JWT token from HTTP headers
    const auto token = getJwtToken(message);

    // First verify the token's validity with the specified audience
    const auto tokenValidationResult = verifyToken(token, audience);

    const auto &userName = std::get<0>(tokenValidationResult);
    const auto &groupName = std::get<1>(tokenValidationResult);

    // If specific permission check is required
    if (!permission.empty())
    {
        std::set<std::string> userPermissions;
        if (Configuration::instance()->getJwt()->getJwtInterface() == JSON_KEY_USER_key_method_oauth2)
        {
            // For OAuth2(Keycloak): extract permissions from roles in the token
            const auto &userRoles = std::get<2>(tokenValidationResult);
            // Collect permissions from all roles the user has
            for (const auto &roleName : userRoles)
            {
                const auto roleObj = Security::instance()->getRole(roleName);
                const auto rolePermissions = roleObj->getPermissions();
                userPermissions.insert(rolePermissions.begin(), rolePermissions.end());
            }

            // TODO: on-line permission check follow "Keycloak Authorization API"
            // curl -H "Authorization: Bearer {access_token}" -X POST "http://localhost:8080/auth/realms/appmesh-realm/protocol/openid-connect/token/introspect"
        }
        else
        {
            // For internal auth: get permissions directly from security system
            userPermissions = Security::instance()->getUserPermissions(userName, groupName);
        }

        // Verify user has the required permission
        if (userPermissions.count(permission) == 0)
        {
            LOG_WAR << fname << "Permission denied: '" << permission << "' for user '" << userName << "'";
            throw std::invalid_argument(Utility::stringFormat("Permission denied: user '%s' lacks required permission '%s'", userName.c_str(), permission.c_str()));
        }
    }

    LOG_DBG << fname << "Authentication successful for client: " << message.m_remote_address << ", user: " << userName << ", permission: " << (permission.empty() ? "none" : permission);
    return userName;
}

const std::string RestBase::formatCertificateToPem(const std::string &cert_base64)
{
    std::string cert_pem = "-----BEGIN CERTIFICATE-----\n";
    cert_pem += cert_base64;
    cert_pem += "\n-----END CERTIFICATE-----";
    return cert_pem;
}

const std::string RestBase::extractCertificate(const std::string &keysJson, const std::string &kid)
{
    const static char fname[] = "RestBase::extractCertificate() ";
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
        throw std::runtime_error(Utility::stringFormat("Key ID <%s> not found", kid.c_str()));
    }
    catch (const nlohmann::json::exception &e)
    {
        LOG_ERR << fname << "JSON parsing error: " << e.what();
        throw std::runtime_error(Utility::stringFormat("Failed to parse keys JSON: %s", e.what()));
    }
}

const std::string RestBase::fetchKeycloakPublicKeys(const std::string &keycloakUrl, const std::string &realm, const std::string &kid)
{
    const static char fname[] = "RestBase::fetchKeycloakPublicKeys() ";

    try
    {
        const auto endpoint = "/realms/" + realm + "/protocol/openid-connect/certs";
        LOG_DBG << fname << "Fetching public keys from " << keycloakUrl << endpoint;

        auto response = RestClient::request(keycloakUrl, web::http::methods::GET, endpoint, "", {}, {});
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

const std::tuple<std::string, std::string, std::set<std::string>> RestBase::extractUserInfo(const jwt::decoded_jwt<jwt::traits::nlohmann_json> &decoded)
{
    const static char fname[] = "RestBase::extractUserInfo() ";
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

    LOG_DBG << fname << "User: " << userName << " Group: " << groupName << " Roles: " << roles.size();
    return std::make_tuple(userName, groupName, roles);
}

// Main function to verify a Keycloak token
const std::tuple<std::string, std::string, std::set<std::string>> RestBase::verifyKeycloakToken(
    const jwt::decoded_jwt<jwt::traits::nlohmann_json> &decoded,
    const std::string &keycloakUrl,
    const std::string &realm,
    const std::string &clientId)
{
    const static char fname[] = "RestBase::verifyKeycloakToken() ";

    try
    {
        LOG_DBG << fname << "Verifying token for realm: " << realm;

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
                pem = fetchKeycloakPublicKeys(keycloakUrl, realm, kid);
                keyCache[kid] = pem;
            }
        }

        // Construct issuer URL
        const std::string issuer = keycloakUrl + "/realms/" + realm;

        // Verify the token
        const auto verifier = jwt::verify()
                                  .allow_algorithm(jwt::algorithm::rs256{pem})
                                  .with_audience("account") // use "acount" or client id, depend on "Direct Access Grants"
                                  .with_issuer(issuer);

        verifier.verify(decoded);

        // Additional checks for token expiration
        auto currentTime = std::chrono::system_clock::now();
        auto exp = decoded.get_payload_claim("exp").as_integer();
        auto expTime = std::chrono::system_clock::from_time_t(exp);
        if (currentTime > expTime)
        {
            LOG_WAR << fname << "Token has expired";
            throw std::runtime_error("Token has expired");
        }

        // Success - parse user info from token
        LOG_DBG << fname << "Token verification successful";
        return extractUserInfo(decoded);
    }
    catch (const std::exception &e)
    {
        LOG_WAR << fname << "Token verification failed: " << e.what();
        throw std::runtime_error(Utility::stringFormat("Token verification failed: %s", e.what()));
    }
}
