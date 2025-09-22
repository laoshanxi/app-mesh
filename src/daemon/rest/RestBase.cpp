#include <functional>

#include <boost/algorithm/string_regex.hpp>

#include "../../common/Utility.h"
#include "../Configuration.h"
#include "../ResourceCollection.h"
#include "../security/Security.h"
#include "../security/SecurityKeycloak.h"
#include "../security/TokenBlacklist.h"
#include "HttpRequest.h"
#include "RestBase.h"

RestBase::RestBase()
{
}

RestBase::~RestBase()
{
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
    const static char fname[] = "RestBase::handleRest() ";
    REST_INFO_PRINT;

    const auto path = Utility::stringReplace(message.m_relative_uri, "//", "/");

    // Root handler
    if (path == "/" || path.empty())
    {
        static std::string body(REST_ROOT_TEXT_MESSAGE);
        static std::string contentType("text/html; charset=utf-8");
        message.reply(web::http::status_codes::OK, body, contentType);
        return;
    }

    // Find matching REST function
    auto it = std::find_if(
        restFunctions.begin(), restFunctions.end(),
        [&](const std::pair<const std::string, std::function<void(const HttpRequest &)>> &kvp)
        {
            return path == kvp.first || boost::regex_match(path, boost::regex(kvp.first));
        });

    if (it == restFunctions.end())
    {
        LOG_WAR << fname << "404 NotFound " << message.m_method << ":" << path;
        message.reply(web::http::status_codes::NotFound, Utility::text2json("Path not found " + message.m_method + ":" + path));
        return;
    }

    // TODO: those exception are well designed for different usage that reflect Client result
    try
    {
        it->second(message);
    }
    catch (const NotFoundException &e)
    {
        LOG_WAR << fname << "404 NotFound " << message.m_method << ":" << path << " - " << e.what();
        message.reply(web::http::status_codes::NotFound, Utility::text2json(e.what()));
    }
    catch (const std::domain_error &e)
    {
        // Security issue: domain_error -> 401
        LOG_WAR << fname << "401 Unauthorized " << message.m_method << ":" << path << " - " << e.what();
        message.reply(web::http::status_codes::Unauthorized, Utility::text2json(e.what()));
    }
    catch (const std::invalid_argument &e)
    {
        // Input issue: invalid_argument -> 400
        LOG_WAR << fname << "400 BadRequest " << message.m_method << ":" << path << " - " << e.what();
        message.reply(web::http::status_codes::BadRequest, Utility::text2json(e.what()));
    }
    catch (const std::runtime_error &e)
    {
        // Logic issue: runtime_error -> 412
        LOG_WAR << fname << "412 RuntimeError " << message.m_method << ":" << path << " - " << e.what();
        message.reply(web::http::status_codes::PreconditionFailed, Utility::text2json(e.what()));
    }
    catch (const std::exception &e)
    {
        // Others: Server issue
        LOG_ERR << fname << "500 InternalServerError " << message.m_method << ":" << path << " - " << e.what();
        message.reply(web::http::status_codes::InternalError, Utility::text2json("Internal server error"));
    }
    catch (...)
    {
        // Others: Server issue
        LOG_ERR << fname << "500 InternalServerError " << message.m_method << ":" << path << " - Unknown exception";
        message.reply(web::http::status_codes::InternalError, Utility::text2json("Unknown exception"));
    }
}

void RestBase::bindRestMethod(const web::http::method &method, const std::string &path, std::function<void(const HttpRequest &)> func)
{
    const static char fname[] = "RestBase::bindRest() ";

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
        throw std::domain_error("No authentication token provided");
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
    static const std::vector<std::pair<boost::regex, std::string>> xssRiskRegexes = {
        {boost::regex("<", boost::regex::icase), "&lt;"},
        {boost::regex(">", boost::regex::icase), "&gt;"},
        {boost::regex("\\(", boost::regex::icase), "&#40;"},
        {boost::regex("\\)", boost::regex::icase), "&#41;"},
        {boost::regex("'", boost::regex::icase), "&#39;"},
        {boost::regex("\"", boost::regex::icase), "&quot;"},
        {boost::regex("%", boost::regex::icase), "&#37;"}};

    auto result = source;
    if (source.length())
    {
        for (const auto &regex_pair : xssRiskRegexes)
        {
            boost::replace_all_regex(result, regex_pair.first, regex_pair.second, boost::match_flag_type::match_default);
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

    // Check if token is blacklisted regardless of authentication method
    if (TOKEN_BLACK_LIST::instance()->isTokenBlacklisted(token))
    {
        LOG_WAR << fname << "Token is blacklisted";
        throw std::domain_error("Token has been revoked");
    }

    const auto decodedToken = decodeJwtToken(token);

    // Check if we're using OAuth2/Keycloak or internal authentication
    if (auto keycloak = dynamic_pointer_cast_if<SecurityKeycloak>(Security::instance()))
    {
        // For OAuth2/Keycloak tokens, delegate to the Keycloak verification method
        return keycloak->verifyKeycloakToken(decodedToken);
    }

    // Verify subject claim exists (contains username)
    if (!decodedToken.has_subject())
    {
        LOG_WAR << fname << "Token missing subject claim";
        throw std::domain_error("No user info in token");
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
        throw std::domain_error(Utility::stringFormat("User <%s> was locked", userName.c_str()));
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
            throw std::domain_error("JWT algorithm not supported");
        }

        // Perform verification
        verifier.verify(decodedToken);
        LOG_DBG << fname << "Token verified successfully";
    }
    catch (const std::exception &e)
    {
        LOG_WAR << fname << "User <" << userName << "> token verification failed: " << e.what();
        throw std::domain_error(Utility::stringFormat("Authentication failed: %s", e.what()));
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

    if (auto keycloak = dynamic_pointer_cast_if<SecurityKeycloak>(Security::instance()))
    {
        return std::get<0>(keycloak->extractUserInfo(decodedToken));
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
        if (auto keycloak = dynamic_pointer_cast_if<SecurityKeycloak>(Security::instance()))
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
