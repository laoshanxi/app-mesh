#include <functional>

#include <boost/algorithm/string_regex.hpp>
#include <jwt-cpp/traits/nlohmann-json/defaults.h>

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
    catch (const std::system_error &e)
    {
        LOG_WAR << fname << "rest " << path << " failed with error code: " << e.code() << ", message: " << e.what();
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
    return token;
}

const std::string RestBase::createJwtToken(const std::string &userName, const std::string &userGroup, const std::string &audience, int timeoutSeconds)
{
    if (userName.empty())
    {
        throw std::invalid_argument("must provide name to generate token");
    }

    std::string targetAudience = audience.empty() ? HTTP_HEADER_JWT_Audience_appmesh : audience;
    if (Configuration::instance()->getJwt()->m_jwtAudience.count(targetAudience) == 0)
    {
        throw std::invalid_argument(Utility::stringFormat("Audience <%s> verification failed", targetAudience.c_str()));
    }

    // https://thalhammer.it/projects/
    const auto token = jwt::create()
                           .set_type(HTTP_HEADER_JWT)
                           .set_issuer(Configuration::instance()->getRestJwtIssuer())  // Issuer: your-app-name
                           .set_subject(userName)                                      // Subject: user identifier
                           .set_audience(targetAudience)                               // Audience: your-api
                           .set_issued_at(jwt::date(std::chrono::system_clock::now())) // Issued at
                           .set_expires_at(jwt::date(std::chrono::system_clock::now() + std::chrono::seconds{timeoutSeconds}))
                           .set_payload_claim(HTTP_HEADER_JWT_user_group, jwt::claim(userGroup))
                           .sign(jwt::algorithm::hs256{Configuration::instance()->getJwt()->m_jwtSalt});
    //  set_id() can be used to set the jti (JWT ID, UUID)  and store in redis with expiration and blacklist
    //  set_audience() can design for multiple services with scope validation:
    /*  JWT Payload Structure:
            const jwtPayload = {
                iss: "https://auth.example.com",    // Token issuer
                sub: "user123",                     // Subject (user)
                aud: ["service1", "service2"],      // Multiple audiences
                iat: Math.floor(Date.now() / 1000), // Issued at
                exp: Math.floor(Date.now() / 1000) + (60 * 60), // Expires in 1 hour
                scope: ["read:service1", "write:service2"],
                claims: {
                    role: "admin",
                    permissions: ["manage_users", "view_reports"]
                }
            };
        JWT Configuration
            const jwtConfig = {
                algorithm: 'RS256',
                keyId: 'key1-Salt',
                issuer: 'https://auth.example.com',
                audience: ['service1', 'service2']
            };
    */
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

const std::tuple<std::string, std::string> RestBase::verifyToken(const HttpRequest &message, const std::string &audience)
{
    const auto token = getJwtToken(message);

    if (TOKEN_BLACK_LIST::instance()->isTokenBlacklisted(token))
        throw std::invalid_argument("token blocked");

    const auto decoded_token = jwt::decode(token);
    if (decoded_token.has_subject())
    {
        // get user info
        const auto userName = decoded_token.get_subject();
        const auto userObj = Security::instance()->getUserInfo(userName);

        // check locked
        if (userObj->locked())
            throw std::invalid_argument(Utility::stringFormat("User <%s> was locked", userName.c_str()));

        // check user token
        try
        {
            const auto verifier = jwt::verify()
                                      .allow_algorithm(jwt::algorithm::hs256{Configuration::instance()->getJwt()->m_jwtSalt})
                                      .with_issuer(Configuration::instance()->getRestJwtIssuer())
                                      .with_audience(audience)
                                      .with_subject(userName)
                                      .with_type(HTTP_HEADER_JWT)
                                      .with_claim(HTTP_HEADER_JWT_user_group, jwt::claim(userObj->getGroup()));

            verifier.verify(decoded_token);
        }
        catch (const std::exception &e)
        {
            LOG_WAR << "User <" << userName << "> verify token failed: " << e.what();
            throw std::runtime_error("Authentication failed");
        }

        return std::make_tuple(userName, userObj->getGroup());
    }
    else
    {
        throw std::invalid_argument("No user info in token");
    }
}

const std::string RestBase::getJwtUserName(const HttpRequest &message)
{
    const auto token = getJwtToken(message);
    const auto decoded_token = jwt::decode(token);
    if (decoded_token.has_subject())
    {
        // get user info
        return decoded_token.get_subject();
    }
    else
    {
        throw std::invalid_argument("No user name info in token");
    }
}

bool RestBase::permissionCheck(const HttpRequest &message, const std::string &permission, const std::string &audience)
{
    const static char fname[] = "RestHandler::permissionCheck() ";

    const auto result = verifyToken(message, audience);
    const auto userName = std::get<0>(result);
    const auto groupName = std::get<1>(result);
    // check user role permission
    if (permission.empty() || Security::instance()->getUserPermissions(userName, groupName).count(permission))
    {
        LOG_DBG << fname << "authentication success for remote: " << message.m_remote_address << " with user: " << userName << " and permission: " << permission;
        return true;
    }
    else
    {
        LOG_WAR << fname << "no such permission " << permission << " for user " << userName;
        throw std::invalid_argument(Utility::stringFormat("no such permission for user <%s>", userName.c_str()));
    }
}
