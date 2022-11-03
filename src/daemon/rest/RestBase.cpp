#include <functional>

#include <boost/algorithm/string_regex.hpp>

#include "../../common/Utility.h"
#include "../../common/jwt-cpp/jwt.h"
#include "../Configuration.h"
#include "../security/Security.h"
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
		message.reply(web::http::status_codes::OK, REST_ROOT_TEXT_MESSAGE);
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
        message.reply(web::http::status_codes::NotFound, convertText2Json(std::string("Path not found: ") + path));
        return;
    }

    try
    {
        // this is REST handler service, defend XSS attach before enter to REST handler
        const_cast<HttpRequest *>(&message)->m_relative_uri = replaceXssRiskChars(message.m_relative_uri);
        if (message.m_body.length())
        {
            auto body = nlohmann::json::parse(message.m_body);
            tranverseJsonTree(body);
            const_cast<HttpRequest *>(&message)->m_body = body.dump();
        }

        stdFunction(message);
    }
    catch (const std::exception &e)
    {
        LOG_WAR << fname << "rest " << path << " failed with error: " << e.what();
        message.reply(web::http::status_codes::BadRequest, convertText2Json(e.what()));
    }
    catch (...)
    {
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
        m_restGetFunctions[path] = func;
    else if (method == web::http::methods::PUT)
        m_restPutFunctions[path] = func;
    else if (method == web::http::methods::POST)
        m_restPstFunctions[path] = func;
    else if (method == web::http::methods::DEL)
        m_restDelFunctions[path] = func;
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

const std::string RestBase::createJwtToken(const std::string &uname, const std::string &userGroup, int timeoutSeconds)
{
    if (uname.empty())
    {
        throw std::invalid_argument("must provide name to generate token");
    }

    // https://thalhammer.it/projects/
    // https://www.cnblogs.com/mantoudev/p/8994341.html
    // 1. Header {"typ": "JWT","alg" : "HS256"}
    // 2. Payload{"iss": "appmesh-auth0","name" : "u-name",}
    // 3. Signature HMACSHA256((base64UrlEncode(header) + "." + base64UrlEncode(payload)), 'secret');
    // creating a token that will expire in one hour
    const auto token = jwt::create()
                           .set_issuer(HTTP_HEADER_JWT_ISSUER)
                           .set_type(HTTP_HEADER_JWT)
                           .set_issued_at(jwt::date(std::chrono::system_clock::now()))
                           .set_expires_at(jwt::date(std::chrono::system_clock::now() + std::chrono::seconds{timeoutSeconds}))
                           .set_payload_claim(HTTP_HEADER_JWT_name, jwt::claim(uname))
                           .set_payload_claim(HTTP_HEADER_JWT_user_group, jwt::claim(userGroup))
                           .sign(jwt::algorithm::hs256{Configuration::instance()->getJwt()->m_jwtSalt});
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

const std::tuple<std::string, std::string> RestBase::verifyToken(const HttpRequest &message)
{
    const auto token = getJwtToken(message);
    const auto decoded_token = jwt::decode(token);
    if (decoded_token.has_payload_claim(HTTP_HEADER_JWT_name))
    {
        // get user info
        const auto userName = decoded_token.get_payload_claim(HTTP_HEADER_JWT_name);
        const auto userObj = Security::instance()->getUserInfo(userName.as_string());
        jwt::claim userGroup;
        if (decoded_token.has_payload_claim(HTTP_HEADER_JWT_user_group))
            userGroup = decoded_token.get_payload_claim(HTTP_HEADER_JWT_user_group);

        // check locked
        if (userObj->locked())
            throw std::invalid_argument(Utility::stringFormat("User <%s> was locked", userName.as_string().c_str()));

        // check user token
        auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::hs256{Configuration::instance()->getJwt()->m_jwtSalt})
                            .with_issuer(HTTP_HEADER_JWT_ISSUER)
                            .with_claim(HTTP_HEADER_JWT_name, userName)
                            .with_claim(HTTP_HEADER_JWT_user_group, userGroup);

        verifier.verify(decoded_token);

        return std::make_tuple(userName.as_string(), userGroup.as_string());
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
    if (decoded_token.has_payload_claim(HTTP_HEADER_JWT_name))
    {
        // get user info
        return decoded_token.get_payload_claim(HTTP_HEADER_JWT_name).as_string();
    }
    else
    {
        throw std::invalid_argument("No user name info in token");
    }
}

bool RestBase::permissionCheck(const HttpRequest &message, const std::string &permission)
{
    const static char fname[] = "RestHandler::permissionCheck() ";

    if (!Configuration::instance()->getJwtEnabled())
    {
        // JWT not enabled
        return true;
    }

    const auto result = verifyToken(message);
    const auto userName = std::get<0>(result);
    const auto groupName = std::get<1>(result);
    // check user role permission
    if (permission.empty() || Security::instance()->getUserPermissions(userName, groupName).count(permission))
    {
        LOG_DBG << fname << "authentication success for remote: " << message.m_remote_address << " with user : " << userName << " and permission : " << permission;
        return true;
    }
    else
    {
        LOG_WAR << fname << "No such permission " << permission << " for user " << userName;
        throw std::invalid_argument(Utility::stringFormat("No permission <%s> for user <%s>", permission.c_str(), userName.c_str()));
    }
}
