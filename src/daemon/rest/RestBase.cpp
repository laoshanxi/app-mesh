// src/daemon/rest/RestBase.cpp
#include <functional>

#include <boost/algorithm/string_regex.hpp>

#include "../../common/Utility.h"
#include "../Configuration.h"
#include "../security/JwtToken.h"
#include "../security/Security.h"
#include "../security/SecurityKeycloak.h"
#include "HttpRequest.h"
#include "RestBase.h"

RestBase::RestBase()
{
}

RestBase::~RestBase()
{
}

void RestBase::handle_get(const std::shared_ptr<HttpRequest> &message)
{
    handleRest(message, m_restGetFunctions);
}

void RestBase::handle_put(const std::shared_ptr<HttpRequest> &message)
{
    handleRest(message, m_restPutFunctions);
}

void RestBase::handle_post(const std::shared_ptr<HttpRequest> &message)
{
    handleRest(message, m_restPstFunctions);
}

void RestBase::handle_delete(const std::shared_ptr<HttpRequest> &message)
{
    handleRest(message, m_restDelFunctions);
}

void RestBase::handle_options(const std::shared_ptr<HttpRequest> &message)
{
    message->reply(web::http::status_codes::OK);
}

void RestBase::handle_head(const std::shared_ptr<HttpRequest> &message)
{
    message->reply(web::http::status_codes::OK);
}

void RestBase::handleRest(const std::shared_ptr<HttpRequest> &message, const std::map<std::string, std::function<void(const std::shared_ptr<HttpRequest> &)>> &restFunctions)
{
    const static char fname[] = "RestBase::handleRest() ";
    REST_INFO_PRINT;

    const auto path = Utility::stringReplace(message->m_relative_uri, "//", "/");

    // Find matching REST function
    auto it = std::find_if(
        restFunctions.begin(), restFunctions.end(),
        [&](const std::pair<const std::string, std::function<void(const std::shared_ptr<HttpRequest> &)>> &kvp)
        {
            return path == kvp.first || boost::regex_match(path, boost::regex(kvp.first));
        });

    if (it == restFunctions.end())
    {
        if (message->m_method == web::http::methods::OPTIONS)
        {
            LOG_DBG << fname << "204 NoContent " << message->m_method << ":" << path;
            message->reply(web::http::status_codes::NoContent);
            return;
        }
        LOG_WAR << fname << "404 NotFound " << message->m_method << ":" << path;
        message->reply(web::http::status_codes::NotFound, Utility::text2json("Path not found " + message->m_method + ":" + path));
        return;
    }

    // TODO: those exception are well designed for different usage that reflect Client result
    try
    {
        it->second(message);
    }
    catch (const NotFoundException &e)
    {
        LOG_WAR << fname << "404 NotFound " << message->m_method << ":" << path << " - " << e.what();
        message->reply(web::http::status_codes::NotFound, Utility::text2json(e.what()));
    }
    catch (const std::domain_error &e)
    {
        // Security issue: domain_error -> 401
        LOG_WAR << fname << "401 Unauthorized " << message->m_method << ":" << path << " - " << e.what();
        message->reply(web::http::status_codes::Unauthorized, Utility::text2json(e.what()));
    }
    catch (const std::invalid_argument &e)
    {
        // Input issue: invalid_argument -> 400
        LOG_WAR << fname << "400 BadRequest " << message->m_method << ":" << path << " - " << e.what();
        message->reply(web::http::status_codes::BadRequest, Utility::text2json(e.what()));
    }
    catch (const std::runtime_error &e)
    {
        // Logic issue: runtime_error -> 412
        LOG_WAR << fname << "412 RuntimeError " << message->m_method << ":" << path << " - " << e.what();
        message->reply(web::http::status_codes::PreconditionFailed, Utility::text2json(e.what()));
    }
    catch (const std::exception &e)
    {
        // Others: Server issue
        LOG_ERR << fname << "500 InternalServerError " << message->m_method << ":" << path << " - " << e.what();
        message->reply(web::http::status_codes::InternalError, Utility::text2json("Internal server error"));
    }
    catch (...)
    {
        // Others: Server issue
        LOG_ERR << fname << "500 InternalServerError " << message->m_method << ":" << path << " - Unknown exception";
        message->reply(web::http::status_codes::InternalError, Utility::text2json("Unknown exception"));
    }
}

void RestBase::bindRestMethod(const web::http::method &method, const std::string &path, std::function<void(const std::shared_ptr<HttpRequest> &)> func)
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

const std::string RestBase::getJwtToken(const std::shared_ptr<HttpRequest> &message)
{
    std::string token;
    if (message->m_headers.count(HTTP_HEADER_JWT_Authorization))
    {
        token = JwtHelper::normalizeBearerToken(message->m_headers.find(HTTP_HEADER_JWT_Authorization)->second);
    }
    else
    {
        throw std::domain_error("No authentication token provided");
    }
    return token;
}

const std::string RestBase::getJwtUserName(const std::shared_ptr<HttpRequest> &message)
{
    const auto decodedToken = JwtHelper::decode(getJwtToken(message));

    if (auto keycloak = dynamic_pointer_cast_if<SecurityKeycloak>(Security::instance()))
    {
        return std::get<0>(keycloak->extractUserInfo(decodedToken));
    }

    if (decodedToken.has_subject())
    {
        return decodedToken.get_subject();
    }
    else
    {
        throw std::invalid_argument("No user name info in token");
    }
}

const std::set<std::string> RestBase::getJwtUserAudience(const std::shared_ptr<HttpRequest> &message)
{
    const auto decodedToken = JwtHelper::decode(getJwtToken(message));

    if (decodedToken.has_audience())
    {
        return decodedToken.get_audience();
    }
    else
    {
        throw std::invalid_argument("No audience info in token");
    }
}

const std::string RestBase::permissionCheck(const std::shared_ptr<HttpRequest> &message, const std::string &permission, const std::string &audience)
{
    const static char fname[] = "RestBase::permissionCheck() ";

    // Extract JWT token from HTTP headers
    const auto token = getJwtToken(message);

    // Verify the token's validity
    const auto tokenValidationResult = JwtToken::verify(token, audience);

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

    LOG_DBG << fname << "Authentication successful for client: " << message->m_remote_address << ", user: " << userName << ", permission: " << (permission.empty() ? "none" : permission);
    return userName;
}
