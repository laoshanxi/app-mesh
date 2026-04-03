// src/daemon/rest/RestBase.h
#pragma once

#include <map>
#include <memory>

#include "../../common/JwtHelper.h"
#include "../../common/Utility.h"

class HttpRequest;

/// REST base class: routing, HTTP-level JWT extraction, and permission checking.
/// Token generation and verification logic lives in JwtToken (security layer).
class RestBase
{
public:
    explicit RestBase();
    virtual ~RestBase();
protected:
    /// Dispatch REST request to specific functions
    virtual void handleRest(const std::shared_ptr<HttpRequest> &message, const std::map<std::string, std::function<void(const std::shared_ptr<HttpRequest> &)>> &restFunctions);
    /// Bind a REST path to a function (supports regex)
    void bindRestMethod(const web::http::method &method, const std::string &path, std::function<void(const std::shared_ptr<HttpRequest> &)> func);

public:
    void handle_get(const std::shared_ptr<HttpRequest> &message);
    void handle_put(const std::shared_ptr<HttpRequest> &message);
    void handle_post(const std::shared_ptr<HttpRequest> &message);
    void handle_delete(const std::shared_ptr<HttpRequest> &message);
    void handle_options(const std::shared_ptr<HttpRequest> &message);
    void handle_head(const std::shared_ptr<HttpRequest> &message);

protected:
    /// Check permission for the request, returns the authenticated username.
    const std::string permissionCheck(const std::shared_ptr<HttpRequest> &message, const std::string &permission, const std::string &audience = HTTP_HEADER_JWT_Audience_appmesh);
    /// Extract username from the JWT token in the request.
    const std::string getJwtUserName(const std::shared_ptr<HttpRequest> &message);
    /// Extract audience set from the JWT token in the request.
    const std::set<std::string> getJwtUserAudience(const std::shared_ptr<HttpRequest> &message);
    /// Extract the raw JWT token string from the Authorization header.
    const std::string getJwtToken(const std::shared_ptr<HttpRequest> &message);

protected:
    // API functions
    std::map<std::string, std::function<void(const std::shared_ptr<HttpRequest> &)>> m_restGetFunctions;
    std::map<std::string, std::function<void(const std::shared_ptr<HttpRequest> &)>> m_restPutFunctions;
    std::map<std::string, std::function<void(const std::shared_ptr<HttpRequest> &)>> m_restPstFunctions;
    std::map<std::string, std::function<void(const std::shared_ptr<HttpRequest> &)>> m_restDelFunctions;
};

#define REST_INFO_PRINT                        \
    LOG_DBG                                    \
        << "Function: " << __FUNCTION__        \
        << " Method: " << message->m_method    \
        << " URI: " << message->m_relative_uri \
        << " Remote: " << message->m_remote_address;
