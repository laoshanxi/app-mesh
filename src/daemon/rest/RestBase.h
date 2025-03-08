#pragma once

#include <jwt-cpp/traits/nlohmann-json/defaults.h>
#include <map>
#include <memory>

#include "../../common/Utility.h"

class HttpRequest;

/// <summary>
/// REST Base class, provide:
///  1. base REST method functions
///  2. JWT authentication
///  3. method to bind rest path to a function
///  4. forward rest request to TCP server
/// </summary>
class RestBase
{
public:
    explicit RestBase();
    virtual ~RestBase();
    nlohmann::json convertText2Json(const std::string &msg);
    // Security: replace XSS risk chars to safe charactor
    const std::string replaceXssRiskChars(const std::string &source);
    // Security: go through JSON tree and replace XSS risk chars for string attributes
    void tranverseJsonTree(nlohmann::json &tree);

protected:
    /// <summary>
    /// Dispatch REST request to specific functions
    /// </summary>
    /// <param name="message"></param>
    /// <param name="restFunctions"></param>
    virtual void handleRest(const HttpRequest &message, const std::map<std::string, std::function<void(const HttpRequest &)>> &restFunctions);
    /// <summary>
    /// Bind a REST path to a function
    /// </summary>
    /// <param name="method"></param>
    /// <param name="path">support regex</param>
    /// <param name="func"></param>
    void bindRestMethod(const web::http::method &method, const std::string &path, std::function<void(const HttpRequest &)> func);

public:
    void handle_get(const HttpRequest &message);
    void handle_put(const HttpRequest &message);
    void handle_post(const HttpRequest &message);
    void handle_delete(const HttpRequest &message);
    void handle_options(const HttpRequest &message);
    void handle_head(const HttpRequest &message);

protected:
    // tuple: username, usergroup
    const std::tuple<std::string, std::string, std::set<std::string>> verifyToken(const HttpRequest &message, const std::string &audience = HTTP_HEADER_JWT_Audience_appmesh);
    bool permissionCheck(const HttpRequest &message, const std::string &permission, const std::string &audience = HTTP_HEADER_JWT_Audience_appmesh);
    const std::string getJwtUserName(const HttpRequest &message);
    const std::string getJwtToken(const HttpRequest &message);
    const std::string generateJwtToken(const std::string &uname, const std::string &userGroup, const std::string &audience, int timeoutSeconds);

protected:
    // API functions
    std::map<std::string, std::function<void(const HttpRequest &)>> m_restGetFunctions;
    std::map<std::string, std::function<void(const HttpRequest &)>> m_restPutFunctions;
    std::map<std::string, std::function<void(const HttpRequest &)>> m_restPstFunctions;
    std::map<std::string, std::function<void(const HttpRequest &)>> m_restDelFunctions;

protected:
    // Keycloak token verification helpers
    static const std::string formatCertificateToPem(const std::string &cert_base64);
    static const std::string extractCertificate(const std::string &keysJson, const std::string &kid);
    static const std::string fetchKeycloakPublicKeys(const std::string &keycloakUrl, const std::string &realm, const std::string &kid);
    static const std::tuple<std::string, std::string, std::set<std::string>> extractUserInfo(const jwt::decoded_jwt<jwt::traits::nlohmann_json> &decoded);
    static const std::tuple<std::string, std::string, std::set<std::string>> verifyKeycloakToken(const std::string &token,
                                                                                                 const std::string &keycloakUrl,
                                                                                                 const std::string &realm,
                                                                                                 const std::string &clientId);
};

#define REST_INFO_PRINT                       \
    LOG_DBG                                   \
        << "Function: " << __FUNCTION__       \
        << " Method: " << message.m_method    \
        << " URI: " << message.m_relative_uri \
        << " Remote: " << message.m_remote_address;
// << " Query: " << message.m_querys
// << " Header: " << message.m_headers
