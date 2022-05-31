#pragma once

#include <map>
#include <memory>

#include <cpprest/http_listener.h> // HTTP server

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
    explicit RestBase(bool forward2TcpServer);
    virtual ~RestBase();
    web::json::value convertText2Json(const std::string &msg);
    // Security: replace XSS risk chars to safe charactor
    const std::string replaceXssRiskChars(const std::string &source);
    // Security: go through JSON tree and replace XSS risk chars for string attributes
    void tranverseJsonTree(web::json::value &tree);

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
    void handle_get(const HttpRequest &message);
    void handle_put(const HttpRequest &message);
    void handle_post(const HttpRequest &message);
    void handle_delete(const HttpRequest &message);
    void handle_options(const HttpRequest &message);
    void handle_head(const HttpRequest &message);

    // tuple: username, usergroup
    const std::tuple<std::string, std::string> verifyToken(const HttpRequest &message);
    const std::string getJwtUserName(const HttpRequest &message);
    bool permissionCheck(const HttpRequest &message, const std::string &permission);
    const std::string getJwtToken(const HttpRequest &message);
    const std::string createJwtToken(const std::string &uname, const std::string &userGroup, int timeoutSeconds);

protected:
    // API functions
    std::map<std::string, std::function<void(const HttpRequest &)>> m_restGetFunctions;
    std::map<std::string, std::function<void(const HttpRequest &)>> m_restPutFunctions;
    std::map<std::string, std::function<void(const HttpRequest &)>> m_restPstFunctions;
    std::map<std::string, std::function<void(const HttpRequest &)>> m_restDelFunctions;

protected:
    const bool m_forward2TcpServer;
};

#define REST_INFO_PRINT                       \
    LOG_DBG                                   \
        << " fname: " << __FUNCTION__         \
        << " Method: " << message.m_method    \
        << " URI: " << message.m_relative_uri \
        << " Query: " << message.m_query      \
        << " Remote: " << message.m_remote_address;
// << " Headers: " << HttpRequest::serializeHeaders(message.m_headers)
