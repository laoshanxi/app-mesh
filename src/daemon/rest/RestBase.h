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

protected:
    /// <summary>
    /// Forward HTTP REST request to TCP Server
    /// </summary>
    /// <param name="message"></param>
    /// <returns>true if need forward and forwared</returns>
    bool forwardRestRequest(const HttpRequest &message);
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

    const std::string verifyToken(const HttpRequest &message);
    const std::string getJwtUserName(const HttpRequest &message);
    bool permissionCheck(const HttpRequest &message, const std::string &permission);
    const std::string getJwtToken(const HttpRequest &message);
    const std::string createJwtToken(const std::string &uname, const std::string &passwd, int timeoutSeconds);

protected:
    // API functions
    std::map<std::string, std::function<void(const HttpRequest &)>> m_restGetFunctions;
    std::map<std::string, std::function<void(const HttpRequest &)>> m_restPutFunctions;
    std::map<std::string, std::function<void(const HttpRequest &)>> m_restPstFunctions;
    std::map<std::string, std::function<void(const HttpRequest &)>> m_restDelFunctions;

private:
    const bool m_forward2TcpServer;
};

/*
#define REST_HEADER_PRINT                                                             \
	for (auto it = message.m_headers().begin(); it != message.m_headers().end(); it++)  \
		LOG_DBG << "Header: " << it->first << " = " << it->second;
*/
#define REST_INFO_PRINT                       \
    LOG_DBG                                   \
        << " fname: " << __FUNCTION__         \
        << " Method: " << message.m_method    \
        << " URI: " << message.m_relative_uri \
        << " Query: " << message.m_query      \
        << " Remote: " << message.m_remote_address;
