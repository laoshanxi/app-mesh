#pragma once

#include <memory>
#include <mutex>
#include <thread>

#include <ace/Message_Block.h>
#include <ace/SOCK_Acceptor.h>
#include <ace/SOCK_Stream.h>
#include <ace/Task.h>

#include "HttpRequest.h"
#include "RestHandler.h"

/// <summary>
/// REST Server, inherit from RestHandler and PrometheusRest
/// Accept REST request from TCP channel and process via RestHandler and PrometheusRest
/// </summary>
class RestTcpServer : public ACE_Task<ACE_MT_SYNCH>, public ACE_SOCK_Acceptor, public RestHandler
{
public:
    RestTcpServer();
    virtual ~RestTcpServer();
    static std::shared_ptr<RestTcpServer> instance();
    static void instance(std::shared_ptr<RestTcpServer> tcpServer);

    /// <summary>
    /// start thread pool and listen port
    /// </summary>
    void startTcpServer();

    /// <summary>
    /// Response REST response to client
    /// </summary>
    /// <param name="requestUri"></param>
    /// <param name="uuid"></param>
    /// <param name="body"></param>
    /// <param name="headers"></param>
    /// <param name="status"></param>
    /// <param name="bodyType"></param>
    void backforwardResponse(const std::string &requestUri, const std::string &uuid, const std::string &body, const web::http::http_headers &headers, const http::status_code &status, const std::string &bodyType);

    /// <summary>
    /// Generate Application json for rest process
    /// </summary>
    /// <returns></returns>
    const web::json::value getRestAppJson() const;

private:
    /// <summary>
    /// ACE_Task_Base::open()
    /// Hook called to initialize a task and prepare it for execution.
    /// </summary>
    /// <param name=""></param>
    /// <returns></returns>
    virtual int open(void *) override;

    /// <summary>
    /// Thread pool to handle TCP REST request asynchronous
    /// </summary>
    /// <param name=""></param>
    /// <returns></returns>
    virtual int svc(void) override;

    /// <summary>
    /// Thread to accept and read socket message
    /// </summary>
    void socketThread();

    /// <summary>
    /// Process TCP request
    /// </summary>
    /// <param name="message"></param>
    void handleTcpRest(const HttpRequest &message);

private:
    mutable std::recursive_mutex m_socketSendLock;
    ACE_SOCK_Stream m_socketStream;
    static std::shared_ptr<RestTcpServer> m_instance;
    std::thread m_socketThread;
};
