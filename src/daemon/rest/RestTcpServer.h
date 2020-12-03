#pragma once
#include <memory>
#include <mutex>
#include <thread>

#include <ace/Task.h>
#include <ace/SOCK_Acceptor.h>
#include <ace/SOCK_Stream.h>
#include <ace/Message_Block.h>

#include "HttpRequest.h"
#include "PrometheusRest.h"

class RestTcpServer : public ACE_Task<ACE_MT_SYNCH>, public ACE_SOCK_Acceptor, public PrometheusRest
{
public:
    RestTcpServer();
    virtual ~RestTcpServer();
    static std::shared_ptr<RestTcpServer> instance();
    static void instance(std::shared_ptr<RestTcpServer> restProcess);

    int open(void *);
    int svc(void);
    void socketThread();

    void startTcpServer();
    web::json::value getRestAppJson();
    void backforwardResponse(const std::string &uuid, const std::string &body, const web::http::http_headers &headers, const http::status_code &status, const std::string &bodyType);

private:
    void handleTcpRest(const HttpRequest &message);

private:
    mutable std::recursive_mutex m_mutex;
    ACE_SOCK_Stream m_socketStream;
    static std::shared_ptr<RestTcpServer> m_instance;
    std::thread m_socketThread;
};
