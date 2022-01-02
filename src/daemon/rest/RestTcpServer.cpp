#include <atomic>

#include <ace/CDR_Stream.h>
#include <ace/INET_Addr.h>
#include <ace/SOCK_Acceptor.h>
#include <ace/SOCK_Stream.h>

#include "../../common/Utility.h"
#include "../Configuration.h"
#include "../application/AppBehavior.h"
#include "HttpRequest.h"
#include "RestChildObject.h"
#include "RestHandler.h"
#include "RestTcpServer.h"

std::shared_ptr<RestTcpServer> RestTcpServer::m_instance = nullptr;
RestTcpServer::RestTcpServer() : RestHandler(false)
{
}

RestTcpServer::~RestTcpServer()
{
}

std::shared_ptr<RestTcpServer> RestTcpServer::instance()
{
    return m_instance;
}

void RestTcpServer::instance(std::shared_ptr<RestTcpServer> tcpServer)
{
    m_instance = tcpServer;
}

int RestTcpServer::open(void *)
{
    static std::atomic_flag lock = ATOMIC_FLAG_INIT;
    if (!lock.test_and_set())
    {
        // no need much thread as cpprestsdk, just set half number and reserve 2.
        auto tcpRestContextThreadNumber = std::max(2, int(Configuration::instance()->getThreadPoolSize() / 2));
        activate(THR_NEW_LWP | THR_BOUND | THR_DETACHED, tcpRestContextThreadNumber);
        // thread used to read socket
        m_socketThread = std::thread(std::bind(&RestTcpServer::socketThread, this));
    }
    return 0;
}

int RestTcpServer::svc(void)
{
    const static char fname[] = "RestTcpServer::svc() ";
    LOG_INF << fname << "Entered";

    try
    {
        LOG_DBG << fname << "thread handle message queue";
        ACE_Message_Block *msg;
        while (this->getq(msg) > -1)
        {
            ACE_InputCDR cdr(msg);
            auto message = HttpRequest::deserialize(cdr);
            if (message)
            {
                handleTcpRest(*message);
            }
            else
            {
                LOG_ERR << fname << "message deserialize failed";
            }
            msg->release();
        }
    }
    catch (const std::exception &e)
    {
        LOG_ERR << fname << "exception: " << e.what();
    }
    catch (...)
    {
        LOG_ERR << fname << "unknown exception: " << std::strerror(errno);
    }

    LOG_INF << fname << "Leaving";
    return 0;
}

void RestTcpServer::socketThread()
{
    const static char fname[] = "RestTcpServer::socketThread() ";
    while (accept(m_socketStream) != -1)
    {
        while (auto msg = RestChildObject::readMessageBlock(m_socketStream))
        {
            this->putq(msg);
        }
        m_socketStream.close();
    }
    LOG_ERR << fname << "socket listhen thread exited";
}

void RestTcpServer::startTcpServer()
{
    const static char fname[] = "RestTcpServer::startTcpServer() ";

    LOG_INF << fname << "starting TCP rest server with listen port: " << Configuration::instance()->getSeparateRestInternalPort();
    ACE_INET_Addr localAddress(Configuration::instance()->getSeparateRestInternalPort(), ACE_LOCALHOST);
    if (ACE_SOCK_Acceptor::open(localAddress, 1) < 0)
    {
        LOG_ERR << fname << "listen port " << localAddress.get_port_number() << " failed with error :" << std::strerror(errno);
        throw std::invalid_argument("rest TCP port is already using");
    }
    this->open(0);
}

const web::json::value RestTcpServer::getRestAppJson() const
{
    web::json::value restApp;
    auto objEnvs = web::json::value::object();
    auto objBehavior = web::json::value::object();
    restApp[JSON_KEY_APP_name] = web::json::value::string(SEPARATE_REST_APP_NAME);
    restApp[JSON_KEY_APP_command] = web::json::value::string(Utility::getSelfDir() + "/appsvc --rest");
    restApp[JSON_KEY_APP_description] = web::json::value::string("REST Service for App Mesh");
    restApp[JSON_KEY_APP_owner_permission] = web::json::value::number(11);
    restApp[JSON_KEY_APP_owner] = web::json::value::string(JWT_ADMIN_NAME);
    // if do not define LD_LIBRARY_PATH here, appmesh will replace to none-appmesh environment
    objEnvs["LD_LIBRARY_PATH"] = web::json::value::string(ACE_OS::getenv("LD_LIBRARY_PATH"));
    objBehavior[JSON_KEY_APP_behavior_exit] = web::json::value::string(AppBehavior::action2str(AppBehavior::Action::RESTART));
    restApp[JSON_KEY_APP_env] = objEnvs;
    restApp[JSON_KEY_APP_behavior] = objBehavior;
    return restApp;
}

void RestTcpServer::backforwardResponse(const std::string &uuid, const std::string &body,
                                        const web::http::http_headers &headers, const http::status_code &status, const std::string &bodyType)
{
    const static char fname[] = "RestTcpServer::backforwardResponse() ";

    std::map<std::string, std::string> stdHeaders;
    for (const auto &kv : headers)
        stdHeaders[kv.first] = kv.second;
    HttpTcpResponse resp(uuid, body, bodyType, stdHeaders, status);
    IoVector io(resp.serialize());
    auto msgLength = io.length();

    std::lock_guard<std::recursive_mutex> guard(m_socketSendLock);
    size_t sendSize = 0;
    if (m_socketStream.get_handle() == ACE_INVALID_HANDLE || (sendSize = m_socketStream.sendv_n(io.data, 2)) < msgLength)
    {
        LOG_ERR << fname << "send response failed with error: " << std::strerror(errno);
    }
    else
    {
        LOG_DBG << fname << "send response: " << uuid << " with header length: " << 8 << " body length: " << msgLength << " sent len:" << sendSize;
    }
}

void RestTcpServer::handleTcpRest(const HttpRequest &message)
{
    const static char fname[] = "RestTcpServer::handleTcpRest() ";
    LOG_DBG << fname << message.m_method << " from " << message.m_remote_address << " path " << message.m_relative_uri << " id " << message.m_uuid;

    if (message.m_method == web::http::methods::GET)
    {
        handleRest(message, m_restGetFunctions);
    }
    else if (message.m_method == web::http::methods::PUT)
    {
        handleRest(message, m_restPutFunctions);
    }
    else if (message.m_method == web::http::methods::DEL)
    {
        handleRest(message, m_restDelFunctions);
    }
    else if (message.m_method == web::http::methods::POST)
    {
        handleRest(message, m_restPstFunctions);
    }
    else
    {
        LOG_ERR << fname << "no such method " << message.m_method << " from " << message.m_remote_address << " with path " << message.m_relative_uri;
    }
}