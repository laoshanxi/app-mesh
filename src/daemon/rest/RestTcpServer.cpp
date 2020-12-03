#include <atomic>
#include <ace/OS.h>
#include <ace/CDR_Stream.h>
#include <ace/SOCK_Acceptor.h>
#include <ace/SOCK_Stream.h>
#include <ace/SOCK_Connector.h>
#include <ace/INET_Addr.h>

#include "HttpRequest.h"
#include "PrometheusRest.h"
#include "RestTcpServer.h"
#include "RestChildObject.h"
#include "../Configuration.h"
#include "../process/AppProcess.h"
#include "../../common/Utility.h"

std::shared_ptr<RestTcpServer> RestTcpServer::m_instance = nullptr;
RestTcpServer::RestTcpServer() : PrometheusRest(false)
{
}

RestTcpServer::~RestTcpServer()
{
}

std::shared_ptr<RestTcpServer> RestTcpServer::instance()
{
    return m_instance;
}

void RestTcpServer::instance(std::shared_ptr<RestTcpServer> config)
{
    m_instance = config;
}

int RestTcpServer::open(void *)
{
    static std::atomic_flag lock = ATOMIC_FLAG_INIT;
    if (!lock.test_and_set())
    {
        activate(THR_NEW_LWP | THR_BOUND | THR_DETACHED, Configuration::instance()->getThreadPoolSize());
        // one thread is used to read socket
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
            std::string method, uri, address, body, headers, query, uuid;
            ACE_InputCDR cdr(msg);
            if (
                cdr >> method &&
                cdr >> uri &&
                cdr >> address &&
                cdr >> body &&
                cdr >> headers &&
                cdr >> query &&
                cdr >> uuid)
            {
                HttpRequest message(method, uri, address, body, headers, query, uuid);
                handleTcpRest(message);
            }
            else
            {
                LOG_ERR << fname << "message deserialize failed";
            }
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

web::json::value RestTcpServer::getRestAppJson()
{
    web::json::value restApp;
    auto objEnvs = web::json::value::object();
    restApp[JSON_KEY_APP_name] = web::json::value::string(SEPARATE_REST_APP_NAME);
    restApp[JSON_KEY_APP_owner] = web::json::value::string("admin");
    restApp[JSON_KEY_APP_command] = web::json::value::string("/opt/appmesh/apprest rest");
    restApp[JSON_KEY_APP_owner_permission] = web::json::value::number(11);
    objEnvs["LD_LIBRARY_PATH"] = web::json::value::string("/opt/appmesh/lib64");
    restApp[JSON_KEY_APP_env] = objEnvs;
    return restApp;
}

void RestTcpServer::backforwardResponse(const std::string &uuid, const std::string &body,
 const web::http::http_headers &headers, const http::status_code &status, const std::string &bodyType)
{
    const static char fname[] = "RestTcpServer::backforwardResponse() ";

    const size_t max_payload_size = ACE_MAXLOGMSGLEN + 1 + ACE_CDR::MAX_ALIGNMENT;

    // Insert contents into payload stream.
    ACE_OutputCDR payload(max_payload_size);
    payload << status;
    payload << uuid;
    payload << body;
    payload << Utility::serialize(headers);
    payload << bodyType;

    // Get the number of bytes used by the CDR stream.
    ACE_CDR::ULong length = ACE_Utils::truncate_cast<ACE_CDR::ULong>(payload.total_length());

    // Send a header so the receiver can determine the byte order and
    // size of the incoming CDR stream.
    ACE_OutputCDR header(ACE_CDR::MAX_ALIGNMENT + 8);
    header << ACE_OutputCDR::from_boolean(ACE_CDR_BYTE_ORDER);
    // Store the size of the payload that follows
    header << ACE_CDR::ULong(length);

    // Use an iovec to send both buffer and payload simultaneously.
    iovec iov[2];
    iov[0].iov_base = header.begin()->rd_ptr();
    iov[0].iov_len = 8;
    iov[1].iov_base = payload.begin()->rd_ptr();
    iov[1].iov_len = length;

    LOG_DBG << fname << "send response with header length: " << 8 << " body length: " << length;

    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    if (m_socketStream.get_handle() == ACE_INVALID_HANDLE || m_socketStream.sendv_n(iov, 2) < (ssize_t)length)
    {
        LOG_ERR << fname << "send response failed with error :" << std::strerror(errno);
    }
}

void RestTcpServer::handleTcpRest(const HttpRequest &message)
{
    const static char fname[] = "RestTcpServer::handleTcpRest() ";
    LOG_DBG << fname << message.m_method << " from " << message.m_remote_address << " with path " << message.m_relative_uri;

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