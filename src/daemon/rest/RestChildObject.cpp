#include <ace/INET_Addr.h>
#include <ace/SOCK_Connector.h>
#include <ace/SOCK_Stream.h>

#include "../../common/Utility.h"
#include "RestChildObject.h"
#include "protoc/ProtobufHelper.h"
#include "protoc/Request.pb.h"
#include "protoc/Response.pb.h"

std::shared_ptr<RestChildObject> RestChildObject::m_instance = nullptr;
RestChildObject::RestChildObject() : RestHandler(true)
{
}

RestChildObject::~RestChildObject()
{
}

std::shared_ptr<RestChildObject> RestChildObject::instance()
{
    return m_instance;
}

void RestChildObject::instance(std::shared_ptr<RestChildObject> config)
{
    m_instance = config;
}

void RestChildObject::connectAndRun(int port)
{
    const static char fname[] = "RestChildObject::connectAndRun() ";

    try
    {
        ACE_SOCK_Connector connector;
        ACE_INET_Addr localAddress(port, ACE_LOCALHOST);
        if (connector.connect(m_socketStream, localAddress) >= 0)
        {
            LOG_INF << fname << "connected to TCP REST port: " << localAddress.get_port_number();
            RestHandler::open();

            while (true)
            {
                auto tup = ProtobufHelper::readMessageBlock(m_socketStream);
                const auto data = std::shared_ptr<char>(std::get<0>(tup), std::default_delete<char[]>());
                // const auto length = std::get<1>(tup);
                if (data)
                {
                    appmesh::Response response;
                    if (ProtobufHelper::deserialize(response, data.get()))
                    {
                        this->replyResponse(response);
                    }
                }
                else
                {
                    LOG_ERR << fname << "failed read message block with error :" << std::strerror(errno);
                    break;
                }
            }
        }
        else
        {
            LOG_ERR << fname << "connect to TCP REST port: " << localAddress.get_port_number() << " failed";
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
    throw std::runtime_error("connection to TCP REST server broken");
}

void RestChildObject::sendRequest2Server(const HttpRequest &message)
{
    const static char fname[] = "RestChildObject::sendRequest2Server() ";

    const auto req = message.serialize();
    const auto tup = ProtobufHelper::serialize(*req);
    const auto buffer = std::get<0>(tup);
    const auto length = std::get<1>(tup);

    const auto timerId = this->registerTimer(1000L * 100, 0, std::bind(&RestChildObject::onResponseTimeout, this, std::placeholders::_1), fname);

    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    if (m_socketStream.get_handle() != ACE_INVALID_HANDLE)
    {
        const auto sendSize = (size_t)m_socketStream.send_n((void *)buffer.get(), length);
        if (sendSize == length)
        {
            m_clientRequests.insert(std::pair<std::string, HttpRequest>(message.m_uuid, HttpRequest(message)));
            // set a timer to force reply in case of no resp from server.
            m_clientRequestsTimer.insert(std::pair<std::string, int>(message.m_uuid, timerId));
            LOG_DBG << fname << "Cache message: " << message.m_uuid << " header len: " << 8 << " total len: " << length << " sent len:" << sendSize;
        }
        else
        {
            LOG_ERR << fname << "send response failed with error: " << std::strerror(errno);
        }
    }
    else
    {
        LOG_WAR << fname << "Socket not available, ignore message: " << message.m_uuid;
    }
}

void RestChildObject::replyResponse(const appmesh::Response &response)
{
    const static char fname[] = "RestChildObject::replyResponse() ";

    int timerId = INVALID_TIMER_ID;
    {
        std::lock_guard<std::recursive_mutex> guard(m_mutex);
        if (m_clientRequests.count(response.uuid()))
        {
            auto &msg = m_clientRequests.find(response.uuid())->second;
            web::http::http_response resp(response.http_status());
            resp.set_status_code(response.http_status());
            if (response.http_body_msg_type() == CONTENT_TYPE_APPLICATION_JSON && response.http_body().length())
            {
                try
                {
                    resp.set_body(web::json::value::parse(response.http_body()));
                }
                catch (...)
                {
                    LOG_ERR << fname << "failed to parse body to JSON :" << response.http_body();
                    resp.set_body(response.http_body());
                }
            }
            else
            {
                resp.set_body(response.http_body());
            }
            for (const auto &h : response.headers())
            {
                resp.headers().add(h.first, h.second);
            }

            try
            {
                msg.reply(resp);
            }
            catch (const std::exception &e)
            {
                LOG_ERR << fname << "reply to client failed: " << e.what();
            }
            catch (...)
            {
                LOG_ERR << fname << "reply to client failed";
            }

            m_clientRequests.erase(response.uuid());
            // clean timer map
            const auto iter = m_clientRequestsTimer.find(response.uuid());
            if (iter != m_clientRequestsTimer.end())
            {
                timerId = iter->second;
                m_clientRequestsTimer.erase(iter);
            }

            LOG_DBG << fname << "reply message success: " << response.uuid() << " left pending request size: " << m_clientRequests.size() << " request timer map size: " << m_clientRequestsTimer.size();
        }
    }
    this->cancelTimer(timerId);
}

void RestChildObject::onResponseTimeout(int timerId)
{
    const static char fname[] = "RestChildObject::onResponseTimeout() ";

    std::lock_guard<std::recursive_mutex> guard(m_mutex);

    auto iter = std::find_if(
        m_clientRequestsTimer.begin(),
        m_clientRequestsTimer.end(),
        [timerId](const std::map<std::string, int>::value_type &pair)
        {
            return timerId == pair.second;
        });
    if (iter != m_clientRequestsTimer.end())
    {
        const auto &uuid = iter->first;
        const auto requestIter = m_clientRequests.find(uuid);
        if (requestIter != m_clientRequests.end())
        {
            const auto &request = requestIter->second;
            LOG_ERR << fname << "timeout for request: " << uuid << " URI: " << request.m_relative_uri;
            request.reply(web::http::status_codes::RequestTimeout);
            m_clientRequests.erase(uuid);

            ACE_OS::_exit(-1);
        }
        m_clientRequestsTimer.erase(iter);
    }
}
