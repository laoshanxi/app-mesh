#include <ace/CDR_Stream.h>
#include <ace/INET_Addr.h>
#include <ace/SOCK_Connector.h>
#include <ace/SOCK_Stream.h>

#include "../../common/Utility.h"
#include "RestChildObject.h"

std::shared_ptr<RestChildObject> RestChildObject::m_instance = nullptr;
RestChildObject::RestChildObject()
    : RestHandler(true)
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
            //auto timerThread = std::make_unique<std::thread>(std::bind(&TimerHandler::runReactorEvent, ACE_Reactor::instance()));
            while (auto response = readMessageBlock(m_socketStream))
            {
                this->replyResponse(response);
                response->release();
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

    IoVector io(message.serialize());
    auto msgLength = io.length();

    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    auto sendSize = m_socketStream.sendv_n(io.data, 2);
    if (sendSize == -1)
    {
        LOG_ERR << fname << "send response failed with error :" << std::strerror(errno);
    }
    else
    {
        LOG_DBG << fname << "Cache message: " << message.m_uuid << " header len: " << 8 << " body len: " << msgLength << " sent len:" << sendSize;
        m_sentMessages.insert(std::pair<std::string, HttpRequest>(message.m_uuid, HttpRequest(message)));
    }
}

void RestChildObject::replyResponse(ACE_Message_Block *response)
{
    const static char fname[] = "RestChildObject::replyResponse() ";

    ACE_InputCDR cdrData(response);
    auto respData = HttpTcpResponse::deserialize(cdrData);
    if (respData)
    {
        std::lock_guard<std::recursive_mutex> guard(m_mutex);
        if (m_sentMessages.count(respData->m_uuid))
        {
            auto &msg = m_sentMessages.find(respData->m_uuid)->second;
            web::http::http_response resp(respData->m_status);
            resp.set_status_code(respData->m_status);
            if (respData->m_bodyType == CONTENT_TYPE_APPLICATION_JSON && respData->m_body.length())
            {
                try
                {
                    resp.set_body(web::json::value::parse(respData->m_body));
                }
                catch (...)
                {
                    LOG_ERR << fname << "failed to parse body to JSON :" << respData->m_body;
                    resp.set_body(respData->m_body);
                }
            }
            else
            {
                resp.set_body(respData->m_body);
            }
            for (const auto &h : respData->m_headers)
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

            m_sentMessages.erase(respData->m_uuid);
            LOG_DBG << fname << "reply message success: " << respData->m_uuid << " left pending request size: " << m_sentMessages.size();
        }
    }
    else
    {
        LOG_ERR << fname << "deserialize response failed, failed to reply to client and clean related memory";
    }
}

ACE_Message_Block *RestChildObject::readMessageBlock(const ACE_SOCK_Stream &socket)
{
    const static char fname[] = "RestChildObject::readMessageBlock() ";
    LOG_DBG << fname << "entered";

    // https://github.com/DOCGroup/ACE_TAO/blob/master/ACE/examples/Logger/simple-server/Logging_Handler.cpp
    // We need to use the old two-read trick here since TCP sockets
    // don't support framing natively.  Allocate a message block for the
    // payload; initially at least large enough to hold the header, but
    // needs some room for alignment.
    auto header = std::make_shared<ACE_Message_Block>(ACE_DEFAULT_CDR_BUFSIZE);
    // Align the Message Block for a CDR stream
    ACE_CDR::mb_align(header.get());

    ACE_CDR::Boolean byte_order;
    ACE_CDR::ULong length;
    if (socket.get_handle() != ACE_INVALID_HANDLE && socket.recv_n(header->wr_ptr(), 8) <= 0)
    {
        LOG_ERR << fname << "read header length failed";
        return nullptr;
    }

    header->wr_ptr(8); // Reflect addition of 8 bytes.
    // Create a CDR stream to parse the 8-byte header.
    ACE_InputCDR header_cdr(header.get());
    // Extract the byte-order and use helper methods to disambiguate
    // octet, booleans, and chars.
    header_cdr >> ACE_InputCDR::to_boolean(byte_order);
    // Set the byte-order on the stream...
    // header_cdr.reset_byte_order(byte_order);
    // Extract the length
    header_cdr >> length;

    std::shared_ptr<ACE_Message_Block> payload = std::make_shared<ACE_Message_Block>(length);
    // Ensure there's sufficient room for payload.
    ACE_CDR::grow(payload.get(), 8 + ACE_CDR::MAX_ALIGNMENT + length);

    // Use <recv_n> to obtain the contents.
    if (socket.get_handle() != ACE_INVALID_HANDLE && socket.recv_n(payload->wr_ptr(), length) <= 0)
    {
        LOG_ERR << fname << "read body failed";
        return nullptr;
    }

    payload->wr_ptr(length); // Reflect additional bytes
    //ACE_InputCDR payload_cdr(payload.get());
    //payload_cdr.reset_byte_order(byte_order);
    LOG_DBG << fname << "read message header len: " << 8 << " body len: " << length;
    return payload->duplicate();
}
