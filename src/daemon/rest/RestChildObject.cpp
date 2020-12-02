#include <thread>
#include <ace/Signal.h>
#include <ace/OS.h>
#include <ace/CDR_Stream.h>
#include <ace/SOCK_Acceptor.h>
#include <ace/SOCK_Stream.h>
#include <ace/SOCK_Connector.h>
#include <ace/INET_Addr.h>

#include "RestChildObject.h"
#include "../Configuration.h"
#include "../../common/Utility.h"

std::shared_ptr<RestChildObject> RestChildObject::m_instance = nullptr;
RestChildObject::RestChildObject()
    : RestHandler(Configuration::instance()->getRestListenAddress(),
                  Configuration::instance()->getRestListenPort(),
                  REST_SCENARIO::SEPARATE_PROCESS)
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
            while (auto msg = readMessageBlock(m_socketStream))
            {
                this->replyResponse(msg);
                msg->release();
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

    // https://github.com/DOCGroup/ACE_TAO/blob/master/ACE/examples/Logger/client/logging_app.cpp
    const size_t max_payload_size = ACE_MAXLOGMSGLEN + 1 + ACE_CDR::MAX_ALIGNMENT;

    // Insert contents into payload stream.
    ACE_OutputCDR payload(max_payload_size);
    payload << message.m_method;
    payload << message.m_relative_uri;
    payload << message.m_remote_address;
    payload << message.m_body;
    payload << Utility::serialize(message.headers());
    payload << message.m_query;
    payload << message.m_uuid;
    //LOG_DBG << fname << "headers: " << Utility::serialize(message.headers());

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

    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    if (m_socketStream.sendv_n(iov, 2) == -1)
    {
        LOG_ERR << fname << "send response failed with error :" << std::strerror(errno);
    }
    else
    {
        LOG_DBG << fname << "pending message id: " << message.m_uuid << " header len: " << 8 << " body len: " << length;
        m_sentMessages.insert(std::pair<std::string, HttpRequest>(message.m_uuid, HttpRequest(message)));
    }
}

void RestChildObject::replyResponse(ACE_Message_Block *msg)
{
    const static char fname[] = "RestChildObject::replyResponse() ";

    std::string uuid, body, headers;
    http::status_code status;
    ACE_InputCDR cdr(msg);
    if (cdr >> status &&
        cdr >> uuid &&
        cdr >> body &&
        cdr >> headers)
    {
        std::lock_guard<std::recursive_mutex> guard(m_mutex);
        if (m_sentMessages.count(uuid))
        {
            auto &msg = m_sentMessages.find(uuid)->second;
            auto headerMap = Utility::parse(headers);
            web::http::http_response resp(status);
            resp.set_status_code(status);
            resp.set_body(body); // TODO: content type
            for (const auto &h : headerMap)
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

            m_sentMessages.erase(uuid);
            LOG_DBG << fname << "reply message success: " << uuid << " left pending request size: " << m_sentMessages.size();
        }
    }
    else
    {
        LOG_ERR << fname << "deserialize response failed: " << uuid;
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
