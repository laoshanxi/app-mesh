// Session.cpp
#include "Session.h"
#include "../../daemon/rest/HttpRequest.h"
#include "../../daemon/rest/RestHandler.h"
#include "../../daemon/rest/TcpServer.h"
#include "WebSocketService.h"

void WSRequest::reply(std::vector<std::uint8_t> &&data) const
{
    WSResponse resp;
    resp.m_session_ref = m_session_ref;
    resp.m_req_id = m_req_id;
    resp.m_payload = std::move(data);
    WebSocketService::instance()->enqueueOutgoingResponse(std::move(resp));
}

WebSocketSession::WebSocketSession(lws *lws)
    : m_lws(lws), m_connected_at(std::time(nullptr)), m_current_msg_offset(0)
{
}

void WebSocketSession::handleRequest(const WSRequest &req)
{
    auto data = std::make_shared<std::vector<std::uint8_t>>(std::move(req.m_payload));
    auto request = HttpRequest::deserializeWS(data, req.m_session_ref);
    TcpHandler::processRequest(request);
}

bool WebSocketSession::verifySession(std::shared_ptr<WSSessionInfo> ssnInfo)
{
    bool success = verify(ssnInfo);
    if (success)
    {
        m_session_info = ssnInfo;
    }
    return success;
}

bool WebSocketSession::verify(std::shared_ptr<WSSessionInfo> ssnInfo)
{
    try
    {
        RESTHANDLER::instance()->verifyToken(ssnInfo->auth);
        return true;
    }
    catch (...)
    {
    }

    return false;
}

void WebSocketSession::enqueueOutgoingMessage(std::vector<std::uint8_t> &&payload)
{
    // Allocate once: LWS_PRE + Payload
    std::vector<uint8_t> buffer(LWS_PRE + payload.size());
    memcpy(buffer.data() + LWS_PRE, payload.data(), payload.size());

    std::lock_guard<std::mutex> lock(m_outgoing_mutex);
    m_outgoing_messages.push(std::move(buffer));
}

void WebSocketSession::enqueueOutgoingMessage(const std::vector<std::uint8_t> &payload)
{
    // Allocate once: LWS_PRE + Payload
    std::vector<uint8_t> buffer(LWS_PRE + payload.size());
    memcpy(buffer.data() + LWS_PRE, payload.data(), payload.size());

    std::lock_guard<std::mutex> lock(m_outgoing_mutex);
    m_outgoing_messages.push(std::move(buffer));
}

std::vector<uint8_t> *WebSocketSession::peekOutgoingMessage()
{
    std::lock_guard<std::mutex> lock(m_outgoing_mutex);
    if (m_outgoing_messages.empty())
        return nullptr;
    return &m_outgoing_messages.front();
}

void WebSocketSession::advanceOutgoingMessage(size_t bytes_sent)
{
    std::lock_guard<std::mutex> lock(m_outgoing_mutex);
    if (m_outgoing_messages.empty())
        return;

    m_current_msg_offset += bytes_sent;

    // The buffer size includes LWS_PRE. We are tracking payload sent.
    // Note: Your buffer creation includes LWS_PRE, so size() is LWS_PRE + payload.
    // Ensure logic handles the raw buffer size correctly.

    // Actually, standard LWS logic is:
    // Buffer: [PRE][PAYLOAD]
    // lws_write sends PAYLOAD.
    // If partial, we need to offset the pointer passed to lws_write next time.

    size_t total_size = m_outgoing_messages.front().size();
    // Since we only send the payload (total - LWS_PRE), we compare against that?
    // No, lws_write returns bytes sent from the buffer pointer we gave it.

    // Logic:
    // The payload size is (total_size - LWS_PRE).
    // If m_current_msg_offset >= (total_size - LWS_PRE), we are done.

    if (m_current_msg_offset >= (total_size - LWS_PRE))
    {
        m_outgoing_messages.pop();
        m_current_msg_offset = 0;
    }
}

bool WebSocketSession::hasOutgoingMessages() const
{
    std::lock_guard<std::mutex> lock(m_outgoing_mutex);
    return !m_outgoing_messages.empty();
}

struct lws *WebSocketSession::getWsi() const
{
    return m_lws;
}

std::time_t WebSocketSession::getConnectionAt() const
{
    return m_connected_at;
}

std::vector<std::uint8_t> WebSocketSession::onReceive(const void *in, size_t len, bool is_first, bool is_final)
{
    if (is_first)
    {
        m_buffer.data.clear();
    }

    // Check limit(e.g., 1024MB)
    constexpr size_t MAX_MSG_SIZE = 1024 * 1024 * 1024;
    if (m_buffer.data.size() + len > MAX_MSG_SIZE)
    {
        throw std::invalid_argument("message size reached limitation");
    }

    const char *p = static_cast<const char *>(in);
    m_buffer.data.insert(m_buffer.data.end(), p, p + len);

    if (is_final)
    {
        std::vector<std::uint8_t> out = std::move(m_buffer.data);
        return out;
    }

    return {}; // not finished
}