// src/common/lwsservice/Session.cpp
#include "Session.h"
#include "../../daemon/rest/HttpRequest.h"
#include "../../daemon/rest/Worker.h"
#include "../../daemon/security/JwtToken.h"
#include "WebSocketService.h"

void WSRequest::reply(std::vector<std::uint8_t> &&data) const
{
    auto resp = std::make_unique<WSResponse>();
    resp->m_session_ref = m_session_ref;
    resp->m_session_id = m_session_id;
    resp->m_req_id = m_req_id;
    resp->m_payload = std::move(data);
    resp->m_is_http = (m_type == Type::HttpMessage);
    WebSocketService::instance()->enqueueOutgoingResponse(std::move(resp));
}

WebSocketSession::WebSocketSession(lws *lws, uint64_t id)
    : m_lws(lws), m_id(id), m_connected_at(std::time(nullptr))
{
}

void WebSocketSession::handleRequest(const WSRequest &req)
{
    auto request = HttpRequest::deserialize(req.m_payload, -1, LwsSessionRef{req.m_session_ref, req.m_req_id, req.m_session_id});
    WORKER::instance()->process(request);
}

bool WebSocketSession::verifyToken(const std::string &token)
{
    try
    {
        JwtToken::verify(token, WEBSOCKET_FILE_AUDIENCE);
        return true;
    }
    catch (...)
    {
    }
    return false;
}

bool WebSocketSession::enqueueOutgoingMessage(std::vector<std::uint8_t> &&payload)
{
    std::vector<uint8_t> buffer;
    buffer.reserve(LWS_PRE + payload.size());
    buffer.resize(LWS_PRE);
    buffer.insert(buffer.end(), payload.begin(), payload.end());

    std::lock_guard<std::mutex> lock(m_outgoing_mutex);
    if (m_outgoing_messages.size() >= MAX_OUTGOING_QUEUE_DEPTH)
    {
        return false;
    }
    m_outgoing_messages.push(std::move(buffer));
    return true;
}

std::vector<uint8_t> WebSocketSession::popOutgoingMessage()
{
    std::lock_guard<std::mutex> lock(m_outgoing_mutex);
    if (m_outgoing_messages.empty())
        return {};
    auto msg = std::move(m_outgoing_messages.front());
    m_outgoing_messages.pop();
    return msg;
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

uint64_t WebSocketSession::getId() const
{
    return m_id;
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

    // Enforce 64 MB message size limit
    if (m_buffer.data.size() + len > MAX_WS_MSG_SIZE)
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
