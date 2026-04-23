// src/common/lwsservice/Session.cpp
#include "Session.h"
#include "../../daemon/rest/HttpRequest.h"
#include "../../daemon/rest/Worker.h"
#include "../../daemon/security/JwtToken.h"

#include <cstring>
#include <libwebsockets.h>

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

bool WebSocketSession::enqueueOutgoingMessage(std::unique_ptr<msgpack::sbuffer> payload)
{
    // lws_write needs an LWS_PRE prefix, so copy the sbuffer body into a prefixed vector.
    const size_t body_sz = payload ? payload->size() : 0;
    std::vector<std::uint8_t> buffer(LWS_PRE + body_sz);
    if (body_sz)
        std::memcpy(buffer.data() + LWS_PRE, payload->data(), body_sz);

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
        m_buffer.data.clear(); // retains capacity across messages
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
        // Pre-reserve same size to skip grow-from-zero on the next similar frame.
        const size_t last_size = m_buffer.data.size();
        std::vector<std::uint8_t> out = std::move(m_buffer.data);
        m_buffer.data.reserve(last_size);
        return out;
    }

    return {}; // not finished
}
