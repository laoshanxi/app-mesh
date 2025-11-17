// Session.cpp
#include "Session.h"

WebSocketSession::WebSocketSession()
    : m_connected_at(std::time(nullptr))
{
}

WSResponse WebSocketSession::handleRequest(const WSRequest &req)
{
    WSResponse resp;
    resp.m_wsi = req.m_wsi;
    resp.m_req_id = req.m_req_id;

    if (req.m_type == WSRequest::Type::WebSocketMessage)
    {
        resp.m_payload = "[Echo] " + req.m_payload;
    }
    else
    {
        resp.m_payload = "HTTP response";
    }
    return resp;
}

bool WebSocketSession::verifySession(std::shared_ptr<WSSessionInfo> ssnInfo)
{
    m_session_info = ssnInfo;
    // TODO: validate
    return true;
}

void WebSocketSession::enqueueOutgoingMessage(std::string &&msg)
{
    std::lock_guard<std::mutex> lock(m_outgoing_mutex);
    m_outgoing_messages.push(std::move(msg));
}

void WebSocketSession::enqueueOutgoingMessage(const std::string &msg)
{
    std::lock_guard<std::mutex> lock(m_outgoing_mutex);
    m_outgoing_messages.push(msg);
}

bool WebSocketSession::dequeueOutgoingMessage(std::string &output)
{
    std::lock_guard<std::mutex> lock(m_outgoing_mutex);
    if (m_outgoing_messages.empty())
    {
        return false;
    }

    output = m_outgoing_messages.front();
    m_outgoing_messages.pop();
    return true;
}

bool WebSocketSession::hasOutgoingMessages() const
{
    std::lock_guard<std::mutex> lock(m_outgoing_mutex);
    return !m_outgoing_messages.empty();
}

std::time_t WebSocketSession::getConnectionAt() const
{
    return m_connected_at;
}
