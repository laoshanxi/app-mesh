// Session.h
#pragma once

#include <ctime>
#include <fstream>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <vector>

struct lws;
class WebSocketSession;

// Client connection information
struct WSSessionInfo
{
    std::string method;
    std::string path;
    std::string query;
    std::string auth;
    std::string ext_x_file_path;
};

// -----------------------------------------------------------------------------
// Message Types
// -----------------------------------------------------------------------------

struct WSResponse
{
    std::weak_ptr<WebSocketSession> m_session_ref;
    std::vector<std::uint8_t> m_payload;
    uint64_t m_req_id = 0;
};

struct WSRequest
{
    enum class Type
    {
        WebSocketMessage,
        HttpMessage,
        Closing
    } m_type;

    std::weak_ptr<WebSocketSession> m_session_ref;
    std::vector<std::uint8_t> m_payload;
    uint64_t m_req_id = 0;

    void reply(std::vector<std::uint8_t> &&data) const;
};

struct Buffer
{
    std::vector<std::uint8_t> data;
};

class WebSocketSession
{
public:
    explicit WebSocketSession(lws *lws);
    ~WebSocketSession() = default;

    // Processes incoming request and generates response (echo for websocket messages)
    void handleRequest(const WSRequest &req);
    bool verifySession(std::shared_ptr<WSSessionInfo> ssnInfo);
    static bool verify(std::shared_ptr<WSSessionInfo> ssnInfo);

    // Enqueue outgoing message (from worker thread)
    void enqueueOutgoingMessage(std::vector<std::uint8_t> &&payload);
    void enqueueOutgoingMessage(const std::vector<std::uint8_t> &payload);

    // Return a reference to the front, don't pop yet
    std::vector<std::uint8_t> *peekOutgoingMessage();
    // Advance offset, pop if done
    void advanceOutgoingMessage(size_t bytes_sent);
    size_t getOutgoingMessageOffset() { return m_current_msg_offset; }

    bool hasOutgoingMessages() const;

    struct lws *getWsi() const;
    std::time_t getConnectionAt() const;

    std::vector<std::uint8_t> onReceive(const void *in, size_t len, bool is_first, bool is_final);

private:
    lws *m_lws;
    const std::time_t m_connected_at;
    std::shared_ptr<WSSessionInfo> m_session_info;
    Buffer m_buffer;

    mutable std::mutex m_outgoing_mutex;
    std::queue<std::vector<std::uint8_t>> m_outgoing_messages;
    size_t m_current_msg_offset = 0; // Tracks bytes sent for the front message
};
