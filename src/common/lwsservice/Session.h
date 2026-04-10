// src/common/lwsservice/Session.h
#pragma once

#include <ctime>
#include <mutex>
#include <queue>
#include <string>
#include <vector>

struct lws;
class WebSocketSession;

// Limits (MAX_HTTP_BODY_SIZE is in Utility.h — shared across all transport layers)
constexpr size_t MAX_WS_MSG_SIZE = 64 * 1024 * 1024; // 64 MB per message
constexpr size_t MAX_OUTGOING_QUEUE_DEPTH = 1024;     // per session
constexpr size_t MAX_WS_SESSIONS = 10000;             // concurrent WebSocket connections

// Client connection information
struct WSSessionInfo
{
    std::string method;
    std::string path;
    std::string query;
    std::string authorization;
    std::string auth_scheme;
    std::string ext_x_file_path;
};

// -----------------------------------------------------------------------------
// Message Types
// -----------------------------------------------------------------------------

struct WSResponse
{
    void *m_session_ref = nullptr;
    uint64_t m_session_id = 0; // ABA protection: monotonic session/request ID
    std::vector<std::uint8_t> m_payload;
    uint64_t m_req_id = 0;
    bool m_is_http = false;
};

struct WSRequest
{
    enum class Type
    {
        WebSocketMessage,
        HttpMessage,
        Closing
    } m_type = Type::WebSocketMessage;
    std::vector<std::uint8_t> m_payload;
    uint64_t m_req_id = 0;
    uint64_t m_session_id = 0; // ABA protection
    void *m_session_ref = 0;

    void reply(std::vector<std::uint8_t> &&data) const;
};

struct Buffer
{
    std::vector<std::uint8_t> data;
};

class WebSocketSession
{
public:
    explicit WebSocketSession(lws *lws, uint64_t id);
    ~WebSocketSession() = default;

    // Processes incoming request and generates response
    void handleRequest(const WSRequest &req);
    static bool verifyToken(const std::string &token);

    // Enqueue outgoing message (from worker thread). Returns false if queue is full.
    bool enqueueOutgoingMessage(std::vector<std::uint8_t> &&payload);

    // Pop and return the front outgoing message (includes LWS_PRE prefix)
    std::vector<std::uint8_t> popOutgoingMessage();

    bool hasOutgoingMessages() const;

    struct lws *getWsi() const;
    uint64_t getId() const;
    std::time_t getConnectionAt() const;

    std::vector<std::uint8_t> onReceive(const void *in, size_t len, bool is_first, bool is_final);

private:
    lws *m_lws;
    const uint64_t m_id;
    const std::time_t m_connected_at;
    Buffer m_buffer;

    mutable std::mutex m_outgoing_mutex;
    std::queue<std::vector<std::uint8_t>> m_outgoing_messages;
};
