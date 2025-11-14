// Session.h
#pragma once

#include <ctime>
#include <memory>
#include <mutex>
#include <queue>
#include <string>

struct lws;

// -----------------------------------------------------------------------------
// Message Types
// -----------------------------------------------------------------------------
struct WSRequest
{
    enum class Type
    {
        WebSocketMessage,
        HttpRequest
    } m_type;

    struct lws *m_wsi = nullptr;
    std::string m_payload;
    uint64_t m_req_id = 0;
};

struct WSResponse
{
    struct lws *m_wsi = nullptr;
    std::string m_payload;
    uint64_t m_req_id = 0;
};

class WebSocketSession
{
public:
    explicit WebSocketSession(struct lws *wsi);
    ~WebSocketSession() = default;

    // Processes incoming request and generates response (echo for websocket messages)
    WSResponse handleRequest(const WSRequest &req);

    // Enqueue outgoing message (from worker thread)
    void enqueueOutgoingMessage(std::string &&msg);
    void enqueueOutgoingMessage(const std::string &msg);

    // Pop next outgoing message. Returns true if message obtained.
    // called by I/O thread when WSI is writable
    bool dequeueOutgoingMessage(std::string &output);

    bool hasOutgoingMessages() const;

    struct lws *getWsi() const;
    std::time_t getConnectionAt() const;

private:
    struct lws *m_wsi;
    std::time_t m_connected_at;

    mutable std::mutex m_outgoing_mutex;
    std::queue<std::string> m_outgoing_messages;
};
