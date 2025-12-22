// src/common/lwsservice/WebSocketService.h
#pragma once

#include "Session.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#include <ace/INET_Addr.h>
#include <concurrentqueue/blockingconcurrentqueue.h>
#include <libwebsockets.h>

// Blocking concurrent queues for incoming requests and outgoing responses
using REQUEST_QUEUE = moodycamel::BlockingConcurrentQueue<WSRequest>;
using RESPONSE_QUEUE = moodycamel::ConcurrentQueue<std::unique_ptr<WSResponse>>;

class WebSocketService
{
public:
    explicit WebSocketService();
    ~WebSocketService();

    static WebSocketService *instance();

    // Session management
    std::shared_ptr<WSSessionInfo> getSessionInfo(struct lws *wsi);
    std::shared_ptr<WebSocketSession> findSession(struct lws *wsi);
    std::shared_ptr<WebSocketSession> createSession(struct lws *wsi);
    void destroySession(struct lws *wsi);

    // Initialize without TLS
    bool initialize(ACE_INET_Addr addr);

    // Initialize with TLS
    bool initialize(ACE_INET_Addr addr, const std::string &cert_path, const std::string &key_path, const std::string &ca_path);

    // Start event loop and worker threads
    bool start(int worker_count);

    // Shutdown service gracefully
    void stop();

    // Enqueue outgoing/incoming
    void enqueueOutgoingResponse(std::unique_ptr<WSResponse> &&resp);
    void enqueueIncomingRequest(WSRequest &&request);

private:
    // Internal helpers
    void deliverResponse(const std::unique_ptr<WSResponse> &resp);
    void broadcastMessage(const std::string &msg);

    // Threads
    void runIOEventLoop();
    void runWorkerLoop(int worker_id);

    // Create/init lws_context
    bool createContext(const char *cert_path, const char *key_path, const char *ca_path);

    // HTTP and WebSocket callbacks (called from C)
    int handleHttpCallback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);
    int handleWebSocketCallback(struct lws *wsi, enum lws_callback_reasons reason, void *in, size_t len);

    // Static C callbacks that forward to singleton instance
    static int staticHttpCallback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);
    static int staticWebSocketCallback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);

private:
    ACE_INET_Addr m_addr;
    std::atomic<struct lws_context *> m_context;

    std::thread m_event_loop_thread;
    std::vector<std::thread> m_worker_threads;

    REQUEST_QUEUE m_incoming_queue;
    RESPONSE_QUEUE m_outgoing_queue;

    std::atomic<bool> m_is_running;
    std::atomic<uint64_t> m_next_request_id;

    mutable std::mutex m_sessions_mutex;
    std::unordered_map<struct lws *, std::shared_ptr<WebSocketSession>> m_sessions; // TODO: use ID to avoid address re-use
};
