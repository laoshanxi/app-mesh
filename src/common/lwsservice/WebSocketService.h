// src/common/lwsservice/WebSocketService.h
#pragma once

/*
 * Architecture Overview:
 * ===================
 * 1. SINGLE EVENT LOOP THREAD (runIOEventLoop):
 *    - Processes I/O events for both protocols
 *    - Dequeues responses from m_outgoing_queue
 *    - Calls deliverResponse() for each response
 *
 * 2. MULTIPLE WORKER THREADS (runWorkerLoop OR WORKER::instance()
 *
 * 3. REQUEST FLOW:
 *    - HTTP: handleHttpCallback() → buildHttpRequest() → enqueueIncomingRequest(Type::HttpMessage)
 *    - WebSocket: handleWebSocketCallback() → enqueueIncomingRequest(Type::WebSocketMessage)
 *
 * 4. RESPONSE FLOW:
 *    - HttpRequest::reply() sets WSResponse::m_is_http flag
 *    - deliverResponse() routes based on m_is_http:
 *      * false (WebSocket): m_sessions map → session.enqueueOutgoingMessage(LWS_PRE)
 *      * true (HTTP): HttpSessionData (PSS) → direct lws_write(HTTP_HEADERS/FINAL)
 *
 * Key Design Decisions:
 * ====================
 * - Shared queues (m_incoming_queue, m_outgoing_queue) for both protocols
 * - HTTP is stateless (no session in m_sessions), uses PSS for per-request state
 * - WebSocket is stateful (session in m_sessions), persistent connection
 * - m_is_http flag in WSResponse ensures correct libwebsockets API usage
 * - TODO: Cookie not supported yet, so only none-authenticated HTTP SDK APIs are avialable now
 */

#include "Session.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <ace/INET_Addr.h>
#include <concurrentqueue/blockingconcurrentqueue.h>
#include <libwebsockets.h>

class Request;

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

    // HTTP request builder
    Request *buildHttpRequest(struct lws *wsi);

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
    std::unordered_set<struct lws *> m_valid_http_wsi;
};
