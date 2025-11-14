// WebSocketService.cpp
#include <cstring>
#include <iostream>

#include <libwebsockets.h>

#include "../Utility.h"
#include "WebSocketService.h"

// -------------------------------
// Constructor / Destructor
// -------------------------------
WebSocketService::WebSocketService()
    : m_context(nullptr), m_is_running(false), m_next_request_id(1)
{
}

WebSocketService::~WebSocketService()
{
    shutdown();
}

WebSocketService *WebSocketService::instance()
{
    static WebSocketService instance;
    return &instance;
}

// -------------------------------
// Session management
// -------------------------------
std::shared_ptr<WebSocketSession> WebSocketService::findSession(struct lws *wsi)
{
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    auto it = m_sessions.find(wsi);
    if (it != m_sessions.end())
        return it->second;
    return nullptr;
}

void WebSocketService::createSession(struct lws *wsi)
{
    const static char fname[] = "WebSocketService::createSession() ";

    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    m_sessions.emplace(wsi, std::make_shared<WebSocketSession>(wsi));

    LOG_INF << fname << "Connection established: " << wsi << " (total=" << m_sessions.size() << ")";
}

std::shared_ptr<WebSocketSession> WebSocketService::destroySession(struct lws *wsi)
{
    const static char fname[] = "WebSocketService::destroySession() ";

    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    auto it = m_sessions.find(wsi);
    if (it == m_sessions.end())
    {
        LOG_WAR << fname << "Session not found: " << wsi;
        return nullptr;
    }
    auto session = it->second;
    m_sessions.erase(it);
    LOG_INF << fname << "Session destroyed: " << wsi << " (total=" << m_sessions.size() << ")";
    return session;
}

// -------------------------------
// Initialization
// -------------------------------
bool WebSocketService::initialize(ACE_INET_Addr addr)
{
    m_addr = addr;
    return createContext(nullptr, nullptr, nullptr);
}

bool WebSocketService::initialize(ACE_INET_Addr addr, const std::string &cert_path, const std::string &key_path, const std::string &ca_path)
{
    m_addr = addr;
    return createContext(cert_path.c_str(), key_path.c_str(), ca_path.c_str());
}

// -------------------------------
// Start / Shutdown
// -------------------------------
bool WebSocketService::start(int worker_count)
{
    const static char fname[] = "WebSocketService::start() ";

    if (!m_context)
    {
        throw std::runtime_error("lws_context not initialized");
        return false;
    }

    m_is_running.store(true);

    // Start event loop thread
    m_event_loop_thread = std::thread([this]
                                      { runIOEventLoop(); });

    // Start worker threads
    for (int i = 0; i < worker_count; ++i)
    {
        m_worker_threads.emplace_back([this, i]
                                      { runWorkerLoop(i); });
    }

    LOG_INF << fname << "Started (workers=" << worker_count << ")";
    return true;
}

void WebSocketService::shutdown()
{
    const static char fname[] = "WebSocketService::shutdown() ";

    if (!m_is_running.exchange(false))
        return;

    LOG_INF << fname << "Shutting down...";

    // m_incoming_queue.stop();
    // m_outgoing_queue.stop();

    if (m_context)
        lws_cancel_service(m_context);

    if (m_event_loop_thread.joinable())
        m_event_loop_thread.join();

    for (auto &worker : m_worker_threads)
        if (worker.joinable())
            worker.join();
    m_worker_threads.clear();

    if (m_context)
    {
        lws_context_destroy(m_context);
        m_context = nullptr;
    }

    {
        std::lock_guard<std::mutex> lock(m_sessions_mutex);
        m_sessions.clear();
    }

    LOG_INF << fname << "Shutdown complete";
}

// -------------------------------
// HTTP callback (called from C)
// -------------------------------
int WebSocketService::handleHttpCallback(struct lws *wsi, enum lws_callback_reasons reason, void *in, size_t len)
{
    switch (reason)
    {
    case LWS_CALLBACK_ADD_HEADERS:
    {
        auto *header_args = static_cast<lws_process_html_args *>(in);
        unsigned char *buffer_ptr = reinterpret_cast<unsigned char *>(header_args->p);
        unsigned char *buffer_end = buffer_ptr + header_args->max_len;
        std::string cookie_value = "sessionid=secure_" + std::to_string(std::time(nullptr)) +
                                   "; Path=/; HttpOnly; Secure; SameSite=Strict";
        if (lws_add_http_header_by_name(wsi,
                                        reinterpret_cast<const unsigned char *>("set-cookie:"),
                                        reinterpret_cast<const unsigned char *>(cookie_value.c_str()),
                                        static_cast<int>(cookie_value.length()),
                                        &buffer_ptr, buffer_end))
        {
            lwsl_err("Failed to add Set-Cookie header\n");
            return -1;
        }
        header_args->p = reinterpret_cast<char *>(buffer_ptr);
        return 0;
    }
    case LWS_CALLBACK_HTTP:
    {
        char uri_buffer[256] = {0};
        lws_hdr_copy(wsi, uri_buffer, sizeof(uri_buffer), WSI_TOKEN_GET_URI);

        if (strcmp(uri_buffer, "/") == 0 || strcmp(uri_buffer, "/index.html") == 0)
        {
            if (lws_serve_http_file(wsi, "index.html", "text/html; charset=utf-8", nullptr, 0) < 0)
            {
                lwsl_err("Failed to serve index.html\n");
                return -1;
            }
            return 0;
        }
        else if (strcmp(uri_buffer, "/style.css") == 0)
        {
            if (lws_serve_http_file(wsi, "style.css", "text/css", nullptr, 0) < 0)
                return -1;
            return 0;
        }
        else if (strcmp(uri_buffer, "/script.js") == 0)
        {
            if (lws_serve_http_file(wsi, "script.js", "application/javascript", nullptr, 0) < 0)
                return -1;
            return 0;
        }
        lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, nullptr);
        return -1;
    }
    default:
        break;
    }
    return lws_callback_http_dummy(wsi, reason, nullptr, in, len);
}

// -------------------------------
// WebSocket callback (called from C)
// -------------------------------
int WebSocketService::handleWebSocketCallback(struct lws *wsi, enum lws_callback_reasons reason, void *in, size_t len)
{
    switch (reason)
    {
    case LWS_CALLBACK_ESTABLISHED:
    {
        createSession(wsi);
        break;
    }
    case LWS_CALLBACK_RECEIVE:
    {
        std::string message(static_cast<const char *>(in), len);

        WSRequest req;
        req.m_type = WSRequest::Type::WebSocketMessage;
        req.m_wsi = wsi;
        req.m_payload = std::move(message);
        req.m_req_id = m_next_request_id.fetch_add(1, std::memory_order_relaxed);
        enqueueIncomingRequest(std::move(req));
        break;
    }
    case LWS_CALLBACK_SERVER_WRITEABLE:
    {
        // Only the IO thread gets this callback; pop one message from session queue and send.
        auto session = findSession(wsi);
        if (!session)
            break;

        std::string msg;
        if (session->dequeueOutgoingMessage(msg))
        {
            int result = sendWebSocketMessage(wsi, msg);
            if (result < 0)
            {
                lwsl_err("Failed to send WebSocket message\n");
                return -1;
            }
            // If session still has more messages, request writable again.
            if (session->hasOutgoingMessages())
            {
                lws_callback_on_writable(wsi);
            }
        }
        break;
    }
    case LWS_CALLBACK_CLOSED:
    case LWS_CALLBACK_WSI_DESTROY:
    {
        destroySession(wsi);
        break;
    }
    default:
        break;
    }
    return 0;
}

// -------------------------------
// Queue operations
// -------------------------------
void WebSocketService::enqueueOutgoingResponse(WSResponse &&resp)
{
    auto lswi = resp.m_wsi;
    if (!lswi || !m_context)
        return;

    m_outgoing_queue.enqueue(std::move(resp));
    // Wake lws service so the IO loop will process the response
    lws_cancel_service(m_context);
}

void WebSocketService::enqueueIncomingRequest(WSRequest &&req)
{
    static const char fname[] = "WebSocketService::enqueueIncomingRequest() ";

    LOG_DBG << fname << "Received (" << req.m_payload.length() << " bytes)";
    m_incoming_queue.enqueue(std::move(req));
}

// -------------------------------
// Low-level send
// -------------------------------
int WebSocketService::sendWebSocketMessage(struct lws *wsi, const std::string &msg)
{
    size_t len = msg.size();
    std::vector<unsigned char> buffer(LWS_PRE + len);
    memcpy(buffer.data() + LWS_PRE, msg.data(), len);
    int bytes_written = lws_write(wsi, buffer.data() + LWS_PRE, static_cast<int>(len), LWS_WRITE_TEXT);
    return bytes_written;
}

void WebSocketService::deliverResponse(WSResponse &&resp)
{
    const static char fname[] = "WebSocketService::deliverResponse() ";

    if (!resp.m_wsi)
        return;

    auto session = findSession(resp.m_wsi);
    if (!session)
    {
        LOG_ERR << fname << "Cannot deliver response: session not found for wsi=" << resp.m_wsi;
        return;
    }

    session->enqueueOutgoingMessage(std::move(resp.m_payload));
    // request LWS to call SERVER_WRITEABLE for this wsi
    lws_callback_on_writable(resp.m_wsi);
}

void WebSocketService::broadcastMessage(const std::string &msg)
{
    std::vector<struct lws *> active_connections;
    {
        std::lock_guard<std::mutex> lock(m_sessions_mutex);
        for (auto &session_pair : m_sessions)
            active_connections.push_back(session_pair.first);
    }

    for (auto wsi : active_connections)
    {
        WSResponse resp;
        resp.m_wsi = wsi;
        resp.m_payload = msg;
        enqueueOutgoingResponse(std::move(resp));
    }
}

// -------------------------------
// Event loop & workers
// -------------------------------
void WebSocketService::runIOEventLoop()
{
    const static char fname[] = "WebSocketService::runIOEventLoop() ";

    LOG_INF << fname << "Thread started";

    // using Clock = std::chrono::steady_clock;
    // auto last_broadcast_time = Clock::now();

    while (m_is_running)
    {
        int result = lws_service(m_context, 0);
        if (result < 0)
        {
            lwsl_err("lws_service error: %d\n", result);
            break;
        }

        // Periodic broadcast
        /*
        auto now = Clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_broadcast_time).count() >= BROADCAST_INTERVAL_SEC)
        {
            std::string broadcast_msg = "[Server] Heartbeat at " + std::to_string(std::time(nullptr));
            broadcastMessage(broadcast_msg);
            last_broadcast_time = now;
        }
        */

        // Process outgoing responses
        WSResponse resp;
        while (m_outgoing_queue.try_dequeue(resp))
        {
            deliverResponse(std::move(resp));
        }
    }

    LOG_INF << fname << "Thread stopped";
}

void WebSocketService::runWorkerLoop(int worker_id)
{
    const static char fname[] = "WebSocketService::runWorkerLoop() ";
    LOG_INF << fname << "Thread started: ID=" << worker_id;
    while (m_is_running)
    {
        WSRequest req;
        m_incoming_queue.wait_dequeue(req);

        if (!req.m_wsi)
            continue;

        auto session = findSession(req.m_wsi);
        if (!session)
            continue;

        WSResponse resp = session->handleRequest(req);
        enqueueOutgoingResponse(std::move(resp));
    }
    LOG_INF << fname << "Thread stopped: ID=" << worker_id;
}

// -------------------------------
// lws init
// -------------------------------
bool WebSocketService::createContext(const char *cert_path, const char *key_path, const char *ca_path)
{
    const static char fname[] = "WebSocketService::createContext() ";

    LOG_DBG << fname << "Initializing lws_context";

    static struct lws_protocols protocols[] = {
        {"http", &WebSocketService::staticHttpCallback, 0, 0, 0, nullptr, 0},
        {"appmesh-ws", &WebSocketService::staticWebSocketCallback, 0, 4096, 0, nullptr, 0},
        {nullptr, nullptr, 0, 0, 0, nullptr, 0}};

    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = m_addr.get_port_number();
    info.iface = m_addr.get_host_addr();
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
                   LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE |
                   LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED;

    // client cert verify enable/disable
    bool verify_client_cert = ca_path && strlen(ca_path) > 0;
    if (!verify_client_cert)
        info.options |= LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED;
    info.ssl_ca_filepath = ca_path;
    // server certificate and key
    info.ssl_cert_filepath = cert_path;
    info.ssl_private_key_filepath = key_path;

    // TLS 1.2 cipher list
    info.ssl_cipher_list = "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5";

    // TLS 1.3 cipher suites
    info.tls1_3_plus_cipher_list =
        "TLS_AES_256_GCM_SHA384:"
        "TLS_CHACHA20_POLY1305_SHA256:"
        "TLS_AES_128_GCM_SHA256";

    // Disable TLS 1.0 and 1.1
    info.ssl_options_set =
        SSL_OP_NO_TLSv1 |
        SSL_OP_NO_TLSv1_1 |
        SSL_OP_CIPHER_SERVER_PREFERENCE;

    info.ssl_options_clear = SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;

    // TCP keepalive settings
    info.ka_time = 60;
    info.ka_probes = 3;
    info.ka_interval = 5;

    // Ping/pong and retry configuration
    static lws_retry_bo_t retry = {};
    retry.secs_since_valid_ping = 30;
    retry.secs_since_valid_hangup = 35;
    info.retry_and_idle_policy = &retry;

    m_context = lws_create_context(&info);
    if (!m_context)
    {
        throw std::runtime_error("lws_create_context failed");
        return false;
    }

    LOG_INF << fname << "lws_context created";
    return true;
}

// -------------------------------
// Static C callbacks (forwarders)
// -------------------------------
int WebSocketService::staticHttpCallback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
    return WebSocketService::instance()->handleHttpCallback(wsi, reason, in, len);
}

int WebSocketService::staticWebSocketCallback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
    return WebSocketService::instance()->handleWebSocketCallback(wsi, reason, in, len);
}
