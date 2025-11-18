// WebSocketService.cpp
#include <cstring>
#include <iostream>
#include <memory>

#include <libwebsockets.h>

#include "../Utility.h"
#include "WebSocketService.h"

constexpr int LWS_RX_BUFFER_SIZE = 8192;

struct HttpSessionData
{
    // char auth[1024] = {0};
    // char ext_x_file_path[512] = {0};
    std::ofstream *upload_stream = nullptr;

    void close()
    {
        if (upload_stream)
        {
            if (upload_stream->is_open())
                upload_stream->close();
            delete upload_stream;
            upload_stream = nullptr;
        }
    }
};

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

std::shared_ptr<WSSessionInfo> WebSocketService::getSessionInfo(struct lws *wsi)
{
    if (!wsi)
    {
        return nullptr;
    }

    auto ssnInfo = std::make_shared<WSSessionInfo>();

    // ---- Standard Header Grabber ----
    auto grabToken = [&](lws_token_indexes token) -> std::string
    {
        int len = lws_hdr_total_length(wsi, token);
        if (len <= 0)
        {
            return {};
        }

        // Allocate buffer (len + 1 for null terminator)
        std::vector<char> buf(len + 1);
        int result_len = lws_hdr_copy(wsi, buf.data(), buf.size(), token);

        if (result_len <= 0)
        {
            return {};
        }
        return std::string(buf.data(), result_len);
    };

    // ---- Custom Header Grabber (MUST be lowercase) ----
    auto grabCustom = [&](std::string name, size_t maxLen = 1024) -> std::string
    {
        // lws requires lowercase header name + colon
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        name.push_back(':'); // Add colon to header name

        int header_len = lws_hdr_custom_length(wsi, name.c_str(), name.length());
        if (header_len <= 0)
        {
            return {};
        }

        size_t buf_size = std::min(maxLen, static_cast<size_t>(header_len + 1));
        std::vector<char> buf(buf_size);

        int len = lws_hdr_custom_copy(wsi, buf.data(), buf.size(), name.c_str(), name.length());
        if (len <= 0)
        {
            LOG_ERR << "Failed to copy custom header " << name << ", lws err=" << len;
            return {};
        }

        return std::string(buf.data(), len);
    };

    // ---- Method + Path ----

    // Check HTTP/2 Pseudo-headers
    if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COLON_METHOD))
    {
        ssnInfo->method = grabToken(WSI_TOKEN_HTTP_COLON_METHOD);
        ssnInfo->path = grabToken(WSI_TOKEN_HTTP_COLON_PATH);
    }
    // Check HTTP/1.1 GET
    else if (lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI))
    {
        ssnInfo->method = "GET";
        ssnInfo->path = grabToken(WSI_TOKEN_GET_URI);
    }
    // Check HTTP/1.1 POST
    else if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI))
    {
        ssnInfo->method = "POST";
        ssnInfo->path = grabToken(WSI_TOKEN_POST_URI);
    }

    // ---- Standard headers ----
    ssnInfo->query = grabToken(WSI_TOKEN_HTTP_URI_ARGS);
    ssnInfo->auth = grabToken(WSI_TOKEN_HTTP_AUTHORIZATION);

    // ---- Custom headers ----
    ssnInfo->ext_x_file_path = grabCustom("X-File-Path");

    return ssnInfo;
}

std::shared_ptr<WebSocketSession> WebSocketService::findSession(struct lws *wsi)
{
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    auto it = m_sessions.find(wsi);
    if (it != m_sessions.end())
        return it->second;
    return nullptr;
}

std::shared_ptr<WebSocketSession> WebSocketService::createSession(struct lws *wsi)
{
    const static char fname[] = "WebSocketService::createSession() ";

    auto ssn = std::make_shared<WebSocketSession>(wsi);
    {
        std::lock_guard<std::mutex> lock(m_sessions_mutex);
        m_sessions.emplace(wsi, ssn);
    }

    LOG_INF << fname << "Connection established: " << wsi << " (total=" << m_sessions.size() << ")";
    return ssn;
}

void WebSocketService::destroySession(struct lws *wsi)
{
    const static char fname[] = "WebSocketService::destroySession() ";

    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    auto it = m_sessions.find(wsi);
    if (it == m_sessions.end())
    {
        LOG_WAR << fname << "Session not found: " << wsi;
    }
    else
    {
        time_t duration = time(nullptr) - it->second->getConnectionAt();
        m_sessions.erase(it);
        LOG_INF << fname << "Session destroyed: " << wsi << " (duration=" << duration << "s, sessions=" << m_sessions.size() << ")";
    }
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

    // Send sentinel values to wake up workers
    for (size_t i = 0; i < m_worker_threads.size(); ++i)
    {
        WSRequest sentinel;
        sentinel.m_type = WSRequest::Type::Closing;
        m_incoming_queue.enqueue(std::move(sentinel));
    }
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
int WebSocketService::handleHttpCallback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
    auto *pss = static_cast<HttpSessionData *>(user);

    switch (reason)
    {
    case LWS_CALLBACK_HTTP:
    {
        auto ssnInfo = getSessionInfo(wsi);
        if (!ssnInfo)
        {
            lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, nullptr);
            return -1;
        }

        // MANUAL PSS INITIALIZATION
        if (pss)
            pss->upload_stream = nullptr;

        // 1. Serve Index
        if (ssnInfo->path == "/" || ssnInfo->path == "/index.html")
        {
            if (lws_serve_http_file(wsi, "index.html", "text/html; charset=utf-8", nullptr, 0) < 0)
                return -1;
            return 0; // Standard LWS return for serving file
        }

        // 2. Authentication Check
        if (!WebSocketSession::verify(ssnInfo))
        {
            lws_return_http_status(wsi, HTTP_STATUS_UNAUTHORIZED, "Authentication failed");
            return -1;
        }

        // std::strncpy(pss->ext_x_file_path, ssnInfo->ext_x_file_path.c_str(), sizeof(pss->ext_x_file_path) - 1);
        // std::strncpy(pss->auth, ssnInfo->auth.c_str(), sizeof(pss->auth) - 1);

        // 3. File Download
        if (ssnInfo->method == "GET" && ssnInfo->path == "/appmesh/file/download" && !ssnInfo->ext_x_file_path.empty())
        {
            // Note: lws_serve_http_file handles LWS_PRE internally
            if (lws_serve_http_file(wsi, ssnInfo->ext_x_file_path.c_str(), "application/octet-stream", nullptr, 0) < 0)
                return -1;
            return 0;
        }

        // 4. File Upload Setup
        if (ssnInfo->method == "POST" && ssnInfo->path == "/appmesh/file/upload" && !ssnInfo->ext_x_file_path.empty())
        {
            if (pss)
            {
                pss->upload_stream = new std::ofstream(ssnInfo->ext_x_file_path, std::ios::binary);
                if (!pss->upload_stream->is_open())
                {
                    pss->close();
                    lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Cannot open file");
                    return -1;
                }
                // Return 0 to allow LWS to proceed to LWS_CALLBACK_HTTP_BODY
                return 0;
            }
            return 0; // Ready to receive body
        }

        lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, nullptr);
        return -1;
    }

    case LWS_CALLBACK_HTTP_BODY:
    {
        if (pss && pss->upload_stream)
        {
            // Write chunk to disk (BLOCKING I/O - Careful)
            pss->upload_stream->write(reinterpret_cast<const char *>(in), static_cast<std::streamsize>(len));

            if (!pss->upload_stream->good())
            {
                pss->close();
                lwsl_err("File write failed\n");
                return -1; // Abort connection
            }
        }
        return 0;
    }

    case LWS_CALLBACK_HTTP_BODY_COMPLETION:
    {
        if (pss && pss->upload_stream)
        {
            pss->close();

            // HTTP replies in libwebsockets do NOT require LWS_PRE
            std::string msg = "Upload OK";
            lws_return_http_status(wsi, HTTP_STATUS_OK, nullptr);
            lws_write(wsi, (unsigned char *)msg.c_str(), msg.size(), LWS_WRITE_HTTP_FINAL);
            lws_http_transaction_completed(wsi);
        }
        return 0;
    }

    case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
    case LWS_CALLBACK_CLOSED_HTTP:
    {
        if (pss)
            pss->close();
        // Optional: Delete partial file
        break;
    }

    case LWS_CALLBACK_HTTP_FILE_COMPLETION:
    {
        // Good place to log download success
        // lwsl_info("File download completed\n");
        return lws_http_transaction_completed(wsi);
    }

    default:
        break;
    }
    return lws_callback_http_dummy(wsi, reason, user, in, len);
}

// -------------------------------
// WebSocket callback (called from C)
// -------------------------------
int WebSocketService::handleWebSocketCallback(struct lws *wsi, enum lws_callback_reasons reason, void *in, size_t len)
{
    switch (reason)
    {
    case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
    {
        // Retrieve session info (from header) and cache to Session
        // Note: opaque_user_data is not avialable in this stage
        auto ssnInfo = getSessionInfo(wsi);
        /* TODO: Websocket can use auth here to replace the auth in RestBase::verifyToken
        // Verify headers BEFORE creating a full session object if possible
        if (!WebSocketSession::verify(ssnInfo))
        {
            return -1; // 403 Forbidden (implied)
        }
        */
        // Pass the info to createSession so it doesn't have to parse it again
        auto ssn = createSession(wsi);
        ssn->verifySession(ssnInfo);
        break;
    }
    case LWS_CALLBACK_ESTABLISHED:
    {
        // Promote createSession to LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION for session validation
        // header info is not avialable here
        // createSession(wsi);
        break;
    }
    case LWS_CALLBACK_RECEIVE:
    {
        const bool is_first = lws_is_first_fragment(wsi);
        const bool is_final = lws_is_final_fragment(wsi);
        // const bool is_binary = lws_frame_is_binary(wsi); // Check if text or binary

        auto session = findSession(wsi);
        if (session)
        {
            try
            {
                auto full_data = session->onReceive(in, len, is_first, is_final);
                if (!full_data.empty())
                {
                    WSRequest req;
                    req.m_type = WSRequest::Type::WebSocketMessage;
                    req.m_session_ref = session;
                    req.m_payload = std::move(full_data);
                    req.m_req_id = m_next_request_id.fetch_add(1, std::memory_order_relaxed);
                    enqueueIncomingRequest(std::move(req));
                }
            }
            catch (const std::exception &e)
            {
                return -1; // Error
            }
        }
        break;
    }
    case LWS_CALLBACK_SERVER_WRITEABLE:
    {
        auto session = findSession(wsi);
        if (!session)
            break;

        // Keep writing while we have messages and socket accepts data
        while (true)
        {
            auto *msg_ptr = session->peekOutgoingMessage();
            if (!msg_ptr)
                break; // Queue empty

            // Calculate pointer and length based on offset
            // Buffer: [ LWS_PRE area ... | Data ... ]
            // Ptr = buffer.data() + LWS_PRE + offset
            size_t total_len = msg_ptr->size();
            size_t offset = session->getOutgoingMessageOffset();

            unsigned char *p = (unsigned char *)msg_ptr->data() + LWS_PRE + offset;
            size_t len = (total_len - LWS_PRE) - offset;

            int sent = lws_write(wsi, p, len, LWS_WRITE_BINARY);

            if (sent < 0)
            {
                return -1; // Error
            }

            // Mark progress
            session->advanceOutgoingMessage(sent);

            // If partial write occurred, lws_write usually implies choke.
            // Or if we successfully sent this message but lws says choked now:
            if (lws_send_pipe_choked(wsi))
            {
                lws_callback_on_writable(wsi); // Re-schedule
                break;
            }

            // If we finished the message, loop continues to try sending the next one
            // unless we want to yield to let other connections handle.
            // Usually good to break after a few writes or if nothing left.
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
    auto ssn = resp.m_session_ref.lock();
    if (!ssn || !m_context)
        return;

    m_outgoing_queue.enqueue(std::move(resp));
    // Wake lws service so the IO loop will process the response
    lws_cancel_service(m_context);
}

void WebSocketService::enqueueIncomingRequest(WSRequest &&req)
{
    static const char fname[] = "WebSocketService::enqueueIncomingRequest() ";

    LOG_DBG << fname << "Received (" << req.m_payload.size() << " bytes)";
    m_incoming_queue.enqueue(std::move(req));
}

// -------------------------------
// Low-level send
// -------------------------------
int WebSocketService::sendWebSocketMessage(struct lws *wsi, const std::vector<std::uint8_t> &pre_padded_msg)
{
    if (!wsi)
        return -1;

    // Assume pre_padded_msg already has LWS_PRE size reserved at the front
    // and data starts at pre_padded_msg.data() + LWS_PRE

    size_t payload_len = pre_padded_msg.size() - LWS_PRE;
    unsigned char *p = (unsigned char *)pre_padded_msg.data() + LWS_PRE;

    return lws_write(wsi, p, payload_len, LWS_WRITE_BINARY);
}

void WebSocketService::deliverResponse(WSResponse &&resp)
{
    // Lock is essential here to prevent race with destroySession logic
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    auto ssn = resp.m_session_ref.lock();

    if (ssn)
    {
        // Verify the wsi is still in our map (Double check validity)
        auto it = m_sessions.find(ssn->getWsi());
        if (it != m_sessions.end())
        {
            ssn->enqueueOutgoingMessage(std::move(resp.m_payload));
            lws_callback_on_writable(ssn->getWsi());
        }
    }
}

void WebSocketService::broadcastMessage(const std::string &msg)
{
    std::vector<std::shared_ptr<WebSocketSession>> active_connections;
    {
        std::lock_guard<std::mutex> lock(m_sessions_mutex);
        for (auto &session_pair : m_sessions)
            active_connections.push_back(session_pair.second);
    }

    for (auto ssn : active_connections)
    {
        WSResponse resp;
        resp.m_session_ref = ssn;
        resp.m_payload.assign(msg.begin(), msg.end());
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
        // Process ALL pending outgoing responses before servicing
        WSResponse resp;
        while (m_outgoing_queue.try_dequeue(resp))
        {
            deliverResponse(std::move(resp));
        }

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

        if (req.m_type == WSRequest::Type::Closing)
            break;

        if (auto session = req.m_session_ref.lock())
        {
            session->handleRequest(req);
        }
        else
        {
            LOG_WAR << "Session expired for request " << req.m_req_id;
        }
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
        {"http", &WebSocketService::staticHttpCallback, sizeof(HttpSessionData), 0, 0, nullptr, 0},
        {"appmesh-ws", &WebSocketService::staticWebSocketCallback, 0, LWS_RX_BUFFER_SIZE, 0, nullptr, 0},
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
    return WebSocketService::instance()->handleHttpCallback(wsi, reason, user, in, len);
}

int WebSocketService::staticWebSocketCallback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
    return WebSocketService::instance()->handleWebSocketCallback(wsi, reason, in, len);
}
