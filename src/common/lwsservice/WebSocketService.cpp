// src/common/lwsservice/WebSocketService.cpp
#include <algorithm>
#include <cstring>
#include <iostream>
#include <memory>

#include <libwebsockets.h>

#include "../../daemon/rest/Data.h"
#include "../../daemon/rest/HttpRequest.h"
#include "../../daemon/rest/Worker.h"
#include "../Utility.h"
#include "WebSocketService.h"

constexpr int LWS_RX_BUFFER_SIZE = 8192;

// PSS Structure for HTTP
struct HttpSessionData
{
    std::ofstream *upload_stream = nullptr;

    // HTTP request data
    bool http_pending = false;
    Request *http_request = nullptr;
    std::vector<uint8_t> *http_response_data = nullptr;

    HttpSessionData()
    {
        cleanup();
        upload_stream = nullptr;
        http_request = nullptr;
        http_response_data = new std::vector<uint8_t>();
    }

    ~HttpSessionData()
    {
        cleanup();
    }

    void cleanup()
    {
        if (upload_stream && upload_stream->is_open())
        {
            upload_stream->close();
        }
        SAFE_DELETE(upload_stream);
        SAFE_DELETE(http_request);
        http_pending = false;
        SAFE_DELETE(http_response_data);
    }
};

// -------------------------------
// Constructor / Destructor
// -------------------------------
WebSocketService::WebSocketService() : m_context(nullptr), m_is_running(false), m_next_request_id(1)
{
}

WebSocketService::~WebSocketService()
{
    stop();
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

    // ---- Get Authorization Scheme (e.g., "Bearer" or "Basic") ----
    auto getAuthScheme = [&](size_t maxLen = 64) -> std::string
    {
        // Use fragment index 0 to get the scheme (prefix)
        std::vector<char> buf(maxLen);
        int scheme_len = lws_hdr_copy_fragment(wsi, buf.data(), buf.size(), WSI_TOKEN_HTTP_AUTHORIZATION, 0); // Index 0: Scheme/Prefix
        if (scheme_len <= 0)
        {
            return {};
        }
        // Trim any trailing space that LWS might include after the scheme
        std::string scheme(buf.data(), scheme_len);
        if (!scheme.empty() && scheme.back() == ' ')
        {
            scheme.pop_back();
        }
        return scheme;
    };

    // ---- Custom Header Grabber (MUST be lowercase, Used for non-tokenized headers) ----
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
    // Check HTTP/1.1 PUT
    else if (lws_hdr_total_length(wsi, WSI_TOKEN_PUT_URI))
    {
        ssnInfo->method = "PUT";
        ssnInfo->path = grabToken(WSI_TOKEN_PUT_URI);
    }
    // Check HTTP/1.1 DELETE
    else if (lws_hdr_total_length(wsi, WSI_TOKEN_DELETE_URI))
    {
        ssnInfo->method = "DELETE";
        ssnInfo->path = grabToken(WSI_TOKEN_DELETE_URI);
    }
    // Check HTTP/1.1 OPTIONS
    else if (lws_hdr_total_length(wsi, WSI_TOKEN_OPTIONS_URI))
    {
        ssnInfo->method = "OPTIONS";
        ssnInfo->path = grabToken(WSI_TOKEN_OPTIONS_URI);
    }
    // Check HTTP/1.1 HEAD
    else if (lws_hdr_total_length(wsi, WSI_TOKEN_HEAD_URI))
    {
        ssnInfo->method = "HEAD";
        ssnInfo->path = grabToken(WSI_TOKEN_HEAD_URI);
    }
    // Check HTTP/1.1 PATCH
    else if (lws_hdr_total_length(wsi, WSI_TOKEN_PATCH_URI))
    {
        ssnInfo->method = "PATCH";
        ssnInfo->path = grabToken(WSI_TOKEN_PATCH_URI);
    }

    // ---- Standard headers ----
    ssnInfo->query = grabToken(WSI_TOKEN_HTTP_URI_ARGS);
    ssnInfo->autherization = grabToken(WSI_TOKEN_HTTP_AUTHORIZATION);

    if (!ssnInfo->autherization.empty())
    {
        // Get the scheme (e.g., "Bearer" or "Basic")
        ssnInfo->auth_scheme = getAuthScheme();
    }

    // ---- Custom headers ----
    ssnInfo->ext_x_file_path = grabCustom("X-File-Path");

    return ssnInfo;
}

Request *WebSocketService::buildHttpRequest(struct lws *wsi)
{
    auto *req = new Request();
    auto ssnInfo = getSessionInfo(wsi);

    req->uuid = Utility::uuid();
    req->request_uri = ssnInfo->path;
    req->http_method = ssnInfo->method;

    // Client address
    char ip[64] = {};
    lws_get_peer_simple(wsi, ip, sizeof(ip));
    req->client_addr = ip;

    // Extract all HTTP headers
    for (int tok = 0; tok < 100; ++tok)
    {
        int len = lws_hdr_total_length(wsi, (lws_token_indexes)tok);
        if (len <= 0)
            continue;

        std::vector<char> buf(len + 1);
        int n = lws_hdr_copy(wsi, buf.data(), buf.size(), (lws_token_indexes)tok);
        if (n <= 0)
            continue;

        const char *raw = (const char *)lws_token_to_string((lws_token_indexes)tok);
        if (!raw)
            continue;

        std::string name(raw);
        // Normalize header name: remove trailing colon, lowercase (optional but recommended)
        if (!name.empty() && name.back() == ':')
            name.pop_back();

        // Skip non-header tokens (URI tokens and request-line metadata)
        // URI tokens end with "_URI" (GET_URI, PUT_URI, etc.)
        // Also skip HTTP/2 pseudo-headers and version information
        if (name.empty() ||
            (name.find("_URI") != std::string::npos) ||
            (name.find("HTTP/") != std::string::npos) ||
            (name.find(":method") == 0) ||
            (name.find(":path") == 0))
        {
            continue;
        }

        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        req->headers[name] = std::string(buf.data(), n);
    }

    // Parse query string (?a=b&c=d)
    if (!ssnInfo->query.empty())
    {
        std::istringstream iss(ssnInfo->query);
        std::string pair;
        while (std::getline(iss, pair, '&'))
        {
            auto pos = pair.find('=');
            if (pos != std::string::npos)
            {
                req->query[pair.substr(0, pos)] = pair.substr(pos + 1);
            }
        }
    }

    // IMPORTANT: Distinguish HTTP vs WebSocket
    req->headers[HTTP_HEADER_KEY_X_LWS_Protocol] = HTTP_HEADER_VALUE_X_LWS_Protocol_HTTP;

    // Convert cookie to Authorization header if present (follows agent_request.go pattern)
    req->convertCookieToAuthorization();

    return req;
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
        // Only warn if this was a known session (not just an HTTP one)
        // LOG_WAR << fname << "Session not found: " << wsi;
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

void WebSocketService::stop()
{
    const static char fname[] = "WebSocketService::stop() ";

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

    // 3. Wake up lws event loop safely
    struct lws_context *ctx = m_context.load();
    if (ctx)
    {
        lws_cancel_service(ctx);
    }

    // 4. Join all threads
    for (auto &worker : m_worker_threads)
    {
        if (worker.joinable())
            worker.join();
    }
    m_worker_threads.clear();

    if (m_event_loop_thread.joinable())
    {
        m_event_loop_thread.join();
    }

    // 5. Cleanup sessions
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
    // Cast user data to PSS
    auto *pss = static_cast<HttpSessionData *>(user);

    switch (reason)
    {
    case LWS_CALLBACK_HTTP_BIND_PROTOCOL:
        // CRITICAL: Initialize PSS via placement new
        if (pss)
            new (pss) HttpSessionData();
        m_valid_http_wsi.insert(wsi);
        return 0;

    case LWS_CALLBACK_HTTP:
    {
        auto ssnInfo = getSessionInfo(wsi);
        if (!ssnInfo)
            return lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, nullptr);

        // 1. File download
        if (ssnInfo->method == "GET" && ssnInfo->path == "/appmesh/file/download/ws" && !ssnInfo->ext_x_file_path.empty())
        {
            if (!WebSocketSession::verifyToken(ssnInfo->autherization))
            {
                return lws_return_http_status(wsi, HTTP_STATUS_UNAUTHORIZED, "Authentication failed");
            }
            return lws_serve_http_file(wsi, ssnInfo->ext_x_file_path.c_str(), "application/octet-stream", nullptr, 0);
        }

        // 2. File upload setup
        if (ssnInfo->method == "POST" && ssnInfo->path == "/appmesh/file/upload/ws" && !ssnInfo->ext_x_file_path.empty())
        {
            if (!WebSocketSession::verifyToken(ssnInfo->autherization))
            {
                return lws_return_http_status(wsi, HTTP_STATUS_UNAUTHORIZED, "Authentication failed");
            }
            if (pss)
            {
                pss->upload_stream = new std::ofstream(ssnInfo->ext_x_file_path, std::ios::binary);
                if (!pss->upload_stream->is_open())
                {
                    pss->cleanup();
                    return lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Cannot open file");
                }
                return 0; // Proceed to LWS_CALLBACK_HTTP_BODY to receive body
            }
        }

        // 3. Enqueue HTTP request for async processing
        if (pss)
        {
            pss->http_request = buildHttpRequest(wsi);
            if (pss->http_request->contain_body())
            {
                // Body will arrive via HTTP_BODY callbacks
                pss->http_pending = true;
                return 0;
            }

            auto serialized = pss->http_request->serialize();
            WSRequest ws_req;
            ws_req.m_type = WSRequest::Type::HttpMessage;
            ws_req.m_session_ref = wsi;
            ws_req.m_payload.assign(serialized->data(), serialized->data() + serialized->size());
            ws_req.m_req_id = m_next_request_id.fetch_add(1);

            enqueueIncomingRequest(std::move(ws_req));
            pss->http_pending = true;
            return 0;
        }
        return lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, nullptr);
    }

    case LWS_CALLBACK_HTTP_BODY:
    {
        if (pss && pss->upload_stream)
        {
            // Write chunk to disk (BLOCKING I/O - Careful)
            pss->upload_stream->write(reinterpret_cast<const char *>(in), static_cast<std::streamsize>(len));
            if (!pss->upload_stream->good())
            {
                pss->cleanup();
                return -1; // Abort
            }
        }
        else if (pss && pss->http_pending)
        {
            auto &body = pss->http_request->body;
            body.insert(body.end(), static_cast<const uint8_t *>(in), static_cast<const uint8_t *>(in) + len);
        }
        return 0;
    }

    case LWS_CALLBACK_HTTP_BODY_COMPLETION:
    {
        if (pss && pss->upload_stream)
        {
            pss->cleanup();
            const std::string msg = "Upload OK";
            unsigned char buf[LWS_PRE + msg.size()];
            memcpy(buf + LWS_PRE, msg.data(), msg.size());
            lws_return_http_status(wsi, HTTP_STATUS_OK, nullptr);
            lws_write(wsi, buf + LWS_PRE, msg.size(), LWS_WRITE_HTTP_FINAL);
            return lws_http_transaction_completed(wsi);
        }

        if (pss && pss->http_pending && pss->http_request)
        {
            auto serialized = pss->http_request->serialize();
            WSRequest ws_req;
            ws_req.m_type = WSRequest::Type::HttpMessage;
            ws_req.m_session_ref = wsi;
            ws_req.m_payload.assign(serialized->data(), serialized->data() + serialized->size());
            ws_req.m_req_id = m_next_request_id.fetch_add(1);

            enqueueIncomingRequest(std::move(ws_req));
        }
        return 0;
    }

    case LWS_CALLBACK_HTTP_WRITEABLE:
    {
        if (!pss || !pss->http_response_data || pss->http_response_data->empty())
            return 0;

        Response http_resp;
        if (!http_resp.deserialize(pss->http_response_data->data(), pss->http_response_data->size()))
        {
            pss->http_response_data->clear();
            pss->http_pending = false;
            return lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, nullptr);
        }

        int status_code = http_resp.http_status > 0 ? http_resp.http_status : HTTP_STATUS_OK;

        // Handle authentication cookies (Set-Cookie header)
        http_resp.handleAuthCookies();

        // HTTP headers
        unsigned char headers[LWS_PRE + 4096];
        unsigned char *p = headers + LWS_PRE;
        unsigned char *end = headers + sizeof(headers) - 1;

        if (lws_add_http_header_status(wsi, status_code, &p, end))
            return 1;

        // Standard headers
        std::string content_type = http_resp.body_msg_type.empty() ? "application/json" : http_resp.body_msg_type;
        if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE, (const unsigned char *)content_type.c_str(), (int)content_type.length(), &p, end))
            return 1;
        std::string content_length = std::to_string(http_resp.body.size());
        if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH, (const unsigned char *)content_length.c_str(), (int)content_length.length(), &p, end))
            return 1;

        // Custom headers (skip CT / CL)
        for (const auto &h : http_resp.headers)
        {
            std::string lower = h.first;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
            if (lower == "content-type" || lower == "content-length")
                continue;
            if (lws_add_http_header_by_name(wsi, (const unsigned char *)h.first.c_str(), (const unsigned char *)h.second.c_str(), (int)h.second.length(), &p, end))
                return 1;
        }

        if (lws_finalize_http_header(wsi, &p, end))
            return 1;

        // WRITE HEADERS
        int header_len = lws_ptr_diff(p, headers + LWS_PRE);
        int n = lws_write(wsi, headers + LWS_PRE, header_len, LWS_WRITE_HTTP_HEADERS);
        if (n < 0)
            return 1;

        // Buffer with LWS_PRE for BODY
        if (!http_resp.body.empty())
        {
            std::vector<unsigned char> body(LWS_PRE + http_resp.body.size());
            memcpy(body.data() + LWS_PRE, http_resp.body.data(), http_resp.body.size());
            n = lws_write(wsi, body.data() + LWS_PRE, http_resp.body.size(), LWS_WRITE_HTTP_FINAL);
            if (n < 0)
                return 1;
        }
        else
        {
            /* HTTP/2 requires explicit stream finalization */
            unsigned char dummy[LWS_PRE];
            lws_write(wsi, dummy + LWS_PRE, 0, LWS_WRITE_HTTP_FINAL);
        }

        // Cleanup after successful write
        pss->http_response_data->clear();
        pss->http_pending = false;

        // Close transaction (keep-alive handled by LWS automatically based on headers)
        if (lws_http_transaction_completed(wsi))
            return -1;

        return 0;
    }

    case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
    case LWS_CALLBACK_CLOSED_HTTP:
    {
        // CRITICAL: Destruct PSS
        if (pss)
            pss->~HttpSessionData();
        m_valid_http_wsi.erase(wsi);
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
        // Note: opaque_user_data is not avialable in this stage
        // header info is avialable here
        // auto ssnInfo = getSessionInfo(wsi);
        break;
    }

    case LWS_CALLBACK_ESTABLISHED:
        // Promote createSession to LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION for session validation
        // header info is not avialable here
        createSession(wsi);
        break;

    case LWS_CALLBACK_RECEIVE:
    {
        const bool is_first = lws_is_first_fragment(wsi);
        const bool is_final = lws_is_final_fragment(wsi);

        auto session = findSession(wsi);
        if (session)
        {
            auto full_data = session->onReceive(in, len, is_first, is_final);
            if (!full_data.empty())
            {
                WSRequest req;
                req.m_type = WSRequest::Type::WebSocketMessage;
                req.m_session_ref = wsi;
                req.m_payload = std::move(full_data);
                req.m_req_id = m_next_request_id.fetch_add(1, std::memory_order_relaxed);
                enqueueIncomingRequest(std::move(req));
            }
        }
        break;
    }

    case LWS_CALLBACK_SERVER_WRITEABLE:
    {
        auto session = findSession(wsi);
        if (!session)
            break;

        // Don't loop blindly. Check choked state effectively.
        while (session->hasOutgoingMessages())
        {
            auto *msg_ptr = session->peekOutgoingMessage();
            if (!msg_ptr || msg_ptr->size() <= LWS_PRE)
            {
                // Should not happen, but if it does, pop to avoid infinite loop
                session->advanceOutgoingMessage(msg_ptr ? msg_ptr->size() : 0);
                break;
            }

            size_t total_len = msg_ptr->size();
            size_t offset = session->getOutgoingMessageOffset();

            // Bounds check
            if (LWS_PRE + offset >= total_len)
            {
                // Logic error, force advance to pop
                session->advanceOutgoingMessage(total_len);
                break;
            }

            unsigned char *p = (unsigned char *)msg_ptr->data() + LWS_PRE + offset;
            size_t payload_left = (total_len - LWS_PRE) - offset;

            int sent = lws_write(wsi, p, payload_left, LWS_WRITE_BINARY);

            if (sent < 0)
                return -1; // Error closing

            session->advanceOutgoingMessage(sent);

            // If lws says choked, or we sent less than requested (partial), yield
            if (lws_send_pipe_choked(wsi) || static_cast<size_t>(sent) < payload_left)
            {
                lws_callback_on_writable(wsi); // Ensure we get called back
                break;                         // Yield to event loop
            }

            // If we finished the message, loop continues to try sending the next one
            // unless we want to yield to let other connections handle.
            // Usually good to break after a few writes or if nothing left.
        }
        break;
    }

    case LWS_CALLBACK_CLOSED:
    case LWS_CALLBACK_PROTOCOL_DESTROY: // Catch all closures
        destroySession(wsi);
        break;

    default:
        break;
    }

    return 0;
}

// -------------------------------
// Queue operations
// -------------------------------
void WebSocketService::enqueueOutgoingResponse(std::unique_ptr<WSResponse> &&resp)
{
    static const char fname[] = "WebSocketService::enqueueOutgoingResponse() ";

    if (!m_is_running.load())
    {
        LOG_WAR << fname << "lws is not running, dropping response";
        return;
    }

    // WS session validation
    if (resp->m_is_http == false && findSession((lws *)resp->m_session_ref) == nullptr)
    {
        LOG_WAR << fname << "WebSocket Session invalid or closed, dropping response";
        return;
    }

    struct lws_context *ctx = m_context.load();
    if (!ctx)
    {
        LOG_WAR << fname << "lws_context is not available, dropping response";
        return;
    }

    m_outgoing_queue.enqueue(std::move(resp));

    // Wake lws service so the IO loop will process the response
    lws_cancel_service(ctx);
}

void WebSocketService::enqueueIncomingRequest(WSRequest &&req)
{
    static const char fname[] = "WebSocketService::enqueueIncomingRequest() ";

    static bool use_this_worker_pool = !m_worker_threads.empty();

    LOG_DBG << fname << "Received (" << req.m_payload.size() << " bytes)";
    if (use_this_worker_pool)
    {
        m_incoming_queue.enqueue(std::move(req));
    }
    else
    {
        WORKER::instance()->queueLwsRequest(std::move(req.m_payload), req.m_session_ref);
    }
}

void WebSocketService::deliverResponse(const std::unique_ptr<WSResponse> &resp)
{
    // HTTP connections use HttpSessionData (per-connection user data), WebSocketSession in m_sessions
    struct lws *wsi = (struct lws *)resp->m_session_ref;

    if (resp->m_is_http)
    {
        if (m_valid_http_wsi.find(wsi) == m_valid_http_wsi.end())
        {
            LOG_WAR << "HTTP Session invalid or closed, dropping response";
            return;
        }

        auto *pss = static_cast<HttpSessionData *>(lws_wsi_user(wsi));
        if (!pss || !pss->http_pending)
            return;

        *(pss->http_response_data) = std::move(resp->m_payload);
        lws_callback_on_writable(wsi);
    }
    else
    {
        std::lock_guard<std::mutex> lock(m_sessions_mutex);
        // Verify the wsi is still in our map (Double check validity)
        auto it = m_sessions.find(wsi);
        if (it != m_sessions.end())
        {
            it->second->enqueueOutgoingMessage(std::move(resp->m_payload));
            lws_callback_on_writable(it->first);
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
        auto resp = std::make_unique<WSResponse>();
        resp->m_session_ref = ssn->getWsi();
        resp->m_payload.assign(msg.begin(), msg.end());
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

    while (m_is_running.load())
    {
        // Process ALL pending outgoing responses before servicing
        std::unique_ptr<WSResponse> resp;
        while (m_outgoing_queue.try_dequeue(resp) && m_is_running.load())
        {
            deliverResponse(resp);
        }

        // Load context atomically
        struct lws_context *ctx = m_context.load();
        if (!ctx)
            break;

        // Service the loop
        int result = lws_service(ctx, 0);
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

    m_context.store(nullptr);
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
        {
            // Closing
            break;
        }
        else if (req.m_type == WSRequest::Type::WebSocketMessage)
        {
            // WS messages require session
            if (auto session = findSession((lws *)req.m_session_ref))
                session->handleRequest(req);
        }
        else if (req.m_type == WSRequest::Type::HttpMessage)
        {
            // HTTP messages do not require session
            auto request = HttpRequest::deserialize(std::move(req.m_payload), -1, req.m_session_ref, nullptr);
            if (request)
                WORKER::instance()->process(request);
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

    // ALLOW_HTTP_ON_HTTPS_LISTENER for HTTP/2 support
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
                   LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE |
                   LWS_SERVER_OPTION_ALLOW_HTTP_ON_HTTPS_LISTENER;

    // For HTTP/2, we need to set ALPN protocols
    static const char *alpn_protos = "h2,http/1.1";
    info.alpn = alpn_protos;

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

    struct lws_context *ctx = lws_create_context(&info);
    if (!ctx)
    {
        throw std::runtime_error("lws_create_context failed");
        return false;
    }

    m_context.store(ctx);
    LOG_INF << fname << "lws_context created";
    return true;
}

// -------------------------------
// Static C callbacks (forwarders)
// -------------------------------
int WebSocketService::staticHttpCallback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
    const static char fname[] = "WebSocketService::staticHttpCallback() ";
    try
    {
        return instance()->handleHttpCallback(wsi, reason, user, in, len);
    }
    catch (const std::exception &e)
    {
        if (auto *pss = static_cast<HttpSessionData *>(user))
            pss->cleanup();
        LOG_ERR << fname << "Exception in HTTP Callback: " << e.what();
        return -1; // Close connection on exception
    }
    catch (...)
    {
        if (auto *pss = static_cast<HttpSessionData *>(user))
            pss->cleanup();
        LOG_ERR << fname << "Exception in HTTP Callback";
        return -1;
    }
}

int WebSocketService::staticWebSocketCallback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
    const static char fname[] = "WebSocketService::staticWebSocketCallback() ";
    try
    {
        return instance()->handleWebSocketCallback(wsi, reason, in, len);
    }
    catch (const std::exception &e)
    {
        LOG_ERR << fname << "Exception in WS Callback: " << e.what();
        instance()->destroySession(wsi); // Ensure cleanup
        return -1;
    }
    catch (...)
    {
        LOG_ERR << fname << "Exception in WS Callback";
        instance()->destroySession(wsi);
        return -1;
    }
}
