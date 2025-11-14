// ws-service-example.cpp
//
// Production-grade libwebsockets WSS server (C++17)
// - WebSocketService: manages lws_context, event loop thread, sessions, worker pool
// - WebSocketSession: per-connection state with thread-safe message queue
// - ThreadSafeQueue: lock-based queue with timeout and stop notification
//
// Build:
//   g++ -std=c++17 ws-service-example.cpp -lwebsockets -lssl -lcrypto -lpthread -o wss_server
//   or: g++ ws-service-example.cpp $(pkg-config --cflags --libs libwebsockets openssl)
//
// Environment Setup:
//   sudo apt install libwebsockets-dev libssl-dev
//   vcpkg.exe install libwebsockets openssl
//
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <ctime>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <libwebsockets.h>

// -----------------------------------------------------------------------------
// Server Configuration
// -----------------------------------------------------------------------------
static constexpr int SERVER_PORT = 7681;
static constexpr int WORKER_THREAD_COUNT = 4;
static constexpr int BROADCAST_INTERVAL_SEC = 10;
static constexpr int WORKER_POLL_TIMEOUT_MS = 200;

static constexpr char const *TLS_CERT_PATH = "/opt/appmesh/ssl/server.pem";
static constexpr char const *TLS_KEY_PATH = "/opt/appmesh/ssl/server-key.pem";
static constexpr char const *TLS_CA_PATH = "/opt/appmesh/ssl/ca.pem";

// -----------------------------------------------------------------------------
// Embedded Static Assets
// -----------------------------------------------------------------------------
static char const *HTML_INDEX = R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>libwebsockets WSS Echo Demo</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
  <div class="container">
    <h1>🔒 libwebsockets WSS Echo Demo</h1>
    <div id="controls">
      <input id="messageInput" placeholder="Type a message...">
      <button id="sendBtn">Send</button>
    </div>
    <div id="serverMessage"><strong>Server Message:</strong> <span id="serverMsgText"></span></div>
    <div id="log"></div>
  </div>
  <script src="/script.js"></script>
</body>
</html>
)HTML";

static char const *CSS_STYLES = R"CSS(body{font-family:Arial;max-width:800px;margin:40px auto}#log{background:#eee;padding:10px;height:300px;overflow:auto})CSS";

static char const *JS_CLIENT = R"JS(
let ws=null, logDiv=null, input=null, btn=null;
function log(m){ if(!logDiv){ logDiv=document.getElementById('log'); } const e=document.createElement('div'); e.textContent=new Date().toLocaleTimeString()+' - '+m; logDiv.appendChild(e); logDiv.scrollTop=logDiv.scrollHeight; }
function send(){ if(ws && ws.readyState===WebSocket.OPEN){ ws.send(input.value); log('→ '+input.value); input.value=''; } }
window.addEventListener('load',()=>{ input=document.getElementById('messageInput'); btn=document.getElementById('sendBtn'); btn.onclick=send; log('connecting...'); const proto = location.protocol==='https:'? 'wss://' : 'ws://'; ws=new WebSocket(proto+location.host+'/ws','appmesh-ws'); ws.onopen=()=>{ log('connected'); ws.send('Hello from browser!'); }; ws.onmessage=(e)=>{ log('← '+e.data); }; ws.onclose=(ev)=>{ log('closed'); setTimeout(()=>location.reload(),2000); }; });
)JS";

static bool writeFile(const char *filename, const char *content)
{
    std::ofstream file(filename);
    if (!file.good())
        return false;
    file << content;
    return file.good();
}

// -----------------------------------------------------------------------------
// ThreadSafeQueue: generic thread-safe queue with optional timeout
// -----------------------------------------------------------------------------
template <typename T>
class ThreadSafeQueue
{
public:
    ThreadSafeQueue() = default;
    ThreadSafeQueue(const ThreadSafeQueue &) = delete;
    ThreadSafeQueue &operator=(const ThreadSafeQueue &) = delete;

    void push(T &&item)
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_queue.push(std::move(item));
        }
        m_condition.notify_one();
    }

    void push(const T &item)
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_queue.push(item);
        }
        m_condition.notify_one();
    }

    // Pops an item with optional timeout. Returns false if queue stopped or timeout expired.
    bool pop(T &output, int timeout_ms = -1)
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        if (timeout_ms < 0)
        {
            m_condition.wait(lock, [&]
                             { return !m_queue.empty() || m_is_stopped; });
        }
        else
        {
            if (!m_condition.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&]
                                      { return !m_queue.empty() || m_is_stopped; }))
                return false;
        }
        if (m_queue.empty())
            return false;
        output = std::move(m_queue.front());
        m_queue.pop();
        return true;
    }

    void stop()
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_is_stopped = true;
        }
        m_condition.notify_all();
    }

    bool empty() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_queue.empty();
    }

private:
    mutable std::mutex m_mutex;
    std::condition_variable m_condition;
    std::queue<T> m_queue;
    bool m_is_stopped = false;
};

// -----------------------------------------------------------------------------
// Message Types
// -----------------------------------------------------------------------------

struct WSResponse
{
    struct lws *m_wsi = nullptr;
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

    struct lws *m_wsi = nullptr;
    std::vector<std::uint8_t> m_payload;
    uint64_t m_req_id = 0;

    // Reply with a move-only payload (implementation expects a vector<uint8_t>)
    void reply(std::vector<std::uint8_t> &&data) const;
};

// Client connection information
struct WSSessionInfo
{
    std::string path;
    std::string query;
    std::string autherization;
};

struct Buffer
{
    std::vector<std::uint8_t> data;
};

// -----------------------------------------------------------------------------
// WebSocketSession: manages per-connection state
// -----------------------------------------------------------------------------
class WebSocketSession
{
public:
    explicit WebSocketSession(struct lws *wsi)
        : m_wsi(wsi), m_connected_at(std::time(nullptr)) {}

    ~WebSocketSession() = default;

    // Processes incoming request and generates response (echo for websocket messages)
    void handleRequest(const WSRequest &req)
    {
        std::string simulateRespData;
        if (req.m_type == WSRequest::Type::WebSocketMessage)
        {
            simulateRespData = "[Echo] Server Recieved: " + std::string(req.m_payload.begin(), req.m_payload.end());
        }
        else
        {
            simulateRespData = "HTTP response";
        }

        std::vector<std::uint8_t> respData;
        respData.assign(simulateRespData.begin(), simulateRespData.end());

        req.reply(std::move(respData));
    }

    bool verifySession(std::shared_ptr<WSSessionInfo> ssnInfo)
    {
        m_session_info = ssnInfo;
        // TODO: validate
        return true;
    }

    void enqueueOutgoingMessage(std::vector<std::uint8_t> &&msg)
    {
        std::lock_guard<std::mutex> lock(m_outgoing_mutex);
        m_outgoing_messages.push(std::move(msg));
    }

    void enqueueOutgoingMessage(const std::vector<std::uint8_t> &msg)
    {
        std::lock_guard<std::mutex> lock(m_outgoing_mutex);
        m_outgoing_messages.push(msg);
    }

    // Pop next outgoing message. Returns true if message obtained.
    // called by I/O thread when WSI is writable; returns next message to send or empty
    bool dequeueOutgoingMessage(std::vector<std::uint8_t> &output)
    {
        std::lock_guard<std::mutex> lock(m_outgoing_mutex);
        if (m_outgoing_messages.empty())
            return false;
        output = m_outgoing_messages.front();
        m_outgoing_messages.pop();
        return true;
    }

    bool hasOutgoingMessages() const
    {
        std::lock_guard<std::mutex> lock(m_outgoing_mutex);
        return !m_outgoing_messages.empty();
    }

    struct lws *getWsi() const { return m_wsi; }
    std::time_t getConnectionAt() const { return m_connected_at; }

    std::vector<std::uint8_t> onReceive(const void *in, size_t len, bool is_first, bool is_final)
    {
        if (is_first)
        {
            m_buffer.data.clear();
        }

        const char *p = static_cast<const char *>(in);
        m_buffer.data.insert(m_buffer.data.end(), p, p + len);

        if (is_final)
        {
            std::vector<std::uint8_t> out = std::move(m_buffer.data);
            return out;
        }

        return {}; // not finished
    }

private:
    struct lws *m_wsi;
    std::shared_ptr<WSSessionInfo> m_session_info;
    std::time_t m_connected_at;
    mutable std::mutex m_outgoing_mutex;
    std::queue<std::vector<std::uint8_t>> m_outgoing_messages;
    Buffer m_buffer;
};

// -----------------------------------------------------------------------------
// WebSocketService: manages lws_context, event loop, sessions, workers
// -----------------------------------------------------------------------------
class WebSocketService
{
public:
    explicit WebSocketService(int port = SERVER_PORT)
        : m_port(port), m_context(nullptr), m_is_running(false), m_next_request_id(1) {}

    ~WebSocketService() { shutdown(); }

    static WebSocketService *instance()
    {
        static WebSocketService instance;
        return &instance;
    }

    // Session management
    std::shared_ptr<WSSessionInfo> getSessionInfo(struct lws *wsi)
    {
        auto ssnInfo = std::make_shared<WSSessionInfo>();

        auto grab = [&](lws_token_indexes token, size_t bufSize) -> std::string
        {
            std::string out;
            out.resize(bufSize);

            int len = lws_hdr_copy(wsi, &out[0], bufSize, token);
            if (len <= 0)
                return {};

            if (static_cast<size_t>(len) >= bufSize)
                out[bufSize - 1] = '\0';

            return std::string(out.c_str()); // trim to actual length
        };

        ssnInfo->path = grab(WSI_TOKEN_GET_URI, 256);
        ssnInfo->query = grab(WSI_TOKEN_HTTP_URI_ARGS, 512);
        ssnInfo->autherization = grab(WSI_TOKEN_HTTP_AUTHORIZATION, 1024);

        std::cout << "LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION: <" << ssnInfo->path << "> <" << ssnInfo->query << "> <" << ssnInfo->autherization << ">\n";
        return ssnInfo;
    }

    std::shared_ptr<WebSocketSession> findSession(struct lws *wsi)
    {
        std::lock_guard<std::mutex> lock(m_sessions_mutex);
        auto it = m_sessions.find(wsi);
        if (it != m_sessions.end())
            return it->second;
        return nullptr;
    }

    std::shared_ptr<WebSocketSession> createSession(struct lws *wsi)
    {
        auto ssn = std::make_shared<WebSocketSession>(wsi);
        {
            std::lock_guard<std::mutex> lock(m_sessions_mutex);
            m_sessions.emplace(wsi, ssn);
        }

        std::cout << "[WebSocket] Connection established: " << wsi << " (total=" << m_sessions.size() << ")\n";
        return ssn;
    }

    void destroySession(struct lws *wsi)
    {
        std::lock_guard<std::mutex> lock(m_sessions_mutex);
        auto it = m_sessions.find(wsi);
        if (it == m_sessions.end())
        {
            std::cout << "[WebSocket] Session not found: " << wsi << "\n";
        }
        else
        {
            time_t duration = time(nullptr) - it->second->getConnectionAt();
            m_sessions.erase(it);
            std::cout << "Session destroyed: " << wsi << " (duration=" << duration << "s, sessions=" << m_sessions.size() << ")";
        }
    }

    // Initialize without TLS
    bool initialize(int port)
    {
        m_port = port;
        return initializeLwsContext(nullptr, nullptr, nullptr);
    }

    // Initialize with TLS
    bool initialize(int port, const std::string &cert_path, const std::string &key_path, const std::string &ca_path)
    {
        m_port = port;
        return initializeLwsContext(cert_path.c_str(), key_path.c_str(), ca_path.c_str());
    }

    // Start event loop and worker threads
    bool start(int worker_count = WORKER_THREAD_COUNT)
    {
        if (!m_context)
        {
            std::cerr << "[Service] Cannot start: lws_context not initialized\n";
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

        std::cout << "[Service] Started (port=" << m_port << ", workers=" << worker_count << ")\n";
        return true;
    }

    // Shutdown service gracefully
    void shutdown()
    {
        if (!m_is_running.exchange(false))
            return;

        std::cout << "[Service] Shutting down...\n";

        // Send sentinel values to wake up workers
        for (size_t i = 0; i < m_worker_threads.size(); ++i)
        {
            WSRequest sentinel;
            sentinel.m_wsi = nullptr; // Invalid request as signal
            m_incoming_queue.push(std::move(sentinel));
        }

        m_incoming_queue.stop();
        m_outgoing_queue.stop();

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

        std::cout << "[Service] Shutdown complete\n";
    }

    // HTTP callback handler: Called by C callbacks (HTTP)
    int handleHttpCallback(struct lws *wsi, enum lws_callback_reasons reason, void *in, size_t len)
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

    // Called by C callbacks (WebSocket)
    int handleWebSocketCallback(struct lws *wsi, enum lws_callback_reasons reason, void *in, size_t len)
    {
        switch (reason)
        {
        case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
        {
            // Note: opaque_user_data is not available in this stage
            auto ssn = createSession(wsi);
            if (!ssn->verifySession(getSessionInfo(wsi)))
            {
                return -1;
            }
            break;
        }
        case LWS_CALLBACK_ESTABLISHED:
        {
            // Promote createSession to LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION for session validation
            // header info is not available here
            break;
        }
        case LWS_CALLBACK_RECEIVE:
        {
            auto session = findSession(wsi);
            if (session)
            {
                bool is_first = lws_is_first_fragment(wsi) != 0;
                bool is_final = lws_is_final_fragment(wsi) != 0;
                auto full_data = session->onReceive(in, len, is_first, is_final);
                if (!full_data.empty())
                {
                    WSRequest req;
                    req.m_type = WSRequest::Type::WebSocketMessage;
                    req.m_wsi = wsi;
                    req.m_payload = std::move(full_data);
                    req.m_req_id = m_next_request_id.fetch_add(1, std::memory_order_relaxed);
                    enqueueIncomingRequest(std::move(req));
                }
            }
            break;
        }
        case LWS_CALLBACK_SERVER_WRITEABLE:
        {
            // Only the IO thread gets this callback; pop one message from session queue and send.
            auto session = findSession(wsi);
            if (!session)
                break;

            std::vector<std::uint8_t> msg;
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

    // Workers call this to notify there's a response to be sent
    void enqueueOutgoingResponse(WSResponse &&resp)
    {
        auto lswi = resp.m_wsi;
        if (!lswi || !m_context)
            return;

        m_outgoing_queue.push(std::move(resp));
        // Wake lws service so the IO loop will process the response
        lws_cancel_service(m_context);
    }

    // Enqueue incoming request into worker queue
    void enqueueIncomingRequest(WSRequest &&request)
    {
        std::cout << "[WebSocket] Received (" << request.m_payload.size() << " bytes): " << std::string(request.m_payload.begin(), request.m_payload.end()) << "\n";
        m_incoming_queue.push(std::move(request));
    }

private:
    // Send text message over WebSocket (called only from event loop thread)
    static int sendWebSocketMessage(struct lws *wsi, const std::vector<std::uint8_t> &msg)
    {
        if (!wsi || lws_get_protocol(wsi) == nullptr)
        {
            return -1;
        }

        size_t len = msg.size();
        std::vector<std::uint8_t> buffer(LWS_PRE + len);
        memcpy(buffer.data() + LWS_PRE, msg.data(), len);
        int bytes_written = lws_write(wsi, buffer.data() + LWS_PRE,
                                      static_cast<int>(len), LWS_WRITE_TEXT);
        return bytes_written;
    }

    // Deliver response to client by queueing and requesting writable callback
    void deliverResponse(WSResponse &&resp)
    {
        if (!resp.m_wsi)
            return;

        std::shared_ptr<WebSocketSession> session;
        {
            std::lock_guard<std::mutex> lock(m_sessions_mutex);
            auto it = m_sessions.find(resp.m_wsi);
            if (it == m_sessions.end())
            {
                std::cout << "[Service] Cannot deliver response: session not found for wsi=" << resp.m_wsi << "\n";
                return;
            }
            session = it->second;
        }
        // Now operate on session outside the lock - session won't be deleted due to shared_ptr

        session->enqueueOutgoingMessage(std::move(resp.m_payload));
        // request LWS to call SERVER_WRITEABLE for this wsi
        lws_callback_on_writable(resp.m_wsi);
    }

    // Broadcast helper (sends message to all connected sessions)
    void broadcastMessage(const std::string &msg)
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
            resp.m_payload.assign(msg.begin(), msg.end());
            enqueueOutgoingResponse(std::move(resp));
        }
    }

    // IO event loop single thread - processes lws events and outgoing responses
    void runIOEventLoop()
    {
        std::cout << "[EventLoop] Thread started\n";
        using Clock = std::chrono::steady_clock;
        auto last_broadcast_time = Clock::now();

        while (m_is_running)
        {
            // Process ALL pending outgoing responses before servicing
            WSResponse resp;
            while (m_outgoing_queue.pop(resp, 0))
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
            auto now = Clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_broadcast_time).count() >= BROADCAST_INTERVAL_SEC)
            {
                std::string broadcast_msg = "[Server] Heartbeat at " + std::to_string(std::time(nullptr));
                broadcastMessage(broadcast_msg);
                last_broadcast_time = now;
            }
        }

        std::cout << "[EventLoop] Thread stopped\n";
    }

    // Worker thread - processes incoming requests
    void runWorkerLoop(int worker_id)
    {
        std::cout << "[Worker-" << worker_id << "] Thread started\n";
        while (m_is_running)
        {
            WSRequest req;
            if (!m_incoming_queue.pop(req, WORKER_POLL_TIMEOUT_MS))
                continue;

            if (req.m_type == WSRequest::Type::Closing)
                break;

            if (!req.m_wsi)
                continue;

            auto session = findSession(req.m_wsi);
            if (!session)
                continue;

            session->handleRequest(req);
        }
        std::cout << "[Worker-" << worker_id << "] Thread stopped\n";
    }

    // Initialize lws_context with optional TLS
    bool initializeLwsContext(const char *cert_path, const char *key_path, const char *ca_path)
    {
        if (!writeFile("index.html", HTML_INDEX) ||
            !writeFile("style.css", CSS_STYLES) ||
            !writeFile("script.js", JS_CLIENT))
        {
            std::cerr << "[Service] Failed to write static asset files\n";
            return false;
        }

        static struct lws_protocols protocols[] = {
            {"http", &WebSocketService::staticHttpCallback, 0, 0, 0, nullptr, 0},
            {"appmesh-ws", &WebSocketService::staticWebSocketCallback, 0, 8192, 0, nullptr, 0},
            {nullptr, nullptr, 0, 0, 0, nullptr, 0}};

        struct lws_context_creation_info info;
        memset(&info, 0, sizeof(info));
        info.port = m_port;
        info.iface = nullptr;
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
            std::cerr << "[Service] Failed to create lws_context\n";
            return false;
        }

        std::cout << "[Service] lws_context created (port=" << m_port << ")\n";
        return true;
    }

    // Static C callbacks that forward to singleton instance
    static int staticHttpCallback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
    {
        return WebSocketService::instance()->handleHttpCallback(wsi, reason, in, len);
    }
    // Static C callbacks that forward to singleton instance
    static int staticWebSocketCallback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
    {
        return WebSocketService::instance()->handleWebSocketCallback(wsi, reason, in, len);
    }

private:
    int m_port;
    struct lws_context *m_context;

    std::thread m_event_loop_thread;
    std::vector<std::thread> m_worker_threads;

    ThreadSafeQueue<WSRequest> m_incoming_queue;
    ThreadSafeQueue<WSResponse> m_outgoing_queue;

    std::atomic<bool> m_is_running;
    std::atomic<uint64_t> m_next_request_id;

    mutable std::mutex m_sessions_mutex;
    std::unordered_map<struct lws *, std::shared_ptr<WebSocketSession>> m_sessions;
};

void WSRequest::reply(std::vector<std::uint8_t> &&data) const
{
    WSResponse resp;
    resp.m_wsi = m_wsi;
    resp.m_req_id = m_req_id;
    resp.m_payload = std::move(data);
    WebSocketService::instance()->enqueueOutgoingResponse(std::move(resp));
}

// -----------------------------------------------------------------------------
// main
// -----------------------------------------------------------------------------
int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    bool initialized = false;
    if (std::ifstream(TLS_CERT_PATH) && std::ifstream(TLS_KEY_PATH))
    {
        initialized = WebSocketService::instance()->initialize(SERVER_PORT, TLS_CERT_PATH, TLS_KEY_PATH, TLS_CA_PATH);
    }
    else
    {
        std::cout << "[Main] TLS certificates not found; starting without TLS\n";
        initialized = WebSocketService::instance()->initialize(SERVER_PORT);
    }

    if (!initialized)
    {
        std::cerr << "[Main] Failed to initialize WebSocketService\n";
        return 1;
    }

    if (!WebSocketService::instance()->start())
    {
        std::cerr << "[Main] Failed to start WebSocketService\n";
        return 1;
    }

    std::cout << "\n========================================\n";
    std::cout << "🚀 Server started successfully!\n";
    std::cout << "========================================\n";
    std::cout << "   HTTPS: https://localhost:" << SERVER_PORT << "/\n";
    std::cout << "   WSS:   wss://localhost:" << SERVER_PORT << "/ws\n";
    std::cout << "   Press Enter to shutdown...\n";
    std::cout << "========================================\n";

    std::string dummy;
    std::getline(std::cin, dummy);

    WebSocketService::instance()->shutdown();
    std::cout << "[Main] exited\n";
    return 0;
}
