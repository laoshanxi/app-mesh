// main.cpp
//
// Optimized libwebsockets C++ example with modern architecture:
//  - Single dedicated I/O thread for libwebsockets event loop
//  - Separate worker thread pool for business logic processing
//  - HTTPS (TLS) server with proper SSL initialization
//  - HTTP endpoint "/" serves index.html with Set-Cookie header
//  - WebSocket protocol "appmesh-ws" with async processing
//  - Thread-safe message queue for cross-thread communication
//  - Comprehensive connection health monitoring and disconnect detection
//
// Compile:
//    g++ -std=c++17 main.cpp -lwebsockets -lssl -lcrypto -lpthread -o server
//    g++ main.cpp $(pkg-config --cflags --libs libwebsockets) $(pkg-config --cflags --libs openssl)

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <libwebsockets.h>
#include <openssl/ssl.h>

// ============================================================================
// Configuration Constants
// ============================================================================

static const int SERVER_PORT = 7681;
static const int NUM_WORKER_THREADS = 4;
static const char *SERVER_CERT = "/opt/appmesh/ssl/server.pem";
static const char *SERVER_KEY = "/opt/appmesh/ssl/server-key.pem";
static const int CONNECTION_TIMEOUT_SEC = 30; // Connection timeout in seconds

// ============================================================================
// HTML Content
// ============================================================================

static const char *INDEX_HTML = R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>libwebsockets WSS Echo Demo</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
    <div class="container">
        <h1>🔒 libwebsockets WSS Echo Demo</h1>
        <div id="controls">
            <input type="text" id="messageInput" placeholder="Type a message..." />
            <button id="sendBtn">Send</button>
        </div>
        <div id="serverMessage">
            <strong>Server Message:</strong> <span id="serverMsgText"></span>
        </div>
        <div id="log"></div>
    </div>
    
    <script src="/script.js"></script>
</body>
</html>
)HTML";

static const char *STYLE_CSS = R"CSS(body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    max-width: 800px;
    margin: 50px auto;
    padding: 20px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
}
.container {
    background: rgba(255, 255, 255, 0.1);
    border-radius: 10px;
    padding: 30px;
    backdrop-filter: blur(10px);
    box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
}
h1 {
    margin-top: 0;
    text-align: center;
    font-size: 2em;
}
#log {
    background: rgba(0, 0, 0, 0.3);
    padding: 15px;
    border-radius: 5px;
    max-height: 400px;
    overflow-y: auto;
    margin-top: 20px;
    font-family: 'Courier New', monospace;
}
.log-entry {
    padding: 8px;
    margin: 5px 0;
    border-left: 3px solid #4CAF50;
    background: rgba(255, 255, 255, 0.05);
    border-radius: 3px;
}
.log-sent { border-left-color: #2196F3; }
.log-received { border-left-color: #4CAF50; }
.log-error { border-left-color: #f44336; }
#controls {
    margin-top: 20px;
    display: flex;
    gap: 10px;
}
input {
    flex: 1;
    padding: 10px;
    border: none;
    border-radius: 5px;
    font-size: 14px;
}
button {
    padding: 10px 20px;
    background: #4CAF50;
    color: white;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    font-size: 14px;
    transition: background 0.3s;
}
button:hover {
    background: #45a049;
}
button:disabled {
    background: #cccccc;
    cursor: not-allowed;
}
#serverMessage {
    margin-top: 15px;
    padding: 10px;
    background: rgba(255, 255, 0, 0.2);
    border-radius: 5px;
    display: none;
}
)CSS";

static const char *SCRIPT_JS = R"JS(
let ws = null;
const logDiv = document.getElementById('log');
const messageInput = document.getElementById('messageInput');
const sendBtn = document.getElementById('sendBtn');
const serverMessageDiv = document.getElementById('serverMessage');
const serverMsgText = document.getElementById('serverMsgText');
let pingInterval = null;
let lastActivityTime = null;
let connectionActive = false;

function log(message, type = 'info') {
    const entry = document.createElement('div');
    entry.className = 'log-entry log-' + type;
    entry.textContent = new Date().toLocaleTimeString() + ' - ' + message;
    logDiv.appendChild(entry);
    logDiv.scrollTop = logDiv.scrollHeight;
}

function updateConnectionStatus() {
    const statusElement = document.getElementById('connectionStatus') || (function() {
        const elem = document.createElement('div');
        elem.id = 'connectionStatus';
        elem.className = 'connection-status';
        document.body.insertBefore(elem, document.body.firstChild);
        return elem;
    })();
    
    if (connectionActive && lastActivityTime) {
        const timeSinceActivity = Date.now() - lastActivityTime;
        statusElement.innerHTML = `Connection: <span style="color: green">✓ Active</span> | Last activity: ${Math.floor(timeSinceActivity/1000)}s ago`;
        statusElement.className = 'connection-status connected';
        
        // Warn if no activity for too long
        if (timeSinceActivity > 12000) {
            statusElement.innerHTML += ' <span style="color: orange">(Idle)</span>';
        }
    } else {
        statusElement.innerHTML = `Connection: <span style="color: red">✗ Disconnected</span>`;
        statusElement.className = 'connection-status disconnected';
    }
}

function connectWebSocket() {
    const protocol = location.protocol === 'https:' ? 'wss://' : 'ws://';
    const url = protocol + location.host + '/ws';
    
    log('Connecting to ' + url + '...');
    ws = new WebSocket(url, 'appmesh-ws');
    
    ws.onopen = function() {
        log('✓ WebSocket connection established', 'received');
        sendBtn.disabled = false;
        connectionActive = true;
        lastActivityTime = Date.now();
        
        // Start activity monitoring
        startActivityMonitor();
        
        // Send initial handshake
        ws.send('Hello from browser!');
    };
    
    ws.onmessage = function(event) {
        const message = event.data;
        lastActivityTime = Date.now();
        
        // Check if it's a server message or an echo
        if (message.startsWith('[Server] ')) {
            serverMessageDiv.style.display = 'block';
            serverMsgText.textContent = message.substring(9);
            log('← Received: ' + message, 'received');
        } else {
            log('← Received: ' + message, 'received');
        }
    };
    
    ws.onclose = function(event) {
        log('✗ WebSocket connection closed: ' + (event.reason || 'No reason provided') + ' (code: ' + event.code + ')', 'error');
        sendBtn.disabled = true;
        connectionActive = false;
        stopActivityMonitor();
        setTimeout(connectWebSocket, 2000);
    };
    
    ws.onerror = function(error) {
        log('✗ WebSocket error occurred', 'error');
        connectionActive = false;
        stopActivityMonitor();
    };
}

function startActivityMonitor() {
    // Clear existing interval
    if (pingInterval) {
        clearInterval(pingInterval);
    }
    
    // Update connection status every second
    setInterval(updateConnectionStatus, 1000);
}

function stopActivityMonitor() {
    if (pingInterval) {
        clearInterval(pingInterval);
        pingInterval = null;
    }
}

function sendMessage() {
    const message = messageInput.value.trim();
    if (message && ws && ws.readyState === WebSocket.OPEN) {
        ws.send(message);
        lastActivityTime = Date.now();
        log('→ Sent: ' + message, 'sent');
        messageInput.value = '';
    }
}

// Add event listeners
sendBtn.addEventListener('click', sendMessage);
messageInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        sendMessage();
    }
});

// Start connection after page load
window.addEventListener('load', function() {
    log('Page loaded, cookie set by server');
    setTimeout(connectWebSocket, 500);
});

// Remove the 30-second server message interval since we have keep-alive
)JS";

// ============================================================================
// Thread-Safe Request Queue
// ============================================================================

template <typename T>
class ThreadSafeQueue
{
public:
    ThreadSafeQueue() = default;
    ThreadSafeQueue(const ThreadSafeQueue &) = delete;
    ThreadSafeQueue &operator=(const ThreadSafeQueue &) = delete;

    // Push by value or move
    void push(T &&value)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push(std::move(value));
        }
        cv_.notify_one();
    }

    void push(const T &value)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push(value);
        }
        cv_.notify_one();
    }

    // Blocking pop with optional timeout (ms)
    bool pop(T &value, int timeout_ms = -1)
    {
        std::unique_lock<std::mutex> lock(mutex_);

        const auto pred = [this]
        { return !queue_.empty() || stopped_; };

        if (timeout_ms < 0)
        {
            cv_.wait(lock, pred);
        }
        else
        {
            if (!cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), pred))
                return false; // timeout
        }

        if (stopped_ && queue_.empty())
            return false;

        value = std::move(queue_.front());
        queue_.pop();
        return true;
    }

    // Non-blocking pop
    bool try_pop(T &value)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty())
            return false;
        value = std::move(queue_.front());
        queue_.pop();
        return true;
    }

    void stop()
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopped_ = true;
        }
        cv_.notify_all();
    }

    bool stopped() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return stopped_;
    }

    size_t size() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    bool empty() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<T> queue_;
    bool stopped_ = false;
};

// ============================================================================
// Request and WSResponse Structures
// ============================================================================

struct WSRequest
{
    enum Type
    {
        WEBSOCKET_MESSAGE,
        HTTP_REQUEST
    };

    Type type;
    struct lws *wsi;
    std::string data;
    uint64_t task_id;
};

struct WSResponse
{
    struct lws *wsi;
    std::string data;
    uint64_t task_id;
};

// ============================================================================
// WebSocket Session Data
// ============================================================================

struct WebSocketSession
{
    bool writable = false;
    std::queue<std::string> pending_resp_msgs;
    time_t connected_at = 0;
};

// ============================================================================
// Worker Thread Pool
// ============================================================================

class WorkerThreadPool
{
public:
    WorkerThreadPool(int num_threads, ThreadSafeQueue<WSResponse> &response_queue)
        : response_queue_(response_queue), running_(true)
    {

        for (int i = 0; i < num_threads; ++i)
        {
            workers_.emplace_back([this, i]()
                                  { this->workerThread(i); });
        }
    }

    ~WorkerThreadPool()
    {
        shutdown();
    }

    void submitTask(WSRequest task)
    {
        task_queue_.push(std::move(task));
    }

    void shutdown()
    {
        if (running_.exchange(false))
        {
            task_queue_.stop();
            for (auto &worker : workers_)
            {
                if (worker.joinable())
                {
                    worker.join();
                }
            }
        }
    }

private:
    void workerThread(int thread_id)
    {
        std::cout << "[Worker-" << thread_id << "] Started\n";

        while (running_)
        {
            WSRequest task;
            if (!task_queue_.pop(task, 100))
            {
                continue;
            }

            // Process the task (simulate work)
            std::string result;

            switch (task.type)
            {
            case WSRequest::WEBSOCKET_MESSAGE:
                // Check if it's a server message request
                if (task.data.find("[Server]") != std::string::npos)
                {
                    // This is a server message, just pass it through
                    result = task.data;
                }
                else
                {
                    result = "[Echo] " + task.data;
                    std::cout << "[Worker-" << thread_id << "] Processed WS message: " << task.data << "\n";
                }
                break;

            case WSRequest::HTTP_REQUEST:
                result = "HTTP response from worker";
                break;
            }

            // Send the echo response back to I/O thread
            WSResponse response;
            response.wsi = task.wsi;
            response.data = std::move(result);
            response.task_id = task.task_id;
            response_queue_.push(std::move(response));

            // Trigger callback on libwebsockets context
            lws_cancel_service(lws_get_context(task.wsi));
        }

        std::cout << "[Worker-" << thread_id << "] Stopped\n";
    }

    ThreadSafeQueue<WSRequest> task_queue_;
    ThreadSafeQueue<WSResponse> &response_queue_;
    std::vector<std::thread> workers_;
    std::atomic<bool> running_;
};

// ============================================================================
// Global State
// ============================================================================

static ThreadSafeQueue<WSResponse> g_response_queue;
static std::unique_ptr<WorkerThreadPool> g_worker_pool;
static std::atomic<uint64_t> g_request_id_counter{0};
static std::mutex g_sessions_mutex;
static std::unordered_map<struct lws *, std::unique_ptr<WebSocketSession>> g_sessions;

// ============================================================================
// Helper Functions
// ============================================================================

static int sendWebSocketData(struct lws *wsi, const std::string &msg)
{
    size_t len = msg.size();
    std::vector<unsigned char> buf(LWS_PRE + len);

    memcpy(buf.data() + LWS_PRE, msg.data(), len);

    int n = lws_write(wsi, buf.data() + LWS_PRE, len, LWS_WRITE_TEXT);
    return n;
}

static void replyWebSocketMessage(struct lws *wsi, const std::string &msg)
{
    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    auto it = g_sessions.find(wsi);
    if (it != g_sessions.end())
    {
        it->second->pending_resp_msgs.push(msg);
        lws_callback_on_writable(wsi);
    }
}

// Function to broadcast a message to all connected clients
static void broadcastMessage(const std::string &msg)
{
    // Collect all ws handles while holding the lock
    std::vector<struct lws *> clients_to_broadcast;
    {
        std::lock_guard<std::mutex> lock(g_sessions_mutex);
        for (const auto &pair : g_sessions)
        {
            clients_to_broadcast.push_back(pair.first);
        }
    }

    // Now broadcast to each client without holding the global lock
    for (auto client_wsi : clients_to_broadcast)
    {
        replyWebSocketMessage(client_wsi, msg);
    }
}

// ============================================================================
// Protocol Callbacks
// ============================================================================

static int callbackHttp(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
    (void)user;

    switch (reason)
    {
    case LWS_CALLBACK_ADD_HEADERS:
    {
        // Add Set-Cookie header
        auto *args = static_cast<lws_process_html_args *>(in);
        unsigned char *p = reinterpret_cast<unsigned char *>(args->p);
        unsigned char *end = p + args->max_len;

        const auto cookie = std::string("sessionid=secure_") + std::to_string(time(nullptr));
        std::string cookie_header = "sessionid=secure_" +
                                    std::to_string(time(nullptr)) +
                                    "; Path=/; HttpOnly; Secure; SameSite=Strict";

        if (lws_add_http_header_by_name(wsi,
                                        reinterpret_cast<const unsigned char *>("set-cookie:"),
                                        reinterpret_cast<const unsigned char *>(cookie_header.c_str()),
                                        static_cast<int>(cookie_header.length()),
                                        &p, end))
        {
            lwsl_err("Failed to add Set-Cookie header\n");
            return -1;
        }

        args->p = reinterpret_cast<char *>(p);
        return 0;
    }

    case LWS_CALLBACK_HTTP:
    {
        char uri[256];
        int n = lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_GET_URI);

        if (n > 0)
        {
            std::cout << "[HTTP] Request for URI: " << uri << "\n";
        }
        else
        {
            strncpy(uri, "/", sizeof(uri));
        }

        if (strcmp(uri, "/") == 0 || strcmp(uri, "/index.html") == 0)
        {
            // Serve the index.html file
            if (lws_serve_http_file(wsi, "index.html", "text/html; charset=utf-8", nullptr, 0) < 0)
            {
                lwsl_err("Failed to serve index.html\n");
                return -1;
            }
            return 0;
        }
        else if (strcmp(uri, "/style.css") == 0)
        {
            // Serve the CSS file
            if (lws_serve_http_file(wsi, "style.css", "text/css", nullptr, 0) < 0)
            {
                lwsl_err("Failed to serve style.css\n");
                return -1;
            }
            return 0;
        }
        else if (strcmp(uri, "/script.js") == 0)
        {
            // Serve the JavaScript file
            if (lws_serve_http_file(wsi, "script.js", "application/javascript", nullptr, 0) < 0)
            {
                lwsl_err("Failed to serve script.js\n");
                return -1;
            }
            return 0;
        }

        // 404 for other paths
        lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, nullptr);
        return -1;
    }

    case LWS_CALLBACK_CLOSED_HTTP:
        std::cout << "[HTTP] Connection closed: " << wsi << "\n";
        break;

    case LWS_CALLBACK_HTTP_FILE_COMPLETION:
        std::cout << "[HTTP] File transfer completed: " << wsi << "\n";
        break;

    default:
        break;
    }

    return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int callbackAppMeshWS(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
    (void)user;

    switch (reason)
    {
    case LWS_CALLBACK_ESTABLISHED:
    {
        std::lock_guard<std::mutex> lock(g_sessions_mutex);
        g_sessions[wsi] = std::unique_ptr<WebSocketSession>(new WebSocketSession());
        g_sessions[wsi]->writable = false;
        g_sessions[wsi]->connected_at = time(nullptr);

        std::cout << "[WebSocket] Connection established: " << wsi << " (total connections: " << g_sessions.size() << ")\n";
        break;
    }

    case LWS_CALLBACK_SERVER_WRITEABLE:
    {
        std::lock_guard<std::mutex> lock(g_sessions_mutex);
        auto it = g_sessions.find(wsi);
        if (it == g_sessions.end())
        {
            return 0;
        }

        auto &session = it->second;
        if (!session->pending_resp_msgs.empty())
        {
            std::string msg = std::move(session->pending_resp_msgs.front());
            session->pending_resp_msgs.pop();

            if (sendWebSocketData(wsi, msg) < 0)
            {
                lwsl_err("Failed to send message\n");
                return -1;
            }

            // If more messages pending, request writable again
            if (!session->pending_resp_msgs.empty())
            {
                lws_callback_on_writable(wsi);
            }
        }
        break;
    }

    case LWS_CALLBACK_RECEIVE:
    {
        std::string message(static_cast<const char *>(in), len);
        std::cout << "[WebSocket] Received (" << len << " bytes): " << message << "\n";

        // Submit task to worker pool
        WSRequest task;
        task.type = WSRequest::WEBSOCKET_MESSAGE;
        task.wsi = wsi;
        task.data = std::move(message);
        task.task_id = g_request_id_counter.fetch_add(1);

        g_worker_pool->submitTask(std::move(task));
        break;
    }

    case LWS_CALLBACK_CLOSED:
    {
        std::lock_guard<std::mutex> lock(g_sessions_mutex);
        auto it = g_sessions.find(wsi);
        if (it != g_sessions.end())
        {
            time_t duration = time(nullptr) - it->second->connected_at;
            std::cout << "[WebSocket] Connection closed: " << wsi
                      << " (duration: " << duration << "s, total connections: "
                      << (g_sessions.size() - 1) << ")\n";
            g_sessions.erase(it);
        }
        else
        {
            std::cout << "[WebSocket] Connection closed (unknown session): " << wsi << "\n";
        }
        break;
    }

    case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
        std::cout << "[WebSocket] Peer initiated close: " << wsi << "\n";
        break;

    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        std::cout << "[WebSocket] Connection error: " << wsi << "\n";
        break;

    case LWS_CALLBACK_TIMER:
    {
        std::cout << "[WebSocket] Timer callback (simulating ping): " << wsi << "\n";
        break;
    }

    case LWS_CALLBACK_SSL_INFO:
    {
        std::cout << "[WebSocket] SSL info (simulating pong): " << wsi << "\n";
        break;
    }

    case LWS_CALLBACK_GS_EVENT:
        // Generic event - can be used for various purposes
        std::cout << "[WebSocket] Generic event for connection: " << wsi << "\n";
        break;

    default:
        break;
    }

    return 0;
}

// ============================================================================
// I/O Thread
// ============================================================================

static void ioThread(struct lws_context *context, std::atomic<bool> &running)
{
    std::cout << "[I/O Thread] Started\n";

    // Timer for periodic server messages
    auto last_server_msg = std::chrono::steady_clock::now();

    while (running.load())
    {
        // Service libwebsockets (50ms timeout)
        int n = lws_service(context, 50);
        if (n < 0)
        {
            lwsl_err("lws_service returned error: %d\n", n);
            break;
        }

        // Send periodic server messages (every 10 seconds)
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_server_msg).count() >= 10)
        {
            std::string server_msg = "[Server] Hello from server at " + std::to_string(std::time(nullptr));
            broadcastMessage(server_msg);
            last_server_msg = now;
        }

        // Process pending responses from worker threads
        WSResponse response;
        while (g_response_queue.pop(response, 0))
        {
            std::cout << "[I/O Thread] Processing response for task " << response.task_id << "\n";

            // Queue the message to be sent when writable
            replyWebSocketMessage(response.wsi, response.data);
        }
    }

    std::cout << "[I/O Thread] Stopped\n";
}

// ============================================================================
// Main Function
// ============================================================================

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    // Write index.html to disk
    {
        FILE *f = fopen("index.html", "wb");
        if (!f)
        {
            perror("Failed to create index.html");
            return 1;
        }
        fwrite(INDEX_HTML, 1, strlen(INDEX_HTML), f);
        fclose(f);
        std::cout << "[Init] Created index.html\n";
    }

    // Write style.css to disk
    {
        FILE *f = fopen("style.css", "wb");
        if (!f)
        {
            perror("Failed to create style.css");
            return 1;
        }
        fwrite(STYLE_CSS, 1, strlen(STYLE_CSS), f);
        fclose(f);
        std::cout << "[Init] Created style.css\n";
    }

    // Write script.js to disk
    {
        FILE *f = fopen("script.js", "wb");
        if (!f)
        {
            perror("Failed to create script.js");
            return 1;
        }
        fwrite(SCRIPT_JS, 1, strlen(SCRIPT_JS), f);
        fclose(f);
        std::cout << "[Init] Created script.js\n";
    }

    // Initialize OpenSSL
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
    std::cout << "[Init] OpenSSL initialized\n";

    // Define protocols
    static struct lws_protocols protocols[] = {
        {
            "http",       // name
            callbackHttp, // callback
            0,            // per_session_data_size
            0,            // rx_buffer_size
            0,            // id
            nullptr,      // user
            0             // tx_packet_size
        },
        {
            "appmesh-ws",      // name
            callbackAppMeshWS, // callback
            0,                 // per_session_data_size
            4096,              // rx_buffer_size
            0,                 // id
            nullptr,           // user
            0                  // tx_packet_size
        },
        {nullptr, nullptr, 0, 0, 0, nullptr, 0} // terminator
    };

    // Setup context creation info
    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));

    info.port = SERVER_PORT;
    info.iface = nullptr;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
                   LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE |
                   LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED;

    // SSL configuration
    info.ssl_cert_filepath = SERVER_CERT;
    info.ssl_private_key_filepath = SERVER_KEY;

    // Performance and timeout tuning
    info.fd_limit_per_thread = 1024;
    info.max_http_header_pool = 32;
    info.timeout_secs = 30;

    // Keepalive settings
    info.ka_time = 60;
    info.ka_probes = 3;
    info.ka_interval = 5;

    // Enable ping-pong keepalive
    static lws_retry_bo_t retry = {};
    retry.secs_since_valid_ping = 15;   /* if idle, PINGREQ after secs */
    retry.secs_since_valid_hangup = 20; /* hangup if still idle secs */
    info.retry_and_idle_policy = &retry;

    // Create libwebsockets context
    struct lws_context *context = lws_create_context(&info);
    if (!context)
    {
        std::cerr << "[Error] Failed to create libwebsockets context\n";
        return 1;
    }

    std::cout << "\n========================================\n";
    std::cout << "🚀 Server started successfully!\n";
    std::cout << "========================================\n";
    std::cout << "   HTTPS: https://localhost:" << SERVER_PORT << "/\n";
    std::cout << "   WSS:   wss://localhost:" << SERVER_PORT << "/ws\n";
    std::cout << "   Workers: " << NUM_WORKER_THREADS << " threads\n";
    std::cout << "   Timeout: " << CONNECTION_TIMEOUT_SEC << " seconds\n";
    std::cout << "========================================\n\n";

    // Start worker thread pool
    g_worker_pool = std::unique_ptr<WorkerThreadPool>(new WorkerThreadPool(NUM_WORKER_THREADS, g_response_queue));

    // Start I/O thread
    std::atomic<bool> running{true};
    std::thread io_thread(ioThread, context, std::ref(running));

    // Wait for user to press Enter
    std::cout << "Press Enter to shutdown server...\n";
    getchar();

    // Shutdown sequence
    std::cout << "\n[Shutdown] Initiating graceful shutdown...\n";
    running.store(false);

    // Stop worker pool
    g_worker_pool->shutdown();
    g_worker_pool.reset();

    // Stop response queue
    g_response_queue.stop();

    // Wait for I/O thread
    if (io_thread.joinable())
    {
        io_thread.join();
    }

    // Destroy libwebsockets context
    lws_context_destroy(context);

    std::cout << "[Shutdown] Server stopped cleanly\n";
    return 0;
}