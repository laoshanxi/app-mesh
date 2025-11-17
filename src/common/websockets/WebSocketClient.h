// WebSocketClient.h
#pragma once

#include <atomic>
#include <functional>
#include <libwebsockets.h>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include "../RestClient.h"

// Message structure for queuing outbound messages
struct Message
{
    std::vector<uint8_t> data;
    bool is_binary;

    Message(const std::string &text)
        : data(text.begin(), text.end()), is_binary(false) {}

    Message(const std::vector<uint8_t> &binary)
        : data(binary), is_binary(true) {}
};

// Connection configuration
struct ConnectionConfig
{
    ConnectionConfig()
        : protocol_name("appmesh-ws"), timeout_secs(60) {}

    std::string uri;
    std::shared_ptr<ClientSSLConfig> ssl_config;
    std::string protocol_name;
    int timeout_secs;

    std::string auth_basic_username;
    std::string auth_basic_password;
    std::string auth_bearer_token;
};

// Callback types
using OnConnectCallback = std::function<void()>;
using OnDisconnectCallback = std::function<void()>;
using OnMessageCallback = std::function<void(const uint8_t *data, size_t length, bool is_binary)>;
using OnErrorCallback = std::function<void(const std::string &error)>;

// Forward declaration
class Client;

// Per-session data (as in official examples)
struct ProtocolSession
{
    Client *client;
};

// Main WebSocket client class
class Client
{
public:
    Client();
    ~Client();

    // Prevent copying
    Client(const Client &) = delete;
    Client &operator=(const Client &) = delete;

    // Configuration
    void setConfig(const ConnectionConfig &config);

    // Callbacks
    void onConnect(OnConnectCallback callback);
    void onDisconnect(OnDisconnectCallback callback);
    void onMessage(OnMessageCallback callback);
    void onError(OnErrorCallback callback);

    // Connection management
    bool connect();
    void disconnect();
    bool isConnected() const;

    // Send messages
    bool sendText(const std::string &message);
    bool sendBinary(const std::vector<uint8_t> &data);

    // Event loop
    void run();
    void runAsync();
    void stop();
    void poll(int timeout_ms = 0);

private:
    friend int websocket_callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);

    void handleConnect();
    void handleDisconnect();
    void handleMessage(const uint8_t *data, size_t length, bool is_binary);
    void handleError(const std::string &error);
    void handleWritable();

    void enqueueMessage(const Message &msg);
    Message dequeueMessage();
    bool hasMessages() const;

    bool createContext();
    void destroyContext();

    ConnectionConfig m_config;
    struct lws_context *m_context;
    struct lws *m_wsi;

    std::atomic<bool> m_connected;
    std::atomic<bool> m_running;
    std::shared_ptr<std::thread> m_event_thread;

    OnConnectCallback m_on_connect;
    OnDisconnectCallback m_on_disconnect;
    OnMessageCallback m_on_message;
    OnErrorCallback m_on_error;

    std::vector<uint8_t> m_receive_buffer;
    std::queue<Message> m_message_queue;
    mutable std::mutex m_queue_mutex;
    std::mutex m_callback_mutex;
};
