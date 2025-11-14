#ifndef WEBSOCKET_CLIENT_H
#define WEBSOCKET_CLIENT_H

#include <atomic>
#include <functional>
#include <libwebsockets.h>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

namespace WebSocket
{

    // Message structure for queuing outbound messages
    struct Message
    {
        std::vector<uint8_t> data;
        lws_write_protocol protocol;

        Message(const std::string &text)
            : data(text.begin(), text.end()), protocol(LWS_WRITE_TEXT) {}

        Message(const std::vector<uint8_t> &binary)
            : data(binary), protocol(LWS_WRITE_BINARY) {}
    };

    // Connection configuration
    struct ConnectionConfig
    {
        std::string address;
        std::string path;
        int port;
        bool use_ssl;
        std::string protocol_name;
        int timeout_secs;

        ConnectionConfig()
            : path("/"), port(443), use_ssl(true),
              protocol_name("default"), timeout_secs(10) {}
    };

    // Callback types
    using OnConnectCallback = std::function<void()>;
    using OnDisconnectCallback = std::function<void()>;
    using OnMessageCallback = std::function<void(const uint8_t *data, size_t length, bool is_binary)>;
    using OnErrorCallback = std::function<void(const std::string &error)>;

    // Forward declaration
    class Client;

    // Internal protocol handler
    class ProtocolHandler
    {
    public:
        ProtocolHandler(Client *client);

        static int callback(struct lws *wsi, enum lws_callback_reasons reason,
                            void *user, void *in, size_t len);

        void enqueueMessage(const Message &msg);
        Message dequeueMessage();
        bool hasMessages() const;

    private:
        Client *client_;
        std::queue<Message> message_queue_;
        std::mutex queue_mutex_;
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
        friend class ProtocolHandler;

        void handleConnect();
        void handleDisconnect();
        void handleMessage(const uint8_t *data, size_t length, bool is_binary);
        void handleError(const std::string &error);
        void handleWritable();

        bool createContext();
        void destroyContext();

        ConnectionConfig config_;
        struct lws_context *context_;
        struct lws *wsi_;
        std::shared_ptr<ProtocolHandler> protocol_handler_;

        std::atomic<bool> connected_;
        std::atomic<bool> running_;
        std::shared_ptr<std::thread> event_thread_;

        OnConnectCallback on_connect_;
        OnDisconnectCallback on_disconnect_;
        OnMessageCallback on_message_;
        OnErrorCallback on_error_;

        std::vector<char> receive_buffer_;
        std::mutex callback_mutex_;
    };

} // namespace WebSocket

#endif // WEBSOCKET_CLIENT_H