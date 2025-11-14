#include "WebSocketClient.h"
#include <cstring>
#include <iostream>

namespace WebSocket
{

    // ProtocolHandler implementation
    ProtocolHandler::ProtocolHandler(Client *client)
        : client_(client) {}

    int ProtocolHandler::callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
    {
        ProtocolHandler *handler = static_cast<ProtocolHandler *>(lws_get_protocol(wsi)->user);

        if (!handler || !handler->client_)
        {
            return lws_callback_http_dummy(wsi, reason, user, in, len);
        }

        switch (reason)
        {
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            lwsl_err("Connection error: %s\n", in ? (char *)in : "(null)");
            handler->client_->handleError(in ? (char *)in : "Connection error");
            handler->client_->handleDisconnect();
            break;

        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            lwsl_user("Connection established\n");
            handler->client_->handleConnect();
            break;

        case LWS_CALLBACK_CLIENT_RECEIVE:
        {
            bool is_binary = lws_frame_is_binary(wsi);

            if (lws_is_first_fragment(wsi))
            {
                handler->client_->receive_buffer_.clear();
            }

            handler->client_->receive_buffer_.insert(
                handler->client_->receive_buffer_.end(),
                static_cast<char *>(in),
                static_cast<char *>(in) + len);

            if (lws_is_final_fragment(wsi))
            {
                handler->client_->handleMessage(
                    reinterpret_cast<const uint8_t *>(handler->client_->receive_buffer_.data()),
                    handler->client_->receive_buffer_.size(),
                    is_binary);
            }
            break;
        }

        case LWS_CALLBACK_CLIENT_WRITEABLE:
            handler->client_->handleWritable();
            break;

        case LWS_CALLBACK_CLIENT_CLOSED:
            lwsl_user("Connection closed\n");
            handler->client_->handleDisconnect();
            break;

        default:
            break;
        }

        return lws_callback_http_dummy(wsi, reason, user, in, len);
    }

    void ProtocolHandler::enqueueMessage(const Message &msg)
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        message_queue_.push(msg);
    }

    Message ProtocolHandler::dequeueMessage()
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (message_queue_.empty())
        {
            return Message("");
        }
        Message msg = message_queue_.front();
        message_queue_.pop();
        return msg;
    }

    bool ProtocolHandler::hasMessages() const
    {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex &>(queue_mutex_));
        return !message_queue_.empty();
    }

    // Client implementation
    Client::Client()
        : context_(nullptr), wsi_(nullptr),
          connected_(false), running_(false)
    {
        protocol_handler_ = std::make_shared<ProtocolHandler>(this);
    }

    Client::~Client()
    {
        stop();
        disconnect();
        destroyContext();
    }

    void Client::setConfig(const ConnectionConfig &config)
    {
        config_ = config;
    }

    void Client::onConnect(OnConnectCallback callback)
    {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        on_connect_ = callback;
    }

    void Client::onDisconnect(OnDisconnectCallback callback)
    {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        on_disconnect_ = callback;
    }

    void Client::onMessage(OnMessageCallback callback)
    {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        on_message_ = callback;
    }

    void Client::onError(OnErrorCallback callback)
    {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        on_error_ = callback;
    }

    bool Client::createContext()
    {
        if (context_)
        {
            return true;
        }

        static struct lws_protocols protocols[] = {
            {nullptr, // Will be set to config_.protocol_name
             ProtocolHandler::callback,
             0,
             4096,
             0,
             nullptr,
             0},
            {nullptr, nullptr, 0, 0, 0, nullptr, 0} // Terminator
        };

        // Set protocol name and user data
        protocols[0].name = config_.protocol_name.c_str();
        protocols[0].user = protocol_handler_.get();

        struct lws_context_creation_info info;
        memset(&info, 0, sizeof(info));

        info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
        info.port = CONTEXT_PORT_NO_LISTEN;
        info.protocols = protocols;
        info.timeout_secs = config_.timeout_secs;
        info.fd_limit_per_thread = 1 + 1 + 1;

        lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, nullptr);

        context_ = lws_create_context(&info);
        if (!context_)
        {
            lwsl_err("Failed to create context\n");
            return false;
        }

        return true;
    }

    void Client::destroyContext()
    {
        if (context_)
        {
            lws_context_destroy(context_);
            context_ = nullptr;
        }
    }

    bool Client::connect()
    {
        if (connected_)
        {
            return true;
        }

        if (!createContext())
        {
            return false;
        }

        struct lws_client_connect_info connect_info;
        memset(&connect_info, 0, sizeof(connect_info));

        connect_info.context = context_;
        connect_info.address = config_.address.c_str();
        connect_info.port = config_.port;
        connect_info.path = config_.path.c_str();
        connect_info.host = connect_info.address;
        connect_info.origin = connect_info.address;
        connect_info.ssl_connection = config_.use_ssl ? LCCSCF_USE_SSL : 0;
        connect_info.protocol = config_.protocol_name.c_str();
        connect_info.pwsi = &wsi_;

        wsi_ = lws_client_connect_via_info(&connect_info);
        if (!wsi_)
        {
            lwsl_err("Client connect failed\n");
            return false;
        }

        return true;
    }

    void Client::disconnect()
    {
        if (wsi_)
        {
            lws_close_reason(wsi_, LWS_CLOSE_STATUS_NORMAL, nullptr, 0);
            wsi_ = nullptr;
        }
        connected_ = false;
    }

    bool Client::isConnected() const
    {
        return connected_;
    }

    bool Client::sendText(const std::string &message)
    {
        if (!connected_ || !wsi_)
        {
            return false;
        }

        protocol_handler_->enqueueMessage(Message(message));
        lws_callback_on_writable(wsi_);

        return true;
    }

    bool Client::sendBinary(const std::vector<uint8_t> &data)
    {
        if (!connected_ || !wsi_)
        {
            return false;
        }

        protocol_handler_->enqueueMessage(Message(data));
        lws_callback_on_writable(wsi_);

        return true;
    }

    void Client::run()
    {
        running_ = true;
        while (running_)
        {
            poll(50);
        }
    }

    void Client::runAsync()
    {
        if (event_thread_)
        {
            return;
        }

        event_thread_ = std::make_shared<std::thread>([this]()
                                                      { run(); });
    }

    void Client::stop()
    {
        running_ = false;
        if (event_thread_ && event_thread_->joinable())
        {
            event_thread_->join();
            event_thread_.reset();
        }
    }

    void Client::poll(int timeout_ms)
    {
        if (context_)
        {
            lws_service(context_, timeout_ms);
        }
    }

    void Client::handleConnect()
    {
        connected_ = true;
        std::lock_guard<std::mutex> lock(callback_mutex_);
        if (on_connect_)
        {
            on_connect_();
        }
    }

    void Client::handleDisconnect()
    {
        connected_ = false;
        std::lock_guard<std::mutex> lock(callback_mutex_);
        if (on_disconnect_)
        {
            on_disconnect_();
        }
    }

    void Client::handleMessage(const uint8_t *data, size_t length, bool is_binary)
    {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        if (on_message_)
        {
            on_message_(data, length, is_binary);
        }
    }

    void Client::handleError(const std::string &error)
    {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        if (on_error_)
        {
            on_error_(error);
        }
    }

    void Client::handleWritable()
    {
        if (!protocol_handler_->hasMessages())
        {
            return;
        }

        Message msg = protocol_handler_->dequeueMessage();
        if (msg.data.empty())
        {
            return;
        }

        // Allocate buffer with LWS_PRE padding
        std::vector<uint8_t> buffer(LWS_PRE + msg.data.size());
        memcpy(buffer.data() + LWS_PRE, msg.data.data(), msg.data.size());

        int written = lws_write(wsi_, buffer.data() + LWS_PRE,
                                msg.data.size(), msg.protocol);

        if (written < 0)
        {
            lwsl_err("Write failed\n");
            return;
        }

        // Request callback if more messages pending
        if (protocol_handler_->hasMessages())
        {
            lws_callback_on_writable(wsi_);
        }
    }

} // namespace WebSocket