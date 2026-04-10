// src/common/lwsservice/WebSocketClient.cpp
#include "WebSocketClient.h"
#include "../JwtHelper.h"
#include "../UriParser.hpp"

#include <chrono>
#include <cstring>
#include <thread>

constexpr int LWS_RX_BUFFER_SIZE = 8192;
constexpr size_t MAX_CLIENT_MSG_SIZE = 64 * 1024 * 1024; // 64 MB limit

// Protocol callback
int websocket_callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
    ProtocolSession *pss = static_cast<ProtocolSession *>(user);

    switch (reason)
    {
    // 1. handshake (handle auth)
    case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
    {
        unsigned char **p = (unsigned char **)in, *end = (*p) + len;

        Client *client = (Client *)lws_get_opaque_user_data(wsi);
        if (client && !client->m_config.auth_bearer_token.empty())
        {
            std::string jwt = JwtHelper::buildBearerAuthorization(client->m_config.auth_bearer_token);
            if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_AUTHORIZATION, (unsigned char *)jwt.c_str(), (int)jwt.size(), p, end))
            {
                return -1;
            }
        }
    }
    break;
    // 2. after handshake, before HTTP establish connection
    case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH:
        if (pss)
        {
            pss->client = (Client *)lws_get_opaque_user_data(wsi);
        }
        break;

    // 3. connection ready
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
        lwsl_user("CLIENT_ESTABLISHED\n");
        if (pss && pss->client)
        {
            pss->client->handleConnect();
        }
        break;
    // 4. receive data
    case LWS_CALLBACK_CLIENT_RECEIVE:
    {
        if (!pss || !pss->client)
            break;

        bool is_binary = lws_frame_is_binary(wsi);
        bool is_first = lws_is_first_fragment(wsi);
        bool is_final = lws_is_final_fragment(wsi);

        if (is_first)
        {
            pss->client->m_receive_buffer.clear();
        }

        if (pss->client->m_receive_buffer.size() + len > MAX_CLIENT_MSG_SIZE)
        {
            lwsl_err("Message size exceeded limit\n");
            return -1;
        }
        pss->client->m_receive_buffer.insert(
            pss->client->m_receive_buffer.end(),
            static_cast<uint8_t *>(in),
            static_cast<uint8_t *>(in) + len);

        if (is_final)
        {
            pss->client->handleMessage(
                pss->client->m_receive_buffer.data(),
                pss->client->m_receive_buffer.size(),
                is_binary);
        }
        break;
    }

    case LWS_CALLBACK_EVENT_WAIT_CANCELLED:
        if (pss && pss->client)
        {
            // Handle pending disconnect request on the IO thread
            if (pss->client->m_disconnect_requested.load())
            {
                pss->client->m_disconnect_requested.store(false);
                struct lws *cur_wsi = pss->client->m_wsi.load();
                pss->client->m_connected.store(false);
                pss->client->m_wsi.store(nullptr);
                if (cur_wsi)
                {
                    lws_set_opaque_user_data(cur_wsi, nullptr);
                    lws_set_timeout(cur_wsi, PENDING_TIMEOUT_CLOSE_ACK, 1);
                }
                break;
            }
            // Handle pending messages
            if (pss->client->hasMessages())
            {
                struct lws *cur_wsi = pss->client->m_wsi.load();
                if (cur_wsi)
                    lws_callback_on_writable(cur_wsi);
            }
        }
        break;

    case LWS_CALLBACK_CLIENT_WRITEABLE:
        if (pss && pss->client)
        {
            pss->client->handleWritable();
        }
        break;

    case LWS_CALLBACK_CLIENT_CLOSED:
        lwsl_user("CLIENT_CLOSED\n");
        if (pss && pss->client)
        {
            pss->client->m_wsi.store(nullptr);
            pss->client->handleDisconnect();
        }
        break;

    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        lwsl_err("CLIENT_CONNECTION_ERROR: %s\n", in ? (char *)in : "(null)");
        if (pss && pss->client)
        {
            pss->client->m_wsi.store(nullptr);
            pss->client->handleError(in ? (char *)in : "Connection error");
            pss->client->handleDisconnect();
        }
        break;

    default:
        break;
    }

    return 0;
}

// Client implementation
Client::Client()
    : m_context(nullptr), m_wsi(nullptr),
      m_connected(false), m_running(false),
      m_disconnect_requested(false), m_context_created(false)
{
}

Client::~Client()
{
    disconnect();
    if (m_event_thread)
    {
        // Wait for IO thread to process disconnect (bounded wait to avoid hang)
        for (int i = 0; i < 50 && m_connected.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    stop();
    destroyContext();
}

// Guard against setConfig after createContext
void Client::setConfig(const ConnectionConfig &config)
{
    if (m_context_created)
    {
        throw std::logic_error("Cannot call setConfig after context is created");
    }
    m_config = config;
}

void Client::onConnect(OnConnectCallback callback)
{
    std::lock_guard<std::mutex> lock(m_callback_mutex);
    m_on_connect = callback;
}

void Client::onDisconnect(OnDisconnectCallback callback)
{
    std::lock_guard<std::mutex> lock(m_callback_mutex);
    m_on_disconnect = callback;
}

void Client::onMessage(OnMessageCallback callback)
{
    std::lock_guard<std::mutex> lock(m_callback_mutex);
    m_on_message = callback;
}

void Client::onError(OnErrorCallback callback)
{
    std::lock_guard<std::mutex> lock(m_callback_mutex);
    m_on_error = callback;
}

bool Client::createContext()
{
    if (m_context.load())
        return true;

    // CLEAR and RESIZE the member vector
    m_protocols.clear();
    m_protocols.resize(2); // 1 for protocol, 1 for terminator

    // Configure Protocol 0
    m_protocols[0].name = m_config.protocol_name.c_str();
    m_protocols[0].callback = websocket_callback;
    m_protocols[0].per_session_data_size = sizeof(ProtocolSession);
    m_protocols[0].rx_buffer_size = LWS_RX_BUFFER_SIZE;
    m_protocols[0].id = 0;
    m_protocols[0].user = NULL;
    m_protocols[0].tx_packet_size = 0;

    // Configure Terminator
    m_protocols[1] = LWS_PROTOCOL_LIST_TERM;

    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));

    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = m_protocols.data();
    info.fd_limit_per_thread = 2 + 4; // small client usage
    info.timeout_secs = m_config.timeout_secs;
    info.gid = (gid_t)-1;
    info.uid = (uid_t)-1;

    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
                   LWS_SERVER_OPTION_H2_JUST_FIX_WINDOW_UPDATE_OVERFLOW;

    // SSL configuration
    if (m_config.ssl_config)
    {
        auto &ssl = *m_config.ssl_config;

        if (!ssl.m_certificate.empty())
            info.client_ssl_cert_filepath = ssl.m_certificate.c_str();
        if (!ssl.m_private_key.empty())
            info.client_ssl_private_key_filepath = ssl.m_private_key.c_str();
        if (!ssl.m_ca_location.empty())
            info.client_ssl_ca_filepath = ssl.m_ca_location.c_str();
        if (!ssl.m_private_key_passwd.empty())
            info.client_ssl_private_key_password = ssl.m_private_key_passwd.c_str();
    }

    lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, nullptr);

    auto *ctx = lws_create_context(&info);
    if (!ctx)
    {
        lwsl_err("lws_create_context failed\n");
        return false;
    }

    m_context.store(ctx);
    m_context_created = true;
    return true;
}

void Client::destroyContext()
{
    auto *ctx = m_context.exchange(nullptr);
    if (ctx)
    {
        lws_context_destroy(ctx);
    }
    m_context_created = false;
}

bool Client::connect()
{
    if (m_connected.load())
    {
        return true;
    }

    if (!createContext())
    {
        lwsl_err("Client::connect: createContext() failed\n");
        return false;
    }

    struct lws_client_connect_info info;
    memset(&info, 0, sizeof(info));

    auto u = Uri::parse(m_config.uri);
    std::string path_with_query = u.path;
    if (!u.query.empty())
    {
        path_with_query += "?" + u.query;
    }

    info.context = m_context.load();
    info.port = u.port;
    info.address = u.host.c_str();
    info.path = path_with_query.c_str();
    info.host = info.address;
    info.origin = info.address;
    info.protocol = m_config.protocol_name.c_str();
    info.ietf_version_or_minus_one = -1;
    info.opaque_user_data = this;

    // Use temp variable for pwsi since m_wsi is atomic
    struct lws *new_wsi = nullptr;
    info.pwsi = &new_wsi;

    // SSL configuration
    info.ssl_connection = 0;
    if (m_config.ssl_config)
    {
        info.ssl_connection = LCCSCF_USE_SSL;
        if (!m_config.ssl_config->m_verify_server)
        {
            info.ssl_connection |= LCCSCF_ALLOW_SELFSIGNED |
                                   LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
        }
    }

    lwsl_user("Connecting to %s:%d%s\n", info.address, info.port, info.path);

    // Auth: if you need HTTP Basic auth
    info.auth_username = m_config.auth_basic_username.empty() ? nullptr : m_config.auth_basic_username.c_str();
    info.auth_password = m_config.auth_basic_password.empty() ? nullptr : m_config.auth_basic_password.c_str();

    // Websocket reserved bits / unknown opcode behavior (default safe settings)
#if defined(LWS_ROLE_WS)
    info.allow_reserved_bits = 0;
    info.allow_unknown_opcode = 0;
#endif

    if (!lws_client_connect_via_info(&info))
    {
        lwsl_err("lws_client_connect_via_info failed\n");
        destroyContext();
        return false;
    }

    // Store atomically. Tiny race window with event loop reading m_wsi is benign:
    // EVENT_WAIT_CANCELLED checks m_wsi.load() and safely skips if still null.
    m_wsi.store(new_wsi);
    return true;
}

// Disconnect via IO thread to avoid calling non-thread-safe lws APIs
void Client::disconnect()
{
    if (!m_connected.load() && !m_wsi.load())
        return;

    m_disconnect_requested.store(true);
    auto *ctx = m_context.load();
    if (ctx)
        lws_cancel_service(ctx);
}

bool Client::isConnected() const
{
    return m_connected.load();
}

bool Client::sendText(const std::string &message)
{
    if (!m_connected.load() || !m_wsi.load())
        return false;

    enqueueMessage(Message(message));

    auto *ctx = m_context.load();
    if (ctx)
        lws_cancel_service(ctx);

    return true;
}

bool Client::sendBinary(const std::vector<std::uint8_t> &data)
{
    if (!m_connected.load() || !m_wsi.load())
        return false;

    enqueueMessage(Message(data));
    auto *ctx = m_context.load();
    if (ctx)
        lws_cancel_service(ctx);

    return true;
}

void Client::run()
{
    m_running.store(true);
    auto *ctx = m_context.load();
    while (m_running.load() && ctx && lws_service(ctx, 0) >= 0)
    {
        ctx = m_context.load();
    }
    // Handle unexpected exit (lws_service returned < 0)
    if (m_connected.exchange(false))
    {
        handleDisconnect();
    }
    m_running.store(false);
}

void Client::runAsync()
{
    if (m_event_thread)
    {
        return;
    }

    m_event_thread = std::make_shared<std::thread>([this]()
                                                   { run(); });
}

// Call lws_cancel_service to unblock lws_service before joining
void Client::stop()
{
    m_running.store(false);
    auto *ctx = m_context.load();
    if (ctx)
        lws_cancel_service(ctx);
    if (m_event_thread && m_event_thread->joinable())
    {
        m_event_thread->join();
        m_event_thread.reset();
    }
}

void Client::poll(int timeout_ms)
{
    auto *ctx = m_context.load();
    if (ctx)
    {
        lws_service(ctx, timeout_ms);
    }
}

void Client::handleConnect()
{
    m_connected.store(true);
    std::lock_guard<std::mutex> lock(m_callback_mutex);
    if (m_on_connect)
    {
        m_on_connect();
    }
}

void Client::handleDisconnect()
{
    m_connected.store(false);
    std::lock_guard<std::mutex> lock(m_callback_mutex);
    if (m_on_disconnect)
    {
        m_on_disconnect();
    }
}

void Client::handleMessage(const uint8_t *data, size_t length, bool is_binary)
{
    std::lock_guard<std::mutex> lock(m_callback_mutex);
    if (m_on_message)
    {
        m_on_message(data, length, is_binary);
    }
}

void Client::handleError(const std::string &error)
{
    std::lock_guard<std::mutex> lock(m_callback_mutex);
    if (m_on_error)
    {
        m_on_error(error);
    }
}

void Client::handleWritable()
{
    if (!hasMessages())
    {
        return;
    }

    Message msg = dequeueMessage();
    if (msg.data.empty())
    {
        return;
    }

    // Allocate buffer with LWS_PRE padding
    std::vector<std::uint8_t> buffer(LWS_PRE + msg.data.size());
    memcpy(buffer.data() + LWS_PRE, msg.data.data(), msg.data.size());

    // Determine write flags
    lws_write_protocol protocol = msg.is_binary ? LWS_WRITE_BINARY : LWS_WRITE_TEXT;

    struct lws *cur_wsi = m_wsi.load();
    if (!cur_wsi)
        return;

    int written = lws_write(cur_wsi, buffer.data() + LWS_PRE, msg.data.size(), protocol);
    if (written < 0)
    {
        lwsl_err("lws_write error\n");
        return;
    }

    // Request callback if more messages pending
    if (hasMessages())
    {
        lws_callback_on_writable(cur_wsi);
    }
}

void Client::enqueueMessage(const Message &msg)
{
    std::lock_guard<std::mutex> lock(m_queue_mutex);
    m_message_queue.push(msg);
}

Message Client::dequeueMessage()
{
    std::lock_guard<std::mutex> lock(m_queue_mutex);
    if (m_message_queue.empty())
    {
        return Message("");
    }
    Message msg = m_message_queue.front();
    m_message_queue.pop();
    return msg;
}

bool Client::hasMessages() const
{
    std::lock_guard<std::mutex> lock(m_queue_mutex);
    return !m_message_queue.empty();
}
