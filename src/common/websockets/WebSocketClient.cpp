// WebSocketClient.cpp
#include "WebSocketClient.h"
#include "../UriParser.hpp"

#include <cstring>

constexpr int LWS_RX_BUFFER_SIZE = 8192;

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
            std::string jwt = "Bearer " + client->m_config.auth_bearer_token;
            if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_AUTHORIZATION, (unsigned char *)jwt.c_str(), (int)strlen(jwt.c_str()), p, end))
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
    // 4. recieve data
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
            pss->client->handleDisconnect();
        }
        break;

    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        lwsl_err("CLIENT_CONNECTION_ERROR: %s\n", in ? (char *)in : "(null)");
        if (pss && pss->client)
        {
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
      m_connected(false), m_running(false)
{
}

Client::~Client()
{
    stop();
    disconnect();
    destroyContext();
}

void Client::setConfig(const ConnectionConfig &config)
{
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
    if (m_context)
    {
        return true;
    }

    // Protocol definition
    static struct lws_protocols protocols[] = {
        {m_config.protocol_name.c_str(), // protocol name
         websocket_callback,
         sizeof(ProtocolSession),
         LWS_RX_BUFFER_SIZE,
         0, NULL, 0},
        LWS_PROTOCOL_LIST_TERM};

    // Update protocol name dynamically
    protocols[0].name = m_config.protocol_name.c_str();

    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));

    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
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

    m_context = lws_create_context(&info);
    if (!m_context)
    {
        lwsl_err("lws_create_context failed\n");
        return false;
    }

    return true;
}

void Client::destroyContext()
{
    if (m_context)
    {
        lws_context_destroy(m_context);
        m_context = nullptr;
    }
}

bool Client::connect()
{
    if (m_connected)
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

    info.context = m_context;
    info.port = u.port;
    info.address = u.host.c_str();
    info.path = path_with_query.c_str();
    info.host = info.address;
    info.origin = info.address;
    info.protocol = m_config.protocol_name.c_str();
    info.ietf_version_or_minus_one = -1;
    info.pwsi = &m_wsi;
    info.opaque_user_data = this;

    // SSL configuration
    info.ssl_connection = 0;
    if (m_config.ssl_config)
    {
        info.ssl_connection = LCCSCF_USE_SSL;
        // info.sys_tls_client_cert = 0; // 0 means don't use system client cert
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

    return true;
}

void Client::disconnect()
{
    struct lws *wsi_copy = m_wsi;
    m_connected = false;
    m_wsi = nullptr; // Clear pointer before timeout

    if (wsi_copy)
    {
        lws_set_opaque_user_data(wsi_copy, nullptr);
        lws_set_timeout(wsi_copy, PENDING_TIMEOUT_CLOSE_ACK, 1);
    }
}

bool Client::isConnected() const
{
    return m_connected;
}

bool Client::sendText(const std::string &message)
{
    if (!m_connected || !m_wsi)
    {
        return false;
    }

    enqueueMessage(Message(message));
    lws_callback_on_writable(m_wsi);

    return true;
}

bool Client::sendBinary(const std::vector<uint8_t> &data)
{
    if (!m_connected || !m_wsi)
    {
        return false;
    }

    enqueueMessage(Message(data));
    lws_callback_on_writable(m_wsi);

    return true;
}

void Client::run()
{
    m_running = true;
    while (m_running && !lws_service(m_context, 0))
    {
        // Event loop following official examples
    }
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

void Client::stop()
{
    m_running = false;
    if (m_event_thread && m_event_thread->joinable())
    {
        m_event_thread->join();
        m_event_thread.reset();
    }
}

void Client::poll(int timeout_ms)
{
    if (m_context)
    {
        lws_service(m_context, timeout_ms);
    }
}

void Client::handleConnect()
{
    m_connected = true;
    std::lock_guard<std::mutex> lock(m_callback_mutex);
    if (m_on_connect)
    {
        m_on_connect();
    }
}

void Client::handleDisconnect()
{
    m_connected = false;
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
    std::vector<uint8_t> buffer(LWS_PRE + msg.data.size());
    memcpy(buffer.data() + LWS_PRE, msg.data.data(), msg.data.size());

    // Determine write flags
    lws_write_protocol protocol = msg.is_binary ? LWS_WRITE_BINARY : LWS_WRITE_TEXT;

    int written = lws_write(m_wsi, buffer.data() + LWS_PRE, msg.data.size(), protocol);

    if (written < (int)msg.data.size())
    {
        lwsl_err("lws_write failed: %d\n", written);
        return;
    }

    // Request callback if more messages pending
    if (hasMessages())
    {
        lws_callback_on_writable(m_wsi);
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
