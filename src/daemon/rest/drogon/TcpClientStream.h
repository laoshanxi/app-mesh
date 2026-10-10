// src/daemon/rest/drogon/TcpClientStream.h
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <msgpack.hpp>
#include <trantor/net/TcpClient.h>

// Outbound TLS client carrying the length-prefixed msgpack framing (see
// FrameCodec.h), used by ForwardingManager to reach a peer daemon's TCP API.
// Connections are spread over a process-wide event-loop pool.
class TcpClientStream : public std::enable_shared_from_this<TcpClientStream>
{
public:
    using DataCallback = std::function<void(std::vector<std::uint8_t> &&)>;
    using CloseCallback = std::function<void()>;

    TcpClientStream() = default;
    ~TcpClientStream() = default;

    TcpClientStream(const TcpClientStream &) = delete;
    TcpClientStream &operator=(const TcpClientStream &) = delete;

    // Both callbacks must be set before connect(); they fire on the shared
    // event loop thread.
    void onData(DataCallback cb) { m_dataCb = std::move(cb); }
    void onClose(CloseCallback cb) { m_closeCb = std::move(cb); }

    // Blocking connect (TLS handshake included), bounded by timeoutSeconds.
    // ca/verifyPeer mirror the forwarding client TLS configuration.
    bool connect(const std::string &host, int port, const std::string &ca, bool verifyPeer, int timeoutSeconds);

    bool send(const char *data, std::size_t len);
    bool send(const std::unique_ptr<msgpack::sbuffer> &data) { return data ? send(data->data(), data->size()) : false; }

    // Graceful close; the close callback fires when the teardown completes.
    void shutdown();
    bool connected() const { return m_connected.load(std::memory_order_acquire); }

private:
    void onClosed(const std::shared_ptr<TcpClientStream> &self);
    void onMessage(const trantor::TcpConnectionPtr &conn, trantor::MsgBuffer *buf);

    DataCallback m_dataCb;
    CloseCallback m_closeCb;

    // shared_ptr: trantor::TcpClient uses enable_shared_from_this internally.
    std::shared_ptr<trantor::TcpClient> m_client;
    std::mutex m_connMutex;
    trantor::TcpConnectionPtr m_conn; // set/cleared on the event loop, read by worker threads
    std::atomic<bool> m_connected{false};
};
