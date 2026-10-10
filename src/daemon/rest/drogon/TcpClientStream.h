// src/daemon/rest/drogon/TcpClientStream.h
#pragma once

#include <atomic>
#include <mutex>

#include <trantor/net/TcpClient.h>

#include "../ForwardingStream.h"

// Outbound TLS client carrying the length-prefixed msgpack framing (see
// FrameCodec.h), used by ForwardingManager to reach a peer daemon's TCP API.
// Connections are spread over a process-wide event-loop pool.
class TcpClientStream : public ForwardingStream, public std::enable_shared_from_this<TcpClientStream>
{
public:
    TcpClientStream() = default;
    ~TcpClientStream() override = default;

    TcpClientStream(const TcpClientStream &) = delete;
    TcpClientStream &operator=(const TcpClientStream &) = delete;

    // Both callbacks must be set before connect(); they fire on the shared
    // event loop thread.
    void onData(DataCallback cb) override { m_dataCb = std::move(cb); }
    void onClose(CloseCallback cb) override { m_closeCb = std::move(cb); }

    // Blocking connect (TLS handshake included). The peer does not authenticate
    // the connection itself, so options.bearer is unused here.
    bool connect(const ForwardingConnectOptions &options) override;

    bool send(const char *data, std::size_t len) override;

    // Graceful close; the close callback fires when the teardown completes.
    void shutdown() override;
    bool connected() const override { return m_connected.load(std::memory_order_acquire); }

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
