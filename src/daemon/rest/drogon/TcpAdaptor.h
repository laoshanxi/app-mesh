// src/daemon/rest/drogon/TcpAdaptor.h
#ifndef DROGON_TCP_ADAPTOR_H
#define DROGON_TCP_ADAPTOR_H

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include <ace/INET_Addr.h>
#include <trantor/net/TcpServer.h>

#include "../Data.h"
#include "FileTransferHandler.h"

// TLS TCP service carrying length-prefixed msgpack Request/Response frames
// (8-byte header: 4-byte magic + 4-byte body length, network byte order).
// Every accepted connection feeds the shared worker pool through a
// WSS::ReplyContext, so the request pipeline is identical to the WebSocket
// transport.
class TcpAdaptor
{
public:
    static TcpAdaptor *instance()
    {
        static TcpAdaptor inst;
        return &inst;
    }

    void initialize(const ACE_INET_Addr &addr, const std::string &cert, const std::string &key, const std::string &ca, int ioThreads);
    void start();
    void stop();

private:
    TcpAdaptor() = default;
    ~TcpAdaptor();
    TcpAdaptor(const TcpAdaptor &) = delete;
    TcpAdaptor &operator=(const TcpAdaptor &) = delete;
    TcpAdaptor(TcpAdaptor &&) = delete;
    TcpAdaptor &operator=(TcpAdaptor &&) = delete;

    // Transport identity pinned at accept time; stored as the connection context.
    struct Session
    {
        uint64_t numericId{0};
        std::string peerAddress;
        // Socket file upload/download state (X-Send/Recv-File-Socket).
        FileTransferHandler fileTransfer;
    };

    void onConnection(const trantor::TcpConnectionPtr &conn);
    void onMessage(const trantor::TcpConnectionPtr &conn, trantor::MsgBuffer *buf);
    void dispatch(const trantor::TcpConnectionPtr &conn, const std::shared_ptr<Session> &session, std::string &&data);

    std::string m_host;
    int m_port{0};
    std::string m_certFile;
    std::string m_keyFile;
    std::string m_caFile;
    int m_ioThreads{1};

    std::atomic<bool> m_running{false};
    std::unique_ptr<trantor::EventLoopThread> m_acceptThread;
    std::unique_ptr<trantor::TcpServer> m_server;

    std::atomic<uint64_t> m_nextConnId{1};
    std::mutex m_connMutex;
    std::unordered_map<uint64_t, trantor::TcpConnectionPtr> m_connections;
};
#endif
