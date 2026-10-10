// src/daemon/rest/drogon/TcpAdaptor.cpp
#include "TcpAdaptor.h"

#include <algorithm>

#include <trantor/net/EventLoopThread.h>
#include <trantor/utils/MsgBuffer.h>

#include "../../../common/StreamLogger.h"
#include "../../../common/Utility.h"
#include "../EventDispatcher.h"
#include "../ReplyContext.h"
#include "../Worker.h"
#include "Adaptor.h" // dgn::tlsHardeningConf
#include "FrameCodec.h"

namespace
{
    constexpr std::size_t MAX_TCP_CONNECTIONS = 10000;
    // Above one maximum frame, so a legal large reply always enqueues in full.
    constexpr std::size_t SEND_BUFFER_HIGH_WATER = tcpframe::MAX_FRAME_BODY_SIZE + 1024 * 1024;
    // Keep TCP ids disjoint from the WebSocket id space.
    constexpr uint64_t TCP_CONNECTION_ID_FLAG = 1ULL << 63;
}

TcpAdaptor::~TcpAdaptor() = default;

void TcpAdaptor::initialize(const ACE_INET_Addr &addr, const std::string &cert, const std::string &key, const std::string &ca, int ioThreads)
{
    const static char fname[] = "TcpAdaptor::initialize() ";

    m_host = addr.get_host_addr();
    m_port = addr.get_port_number();
    m_certFile = cert;
    m_keyFile = key;
    m_caFile = ca;
    m_ioThreads = std::max(1, ioThreads);

    LOG_INF << fname << "initialized with " << m_ioThreads << " I/O threads on port " << m_port;
}

void TcpAdaptor::start()
{
    const static char fname[] = "TcpAdaptor::start() ";

    if (m_running.exchange(true))
        return;

    m_acceptThread = std::make_unique<trantor::EventLoopThread>("appmesh-tcp");
    m_acceptThread->run();

    trantor::InetAddress listenAddr(m_host, static_cast<uint16_t>(m_port), m_host.find(':') != std::string::npos);
    m_server = std::make_unique<trantor::TcpServer>(m_acceptThread->getLoop(), listenAddr, "appmesh-tcp");
    m_server->setIoLoopNum(static_cast<size_t>(m_ioThreads));
    m_server->setConnectionCallback(
        [this](const trantor::TcpConnectionPtr &conn)
        { onConnection(conn); });
    m_server->setRecvMessageCallback(
        [this](const trantor::TcpConnectionPtr &conn, trantor::MsgBuffer *buf)
        { onMessage(conn, buf); });
    // A vanished peer without a FIN must still release its session.
    m_server->setAfterAcceptSockOptCallback([](int fd) { tcpframe::enableKeepAlive(fd); });

    // TLS: PEM files, cipher hardening, and client-certificate verification
    // when a CA is configured. "require" also rejects a client without a cert.
    auto policy = trantor::TLSPolicy::defaultServerPolicy(m_certFile, m_keyFile);
    policy->setConfCmds(dgn::tlsHardeningConf(m_caFile));
    m_server->enableSSL(policy);

    // A bind/listen failure aborts the process (trantor logs and exits),
    // keeping startup fail-fast.
    m_server->start();

    LOG_INF << fname << "TCP service started on <" << m_host << ":" << m_port << ">";
}

void TcpAdaptor::stop()
{
    const static char fname[] = "TcpAdaptor::stop() ";

    if (!m_running.exchange(false))
        return;

    try
    {
        if (m_server)
        {
            // Blocks until the acceptor is destroyed and all connections close.
            m_server->stop();
            m_server.reset();
        }
        m_acceptThread.reset();

        {
            std::lock_guard lock(m_connMutex);
            m_connections.clear();
        }
        LOG_INF << fname << "TCP service stopped.";
    }
    catch (const std::exception &e)
    {
        LOG_ERR << fname << "exception while stopping: " << e.what();
    }
    catch (...)
    {
        LOG_ERR << fname << "unknown exception while stopping";
    }
}

void TcpAdaptor::onConnection(const trantor::TcpConnectionPtr &conn)
{
    const static char fname[] = "TcpAdaptor::onConnection() ";

    // An exception escaping into the trantor loop terminates the process.
    try
    {
        if (conn->connected())
        {
            auto session = std::make_shared<Session>();
            session->numericId = TCP_CONNECTION_ID_FLAG | m_nextConnId.fetch_add(1, std::memory_order_relaxed);
            session->peerAddress = conn->peerAddr().toIp();

            {
                std::lock_guard lock(m_connMutex);
                if (m_connections.size() >= MAX_TCP_CONNECTIONS)
                {
                    LOG_WAR << fname << "connection limit reached (" << MAX_TCP_CONNECTIONS << "), rejecting connection";
                    conn->forceClose();
                    return;
                }
                conn->setContext(session);
                m_connections[session->numericId] = conn;
            }
            conn->setTcpNoDelay(true);
            conn->setHighWaterMarkCallback(
                [](const trantor::TcpConnectionPtr &c, std::size_t)
                {
                    const static char fname[] = "TcpAdaptor::onConnection() ";
                    // Guarded: forceClose queues into the loop and can allocate.
                    try
                    {
                        c->forceClose();
                    }
                    catch (...)
                    {
                        LOG_ERR << fname << "exception while closing a stuck connection";
                    }
                },
                SEND_BUFFER_HIGH_WATER);
            LOG_DBG << fname << "new connection from <" << session->peerAddress << ">";
        }
        else
        {
            if (conn->hasContext())
            {
                auto session = conn->getContext<Session>();
                if (session)
                {
                    {
                        std::lock_guard lock(m_connMutex);
                        m_connections.erase(session->numericId);
                    }
                    EventDispatcher::instance()->removeByConnection(ConnectionKey::wss(session->numericId));
                    LOG_DBG << fname << "connection from <" << session->peerAddress << "> closed";
                }
            }
        }
    }
    catch (const std::exception &e)
    {
        LOG_ERR << fname << "exception: " << e.what();
        conn->forceClose();
    }
    catch (...)
    {
        LOG_ERR << fname << "unknown exception, closing connection";
        conn->forceClose();
    }
}

void TcpAdaptor::onMessage(const trantor::TcpConnectionPtr &conn, trantor::MsgBuffer *buf)
{
    const static char fname[] = "TcpAdaptor::onMessage() ";

    // Runs in a trantor I/O loop; an escaping exception terminates the
    // process. A throw on this path leaves the frame unconsumed, so the stream
    // position is undefined and the connection must close.
    try
    {
        auto session = conn->getContext<Session>();
        if (!session)
        {
            conn->forceClose();
            return;
        }

        const bool ok = tcpframe::drainFrames(*buf,
                                              [&](const char *payload, uint32_t bodyLen)
                                              {
                                                  std::string data(payload, bodyLen);

                                                  // Socket file transfer: while an upload is armed the payload is raw
                                                  // file data (an empty frame commits it), not a msgpack request.
                                                  {
                                                      std::lock_guard lock(session->fileTransfer.transfer_mutex());
                                                      if (session->fileTransfer.onFrameReceived(data, static_cast<int>(session->numericId & ~TCP_CONNECTION_ID_FLAG)))
                                                          return;
                                                  }
                                                  // An empty frame outside a transfer carries no request payload.
                                                  if (bodyLen == 0)
                                                      return;
                                                  dispatch(conn, session, std::move(data));
                                              });
        if (!ok)
        {
            LOG_WAR << fname << "invalid frame header from <" << session->peerAddress << ">, closing connection";
            conn->forceClose();
        }
    }
    catch (const std::exception &e)
    {
        LOG_ERR << fname << "exception: " << e.what();
        conn->forceClose();
    }
    catch (...)
    {
        LOG_ERR << fname << "unknown exception, closing connection";
        conn->forceClose();
    }
}

void TcpAdaptor::dispatch(const trantor::TcpConnectionPtr &conn, const std::shared_ptr<Session> &session, std::string &&data)
{
    const static char fname[] = "TcpAdaptor::dispatch() ";

    // The frame is consumed; a failure drops only this request.
    try
    {
        auto replyCtx = std::make_shared<WSS::ReplyContext>(
            WSS::ReplyContext::ProtocolType::Framed,
            [conn, session](std::string &&data, const std::string &, const WSS::ReplyContext::Headers &, const std::string &, bool /*isLast*/, bool /*isBinary*/)
            {
                const static char fname[] = "TcpAdaptor::dispatch() ";
                // Worker thread: do not let an exception escape the reply path.
                try
                {
                    // send() is thread-safe; header and body share one buffer.
                    if (!conn || !conn->connected())
                        return;
                    trantor::MsgBuffer frame;
                    tcpframe::appendFrame(frame, data.data(), data.size());
                    conn->send(std::move(frame));
                    // An armed socket download streams after this frame.
                    std::lock_guard lock(session->fileTransfer.transfer_mutex());
                    session->fileTransfer.startDownload(conn, static_cast<int>(session->numericId & ~TCP_CONNECTION_ID_FLAG));
                }
                catch (const std::exception &e)
                {
                    LOG_ERR << fname << "exception while sending reply: " << e.what();
                }
                catch (...)
                {
                    LOG_ERR << fname << "unknown exception while sending reply";
                }
            },
            "appmesh-tcp-" + std::to_string(session->numericId & ~TCP_CONNECTION_ID_FLAG),
            session->numericId,
            session->peerAddress);

        // An undecodable request has no uuid to answer with, so the worker aborts
        // the context. Close the connection instead of leaving the peer waiting.
        replyCtx->setAbortHook(
            [conn]()
            {
                if (!conn)
                    return;
                if (auto *loop = conn->getLoop()) // forceClose() runs on its own loop
                    loop->queueInLoop([conn]() { conn->forceClose(); });
            });

        // Socket file transfer: inspect the reply headers (and possibly amend the
        // response) before it is serialized, arming upload/download state.
        replyCtx->setResponseObserver(
            [session](Response &resp)
            {
                std::lock_guard lock(session->fileTransfer.transfer_mutex());
                session->fileTransfer.prepareTransfer(resp, static_cast<int>(session->numericId & ~TCP_CONNECTION_ID_FLAG));
            });

        WORKER::instance()->queueWsRequest(std::move(data), std::move(replyCtx));
    }
    catch (const std::exception &e)
    {
        LOG_ERR << fname << "exception: " << e.what();
    }
    catch (...)
    {
        LOG_ERR << fname << "unknown exception";
    }
}
