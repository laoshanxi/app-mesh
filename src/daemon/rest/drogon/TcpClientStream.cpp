// src/daemon/rest/drogon/TcpClientStream.cpp
#include "TcpClientStream.h"

#include <chrono>
#include <future>
#include <thread>

#include <trantor/net/EventLoopThreadPool.h>

#include "../../../common/StreamLogger.h"
#include "../../../common/Utility.h"
#include "../../Configuration.h"
#include "FrameCodec.h"

namespace
{
    // Connections are spread over an event-loop pool so one busy peer cannot
    // serialize the rest. A connection binds to one loop for its lifetime.
    trantor::EventLoop *forwardingLoop(const std::string &key)
    {
        static auto pool = []()
        {
            auto created = std::make_shared<trantor::EventLoopThreadPool>(
                Configuration::instance()->getTransportIoThreads(), "appmesh-fwd");
            created->start();
            return created;
        }();

        const auto index = std::hash<std::string>{}(key) % pool->size();
        auto *loop = pool->getLoop(index);
        while (loop == nullptr) // pool threads still starting up
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        return loop;
    }

}

bool TcpClientStream::connect(const ForwardingConnectOptions &options)
{
    const static char fname[] = "TcpClientStream::connect() ";

    const std::string &host = options.host;
    const int port = options.port;
    const std::string &ca = options.ca;
    const bool verifyPeer = options.verifyPeer;
    const int timeoutSeconds = options.timeoutSeconds;

    // trantor::InetAddress takes numeric addresses only; the name stays for the TLS check below.
    std::string resolveError;
    const std::string ip = Utility::resolveHostAddress(host, resolveError);
    if (ip.empty())
    {
        LOG_ERR << fname << "Cannot resolve forwarding host <" << host << ">: " << resolveError;
        return false;
    }
    const bool ipv6 = ip.find(':') != std::string::npos;

    auto result = std::make_shared<std::promise<bool>>();
    auto completed = std::make_shared<std::atomic<bool>>(false);
    std::weak_ptr<TcpClientStream> weakSelf = shared_from_this();

    // enableSSL() builds the TLS context synchronously and can throw.
    try
    {
        // trantor::TcpClient uses enable_shared_from_this internally.
        m_client = std::make_shared<trantor::TcpClient>(forwardingLoop(host + ":" + std::to_string(port)), trantor::InetAddress(ip, static_cast<uint16_t>(port), ipv6), "appmesh-forward");

        m_client->setConnectionCallback(
            [weakSelf, result, completed](const trantor::TcpConnectionPtr &conn)
            {
                auto self = weakSelf.lock();
                if (conn->connected())
                {
                    if (self)
                    {
                        std::lock_guard<std::mutex> lock(self->m_connMutex);
                        self->m_conn = conn;
                        self->m_connected.store(true, std::memory_order_release);
                    }
                    if (!completed->exchange(true))
                        result->set_value(true);
                }
                else
                {
                    if (self)
                        self->onClosed(self);
                    if (!completed->exchange(true))
                        result->set_value(false);
                }
            });
        m_client->setConnectionErrorCallback(
            [result, completed]()
            {
                if (!completed->exchange(true))
                    result->set_value(false);
            });
        m_client->setMessageCallback(
            [weakSelf](const trantor::TcpConnectionPtr &conn, trantor::MsgBuffer *buf)
            {
                if (auto self = weakSelf.lock())
                    self->onMessage(conn, buf);
            });

        auto policy = std::make_shared<trantor::TLSPolicy>();
        policy->setValidate(verifyPeer).setUseOldTLS(false).setUseSystemCertStore(false).setHostname(host);
        if (verifyPeer && !ca.empty())
            policy->setCaPath(ca);
        if (!options.clientCert.empty() && !options.clientKey.empty())
            policy->setCertPath(options.clientCert).setKeyPath(options.clientKey);
        m_client->enableSSL(policy);
        m_client->setSockOptCallback([](int fd) { tcpframe::enableKeepAlive(fd); });
    }
    catch (const std::exception &ex)
    {
        // A failed outbound connect must never take the daemon down.
        LOG_ERR << fname << "Cannot create a client for <" << host << ":" << port << ">: " << ex.what();
        return false;
    }

    try
    {
        m_client->connect();
    }
    catch (const std::exception &ex)
    {
        LOG_ERR << fname << "Connect to <" << host << ":" << port << "> failed: " << ex.what();
        return false;
    }

    auto future = result->get_future();
    if (future.wait_for(std::chrono::seconds(timeoutSeconds)) != std::future_status::ready)
    {
        LOG_WAR << fname << "Connect to <" << host << ":" << port << "> timed out after " << timeoutSeconds << "s";
        m_client->stop();
        return false;
    }
    return future.get();
}

void TcpClientStream::onClosed(const std::shared_ptr<TcpClientStream> &self)
{
    {
        std::lock_guard<std::mutex> lock(m_connMutex);
        m_conn.reset();
    }
    m_connected.store(false, std::memory_order_release);

    if (m_closeCb)
        m_closeCb();

    // Defer releasing this reference to the next loop turn: the close callback
    // may drop the last owner, and destroying the stream (and its trantor
    // client) inside trantor's own callback stack is not safe.
    if (m_client && m_client->getLoop())
        m_client->getLoop()->queueInLoop([self]() {});
}

void TcpClientStream::onMessage(const trantor::TcpConnectionPtr &conn, trantor::MsgBuffer *buf)
{
    const static char fname[] = "TcpClientStream::onMessage() ";

    try
    {
        const bool ok = tcpframe::drainFrames(*buf,
                                              [this](const char *payload, uint32_t len)
                                              {
                                                  // An empty frame carries no response payload.
                                                  if (len > 0 && m_dataCb)
                                                      m_dataCb(std::vector<std::uint8_t>(payload, payload + len));
                                              });
        if (!ok)
        {
            LOG_WAR << fname << "Invalid frame header from forwarding peer, closing connection";
            conn->forceClose();
        }
    }
    catch (const std::exception &ex)
    {
        // Do not let a reply-path exception terminate the event loop.
        LOG_ERR << fname << "exception: " << ex.what();
    }
    catch (...)
    {
        LOG_ERR << fname << "unknown exception";
    }
}

bool TcpClientStream::send(const char *data, std::size_t len)
{
    trantor::TcpConnectionPtr conn;
    {
        std::lock_guard<std::mutex> lock(m_connMutex);
        conn = m_conn;
    }
    if (!conn || !conn->connected())
    {
        // Tear down: the close path fails pending requests, the next one reconnects.
        shutdown();
        return false;
    }

    trantor::MsgBuffer frame;
    tcpframe::appendFrame(frame, data, len);
    conn->send(std::move(frame));
    return true;
}

void TcpClientStream::shutdown()
{
    m_connected.store(false, std::memory_order_release);
    if (m_client)
        m_client->disconnect();
}
