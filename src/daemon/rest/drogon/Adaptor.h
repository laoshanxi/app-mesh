// src/daemon/rest/drogon/Adaptor.h
#ifndef DROGON_ADAPTOR_H
#define DROGON_ADAPTOR_H

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <ace/INET_Addr.h>
#include <drogon/drogon.h>
#include <drogon/RequestStream.h>
#include <drogon/WebSocketConnection.h>

#include "../ReplyContext.h"

namespace dgn
{
    // Transport identity pinned at WS upgrade time; stored as the drogon
    // connection context.
    struct WsSession
    {
        std::string connId;
        uint64_t numericId{0};
        std::string peerAddress;
        std::string principalId;
    };

    // TLS hardening pairs shared by every listener: protocol floor, cipher
    // allow-list, and client-certificate verification when a CA is configured.
    // "require" also rejects a client without a certificate.
    std::vector<std::pair<std::string, std::string>> tlsHardeningConf(const std::string &caFile);
}

// Manages the Drogon HTTPS/WSS service: lifecycle, HTTP catch-all bridging
// into the shared msgpack worker queue, streaming file endpoints and the
// WebSocket connection registry.
class DrogonAdaptor
{
public:
    static DrogonAdaptor *instance()
    {
        static DrogonAdaptor inst;
        return &inst;
    }

    void initialize(const ACE_INET_Addr &addr, const std::string &cert, const std::string &key, const std::string &ca, int ioThreads);
    void start();
    void stop();

    // WS controller callbacks (run on drogon IO loop threads).
    void onWsOpen(const drogon::HttpRequestPtr &req, const drogon::WebSocketConnectionPtr &conn);
    void onWsMessage(const drogon::WebSocketConnectionPtr &conn, std::string &&message, drogon::WebSocketMessageType type);
    void onWsClose(const drogon::WebSocketConnectionPtr &conn);

private:
    DrogonAdaptor() = default;
    DrogonAdaptor(const DrogonAdaptor &) = delete;
    DrogonAdaptor &operator=(const DrogonAdaptor &) = delete;
    DrogonAdaptor(DrogonAdaptor &&) = delete;
    DrogonAdaptor &operator=(DrogonAdaptor &&) = delete;

    void setupRoutes();
    bool waitForLoopState(bool running, int timeoutMs);
    void handleHttpRequest(const drogon::HttpRequestPtr &req, drogon::RequestStreamPtr &&stream, drogon::AdviceCallback &&callback);
    void handleDownload(const drogon::HttpRequestPtr &req, drogon::AdviceCallback &&callback);
    void handleUpload(const drogon::HttpRequestPtr &req, drogon::RequestStreamPtr &&stream, drogon::AdviceCallback &&callback);

    std::shared_ptr<WSS::ReplyContext> createHttpReplyContext(drogon::AdviceCallback &&callback);
    std::shared_ptr<WSS::ReplyContext> createWebSocketReplyContext(const drogon::WebSocketConnectionPtr &conn,
                                                                   const std::shared_ptr<dgn::WsSession> &session);

    std::string m_host;
    int m_port{0};
    std::string m_certFile;
    std::string m_keyFile;
    std::string m_caFile;
    int m_ioThreads{1};

    std::atomic<bool> m_running{false};
    std::thread m_appThread;

    std::atomic<uint64_t> m_nextConnId{1};
    mutable std::mutex m_connMutex;
    std::unordered_map<std::string, drogon::WebSocketConnectionPtr> m_connections;
};
#endif
