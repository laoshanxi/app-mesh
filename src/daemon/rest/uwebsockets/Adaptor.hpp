#include "WSService.h"

#include <chrono>
#include <condition_variable>
#include <csignal>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string_view>
#include <thread>

#include "../../../common/Utility.h"
#include "../../Configuration.h"
#include "../TcpServer.h"

using json = nlohmann::json;

namespace WSS
{
    WSS::SSLContextOptions ssl;
    std::shared_ptr<WSS::SSLServer> server;

    void start(std::shared_ptr<Configuration> config, int ioThreadNum)
    {
        const static char fname[] = "WSS::start() ";

        // SSL
        ssl.cert_file_name = config->getSSLCertificateFile();
        ssl.key_file_name = config->getSSLCertificateKeyFile();
        if (config->getSslVerifyClient())
            ssl.ca_file_name = config->getSSLCaPath();
        ssl.ssl_ciphers = "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5";

        // Instantiate SSL Server
        server = std::make_shared<WSS::SSLServer>(config->getWebSocketPort(), ssl, ioThreadNum);

        // sub-protocol
        server->registerSupportedProtocol("appmesh-ws");

        // HTTP Route: Simple immediate reply (exact match)
        server->route("GET", "/index.html", [](auto * /*res*/, auto * /*req*/, auto replyCtx, const auto & /*match*/)
        {
            json response = {{"status", "ok"}, {"timestamp", std::time(nullptr)}};
            replyCtx->sendReply(response.dump(), true);
        });

        // WebSocket: Handle messages
        server->onWSMessage([](std::string_view message, auto connection, auto replyCtx, bool isBinary)
        {
            auto data = std::make_shared<std::vector<std::uint8_t>>(message.begin(), message.end());
            TcpHandler::queueInputRequest(data, 0, 0, replyCtx);
        });

        // WebSocket: Handle new connections
        server->onWSOpen([](auto connection)
        {
            LOG_DBG << "New connection: " << connection->getId() << " | Protocol: " << connection->getProtocol();
        });

        // WebSocket: Handle connection close
        server->onWSClose([](const std::string &connId, int code, std::string_view message)
        {
            LOG_DBG << "Connection closed: " << connId << " | Code: " << code << " | Reason: " << message;
        });

        server->start();
        LOG_INF << fname << "WebSocket service started on " << config->getWebSocketPort() << " with threads " << ioThreadNum;
    }

    void stop()
    {
        const static char fname[] = "WSS::stop() ";
        if (server)
        {
            LOG_INF << fname << "Shutting down...";
            server->stop();
            LOG_INF << fname << "WebSocket service stopped.";
        }
    }
}