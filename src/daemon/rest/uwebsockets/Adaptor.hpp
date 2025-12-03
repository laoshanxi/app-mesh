#include "WSService.h"

#include <ace/INET_Addr.h>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <string_view>
#include <thread>
#include <vector>

#include "../../../common/StreamLogger.h"
#include "../RestHandler.h"
#include "../TcpServer.h"

using json = nlohmann::json;

// Manages the lifecycle of the UWebSocket Secure (WSS) server.
class UWebSocketService
{
private:
    WSS::SSLContextOptions m_sslOptions;
    std::shared_ptr<WSS::SSLServer> m_server;
    ACE_INET_Addr m_addr;

    // Enforce Singleton Pattern: Make constructor private
    UWebSocketService() = default;
    // Delete copy/move constructors and assignment operators
    UWebSocketService(const UWebSocketService &) = delete;
    UWebSocketService &operator=(const UWebSocketService &) = delete;
    UWebSocketService(UWebSocketService &&) = delete;
    UWebSocketService &operator=(UWebSocketService &&) = delete;

    void setupHandlers()
    {
        const static char fname[] = "UWebSocketService::setupHandlers() ";
        LOG_DBG << fname << "Setting up server routes and handlers.";

        // Register a supported sub-protocol for WebSocket
        m_server->registerSupportedProtocol("appmesh-ws");

        // HTTP Route: Simple immediate reply (exact match)
        m_server->route("GET", "/index.html", [](auto * /*res*/, auto * /*req*/, auto replyCtx, const auto & /*match*/)
        {
            json response = {{"status", "ok"}, {"timestamp", std::time(nullptr)}};
            replyCtx->sendReply(std::move(response.dump()), true);
        });

        
        //m_server->route("GET", "/appmesh/file/download", [](auto * res, auto *req, auto replyCtx, const auto & /*match*/)
        /*{
            auto token = req->getHeader("authorization");
            try
            {
                RESTHANDLER::instance()->verifyToken(std::string(token), WEBSOCKET_FILE_AUDIENCE); 
                auto filePath = std::string(req->getHeader("x-file-path"));

                // Set the download headers
                res->writeHeader("Content-Type", "application/octet-stream");
                res->writeHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
                
                AsyncFileReader::read(filePath, [res](std::string_view file_content) {
                if (!file_content.empty()) {
                    res->end(file_content);
                } else {
                    res->end("400 HTTP_ERROR_400_BAD_REQUEST");
                }
            }
            catch (...)
            {
                res->writeStatus("400 HTTP_ERROR_400_BAD_REQUEST")->end();
            }
        });
        */

        // WebSocket: Handle incoming messages
        m_server->onWSMessage([](std::string_view message, auto connection, auto replyCtx, bool isBinary)
        {
            // Convert message view to a shared vector for asynchronous processing.
            auto data = std::make_shared<std::vector<std::uint8_t>>(message.begin(), message.end());

            // Forward the message to the main TCP handler's queue. 
            TcpHandler::queueInputRequest(data, 0, 0, replyCtx);
        });

        // WebSocket: Handle new connections
        m_server->onWSOpen([](auto connection)
        {
            LOG_DBG << "New WS connection: " << connection->getId() << " | Protocol: " << connection->getProtocol();
        });

        // WebSocket: Handle connection close
        m_server->onWSClose([](const std::string &connId, int code, std::string_view message)
        {
            LOG_DBG << "WS connection closed: " << connId << " | Code: " << code << " | Reason: " << message;
        });
    }

public:
    static UWebSocketService *instance()
    {
        static UWebSocketService inst;
        return &inst;
    }

    void initialize(ACE_INET_Addr addr, const std::string &cert_path, const std::string &key_path, const std::string &ca_path, int ioThreads)
    {
        const static char fname[] = "UWebSocketService::initialize() ";
        m_addr = addr;

        m_sslOptions.ca_file_name = ca_path;
        m_sslOptions.cert_file_name = cert_path;
        m_sslOptions.key_file_name = key_path;
        m_sslOptions.ssl_ciphers = "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5";

        m_server = std::make_shared<WSS::SSLServer>(m_addr.get_port_number(), m_sslOptions, ioThreads);

        LOG_INF << fname << "Manager initialized with " << ioThreads << " I/O threads.";
    }

    void start()
    {
        const static char fname[] = "UWebSocketService::start() ";

        if (!m_server)
        {
            LOG_ERR << fname << "Server is not initialized. Call initialize() first.";
            return;
        }

        // Setup handlers and routes
        setupHandlers();

        // Start the server's event loop
        m_server->start();

        LOG_INF << fname << "WebSocket service started on port " << m_addr.get_port_number();
    }

    void stop()
    {
        const static char fname[] = "UWebSocketService::stop() ";
        if (m_server)
        {
            LOG_INF << fname << "Initiating server shutdown...";
            // This call blocks until the server is fully stopped
            m_server->stop();
            m_server.reset(); // Release the shared pointer
            LOG_INF << fname << "WebSocket service stopped and resources released.";
        }
        else
        {
            LOG_DBG << fname << "WebSocket service not running or already stopped.";
        }
    }
};
