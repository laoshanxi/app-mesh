#include "WSService.h"

#include <chrono>
#include <condition_variable>
#include <csignal>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string_view>
#include <thread>

using json = nlohmann::json;

// Compile: g++ test_server.cpp -o server -ggdb3 -luSockets -lz -lpthread -lssl -lcrypto -std=c++17

class AsyncTaskProcessor
{
public:
    void processTask(const std::string &taskId, WSS::ReplyContextPtr replyCtx)
    {
        // Simulate processing in another thread
        // WARNING: Detached threads can cause crashes if they outlive the Server object.
        // In production, use a joinable thread pool or ensure these threads complete before Server destruction.
        std::thread([taskId, replyCtx]()
        {
            // Send initial acknowledgment
            json ack = {{"status", "processing"}, {"taskId", taskId}, {"progress", 0}};
            replyCtx->replyData(ack.dump(), false);

            // Simulate progressive updates
            for (int i = 1; i <= 5; ++i)
            {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                json progress = {{"status", "processing"}, {"taskId", taskId}, {"progress", i * 20}};
                replyCtx->replyData(progress.dump(), false);
            }

            // Send final result
            std::this_thread::sleep_for(std::chrono::seconds(1));
            json result = {
                {"status", "completed"},
                {"taskId", taskId},
                {"progress", 100},
                {"result", "Task completed successfully"}};
            replyCtx->replyData(result.dump(), true);
        }).detach();
    }
};

// Broadcasts periodic messages to all connected clients
template <bool SSL>
class TimerNotifier
{
public:
    explicit TimerNotifier(WSS::Server<SSL> *server)
        : m_server(server), m_running(false) {}

    ~TimerNotifier()
    {
        stop();
    }

    void start()
    {
        if (m_running.exchange(true))
            return;

        m_timerThread = std::thread([this]()
        {
            while (m_running)
            {
                // Sleep with check for interrupt
                for (int i = 0; i < 50 && m_running; ++i) 
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }

                if (m_running && m_server->isRunning())
                {
                    json notification = {
                        {"type", "timer"},
                        {"timestamp", std::time(nullptr)},
                        {"message", "Periodic server notification"}
                    };
                    
                    m_server->broadcast(std::make_shared<std::string>(notification.dump()));
                }
            }
        });
    }

    void stop()
    {
        if (!m_running.exchange(false))
            return;

        if (m_timerThread.joinable())
            m_timerThread.join();
    }

private:
    WSS::Server<SSL> *m_server;
    std::atomic<bool> m_running;
    std::thread m_timerThread;
};

int main()
{
    const int NUM_THREADS = 2;
    std::cout << "Starting server with " << NUM_THREADS << " worker threads." << std::endl;

    WSS::SSLContextOptions ssl{
        .key_file_name = "/opt/appmesh/ssl/server-key.pem",
        .cert_file_name = "/opt/appmesh/ssl/server.pem",
    };

    // Instantiate SSL Server
    WSS::SSLServer server(9001, ssl, NUM_THREADS);

    server.registerSupportedProtocol("appmesh-ws");

    AsyncTaskProcessor taskProcessor;
    TimerNotifier<true> notifier(&server);

    // HTTP Route: Simple immediate reply (exact match)
    server.route("GET", "/api/status", [](auto * /*res*/, auto * /*req*/, auto replyCtx, const auto & /*match*/)
    {
        json response = {{"status", "ok"}, {"timestamp", std::time(nullptr)}};
        replyCtx->replyData(response.dump(), true);
    });

    // HTTP Route: Regex example - get user's specific resource
    // Matches: /api/users/123/orders/456
    server.routeRegex("GET", R"(/api/users/(\d+)/orders/(\d+))", [](auto * /*res*/, auto * /*req*/, auto replyCtx, const auto &match)
    {
        std::string userId = match.getParam(0);
        std::string orderId = match.getParam(1);
        json response = {
            {"userId", userId},
            {"orderId", orderId},
            {"status", "completed"},
            {"total", 99.99}
        };
        replyCtx->replyData(response.dump(), true);
    });

    // HTTP Route: Async task processing
    server.route("POST", "/api/task", [&taskProcessor](auto *res, auto * /*req*/, auto replyCtx, const auto & /*match*/)
    {
        auto body = std::make_shared<std::string>();

        res->onData([replyCtx, &taskProcessor, body](std::string_view chunk, bool isLast)
        {
            body->append(chunk.data(), chunk.size());

            if (isLast)
            {
                try
                {
                    auto reqData = json::parse(*body);
                    std::string taskId = reqData.value("taskId", "unknown");
                    taskProcessor.processTask(taskId, replyCtx);
                }
                catch (const std::exception &e)
                {
                    json error = {{"error", e.what()}};
                    replyCtx->replyData(error.dump(), true);
                }
            }
        });

        res->onAborted([]() {});
    });

    // HTTP Route: Send notification to specific client
    server.route("POST", "/api/notify", [&server](auto *res, auto * /*req*/, auto replyCtx, const auto & /*match*/)
    {
        auto body = std::make_shared<std::string>();
        const size_t MAX_PAYLOAD_SIZE = 64 * 1024; // 64KB for notifications
        res->onData([replyCtx, &server, body, MAX_PAYLOAD_SIZE, res](std::string_view chunk, bool isLast)
        {
            if (body->size() + chunk.size() > MAX_PAYLOAD_SIZE) {
                res->writeStatus("413 Payload Too Large")->end();
                return;
            }

            body->append(chunk.data(), chunk.size());

            if (isLast)
            {
                try
                {
                    auto reqData = json::parse(*body);

                    if (!reqData.contains("clientId") || !reqData.contains("message"))
                    {
                        json error = {{"error", "Missing clientId or message"}};
                        replyCtx->replyData(error.dump(), true);
                        return;
                    }

                    std::string clientId = reqData["clientId"];
                    std::string message = reqData["message"];

                    json notification = {{"type", "direct"}, {"message", message}};
                    bool sent = server.sendToClient(clientId, notification.dump());

                    json response = {{"success", sent}, {"clientId", clientId}};
                    replyCtx->replyData(response.dump(), true);
                }
                catch (const std::exception &e)
                {
                    json error = {{"error", e.what()}};
                    replyCtx->replyData(error.dump(), true);
                }
            }
        });

        res->onAborted([]() {});
    });

    // WebSocket: Handle messages
    server.onWSMessage([&taskProcessor](std::string_view message, auto connection, auto replyCtx, bool isBinary)
    {
        if (isBinary)
        {
            // Echo binary, thread safe
            connection->send(std::string(message), uWS::OpCode::BINARY);
            return;
        }

        try
        {
            auto msgData = json::parse(message);
            std::string action = msgData.value("action", "");

            if (action == "echo")
            {
                json response = {
                    {"type", "echo"},
                    {"data", msgData["data"]},
                    {"clientId", connection->getId()},
                    {"protocol", connection->getProtocol()} // Echo back the protocol
                };
                replyCtx->replyData(response.dump(), true);
            }
            else if (action == "ping")
            {
                json pong = {{"type", "pong"}, {"timestamp", std::time(nullptr)}};
                connection->send(pong.dump());
            }
            else if (action == "task")
            {
                std::string taskId = msgData.value("taskId", "unknown");
                taskProcessor.processTask(taskId, replyCtx);
            }
            else
            {
                json response = {{"type", "unknown_action"}, {"action", action}};
                connection->send(response.dump());
            }
        }
        catch (const std::exception& e)
        {
            json error = {{"type", "error"}, {"message", e.what()}};
            connection->send(error.dump());
        }
    });

    // HTTP Route: Broadcast to all clients
    server.route("POST", "/api/broadcast", [&server](auto *res, auto * /*req*/, auto replyCtx, const auto & /*match*/)
    {
        auto body = std::make_shared<std::string>();
        constexpr size_t MAX_PAYLOAD_SIZE = 64 * 1024;

        res->onData([replyCtx, &server, body, res](std::string_view chunk, bool isLast)
        {
            if (body->size() + chunk.size() > MAX_PAYLOAD_SIZE)
            {
                res->writeStatus("413 Payload Too Large")->end();
                return;
            }

            body->append(chunk.data(), chunk.size());

            if (isLast)
            {
                try
                {
                    auto reqData = json::parse(*body);
                    std::string message = reqData.value("message", "");

                    if (message.empty())
                    {
                        json error = {{"error", "Missing message"}};
                        replyCtx->replyData(error.dump(), true);
                        return;
                    }

                    json notification = {{"type", "broadcast"}, {"message", message}};
                    server.broadcast(std::make_shared<std::string>(notification.dump()));

                    json response = {{"success", true}, {"recipients", server.getConnectionCount()}};
                    replyCtx->replyData(response.dump(), true);
                }
                catch (const std::exception &e)
                {
                    json error = {{"error", e.what()}};
                    replyCtx->replyData(error.dump(), true);
                }
            }
        });

        res->onAborted([]() {});
    });

    // WebSocket: Handle new connections
    server.onWSOpen([](auto connection)
    {
        std::cout << "New connection: " << connection->getId() << " | Protocol: " << (connection->getProtocol().empty() ? "(none)" : connection->getProtocol()) << std::endl;
        json welcome = {{"type", "welcome"}, {"id", connection->getId()}};
        connection->send(welcome.dump());
    });

    // WebSocket: Handle connection close
    server.onWSClose([](const std::string &connId, int code, std::string_view message)
    {
        std::cout << "Connection closed: " << connId << " | Code: " << code << " | Reason: " << message << std::endl; 
    });

    server.start();
    notifier.start();

    std::cout << "Server started. Press Enter to stop." << std::endl;

    // --- Wait for user input ---
    std::cin.get();

    std::cout << "Shutting down..." << std::endl;
    
    // STOP notifier FIRST to prevent it from broadcasting to a dying server
    notifier.stop();
    server.stop();
    std::cout << "Server stopped." << std::endl;

    return 0;
}
