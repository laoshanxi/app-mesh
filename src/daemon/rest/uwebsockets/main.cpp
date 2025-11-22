#include "Server.h"

#include <chrono>
#include <condition_variable>
#include <csignal>
#include <iostream>
#include <json.hpp>
#include <string_view>
#include <thread>

using json = nlohmann::json;

// Compile: g++ main.cpp -o server -ggdb3 -luSockets -lz -lpthread -lssl -lcrypto -std=c++17 -I /usr/local/include/uWebSockets/ -I /usr/local/include/nlohmann/

class AsyncTaskProcessor
{
public:
    void processTask(const std::string &taskId, WSS::ReplyContextPtr replyCtx)
    {
        // Simulate processing in another thread
        // NOTE: std::thread::detach is used for simplicity; in production use a thread pool.
        std::thread([taskId, replyCtx]()
        {
            // Send initial acknowledgment
            json ack = {{"status", "processing"}, {"taskId", taskId}, {"progress", 0}};
            replyCtx->sendReply(ack.dump(), false);

            // Simulate progressive updates
            for (int i = 1; i <= 5; ++i)
            {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                json progress = {{"status", "processing"}, {"taskId", taskId}, {"progress", i * 20}};
                replyCtx->sendReply(progress.dump(), false);
            }

            // Send final result
            std::this_thread::sleep_for(std::chrono::seconds(1));
            json result = {
                {"status", "completed"},
                {"taskId", taskId},
                {"progress", 100},
                {"result", "Task completed successfully"}
            };
            replyCtx->sendReply(result.dump(), true);
        }).detach();
    }
};

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
        {
            return;
        }

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
                    
                    m_server->broadcast(notification.dump());
                }
            }
        });
    }

    void stop()
    {
        if (!m_running.exchange(false))
        {
            return;
        }

        if (m_timerThread.joinable())
        {
            m_timerThread.join();
        }
    }

private:
    WSS::Server<SSL> *m_server;
    std::atomic<bool> m_running;
    std::thread m_timerThread;
};

int main()
{
    const int NUM_THREADS = 4;
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

    // HTTP Route: Simple immediate reply
    server.route("get", "/api/status", [](auto * /*res*/, auto * /*req*/, auto replyCtx)
    {
        json response = {{"status", "ok"}, {"timestamp", std::time(nullptr)}};
        replyCtx->sendReply(response.dump(), true); 
    });

    // HTTP Route: Async task processing
    server.route("post", "/api/task", [&taskProcessor](auto *res, auto * /*req*/, auto replyCtx)
    {
        auto body = std::make_shared<std::string>();
        
        // Accumulate body
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
                catch (const std::exception& e)
                {
                    json error = {{"error", e.what()}};
                    replyCtx->sendReply(error.dump(), true);
                }
            }
        });

        res->onAborted([]() {});
    });

    server.route("post", "/api/notify", [&server](auto *res, auto * /*req*/, auto replyCtx)
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
                        replyCtx->sendReply(error.dump(), true);
                        return;
                    }

                    std::string clientId = reqData["clientId"];
                    std::string message = reqData["message"];

                    json notification = {{"type", "direct"}, {"message", message}};
                    bool sent = server.sendToClient(clientId, notification.dump());

                    json response = {{"success", sent}, {"clientId", clientId}};
                    replyCtx->sendReply(response.dump(), true);
                }
                catch (const std::exception& e)
                {
                    json error = {{"error", e.what()}};
                    replyCtx->sendReply(error.dump(), true);
                }
            }
        });

        res->onAborted([]() {}); 
    });

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
                // Use the context reply for simplicity in request/response patterns
                replyCtx->sendReply(response.dump(), true);
            }
            else if (action == "ping")
            {
                json pong = {{"type", "pong"}, {"timestamp", std::time(nullptr)}};
                connection->send(pong.dump());
            }
            else if (action == "task")
            {
                // Example of async task processing
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
            // connection->send is safe to call from here (same thread) or anywhere else
            json error = {{"type", "error"}, {"message", e.what()}};
            connection->send(error.dump());
        }
    });

    // Optional: Handle new connections
    server.onWSOpen([](auto connection)
    { 
        std::cout << "New connection: " << connection->getId() << " | Protocol: " << (connection->getProtocol().empty() ? "(none)" : connection->getProtocol()) << std::endl;
        // Send initial welcome message
        json welcome = {{"type", "welcome"}, {"id", connection->getId()}};
        connection->send(welcome.dump());
    });

    // Optional: Handle connection close
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
    notifier.stop();
    server.stop();

    return 0;
}
