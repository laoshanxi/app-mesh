#include <algorithm>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility> // Required for std::move
#include <vector>

// Make sure uWebSockets is in your include path.
// Typically this is "App.h" or "uWebSockets/App.h" depending on installation.
#include "App.h"

// g++ Server.cpp -o server -luSockets -lz -lpthread -lssl -lcrypto -std=c++17 -I /usr/local/include/uWebSockets/

// --- CONFIGURATION ---
struct ServerConfig
{
    int port = 9001;
    int thread_count = 4;
    // Simple boolean to toggle SSL for this demo,
    // though in production you'd pass the options struct.
    bool use_ssl = false;
    uWS::SocketContextOptions ssl_opts;
};

// --- PER SOCKET DATA ---
struct PerSocketData
{
    std::string user_id;
};

// --- SESSION MANAGER ---
// Keeps track of which thread holds which user
class SessionManager
{
private:
    std::mutex mtx;
    // Maps UserID -> Thread Index
    std::unordered_map<std::string, int> user_location;

public:
    void registerUser(const std::string &userId, int threadIdx)
    {
        std::lock_guard<std::mutex> lock(mtx);
        user_location[userId] = threadIdx;
        // std::cout << "[SessionManager] Registered " << userId << " on Thread " << threadIdx << std::endl;
    }

    void removeUser(const std::string &userId)
    {
        std::lock_guard<std::mutex> lock(mtx);
        user_location.erase(userId);
        // std::cout << "[SessionManager] Removed " << userId << std::endl;
    }

    // Returns -1 if user not found
    int getUserThread(const std::string &userId)
    {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = user_location.find(userId);
        if (it != user_location.end())
        {
            return it->second;
        }
        return -1;
    }

    std::vector<std::string> getAllUsers()
    {
        std::lock_guard<std::mutex> lock(mtx);
        std::vector<std::string> users;
        users.reserve(user_location.size());
        for (auto const &[key, val] : user_location)
        {
            users.push_back(key);
        }
        return users;
    }
};

// --- SERVER CONTEXT ---
// Helps the main thread access inner loops safely
struct ThreadContext
{
    int thread_idx;
    uWS::Loop *loop;
    uWS::App *app = nullptr;
    uWS::SSLApp *ssl_app = nullptr;
};

class WSServer
{
    ServerConfig config;
    std::vector<std::thread> threads;
    std::vector<ThreadContext *> contexts;
    std::mutex ctx_mutex;
    SessionManager sessions;

    // --- SETUP ROUTES ---
    // Templated to handle both App (HTTP) and SSLApp (HTTPS)
    template <typename AppType>
    void setup_routes(AppType &app, int threadIdx)
    {
        // 1. HTTP Status Handler
        app.get("/api/status", [](auto *res, auto *req)
                { res->end("Server Running"); });

        // 2. WebSocket Handler
        // Note: usage of .template ws<PerSocketData> is required because we are in a template
        app.template ws<PerSocketData>("/*", {.compression = uWS::SHARED_COMPRESSOR,
                                              .maxPayloadLength = 16 * 1024 * 1024,
                                              .idleTimeout = 60,
                                              .maxBackpressure = 1 * 1024 * 1024,
                                              .closeOnBackpressureLimit = false,
                                              .resetIdleTimeoutOnSend = true,
                                              .sendPingsAutomatically = true,

                                              /* HANDLER: UPGRADE
                                                 This is where we parse the URL/Headers to authenticate or identify the user.
                                                 We initialize PerSocketData here. */
                                              .upgrade = [this](auto *res, auto *req, auto *context)
                                              {
                // Extract UserID from URL (e.g., ws://localhost:9001/alice -> id: "alice")
                std::string url(req->getUrl());
                std::string user_id = (url.length() > 1) ? url.substr(1) : "anon";
                
                // You can also check headers here:
                // std::string token(req->getHeader("authorization"));

                // Construct our data structure
                PerSocketData userData;
                userData.user_id = user_id;

                // Perform the upgrade
                // FIX: Use std::move() because uWS expects an rvalue reference
                res->template upgrade<PerSocketData>(
                    std::move(userData),
                    req->getHeader("sec-websocket-key"),
                    req->getHeader("sec-websocket-protocol"),
                    req->getHeader("sec-websocket-extensions"),
                    context
                ); },

                                              /* HANDLER: OPEN
                                                 Socket is now live. We subscribe to topics here. */
                                              .open = [this, threadIdx](auto *ws)
                                              {
                PerSocketData* data = (PerSocketData*)ws->getUserData();
                
                // 1. Subscribe to their personal topic for private messaging
                // Pattern: "user:<userid>"
                ws->subscribe("user:" + data->user_id);

                // 2. Register globally so we know which thread they are on
                sessions.registerUser(data->user_id, threadIdx);
                
                std::cout << "User connected: " << data->user_id << " (Thread " << threadIdx << ")" << std::endl; },

                                              /* HANDLER: MESSAGE */
                                              .message = [](auto *ws, std::string_view message, uWS::OpCode opCode)
                                              {
                // Simple Echo
                ws->send("You said: " + std::string(message), opCode, true); },

                                              /* HANDLER: CLOSE */
                                              .close = [this](auto *ws, int code, std::string_view message)
                                              {
                                                  PerSocketData *data = (PerSocketData *)ws->getUserData();
                                                  sessions.removeUser(data->user_id);
                                                  // std::cout << "User disconnected: " << data->user_id << std::endl;
                                              }});
    }

public:
    WSServer(ServerConfig cfg) : config(cfg) {}

    void start()
    {
        // Reserve context pointers to avoid resize reallocation issues
        contexts.reserve(config.thread_count);

        for (int i = 0; i < config.thread_count; i++)
        {
            threads.emplace_back([this, i]()
                                 {
                ThreadContext ctx;
                ctx.thread_idx = i;
                // Get the loop for THIS thread
                ctx.loop = uWS::Loop::get();

                // Store context safely
                {
                    std::lock_guard<std::mutex> lock(ctx_mutex);
                    contexts.push_back(&ctx);
                }

                auto listen_cb = [i](auto *token) {
                    if (token) {
                        std::cout << "Thread " << i << " listening on port " << 9001 << std::endl;
                    } else {
                        std::cerr << "Thread " << i << " failed to listen on port " << 9001 << std::endl;
                    }
                };

                // Run either SSL or Non-SSL app
                if (config.use_ssl) {
                    uWS::SSLApp app(config.ssl_opts);
                    ctx.ssl_app = &app;
                    setup_routes(app, i);
                    app.listen(config.port, listen_cb).run();
                } else {
                    uWS::App app;
                    ctx.app = &app;
                    setup_routes(app, i);
                    app.listen(config.port, listen_cb).run();
                } });
        }
    }

    // --- THE CORE SEND FUNCTION ---
    // Thread-safe way to send to a specific user from any thread (like main)
    bool sendPrivateMessage(const std::string &userId, const std::string &message)
    {
        // 1. Look up user location
        int threadIdx = sessions.getUserThread(userId);
        if (threadIdx == -1)
        {
            std::cerr << "User " << userId << " not found." << std::endl;
            return false;
        }

        // 2. Find the context for that thread
        ThreadContext *targetCtx = nullptr;
        {
            std::lock_guard<std::mutex> lock(ctx_mutex);
            for (auto *ctx : contexts)
            {
                if (ctx->thread_idx == threadIdx)
                {
                    targetCtx = ctx;
                    break;
                }
            }
        }

        if (!targetCtx)
            return false;

        // 3. Defer execution to the specific thread that owns the socket.
        // uWS::Loop::defer is thread-safe.
        targetCtx->loop->defer([targetCtx, userId, message]()
                               {
            std::string topic = "user:" + userId;
            
            // publish() is very efficient; if the user disconnected in the meantime,
            // this simply does nothing (0 subscribers).
            if (targetCtx->ssl_app) {
                targetCtx->ssl_app->publish(topic, message, uWS::OpCode::TEXT);
            } else if (targetCtx->app) {
                targetCtx->app->publish(topic, message, uWS::OpCode::TEXT);
            } });

        return true;
    }

    void block()
    {
        for (auto &t : threads)
        {
            if (t.joinable())
                t.join();
        }
    }

    void listUsers()
    {
        auto users = sessions.getAllUsers();
        std::cout << "--- Connected Users ---" << std::endl;
        if (users.empty())
            std::cout << "(none)" << std::endl;
        for (const auto &u : users)
        {
            std::cout << "- " << u << std::endl;
        }
        std::cout << "-----------------------" << std::endl;
    }
};

int main()
{
    ServerConfig config;
    config.port = 9001;
    config.thread_count = 4;
    config.use_ssl = false;

    WSServer server(config);
    server.start();

    // Console Input Thread
    std::thread console([&server]()
                        {
        std::this_thread::sleep_for(std::chrono::seconds(1)); // wait for startup
        std::cout << "\nCOMMANDS:\n 'list' -> Show users\n 'send <userid> <msg>' -> Send private msg\n 'exit' -> quit\n";
        
        while(true) {
            std::string line;
            if (!std::getline(std::cin, line)) break;
            
            if (line == "exit") exit(0);
            
            if (line == "list") {
                server.listUsers();
                continue;
            }

            // Parse "send clientA hello world"
            if (line.rfind("send ", 0) == 0) {
                size_t first_space = line.find(' ');
                size_t second_space = line.find(' ', first_space + 1);
                
                if (second_space != std::string::npos) {
                    std::string targetUser = line.substr(first_space + 1, second_space - first_space - 1);
                    std::string msg = line.substr(second_space + 1);
                    
                    bool success = server.sendPrivateMessage(targetUser, msg);
                    if(success) std::cout << "-> Queued message for " << targetUser << std::endl;
                } else {
                    std::cout << "Usage: send <userid> <message>" << std::endl;
                }
            }
        } });
    console.detach();

    server.block();
    return 0;
}