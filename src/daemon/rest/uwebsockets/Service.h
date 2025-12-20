// src/daemon/rest/uwebsockets/Service.h
#ifndef WSSERVICE_H
#define WSSERVICE_H

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <regex>
#include <shared_mutex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <map>
#include <vector>

// TCP_NODELAY includes
#ifdef _WIN32
#include <mstcpip.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <cerrno>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <uWebSockets/App.h>
#include "ReplyContext.h"

namespace WSS
{
    // Configuration constants
    namespace Config
    {
        constexpr size_t MAX_PAYLOAD_LENGTH = 64 * 1024 * 1024; // 64 MB
        constexpr unsigned int IDLE_TIMEOUT = 120;              // seconds
        constexpr int DEFAULT_CLOSE_CODE = 1000;
    }

    // Options for configuring the SSL context.
    struct SSLContextOptions
    {
        std::string key_file_name;
        std::string cert_file_name;
        std::string passphrase;
        std::string dh_params_file_name;
        std::string ca_file_name;
        std::string ssl_ciphers;
        int ssl_prefer_low_memory_usage = 0;

        uWS::SocketContextOptions toNative() const
        {
            return uWS::SocketContextOptions{
                .key_file_name = key_file_name.empty() ? nullptr : key_file_name.c_str(),
                .cert_file_name = cert_file_name.empty() ? nullptr : cert_file_name.c_str(),
                .passphrase = passphrase.empty() ? nullptr : passphrase.c_str(),
                .dh_params_file_name = dh_params_file_name.empty() ? nullptr : dh_params_file_name.c_str(),
                .ca_file_name = ca_file_name.empty() ? nullptr : ca_file_name.c_str(),
                .ssl_ciphers = ssl_ciphers.empty() ? nullptr : ssl_ciphers.c_str(),
                .ssl_prefer_low_memory_usage = ssl_prefer_low_memory_usage};
        }
    };

    // Data structure stored in the uWS user data slot for each connection.
    struct SessionData
    {
        std::weak_ptr<void> connectionPtr;
        std::string subProtocol;
    };

    // Route match result containing captured groups from regex
    struct RouteMatch
    {
        std::vector<std::string> params; // Captured groups from regex
        std::string getParam(size_t index) const { return index < params.size() ? params[index] : ""; }
        size_t paramCount() const { return params.size(); }
    };

    // Forward declaration for ReplyContextPtr
    using ReplyContextPtr = std::shared_ptr<ReplyContext>;

    // Thread-safe WebSocket connection wrapper
    template <bool SSL>
    class WSConnection : public std::enable_shared_from_this<WSConnection<SSL>>
    {
    public:
        using WebSocketType = uWS::WebSocket<SSL, true, SessionData>;

        WSConnection(WebSocketType *ws, std::string id, std::string protocol, uWS::Loop *loop)
            : m_ws(ws), m_id(std::move(id)), m_protocol(std::move(protocol)), m_valid(true), m_loop(loop) {}

        // Sends data to the client safely from ANY thread.
        void send(std::string &&data, uWS::OpCode opcode = uWS::OpCode::TEXT)
        {
            runOnLoop([data = std::move(data), opcode](WebSocketType* ws) mutable {
                ws->send(std::move(data), opcode);
            });
        }

        // Closes the WebSocket connection safely from ANY thread.
        void close(int code = Config::DEFAULT_CLOSE_CODE, std::string reason = "")
        {
            runOnLoop([code, reason = std::move(reason)](WebSocketType* ws) mutable {
                ws->end(code, std::move(reason));
            });
        }

        // CRITICAL: Called only from the loop thread when uWS reports disconnection
        void invalidate()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_valid = false;
            m_ws = nullptr;
        }

        bool isValid() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_valid && m_ws;
        }

        // Getter methods
        const std::string &getId() const { return m_id; }
        const std::string &getProtocol() const { return m_protocol; }
        uWS::Loop *getLoop() const { return m_loop; }

    private:
        // Helper function to execute a WebSocket operation on the owner thread
        // The Func is a lambda taking a pointer to WebSocketType*
        template <typename Func>
        void runOnLoop(Func&& func)
        {
            // WARNING: Ensure m_loop is valid if called after Server::stop().
            if (uWS::Loop::get() == m_loop)
            {
                // We are on the owner thread, just execute if valid
                WebSocketType *ws = nullptr;
                bool valid = false;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    ws = m_ws;
                    valid = m_valid;
                }
                if (valid && ws)
                {
                    func(ws);
                }
            }
            else
            {
                // Defer to the owner loop. Capture shared_from_this() to keep object alive.
                m_loop->defer([self = this->shared_from_this(), func = std::forward<Func>(func)]() mutable {
                    // Once inside the defer, we are on the owner thread
                    WebSocketType *ws = nullptr;
                    bool valid = false;
                    {
                        std::lock_guard<std::mutex> lock(self->m_mutex);
                        ws = self->m_ws;
                        valid = self->m_valid;
                    }
                    if (valid && ws)
                    {
                        func(ws);
                    }
                });
            }
        }

    private:
        WebSocketType *m_ws;
        const std::string m_id;
        const std::string m_protocol;
        bool m_valid;
        uWS::Loop *const m_loop;
        mutable std::mutex m_mutex;
    };

    template <bool SSL>
    class Server
    {
    public:
        using WSConnectionType = WSConnection<SSL>;
        using WSConnectionPtr = std::shared_ptr<WSConnectionType>;
        using AppType = typename std::conditional<SSL, uWS::SSLApp, uWS::App>::type;
        using HttpResponseType = uWS::HttpResponse<SSL>;
        using HttpRequestType = uWS::HttpRequest;
        using WebSocketType = uWS::WebSocket<SSL, true, SessionData>;

        using HttpHandler = std::function<void(HttpResponseType *res, HttpRequestType *req, ReplyContextPtr replyCtx, const RouteMatch &match)>;
        using WSMessageHandler = std::function<void(std::string_view message, WSConnectionPtr connection, ReplyContextPtr replyCtx, bool isBinary)>;
        using WSOpenHandler = std::function<void(WSConnectionPtr connection)>;
        using WSCloseHandler = std::function<void(const std::string &connID, int code, std::string_view message)>;

        Server(int port, SSLContextOptions ssl = {}, int numThreads = 1)
            : m_port(port), m_numThreads(std::max(1, numThreads)), m_ssl(std::move(ssl)), 
              m_running(false), m_nextConnId(1), m_startedThreads(0)
        {
            m_serverThreads.resize(m_numThreads);
            m_listenSockets.resize(m_numThreads, nullptr);
            m_appLoops.resize(m_numThreads, nullptr);
            m_broadcasters.resize(m_numThreads);
        }

        ~Server()
        {
            stop();
        }

        void checkNotRunning() const
        {
            if (isRunning()) throw std::runtime_error("Cannot configure running server");
        }

        // Register an exact match route
        void route(const std::string &method, const std::string &pattern, HttpHandler handler)
        {
            checkNotRunning();
            std::string upperMethod = toUpperCase(method);
            std::string routeKey = upperMethod + ":" + pattern;
            m_exactRoutes[routeKey] = std::move(handler);
        }

        // Register a regex pattern route
        void routeRegex(const std::string &method, const std::string &regexPattern, HttpHandler handler)
        {
            checkNotRunning();
            std::string upperMethod = toUpperCase(method);
            try
            {
                RegexRoute route;
                route.method = upperMethod;
                route.pattern = std::regex(regexPattern, std::regex::ECMAScript | std::regex::optimize);
                route.patternStr = regexPattern;
                route.handler = std::move(handler);
                m_regexRoutes.push_back(std::move(route));
            }
            catch (const std::regex_error &e)
            {
                throw std::invalid_argument("Invalid regex pattern: " + regexPattern + " - " + e.what());
            }
        }

        void registerSupportedProtocol(const std::string &protocol)
        {
            checkNotRunning();
            m_supportedProtocols.insert(protocol);
        }

        void onWSMessage(WSMessageHandler handler)
        {
            checkNotRunning();
            m_wsMessageHandler = std::move(handler);
        }

        void onWSOpen(WSOpenHandler handler)
        {
            checkNotRunning();
            m_wsOpenHandler = std::move(handler);
        }

        void onWSClose(WSCloseHandler handler)
        {
            checkNotRunning();
            m_wsCloseHandler = std::move(handler);
        }

        // Sends data to a specific client. Thread-safe.
        bool sendToClient(const std::string &clientId, std::string &&data, uWS::OpCode opcode = uWS::OpCode::TEXT)
        {
            if (!isRunning())
                return false;

            WSConnectionPtr conn = getConnection(clientId);
            if (conn)
            {
                conn->send(std::move(data), opcode);
                return true;
            }
            return false;
        }

        // Thread-safe broadcasts using uWS Pub/Sub
        void broadcast(const std::shared_ptr<std::string> data, uWS::OpCode opcode = uWS::OpCode::TEXT)
        {
            // Protect against accessing loops while stop() is running
            std::shared_lock<std::shared_mutex> lock(m_stateMutex);
            
            if (!m_running)
                return;

            for (int i = 0; i < m_numThreads; ++i)
            {
                uWS::Loop *loop = m_appLoops[i];
                auto broadcaster = m_broadcasters[i];
                if (loop && broadcaster)
                {
                    // shared data to avoid copying for each thread
                    loop->defer([broadcaster, data, opcode]()
                    {
                        if (broadcaster && *broadcaster)
                        {
                            (*broadcaster)(*data, opcode);
                        }
                    });
                }
            }
        }

        // Get connection count
        size_t getConnectionCount() const
        {
            std::shared_lock<std::shared_mutex> lock(m_connectionsMutex);
            return m_connections.size();
        }

        void start()
        {
            if (m_running.exchange(true))
                return;

            m_startedThreads = 0;

            for (int i = 0; i < m_numThreads; ++i)
            {
                m_serverThreads[i] = std::thread(&Server::runServerInstance, this, i);
            }

            std::unique_lock<std::mutex> lock(m_startMutex);
            m_startCv.wait(lock, [this]()
                           { return m_startedThreads >= m_numThreads || !m_running; });
        }

        void stop()
        {
            // Take write lock to prevent broadcast/routes from accessing loops during destruction
            std::unique_lock<std::shared_mutex> stateLock(m_stateMutex);

            if (!m_running.exchange(false))
                return;

            // 1. Close all listen sockets to prevent new connections
            for (size_t i = 0; i < m_appLoops.size(); ++i)
            {
                if (m_appLoops[i] && m_listenSockets[i])
                {
                    us_listen_socket_t *socket = m_listenSockets[i];
                    m_appLoops[i]->defer([socket]()
                    {
                        us_listen_socket_close(0, socket);
                    });
                }
            }

            // 2. Force close all existing connections
            {
                std::vector<WSConnectionPtr> connectionsToClose;
                {
                    std::shared_lock<std::shared_mutex> lock(m_connectionsMutex);
                    connectionsToClose.reserve(m_connections.size());
                    for (const auto &pair : m_connections)
                    {
                        if (pair.second)
                            connectionsToClose.push_back(pair.second);
                    }
                }
                // Close connections outside the lock
                for (auto &conn : connectionsToClose)
                {
                    conn->close(1001, "Server shutting down");
                }
            }

            // Release lock here to allow loops to process the close events
            stateLock.unlock();

            // 3. Join threads
            for (auto &thread : m_serverThreads)
            {
                if (thread.joinable())
                    thread.join();
            }
            
            // Re-acquire lock to safely clear structures
            stateLock.lock();

            // Cleanup
            m_appLoops.assign(m_numThreads, nullptr);
            m_listenSockets.assign(m_numThreads, nullptr);

            // Clear broadcasters
            for (auto &b : m_broadcasters)
                b.reset();

            // Clear connections
            {
                std::unique_lock<std::shared_mutex> lock(m_connectionsMutex);
                m_connections.clear();
            }
        }

        bool isRunning() const { return m_running.load(); }

    private:
        struct ResponseState
        {
            std::atomic<bool> aborted{false};
            std::atomic<bool> responded{false};
            bool headersWritten{false};
        };

        struct RegexRoute
        {
            std::string method;
            std::regex pattern;
            std::string patternStr;
            HttpHandler handler;
        };

        static std::string toUpperCase(const std::string &str)
        {
            std::string result = str;
            std::transform(result.begin(), result.end(), result.begin(), ::toupper);
            return result;
        }

        // Factory for creating a safe WebSocket reply context
        static ReplyContextPtr createWebSocketReplyContext(WSConnectionPtr connection)
        {
            return std::make_shared<ReplyContext>(ReplyContext::ProtocolType::WebSocket,
                [connection](std::string &&data, const std::string &, const std::map<std::string, std::string> &, const std::string &, bool /*isLast*/, bool isBinary)
                {
                    if (connection && connection->isValid())
                    {
                        connection->send(std::move(data), isBinary ? uWS::OpCode::BINARY : uWS::OpCode::TEXT);
                    }
                });
        }

        // Factory for creating a safe HTTP reply context
        static ReplyContextPtr createHttpReplyContext(HttpResponseType *res)
        {
            auto state = std::make_shared<ResponseState>();
            res->onAborted([state]() { state->aborted = true; });

            // The ownerLoop is the loop of the thread that handled the incoming request.
            uWS::Loop *ownerLoop = uWS::Loop::get();

            return std::make_shared<ReplyContext>(ReplyContext::ProtocolType::Http,
                [res, state, ownerLoop](std::string &&data, const std::string &status, const std::map<std::string, std::string> &headers, const std::string &contentType, bool isLast, bool /*isBinary*/)
                {
                    // Define the actual write operation
                    auto writeResponse = [res, state, data = std::move(data), status, headers, contentType, isLast]()
                    {
                        if (state->aborted || state->responded)
                            return;

                        // Use corking for efficient header/body writing
                        res->cork([res, state, &data, &status, &headers, &contentType, isLast]()
                        {
                            if (state->aborted || state->responded)
                                return;

                            if (!state->headersWritten)
                            {
                                res->writeStatus(status);
                                for (const auto &[key, value] : headers)
                                    res->writeHeader(key, value);
                                if (!contentType.empty())
                                    res->writeHeader("Content-Type", contentType);
                                state->headersWritten = true;
                            }

                            if (isLast)
                            {
                                res->end(data);
                                state->responded = true;
                            }
                            else
                            {
                                res->write(data);
                            }
                        });
                    };

                    // Check if we're on the same thread
                    if (uWS::Loop::get() == ownerLoop)
                    {
                        writeResponse();
                    }
                    else if (ownerLoop)
                    {
                        ownerLoop->defer(std::move(writeResponse));
                    }
                });
        }

        void enableTcpNoDelay(void *nativeHandle)
        {
            if (!nativeHandle)
                return;
#ifdef _WIN32
            SOCKET s = reinterpret_cast<SOCKET>(nativeHandle);
            int flag = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&flag), sizeof(flag));
#else
            int fd = static_cast<int>(reinterpret_cast<intptr_t>(nativeHandle));
            int flag = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
#endif
        }

        static std::string_view trim(std::string_view s)
        {
            size_t start = s.find_first_not_of(" \t\r\n");
            if (start == std::string_view::npos)
                return "";
            size_t end = s.find_last_not_of(" \t\r\n");
            return s.substr(start, end - start + 1);
        }

        // Parses the Sec-WebSocket-Protocol header ("protocol1, protocol2") to vector.
        static std::vector<std::string> parseProtocolHeader(std::string_view header)
        {
            std::vector<std::string> protocols;
            if (header.empty())
                return protocols;

            size_t start = 0;
            while (start < header.size())
            {
                size_t end = header.find(',', start);
                if (end == std::string_view::npos)
                    end = header.size();

                std::string_view token = trim(header.substr(start, end - start));
                if (!token.empty())
                {
                    protocols.emplace_back(std::string(token));
                }
                start = end + 1;
            }
            return protocols;
        }

        std::pair<HttpHandler, RouteMatch> findRoute(const std::string &method, const std::string &url)
        {
            // First try exact match
            std::string routeKey = method + ":" + url;
            auto exactIt = m_exactRoutes.find(routeKey);
            if (exactIt != m_exactRoutes.end())
            {
                return {exactIt->second, RouteMatch{}};
            }

            // Then try regex routes
            for (const auto &route : m_regexRoutes)
            {
                if (route.method != method)
                    continue;

                std::smatch matches;
                if (std::regex_match(url, matches, route.pattern))
                {
                    RouteMatch match;
                    // Skip the first match (full string), capture groups start at index 1
                    for (size_t i = 1; i < matches.size(); ++i)
                    {
                        match.params.push_back(matches[i].str());
                    }
                    return {route.handler, match};
                }
            }

            return {nullptr, RouteMatch{}};
        }

        void runServerInstance(int threadId)
        {
            AppType app = createApp();

            auto broadcaster = std::make_shared<std::function<void(std::string_view, uWS::OpCode)>>(
                [&app](std::string_view data, uWS::OpCode opcode)
                {
                    app.publish("broadcast", data, opcode);
                });

            m_broadcasters[threadId] = std::move(broadcaster);

            setupRoutes(app, threadId);

            app.listen(m_port, [this, threadId](auto *socket)
            {
                m_listenSockets[threadId] = socket;
                m_appLoops[threadId] = uWS::Loop::get();
                {
                    std::lock_guard<std::mutex> lock(m_startMutex);
                    ++m_startedThreads;
                }
                m_startCv.notify_all();
            });

            app.run();
        }

        AppType createApp()
        {
            if constexpr (SSL)
                return AppType(m_ssl.toNative());
            else
                return AppType();
        }

        void setupRoutes(AppType &app, int /*threadId*/)
        {
            // WebSocket route (catch-all path)
            app.template ws<SessionData>(
                "/*",
                {.compression = uWS::SHARED_COMPRESSOR,
                 .maxPayloadLength = Config::MAX_PAYLOAD_LENGTH,
                 .idleTimeout = Config::IDLE_TIMEOUT,
                 .upgrade = [this](auto *res, auto *req, auto *context)
                 {
                     // Protocol negotiation logic
                     std::string_view requestedHeader = req->getHeader("sec-websocket-protocol");
                     std::string acceptedProtocol = "";

                     if (!requestedHeader.empty())
                     {
                         std::vector<std::string> requestedProtocols = parseProtocolHeader(requestedHeader);
                         // Find the first requested protocol that we support
                         for (const auto &proto : requestedProtocols)
                         {
                             if (m_supportedProtocols.find(proto) != m_supportedProtocols.end())
                             {
                                 acceptedProtocol = proto;
                                 break;
                             }
                         }

                         // If client requested specific protocols but none are supported, reject the upgrade
                         if (acceptedProtocol.empty())
                         {
                             res->writeStatus("400 Bad Request")->end("Unsupported sub-protocol");
                             return;
                         }
                     }
                     // If no protocol header was sent, we accept without a subprotocol (acceptedProtocol stays empty)
                     res->template upgrade<SessionData>(
                         SessionData{.subProtocol = acceptedProtocol},
                         req->getHeader("sec-websocket-key"),
                         acceptedProtocol.empty() ? std::string_view() : std::string_view(acceptedProtocol),
                         req->getHeader("sec-websocket-extensions"),
                         context);
                 },
                 .open = [this](auto *ws)
                 {
                     enableTcpNoDelay(ws->getNativeHandle());
                     ws->subscribe("broadcast"); // Subscribe to the global broadcast topic

                     SessionData *data = ws->getUserData();
                     auto connection = createConnection(ws, data->subProtocol);
                     data->connectionPtr = connection;

                     if (auto handler = m_wsOpenHandler)
                         handler(connection);
                 },
                 .message = [this](auto *ws, std::string_view message, uWS::OpCode opCode)
                 {
                     SessionData *data = ws->getUserData();
                     if (!data) return;

                     std::shared_ptr<void> connectionShared = data->connectionPtr.lock();
                     if (!connectionShared) return;

                     auto connection = std::static_pointer_cast<WSConnectionType>(connectionShared);
                     bool isBinary = (opCode == uWS::OpCode::BINARY);

                     // Create a ReplyContext that uses the connection's thread-safe send method
                     auto replyCtx = createWebSocketReplyContext(connection);

                     if (auto handler = m_wsMessageHandler)
                         handler(message, connection, replyCtx, isBinary);
                 },
                 .close = [this](auto *ws, int code, std::string_view message)
                 {
                     SessionData *data = ws->getUserData();
                     if (!data) return;

                     std::string connId;
                     if (auto connectionShared = data->connectionPtr.lock())
                     {
                         auto connection = std::static_pointer_cast<WSConnectionType>(connectionShared);
                         connId = connection->getId();
                         connection->invalidate();
                         removeConnection(connId);
                     }

                     WSCloseHandler handler = m_wsCloseHandler;
                     if (handler && !connId.empty())
                         handler(connId, code, message);
                 }});

            // HTTP catch-all handler with regex support
            app.any("/*", [this](auto *res, auto *req)
            {
                std::string method = toUpperCase(std::string(req->getMethod()));
                std::string url(req->getUrl());

                auto [handler, match] = findRoute(method, url);

                if (handler)
                {
                    auto replyCtx = createHttpReplyContext(res);
                    handler(res, req, replyCtx, match);
                }
                else
                {
                    res->writeStatus("404 Not Found");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error":"Route not found"})");
                }
            });
        }

        WSConnectionPtr createConnection(WebSocketType *ws, const std::string &subProtocol)
        {
            uWS::Loop *currentLoop = uWS::Loop::get();
            std::string connId = "appmesh-ws-" + std::to_string(m_nextConnId.fetch_add(1));
            auto connection = std::make_shared<WSConnectionType>(ws, connId, subProtocol, currentLoop);
            std::unique_lock<std::shared_mutex> lock(m_connectionsMutex);
            m_connections[connId] = connection;
            return connection;
        }

        WSConnectionPtr getConnection(const std::string &id)
        {
            std::shared_lock<std::shared_mutex> lock(m_connectionsMutex);
            auto it = m_connections.find(id);
            return (it != m_connections.end()) ? it->second : nullptr;
        }

        void removeConnection(const std::string &id)
        {
            std::unique_lock<std::shared_mutex> lock(m_connectionsMutex);
            m_connections.erase(id);
        }

        int m_port;
        int m_numThreads;
        SSLContextOptions m_ssl;
        std::atomic<bool> m_running;
        std::atomic<uint64_t> m_nextConnId;
        std::atomic<int> m_startedThreads;

        std::vector<std::thread> m_serverThreads;
        std::vector<uWS::Loop *> m_appLoops;
        std::vector<us_listen_socket_t *> m_listenSockets;
        std::vector<std::shared_ptr<std::function<void(std::string_view, uWS::OpCode)>>> m_broadcasters;

        std::mutex m_startMutex;
        std::condition_variable m_startCv;

        std::unordered_map<std::string, HttpHandler> m_exactRoutes;
        std::vector<RegexRoute> m_regexRoutes; // Regex routes (checked in order)

        WSMessageHandler m_wsMessageHandler;
        WSOpenHandler m_wsOpenHandler;
        WSCloseHandler m_wsCloseHandler;

        mutable std::shared_mutex m_connectionsMutex;
        std::unordered_map<std::string, WSConnectionPtr> m_connections;

        mutable std::shared_mutex m_stateMutex; // Protect state transitions (Running <-> Stopped) and sensitive lists

        std::set<std::string> m_supportedProtocols;
    };

    using SSLServer = Server<true>;
    using NonSSLServer = Server<false>;
}
#endif
