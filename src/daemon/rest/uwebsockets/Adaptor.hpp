// src/daemon/rest/uwebsockets/Adaptor.hpp
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <string_view>
#include <thread>
#include <vector>

#include <ace/INET_Addr.h>
#include <nlohmann/json.hpp>

#include "../../../common/Utility.h"
#include "../../Configuration.h"
#include "../RestHandler.h"
#include "../Worker.h"
#include "Service.h"

using json = nlohmann::json;
static constexpr std::size_t DOWNLOAD_CHUNK_SIZE = 64 * 1024; // 64KB

// Manages the lifecycle of the UWebSocket Secure (WSS) server.
class WebSocketAdaptor
{
public:
    static WebSocketAdaptor *instance()
    {
        static WebSocketAdaptor inst;
        return &inst;
    }

    void initialize(const ACE_INET_Addr &addr, const std::string &cert, const std::string &key, const std::string &ca, int ioThreads)
    {
        const static char fname[] = "WebSocketAdaptor::initialize() ";
        m_addr = addr;

        m_sslOptions.key_file_name = key;
        m_sslOptions.cert_file_name = cert;
        m_sslOptions.ca_file_name = ca;
        m_sslOptions.ssl_ciphers = "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5";

        m_server = std::make_shared<WSS::SSLServer>(m_addr.get_port_number(), m_sslOptions, ioThreads);

        LOG_INF << fname << "initialized with " << ioThreads << " I/O threads on port " << addr.get_port_number();
    }

    void start()
    {
        const static char fname[] = "WebSocketAdaptor::start() ";

        if (!m_server)
        {
            LOG_ERR << fname << "Server is not initialized. Call initialize() first.";
            return;
        }

        setupHandlers();
        m_server->start();

        LOG_INF << fname << "WebSocket service started";
    }

    void stop()
    {
        const static char fname[] = "WebSocketAdaptor::stop() ";

        if (m_server)
        {
            LOG_INF << fname << "Initiating server shutdown...";
            m_server->stop();
            m_server.reset();
            LOG_INF << fname << "WebSocket service stopped.";
        }
    }

private:
    // Enforce Singleton Pattern: Make constructor private
    WebSocketAdaptor() = default;
    // Delete copy/move constructors and assignment operators
    WebSocketAdaptor(const WebSocketAdaptor &) = delete;
    WebSocketAdaptor &operator=(const WebSocketAdaptor &) = delete;
    WebSocketAdaptor(WebSocketAdaptor &&) = delete;
    WebSocketAdaptor &operator=(WebSocketAdaptor &&) = delete;

    // Helper function to verify token
    static bool verifyToken(std::string_view token, const std::string &audience)
    {
        if (token.empty())
            return false;
        try
        {
            RESTHANDLER::instance()->verifyToken(std::string(token), audience);
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    // Security: Validate path to prevent Directory Traversal attacks
    static bool validatePath(const std::filesystem::path &filePath)
    {
        std::string pathStr = filePath.string();

        // Check for parent directory traversal patterns
        if (pathStr.find("..") != std::string::npos)
        {
            return false;
        }

        // Reject paths with null bytes (could be used for truncation attacks)
        if (pathStr.find('\0') != std::string::npos)
        {
            return false;
        }

        return true;
    }

    // Sanitize filename for Content-Disposition header
    static std::string sanitizeFilename(const std::string &filename)
    {
        std::string out;
        out.reserve(filename.size());
        for (unsigned char c : filename)
        {
            if ((std::isalnum(c) || c=='.' || c=='-' || c=='_' || c==' '))
                out.push_back(c);
            else
                out.push_back('_');
        }
        return out;
    }

    template <typename Res, typename Req>
    static void addCors(Res *res, Req *req)
    {
        std::string reqHeaders = std::string(req->getHeader("access-control-request-headers"));
        res->writeHeader("Access-Control-Allow-Origin", "*")->writeHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        if (!reqHeaders.empty())
        {
            res->writeHeader("Access-Control-Allow-Headers", reqHeaders);
        }
    }

    // State management for async download streaming
    struct DownloadState
    {
        std::ifstream stream;
        std::vector<char> buffer;
        std::uintmax_t totalSize = 0;
        std::uintmax_t bytesSent = 0;
        std::atomic<bool> aborted{false};
        std::atomic<bool> finished{false};

        DownloadState(const std::filesystem::path &path, std::uintmax_t size)
            : stream(path, std::ios::binary), buffer(DOWNLOAD_CHUNK_SIZE), totalSize(size)
        {
        }
    };

    // State management for async upload
    struct UploadState
    {
        std::ofstream file;
        std::string path;
        std::size_t totalBytes = 0;
        std::atomic<bool> hasError{false};
        std::atomic<bool> responded{false};

        explicit UploadState(const std::string &filePath)
            : file(filePath, std::ios::binary | std::ios::out), path(filePath)
        {
        }
    };

    void setupHandlers()
    {
        const static char fname[] = "WebSocketAdaptor::setupHandlers() ";
        LOG_DBG << fname << "Setting up server routes and handlers.";

        // Register a supported sub-protocol for WebSocket
        m_server->registerSupportedProtocol("appmesh-ws");

        // OpenAPI route: serve the OpenAPI YAML
        m_server->route("GET", "/openapi.yaml", [](auto *res, auto *req, auto /*replyCtx*/, const auto & /*match*/)
        {
            static const std::string openAPIContent = Utility::readFileCpp((std::filesystem::path(Configuration::instance()->getWorkDir()) / ".." / "script/openapi.yaml").string());
            addCors(res, req);
            res->writeHeader("Content-Type", "application/x-yaml");
            res->writeStatus("200 OK")->end(openAPIContent);
        });

        // Swagger UI redirect: point to petstore.swagger.io with our openapi.yaml
        m_server->route("GET", "/swagger/", [](auto *res, auto *req, auto /*replyCtx*/, const auto & /*match*/)
        {
            auto host = req->getHeader("host");
            if (host.empty()) host = req->getHeader("Host");
            std::string swaggerURL = "https://petstore.swagger.io/?url=https://" + std::string(host) + "/openapi.yaml";

            res->writeHeader("Location", swaggerURL);
            res->writeStatus("307 Temporary Redirect")->end();
        });

        // HTTP Route: Serve index.html
        m_server->route("GET", "/", [](auto *res, auto * /*req*/, auto /*replyCtx*/, const auto & /*match*/)
        {
            static const std::string indexHtml = Utility::readFileCpp((std::filesystem::path(Configuration::instance()->getWorkDir()) / ".." / "script/index.html").string());
            res->writeHeader("Content-Type", "text/html; charset=utf-8")->end(indexHtml);
        });

        // OPTIONS handler for CORS preflight
        m_server->routeRegex("OPTIONS", "^/appmesh/.*$", [](auto *res, auto *req, auto /*replyCtx*/, const auto & /*match*/)
        {
            addCors(res, req);
            res->writeStatus("204 No Content")->end();
        });

        m_server->route("GET", "/appmesh/file/download/ws", [this](auto *res, auto *req, auto /*replyCtx*/, const auto & /*match*/)
                        { handleDownload(res, req); });

        m_server->route("POST", "/appmesh/file/upload/ws", [this](auto *res, auto *req, auto /*replyCtx*/, const auto & /*match*/)
                        { handleUpload(res, req); });

        // -------------------------------------------------------------------------
        // GENERIC HTTP HANDLER
        // -------------------------------------------------------------------------
        m_server->routeRegex("GET", "^/.*$", [this](auto *res, auto *req, auto replyCtx, const WSS::RouteMatch & /*match*/)
                             { handleHttpRequest(res, req,  std::move(replyCtx)); });
        m_server->routeRegex("POST", "^/.*$", [this](auto *res, auto *req, auto replyCtx, const WSS::RouteMatch & /*match*/)
                             { handleHttpRequest(res, req,  std::move(replyCtx)); });
        m_server->routeRegex("PUT", "^/.*$", [this](auto *res, auto *req, auto replyCtx, const WSS::RouteMatch & /*match*/)
                             { handleHttpRequest(res, req,  std::move(replyCtx)); });
        m_server->routeRegex("DELETE", "^/.*$", [this](auto *res, auto *req, auto replyCtx, const WSS::RouteMatch & /*match*/)
                             { handleHttpRequest(res, req, std::move(replyCtx)); });

        // WebSocket: Handle incoming messages
        m_server->onWSMessage([](std::string_view message, auto /*connection*/, auto replyCtx, bool /*isBinary*/)
        {
            LOG_DBG << "WebSocketAdaptor::onWSMessage()";
            auto data = std::make_shared<std::vector<std::uint8_t>>(message.begin(), message.end());
            WORKER::instance()->queueInputRequest(data, 0, 0,  std::move(replyCtx));
        });

        // WebSocket: Handle new connections
        m_server->onWSOpen([](auto connection)
        {
            LOG_DBG << "WebSocketAdaptor::onWSOpen() New WebSocket connection: " << connection->getId();
        });

        // WebSocket: Handle connection close
        m_server->onWSClose([](const std::string &connId, int code, std::string_view /*message*/)
        {
            LOG_DBG << "WebSocketAdaptor::onWSClose() Connection " << connId << " closed with code: " << code;
        });
    }

    void handleHttpRequest(WSS::SSLServer::HttpResponseType *res, WSS::SSLServer::HttpRequestType *req, WSS::ReplyContextPtr ctx)
    {
        const static char fname[] = "WebSocketAdaptor::handleHttpRequest() ";
        LOG_DBG << fname << "Enter";
        addCors(res, req);

        auto requestState = std::make_shared<Request>();

        std::string m = std::string(req->getMethod());
        std::transform(m.begin(), m.end(), m.begin(), [](unsigned char c) { return std::toupper(c); });
        requestState->http_method = std::move(m);
        requestState->request_uri = std::string(req->getUrl());

        for (auto [k, v] : *req)
        {
            requestState->headers.emplace(k, v);
        }

        auto decoded = Utility::decodeURIComponent(std::string(req->getQuery()));
        for (auto qs = std::string_view(decoded); !qs.empty();)
        {
            auto amp = qs.find('&');
            auto kv = qs.substr(0, amp);
            auto eq = kv.find('=');

            requestState->query.emplace(std::string(kv.substr(0, eq)), eq == std::string_view::npos ? "" : std::string(kv.substr(eq + 1)));

            if (amp == std::string_view::npos)
                break;
            qs.remove_prefix(amp + 1);
        }

        auto ip = res->getRemoteAddressAsText();
        requestState->client_addr.assign(ip.begin(), ip.end());

        auto aborted = std::make_shared<std::atomic<bool>>(false);

        res->onAborted([aborted]()
        {
            aborted->store(true, std::memory_order_release);
        });

        res->onData([requestState, ctx, aborted](std::string_view data, bool last) mutable
        {
            if (aborted->load(std::memory_order_acquire))
            {
                return;
            }

            requestState->body.insert(requestState->body.end(), data.begin(), data.end());

            if (last)
            {
                requestState->convertCookieToAuthorization();
                auto msgPack = requestState->serialize();
                auto packedData = std::make_shared<std::vector<uint8_t>>(msgPack->data(), msgPack->data() + msgPack->size());
                WORKER::instance()->queueInputRequest(packedData, 0, 0, ctx);
            }
        });
    }

    void handleDownload(WSS::SSLServer::HttpResponseType *res, WSS::SSLServer::HttpRequestType *req)
    {
        const static char fname[] = "WebSocketAdaptor::handleDownload() ";
        LOG_DBG << fname << "Enter";
        addCors(res, req);

        auto token = req->getHeader("authorization");
        if (!verifyToken(token, WEBSOCKET_FILE_AUDIENCE))
        {
            res->writeStatus("401 Unauthorized")->end("Authentication failed");
            return;
        }

        auto filePathHeader = req->getHeader("x-file-path");
        if (filePathHeader.empty())
        {
            res->writeStatus("400 Bad Request")->end("Missing X-File-Path header");
            return;
        }

        std::filesystem::path filePath(filePathHeader);
        if (!validatePath(filePath))
        {
            res->writeStatus("403 Forbidden")->end("Invalid file path");
            return;
        }

        std::error_code ec;
        if (!std::filesystem::exists(filePath, ec))
        {
            res->writeStatus("404 Not Found")->end("File not found");
            return;
        }

        if (!std::filesystem::is_regular_file(filePath, ec))
        {
            res->writeStatus("400 Bad Request")->end("Path is not a regular file");
            return;
        }

        auto fileSize = std::filesystem::file_size(filePath, ec);
        if (ec)
        {
            LOG_ERR << fname << "Failed to get file size: " << ec.message();
            res->writeStatus("500 Internal Server Error")->end("Cannot determine file size");
            return;
        }

        // Create state before registering any callbacks
        auto state = std::make_shared<DownloadState>(filePath, fileSize);
        if (!state->stream.is_open())
        {
            LOG_ERR << fname << "Failed to open file: " << filePath;
            res->writeStatus("500 Internal Server Error")->end("Cannot open file for reading");
            return;
        }

        std::string fileName = sanitizeFilename(filePath.filename().string());
        std::string filePathStr = filePath.string();

        // Set response headers
        res->writeHeader("Content-Type", "application/octet-stream");
        res->writeHeader("Content-Disposition", "attachment; filename=\"" + fileName + "\"");
        res->writeHeader("Content-Length", std::to_string(fileSize));

        // Handle client abort - must register before any async operation
        res->onAborted([state, filePathStr]()
        {
            const static char fname[] = "WebSocketAdaptor::download::onAborted() ";
            state->aborted.store(true, std::memory_order_release);
            state->finished.store(true, std::memory_order_release);
            LOG_DBG << fname << "Download aborted for file: " << filePathStr;
        });

        // Streaming function
        auto streamData = [res, state]() -> bool
        {
            const static char fname[] = "WebSocketAdaptor::download::streamData() ";

            if (state->aborted.load(std::memory_order_acquire) ||
                state->finished.load(std::memory_order_acquire))
            {
                return false; // Deregister handler
            }

            while (state->bytesSent < state->totalSize)
            {
                std::size_t remaining = static_cast<std::size_t>(state->totalSize - state->bytesSent);
                std::size_t chunkSize = std::min(remaining, state->buffer.size());

                state->stream.read(state->buffer.data(), static_cast<std::streamsize>(chunkSize));
                std::size_t bytesRead = static_cast<std::size_t>(state->stream.gcount());

                if (bytesRead == 0)
                {
                    if (state->stream.eof())
                    {
                        break;
                    }
                    LOG_ERR << fname << "File read error";
                    state->finished.store(true, std::memory_order_release);
                    res->end();
                    return false;
                }

                auto [ok, done] = res->tryEnd(std::string_view(state->buffer.data(), bytesRead), state->totalSize);
                state->bytesSent += bytesRead;

                if (done)
                {
                    state->finished.store(true, std::memory_order_release);
                    return false;
                }

                if (!ok)
                {
                    // Backpressure - wait for onWritable callback
                    return true; // Keep handler registered
                }
            }

            // All data sent
            if (!state->finished.exchange(true, std::memory_order_acq_rel))
            {
                LOG_DBG << fname << "Download completed, bytes sent: " << state->bytesSent;
            }

            return false; // Deregister handler
        };

        // Register the writable handler
        res->onWritable([streamData](std::uintmax_t /*offset*/) mutable
        {
            return streamData();
        });

        // Trigger the first write attempt immediately
        streamData();
    }

    void handleUpload(WSS::SSLServer::HttpResponseType *res, WSS::SSLServer::HttpRequestType *req)
    {
        const static char fname[] = "WebSocketAdaptor::handleUpload() ";
        LOG_DBG << fname << "Enter";
        addCors(res, req);

        auto token = req->getHeader("authorization");
        if (!verifyToken(token, WEBSOCKET_FILE_AUDIENCE))
        {
            res->writeStatus("401 Unauthorized")->end("Authentication failed");
            return;
        }

        auto filePathHeader = req->getHeader("x-file-path");
        if (filePathHeader.empty())
        {
            res->writeStatus("400 Bad Request")->end("Missing X-File-Path header");
            return;
        }

        std::filesystem::path filePath(filePathHeader);
        if (!validatePath(filePath))
        {
            res->writeStatus("403 Forbidden")->end("Invalid file path");
            return;
        }

        std::string fullPath = filePath.string();
        std::error_code ec;

        if (std::filesystem::exists(filePath, ec))
        {
            res->writeStatus("409 Conflict")->end("File already exists");
            return;
        }

        auto parentPath = filePath.parent_path();
        if (!parentPath.empty() && !std::filesystem::exists(parentPath, ec))
        {
            if (!std::filesystem::create_directories(parentPath, ec))
            {
                LOG_ERR << fname << "Failed to create directory: " << ec.message();
                res->writeStatus("500 Internal Server Error")->end("Cannot create directory");
                return;
            }
        }

        auto state = std::make_shared<UploadState>(fullPath);
        if (!state->file.is_open())
        {
            res->writeStatus("500 Internal Server Error")->end("Failed to open file for writing");
            return;
        }

        // Handle client abort - must register before onData
        res->onAborted([state]()
        {
            const static char fname[] = "WebSocketAdaptor::upload::onAborted() ";
            LOG_ERR << fname << "Upload aborted for file: " << state->path;

            state->hasError.store(true, std::memory_order_release);
            state->responded.store(true, std::memory_order_release);

            if (state->file.is_open())
            {
                state->file.close();
            }

            std::error_code rmEc;
            std::filesystem::remove(state->path, rmEc);
        });

        // Handle incoming data chunks
        res->onData([res, state](std::string_view chunk, bool isLast)
        {
            const static char fname[] = "WebSocketAdaptor::upload::onData() ";

            if (state->hasError.load(std::memory_order_acquire) ||
                state->responded.load(std::memory_order_acquire))
            {
                return;
            }

            if (!chunk.empty())
            {
                state->file.write(chunk.data(), static_cast<std::streamsize>(chunk.length()));
                state->totalBytes += chunk.length();

                if (!state->file.good())
                {
                    LOG_ERR << fname << "Write error for file: " << state->path;
                    state->hasError.store(true, std::memory_order_release);
                    state->file.close();

                    std::error_code rmEc;
                    std::filesystem::remove(state->path, rmEc);

                    if (!state->responded.exchange(true, std::memory_order_acq_rel))
                    {
                        res->writeStatus("500 Internal Server Error")->end("File write error");
                    }
                    return;
                }
            }

            if (isLast)
            {
                state->file.flush();
                bool writeOk = state->file.good();
                state->file.close();

                if (!writeOk)
                {
                    LOG_ERR << fname << "Error flushing file: " << state->path;

                    std::error_code rmEc;
                    std::filesystem::remove(state->path, rmEc);

                    if (!state->responded.exchange(true, std::memory_order_acq_rel))
                    {
                        res->writeStatus("500 Internal Server Error")->end("File write error");
                    }
                    return;
                }

                LOG_INF << fname << "File uploaded successfully: " << state->path << " (" << state->totalBytes << " bytes)";

                if (!state->responded.exchange(true, std::memory_order_acq_rel))
                {
                    json resp = {{"status", "success"}, {"path", state->path}, {"size", state->totalBytes}};
                    res->writeHeader("Content-Type", "application/json");
                    res->writeStatus("201 Created")->end(resp.dump());
                }
            }
        });
    }

private:
    WSS::SSLContextOptions m_sslOptions;
    std::shared_ptr<WSS::SSLServer> m_server;
    ACE_INET_Addr m_addr;
};
