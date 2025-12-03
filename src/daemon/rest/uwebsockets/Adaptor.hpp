#pragma once

#include "WSService.h"

#include <ace/INET_Addr.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string_view>
#include <thread>
#include <vector>

#include "../../../common/StreamLogger.h"
#include "../../Configuration.h"
#include "../RestHandler.h"
#include "../TcpServer.h"

using json = nlohmann::json;

// Manages the lifecycle of the UWebSocket Secure (WSS) server.
class UWebSocketService
{
private:
    static constexpr std::size_t DOWNLOAD_CHUNK_SIZE = 64 * 1024; // 64KB

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

    static std::string loadFile(const std::filesystem::path &path)
    {
        const static char fname[] = "UWebSocketService::loadFile() ";

        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f)
        {
            LOG_ERR << fname << "Failed to open file: " << path;
            return {};
        }

        auto size = f.tellg();
        if (size < 0)
        {
            LOG_ERR << fname << "Failed to get file size: " << path;
            return {};
        }

        f.seekg(0);
        std::string content(static_cast<std::size_t>(size), '\0');

        if (!f.read(content.data(), size))
        {
            LOG_ERR << fname << "Failed to read file: " << path;
            return {};
        }

        return content;
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
        std::string result;
        result.reserve(filename.size());

        for (char c : filename)
        {
            // Remove or replace problematic characters
            if (c == '"' || c == '\\' || c == '\r' || c == '\n')
            {
                result += '_';
            }
            else if (c >= 32 && c < 127)
            {
                result += c;
            }
            else
            {
                result += '_';
            }
        }

        return result;
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
        const static char fname[] = "UWebSocketService::setupHandlers() ";
        LOG_DBG << fname << "Setting up server routes and handlers.";

        // Register a supported sub-protocol for WebSocket
        m_server->registerSupportedProtocol("appmesh-ws");

        // OpenAPI route: serve the OpenAPI YAML
        m_server->route("GET", "/openapi.yaml", [](auto *res, auto *req, auto /*replyCtx*/, const auto & /*match*/)
        {
            static const std::string openAPIContent = loadFile(std::filesystem::path(Configuration::instance()->getWorkDir()) / ".." / "script/openapi.yaml");
            addCors(res, req);
            res->writeHeader("Content-Type", "application/x-yaml");
            res->writeStatus("200 OK")->end(openAPIContent);
        });

        // Swagger UI redirect: point to petstore.swagger.io with our openapi.yaml
        m_server->route("GET", "/swagger/", [](auto *res, auto *req, auto /*replyCtx*/, const auto & /*match*/)
        {
            auto host = req->getHeader("host");
            if (host.empty())
                host = req->getHeader("Host");

            std::string swaggerURL = "https://petstore.swagger.io/?url=https://" + std::string(host) + "/openapi.yaml";

            res->writeHeader("Location", swaggerURL);
            res->writeStatus("307 Temporary Redirect")->end();
        });

        // HTTP Route: Serve index.html
        m_server->route("GET", "/", [](auto *res, auto * /*req*/, auto /*replyCtx*/, const auto & /*match*/)
        {
            static const std::string indexHtml = loadFile(std::filesystem::path(Configuration::instance()->getWorkDir()) / ".." / "script/index.html");
            res->writeHeader("Content-Type", "text/html; charset=utf-8")->end(indexHtml);
        });

        // OPTIONS handler for CORS preflight
        m_server->routeRegex("OPTIONS", "^/appmesh/.*$", [](auto *res, auto *req, auto /*replyCtx*/, const auto & /*match*/)
        {
            addCors(res, req);
            res->writeStatus("204 No Content")->end();
        });

        // -------------------------------------------------------------------------
        // DOWNLOAD HANDLER
        // -------------------------------------------------------------------------
        m_server->route("GET", "/appmesh/file/download/ws", [](auto *res, auto *req, auto /*replyCtx*/, const auto & /*match*/)
        {
            const static char fname[] = "UWebSocketService::download() ";
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
                const static char fname[] = "UWebSocketService::download::onAborted() ";
                state->aborted.store(true, std::memory_order_release);
                state->finished.store(true, std::memory_order_release);
                LOG_DBG << fname << "Download aborted for file: " << filePathStr;
            });

            // Streaming function
            auto streamData = [res, state]() -> bool
            {
                const static char fname[] = "UWebSocketService::download::streamData() ";

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
        });

        // -------------------------------------------------------------------------
        // UPLOAD HANDLER
        // -------------------------------------------------------------------------
        m_server->route("POST", "/appmesh/file/upload/ws", [](auto *res, auto *req, auto /*replyCtx*/, const auto & /*match*/)
        {
            const static char fname[] = "UWebSocketService::fileUpload() ";
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
                const static char fname[] = "UWebSocketService::upload::onAborted() ";
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
                const static char fname[] = "UWebSocketService::upload::onData() ";

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
        });

        // -------------------------------------------------------------------------
        // GENERIC HTTP HANDLER
        // -------------------------------------------------------------------------
        auto httpHandler = [](auto *res, auto *req, auto replyCtx, const auto & /*match*/)
        {
            const static char fname[] = "UWebSocketService::httpHandler() ";
            LOG_DBG << fname << "Enter";
            addCors(res, req);

            auto requestState = std::make_shared<Request>();

            std::string m = std::string(req->getMethod());
            std::transform(m.begin(), m.end(), m.begin(), [](unsigned char c) { return std::toupper(c); });
            requestState->http_method = std::move(m);
            requestState->request_uri = std::string(req->getUrl());

            for (auto [k, v] : *req)
            {
                requestState->headers.emplace(std::pair<std::string, std::string>{k, v});
            }

            for (auto qs = req->getQuery(); !qs.empty();)
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

            res->onData([requestState, replyCtx, aborted](std::string_view data, bool last) mutable
            {
                if (aborted->load(std::memory_order_acquire))
                {
                    return;
                }

                requestState->body.insert(requestState->body.end(), data.begin(), data.end());

                if (last)
                {
                    auto msgPack = requestState->serialize();
                    auto packedData = std::make_shared<std::vector<uint8_t>>(msgPack->data(), msgPack->data() + msgPack->size());
                    TcpHandler::queueInputRequest(packedData, 0, 0, replyCtx);
                }
            });
        };

        m_server->routeRegex("GET", "^/.*$", httpHandler);
        m_server->routeRegex("POST", "^/.*$", httpHandler);
        m_server->routeRegex("PUT", "^/.*$", httpHandler);
        m_server->routeRegex("DELETE", "^/.*$", httpHandler);

        // WebSocket: Handle incoming messages
        m_server->onWSMessage([](std::string_view message, auto /*connection*/, auto replyCtx, bool /*isBinary*/)
        {
            LOG_DBG << "UWebSocketService::onWSMessage()";
            auto data = std::make_shared<std::vector<std::uint8_t>>(message.begin(), message.end());
            TcpHandler::queueInputRequest(data, 0, 0, replyCtx);
        });

        // WebSocket: Handle new connections
        m_server->onWSOpen([](auto connection)
        {
            LOG_DBG << "UWebSocketService::onWSOpen() New WS connection: " << connection->getId();
        });

        // WebSocket: Handle connection close
        m_server->onWSClose([](const std::string &connId, int code, std::string_view /*message*/)
        {
            LOG_DBG << "UWebSocketService::onWSClose() Closed: " << connId << " | Code: " << code;
        });
    }

public:
    static UWebSocketService *instance()
    {
        static UWebSocketService inst;
        return &inst;
    }

    void initialize(const ACE_INET_Addr &addr, const std::string &cert_path, const std::string &key_path, const std::string &ca_path, int ioThreads)
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

        setupHandlers();
        m_server->start();

        LOG_INF << fname << "WebSocket service started on port " << m_addr.get_port_number();
    }

    void stop()
    {
        const static char fname[] = "UWebSocketService::stop() ";

        if (m_server)
        {
            LOG_INF << fname << "Initiating server shutdown...";
            m_server->stop();
            m_server.reset();
            LOG_INF << fname << "WebSocket service stopped.";
        }
    }
};
