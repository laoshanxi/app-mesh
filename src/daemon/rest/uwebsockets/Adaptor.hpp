#pragma once

#include "WSService.h"

#include <ace/INET_Addr.h>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
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
        if (token.empty()) return false;
        try
        {
            RESTHANDLER::instance()->verifyToken(std::string(token), audience);
            return true;
        }
        catch (...) { return false; }
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

    template <typename Res>
    static void addCors(Res *res)
    {
        res->writeHeader("Access-Control-Allow-Origin", "*")
            ->writeHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            ->writeHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-File-Path");
    }

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
            addCors(res);
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
            static const std::string indexHtml = loadFile(std::filesystem::path(Configuration::instance()->getWorkDir()) / ".." / "script/index.html");
            res->writeHeader("Content-Type", "text/html; charset=utf-8")->end(indexHtml);
        });

        // OPTIONS handler for CORS preflight
        m_server->routeRegex("OPTIONS", "/appmesh/file/*", [](auto *res, auto *req, auto /*replyCtx*/, const auto & /*match*/)
        {
            addCors(res);
            res->writeStatus("204 No Content")->end();
        });

        // -------------------------------------------------------------------------
        // DOWNLOAD HANDLER
        // -------------------------------------------------------------------------
        m_server->route("GET", "/appmesh/file/download", [](auto *res, auto *req, auto /*replyCtx*/, const auto & /*match*/)
        {
            const static char fname[] = "UWebSocketService::download() ";
            LOG_DBG << fname << "Enter";

            addCors(res);

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

            // Open file for reading
            auto fileStream = std::make_shared<std::ifstream>(filePath, std::ios::binary);
            if (!fileStream->is_open())
            {
                LOG_ERR << fname << "Failed to open file: " << filePath;
                res->writeStatus("500 Internal Server Error")->end("Cannot open file for reading");
                return;
            }

            std::string fileName = sanitizeFilename(filePath.filename().string());

            // Set response headers
            res->writeHeader("Content-Type", "application/octet-stream");
            // Note: If fileName contains quotes, it should ideally be escaped. 
            res->writeHeader("Content-Disposition", "attachment; filename=\"" + fileName + "\"");
            res->writeHeader("Content-Length", std::to_string(fileSize));

            // State management for async streaming
            struct DownloadState
            {
                std::shared_ptr<std::ifstream> stream;
                std::vector<char> buffer;
                std::uintmax_t offset = 0;
                std::uintmax_t totalSize = 0;
                bool aborted = false;
                bool finished = false;
            };

            auto state = std::make_shared<DownloadState>();
            state->stream = fileStream;
            state->buffer.resize(DOWNLOAD_CHUNK_SIZE);
            state->totalSize = fileSize;

            // Handle client abort
            res->onAborted([state, filePath]()
            {
                const static char fname[] = "UWebSocketService::download::onAborted() ";
                state->aborted = true;
                state->finished = true;
                if (state->stream && state->stream->is_open())
                {
                    state->stream->close();
                }
                LOG_DBG << fname << "Download aborted for file: " << filePath.string();
            });

            // Streaming function (until backpressure or end)
            auto streamData = [res, state]() -> bool
            {
                const static char fname[] = "UWebSocketService::download::streamData() ";

                if (state->aborted || state->finished)
                {
                    return false; // Deregister handler
                }

                // Loop until backpressure (ok == false) or Done
                while (state->offset < state->totalSize)
                {
                    std::size_t remaining = static_cast<std::size_t>(state->totalSize - state->offset);
                    std::size_t chunkSize = std::min(remaining, state->buffer.size());

                    state->stream->read(state->buffer.data(), static_cast<std::streamsize>(chunkSize));
                    std::size_t bytesRead = static_cast<std::size_t>(state->stream->gcount());

                    if (bytesRead == 0)
                    {
                        if (state->stream->fail() && !state->stream->eof())
                        {
                            LOG_ERR << fname << "File read error";
                            state->finished = true;
                            res->end();
                            return false;
                        }
                        break;
                    }

                    // tryEnd returns {ok, done}
                    // ok: true if backpressure is low (can write more)
                    // done: true if response is finished (should usually happen naturally via content-length tracking)
                    auto [ok, done] = res->tryEnd(std::string_view(state->buffer.data(), bytesRead), state->totalSize);
                    state->offset += bytesRead;

                    if (done)
                    {
                        state->finished = true;
                        state->stream->close();
                        return false; // Deregister handler
                    }

                    if (!ok)
                    {
                        // Backpressure - wait for onWritable callback
                        return true; // Keep handler registered
                    }
                }

                // All data sent
                if (!state->finished)
                {
                    state->finished = true;
                    state->stream->close();
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
        m_server->route("POST", "/appmesh/file/upload", [](auto *res, auto *req, auto /*replyCtx*/, const auto & /*match*/)
        {
            const static char fname[] = "UWebSocketService::fileUpload() ";
            LOG_DBG << fname << "Enter";

            addCors(res);

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

            auto outputFile = std::make_shared<std::ofstream>(fullPath, std::ios::binary | std::ios::out);
            if (!outputFile->is_open())
            {
                res->writeStatus("500 Internal Server Error")->end("Failed to open file for writing");
                return;
            }

            struct UploadState
            {
                std::shared_ptr<std::ofstream> file;
                std::string path;
                std::size_t totalBytes = 0;
                bool hasError = false;
                bool responded = false;
            };

            auto state = std::make_shared<UploadState>();
            state->file = outputFile;
            state->path = fullPath;

            // Handle incoming data chunks
            res->onData([res, state](std::string_view chunk, bool isLast)
            {
                const static char fname[] = "UWebSocketService::upload::onData() ";

                if (state->hasError || state->responded)
                {
                    return;
                }

                if (!chunk.empty())
                {
                    state->file->write(chunk.data(), static_cast<std::streamsize>(chunk.length()));
                    state->totalBytes += chunk.length();

                    if (!state->file->good())
                    {
                        LOG_ERR << fname << "Write error for file: " << state->path;
                        state->hasError = true;
                        state->file->close();

                        std::error_code rmEc;
                        std::filesystem::remove(state->path, rmEc); // Clean up partial file

                        if (!state->responded)
                        {
                            state->responded = true;
                            res->writeStatus("500 Internal Server Error")->end("File write error");
                        }
                        return;
                    }
                }

                if (isLast)
                {
                    state->file->flush();
                    state->file->close();

                    if (state->file->fail())
                    {
                        LOG_ERR << fname << "Error closing file: " << state->path;

                        std::error_code rmEc;
                        std::filesystem::remove(state->path, rmEc);

                        if (!state->responded)
                        {
                            state->responded = true;
                            res->writeStatus("500 Internal Server Error")->end("File close error");
                        }
                        return;
                    }

                    LOG_INF << fname << "File uploaded successfully: " << state->path << " (" << state->totalBytes << " bytes)";

                    if (!state->responded)
                    {
                        state->responded = true;
                        json resp = {{"status", "success"}, {"path", state->path}, {"size", state->totalBytes}};
                        res->writeHeader("Content-Type", "application/json");
                        res->writeStatus("201 Created")->end(resp.dump());
                    }
                }
            });

            // Handle client abort
            res->onAborted([state]()
            {
                const static char fname[] = "UWebSocketService::upload::onAborted() ";
                LOG_ERR << fname << "Upload aborted for file: " << state->path;

                state->hasError = true;
                state->responded = true;

                if (state->file->is_open())
                {
                    state->file->close();
                }

                std::error_code rmEc;
                std::filesystem::remove(state->path, rmEc); // Clean up partial file
            });
        });

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
        m_server->onWSClose([](const std::string &connId, int code, std::string_view message)
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
