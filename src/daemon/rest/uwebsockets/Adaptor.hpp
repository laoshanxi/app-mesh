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
#include "../RestHandler.h"
#include "../TcpServer.h"

using json = nlohmann::json;

// Manages the lifecycle of the UWebSocket Secure (WSS) server.
class UWebSocketService
{
private:
    static constexpr std::size_t DOWNLOAD_CHUNK_SIZE = 128 * 1024; // 128KB
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

    void setupHandlers()
    {
        const static char fname[] = "UWebSocketService::setupHandlers() ";
        LOG_DBG << fname << "Setting up server routes and handlers.";

        // Register a supported sub-protocol for WebSocket
        m_server->registerSupportedProtocol("appmesh-ws");

        // HTTP Route: Simple immediate reply (exact match)
        m_server->route("GET", "/index.html", [](auto * /*res*/, auto * /*req*/, auto replyCtx, const auto & /*match*/)
        {
            json resp = {{"status", "ok"}, {"timestamp", std::time(nullptr)}};
            replyCtx->sendReply(std::move(resp.dump()), true);
        });

        // -------------------------------------------------------------------------
        // DOWNLOAD HANDLER
        // -------------------------------------------------------------------------
        m_server->route("GET", "/appmesh/file/download", [](auto *res, auto *req, auto /*replyCtx*/, const auto & /*match*/)
        {
            const static char fname[] = "UWebSocketService::download() ";
            LOG_DBG << fname << "Enter";

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
            if (!std::filesystem::exists(filePath))
            {
                res->writeStatus("404 Not Found")->end("File not found");
                return;
            }

            std::error_code ec;
            auto fileSize = std::filesystem::file_size(filePath, ec);
            if (ec)
            {
                res->writeStatus("500 Internal Server Error")->end("Cannot determine file size");
                return;
            }

            // Open file for reading
            auto fileStream = std::make_shared<std::ifstream>(filePath, std::ios::binary);
            if (!fileStream->is_open())
            {
                res->writeStatus("500 Internal Server Error")->end("Cannot open file for reading");
                return;
            }

            auto fileName = filePath.filename().string();
            
            // Set response headers
            res->writeHeader("Content-Type", "application/octet-stream");
            res->writeHeader("Content-Disposition", "attachment; filename=\"" + fileName + "\"");
            res->writeHeader("Content-Length", std::to_string(fileSize));

            // State management for async streaming
            struct DownloadState {
                std::shared_ptr<std::ifstream> stream;
                std::vector<char> buffer;
                std::uintmax_t offset = 0;
                std::uintmax_t totalSize = 0;
                bool aborted = false;
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
                LOG_DBG << fname << "Download aborted for file: " << filePath.string();
            });

            // Logic to stream data until backpressure or end
            auto streamData = [res, state](auto& self) mutable -> bool {
                if (state->aborted) return true; // Stop

                // Loop until backpressure (ok == false) or Done
                while (state->offset < state->totalSize)
                {
                    std::size_t remaining = state->totalSize - state->offset;
                    std::size_t chunkSize = std::min(remaining, state->buffer.size());

                    state->stream->read(state->buffer.data(), chunkSize);
                    std::size_t bytesRead = state->stream->gcount();

                    if (bytesRead == 0 || state->stream->fail())
                    {
                        // Unexpected read error
                        if (!state->aborted) res->end(); // Close connection
                        return true;
                    }

                    // tryEnd returns {ok, done}
                    // ok: true if backpressure is low (can write more)
                    // done: true if response is finished
                    auto [ok, done] = res->tryEnd(std::string_view(state->buffer.data(), bytesRead), state->totalSize);

                    state->offset += bytesRead;

                    if (done)
                    {
                        return true; // Finished
                    }

                    if (!ok)
                    {
                        // Backpressure is high. Stop writing for now.
                        // We return true to keep the handler registered.
                        // uWS will call this lambda again when the socket is writable.
                        return true; 
                    }
                    
                    // If ok is true, we loop immediately and send the next chunk.
                }

                return true;
            };

            // Register the writable handler
            res->onWritable([streamData](std::uintmax_t /*offset*/) mutable {
                return streamData(streamData);
            });

            // Trigger the first write attempt immediately
            streamData(streamData);
        });

        // -------------------------------------------------------------------------
        // UPLOAD HANDLER
        // -------------------------------------------------------------------------
        m_server->route("POST", "/appmesh/file/upload", [](auto *res, auto *req, auto /*replyCtx*/, const auto & /*match*/)
        {
            const static char fname[] = "UWebSocketService::fileUpload() ";
            LOG_DBG << fname << "Enter";

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
            std::string fullPath = filePath.string();

            if (std::filesystem::exists(filePath))
            {
                res->writeStatus("409 Conflict")->end("File already exists");
                return;
            }

            auto parentPath = filePath.parent_path();
            if (!parentPath.empty() && !std::filesystem::exists(parentPath))
            {
                if (!std::filesystem::create_directories(parentPath))
                {
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

            auto totalBytes = std::make_shared<std::size_t>(0);
            auto hasError = std::make_shared<bool>(false);

            // Handle incoming data chunks
            res->onData([res, outputFile, fullPath, totalBytes, hasError](std::string_view chunk, bool isLast)
            {
                const static char fname[] = "UWebSocketService::upload::onData() ";
                if (*hasError) return;

                if (!chunk.empty())
                {
                    outputFile->write(chunk.data(), chunk.length());
                    *totalBytes += chunk.length();
                    
                    if (!outputFile->good())
                    {
                        LOG_ERR << fname << "Write error for file: " << fullPath;
                        *hasError = true;
                        outputFile->close();
                        std::filesystem::remove(fullPath); // Clean up partial file
                        res->writeStatus("500 Internal Server Error")->end("File write error");
                        return;
                    }
                }

                if (isLast)
                {
                    outputFile->flush();
                    outputFile->close();
                    
                    if (outputFile->fail())
                    {
                        LOG_ERR << fname << "Error closing file: " << fullPath;
                        std::error_code ec;
                        std::filesystem::remove(fullPath, ec);
                        res->writeStatus("500 Internal Server Error")->end("File close error");
                        return;
                    }

                    LOG_INF << fname << "File uploaded successfully: " << fullPath << " (" << *totalBytes << " bytes)";
                    
                    json resp = {
                        {"status", "success"}, 
                        {"path", fullPath},
                        {"size", *totalBytes}
                    };
                    res->writeStatus("201 Created")->end(resp.dump());
                }
            });

            // Handle client abort
            res->onAborted([outputFile, fullPath, hasError]()
            {
                const static char fname[] = "UWebSocketService::upload::onAborted() ";
                LOG_ERR << fname << "Upload aborted for file: " << fullPath;
                *hasError = true;

                if (outputFile->is_open())
                {
                    outputFile->close();
                }
                std::filesystem::remove(fullPath); // Clean up partial file
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
