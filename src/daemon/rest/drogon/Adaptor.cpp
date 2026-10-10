// src/daemon/rest/drogon/Adaptor.cpp
#include "Adaptor.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>

#ifdef _WIN32
#include <mstcpip.h>
#else
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

#include <nlohmann/json.hpp>

#include "../../../common/StreamLogger.h"
#include "../../../common/Utility.h"
#include "../../Configuration.h"
#include "../../security/Security.h"
#include "../Data.h"
#include "../EventDispatcher.h"
#include "../Worker.h"
#include "FileTransferHandler.h" // FileUploadInfo: temp file + atomic rename
#include "FrameCodec.h"          // tcpframe::enableKeepAlive
#include "WsController.h"

namespace
{
    constexpr std::size_t MAX_WS_MESSAGE_SIZE = 64 * 1024 * 1024;  // 64MB, largest WS request
    constexpr std::size_t MAX_JWT_TOKEN_LENGTH = 8 * 1024;         // 8KB
    constexpr std::size_t MAX_WS_CONNECTIONS = 10000;
    constexpr size_t WS_IDLE_TIMEOUT_SECONDS = 120;
    constexpr int APP_LOOP_WAIT_MS = 5000;
    constexpr int APP_LOOP_POLL_MS = 10;

    // Only %XX decodes; '+' stays literal and a malformed escape keeps its raw value.
    std::string decodeQueryComponent(const std::string &value)
    {
        const static char fname[] = "DrogonAdaptor::handleHttpRequest() ";
        if (value.find('%') == std::string::npos)
            return value;
        try
        {
            return Utility::decodeURIComponent(value);
        }
        catch (const std::exception &)
        {
            LOG_WAR << fname << "malformed query escape, using the raw value";
            return value;
        }
    }

    std::string authorize(const std::string &authorization, const std::string &permission = "")
    {
        if (authorization.empty() || authorization.size() > MAX_JWT_TOKEN_LENGTH)
            throw std::domain_error("Authentication required");
        const auto principal = Security::authenticateBearerAuthorization(authorization);
        Security::requirePermission(principal.id(), permission);
        return principal.id();
    }

    drogon::HttpResponsePtr plainResponse(drogon::HttpStatusCode code, const std::string &body)
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(code);
        resp->setBody(body);
        return resp;
    }

    // CORS uses a fixed allow-list.
    void addCors(const drogon::HttpResponsePtr &resp)
    {
        if (Configuration::instance()->getCorsDisabled())
            return;
        resp->addHeader(web::http::header_names::access_control_allow_origin, "*");
        resp->addHeader(web::http::header_names::access_control_allow_methods, "GET, POST, PUT, DELETE, OPTIONS");
        resp->addHeader(web::http::header_names::access_control_allow_headers, "Authorization, Content-Type, X-File-Path");
    }

    // Sanitize filename for Content-Disposition header
    std::string sanitizeFilename(const std::string &filename)
    {
        std::string out;
        out.reserve(filename.size());
        for (unsigned char c : filename)
        {
            if ((std::isalnum(c) || c == '.' || c == '-' || c == '_' || c == ' '))
                out.push_back(static_cast<char>(c));
            else
                out.push_back('_');
        }
        return out;
    }

    std::string upperMethod(const drogon::HttpRequestPtr &req)
    {
        std::string m{req->methodString()};
        std::transform(m.begin(), m.end(), m.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        return m;
    }

    // Per-request state shared by the stream reader callbacks of one HTTP request.
    struct HttpBodyState
    {
        std::shared_ptr<Request> request;
        std::shared_ptr<WSS::ReplyContext> replyCtx;
        std::vector<std::uint8_t> body;
        std::string declaredLength; // content-length header, empty when chunked
        bool answered = false;      // an error reply was sent; drop the remaining body
    };

    // Runs once the body is complete (or the request has none).
    void enqueueHttpRequest(const std::shared_ptr<HttpBodyState> &state)
    {
        const static char fname[] = "DrogonAdaptor::enqueueHttpRequest() ";

        // A declared length that does not match the delivered bytes means a
        // truncated body; the parser enforces this, so treat a mismatch as fatal.
        if (!state->declaredLength.empty())
        {
            std::uint64_t declaredBytes = 0;
            std::from_chars(state->declaredLength.data(), state->declaredLength.data() + state->declaredLength.size(), declaredBytes);
            if (declaredBytes != state->body.size())
            {
                LOG_ERR << fname << "body truncated: declared " << declaredBytes << " got " << state->body.size();
                state->replyCtx->replyHTTP("400", "Request body truncated", {}, "text/plain");
                return;
            }
        }

        state->request->body = std::move(state->body);
        try
        {
            WORKER::instance()->queueWsRequest(state->request->serialize(), std::move(state->replyCtx));
        }
        catch (const std::exception &e)
        {
            LOG_ERR << fname << "serialize/queue exception: " << e.what();
            state->replyCtx->replyHTTP("500 Internal Server Error", "Internal Server Error", {}, "text/plain");
        }
    }
}

namespace dgn
{
    std::vector<std::pair<std::string, std::string>> tlsHardeningConf(const std::string &caFile)
    {
        std::vector<std::pair<std::string, std::string>> sslConf{
            {"MinProtocol", "TLSv1.2"},
            {"CipherString", "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5"},
            {"Ciphersuites", "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"}};
        if (!caFile.empty())
        {
            sslConf.emplace_back("VerifyCAFile", caFile);
            sslConf.emplace_back("VerifyMode", "require");
        }
        return sslConf;
    }
}

void DrogonAdaptor::initialize(const ACE_INET_Addr &addr, const std::string &cert, const std::string &key, const std::string &ca, int ioThreads)
{
    const static char fname[] = "DrogonAdaptor::initialize() ";

    m_host = addr.get_host_addr();
    m_port = addr.get_port_number();
    m_certFile = cert;
    m_keyFile = key;
    m_caFile = ca;
    m_ioThreads = std::max(1, ioThreads);

    trantor::Logger::setLogLevel(trantor::Logger::kWarn);
    // trantor logs to stdout, which the service manager discards: forward them
    // to spdlog so transport errors reach the daemon log.
    trantor::Logger::setOutputFunction(
        [](const char *msg, const uint64_t len)
        {
            std::string line(msg, static_cast<std::size_t>(len));
            while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
                line.pop_back();
            if (line.find("sockets::shutdownWrite") != std::string::npos)
                LOG_DBG << "[trantor] " << line; // peer already closed: benign
            else if (line.find("ERROR") != std::string::npos || line.find("FATAL") != std::string::npos)
                LOG_ERR << "[trantor] " << line;
            else if (line.find("WARN") != std::string::npos)
                LOG_WAR << "[trantor] " << line;
            else
                LOG_INF << "[trantor] " << line;
        },
        [] {});

    LOG_INF << fname << "initialized with " << m_ioThreads << " I/O threads on port " << m_port;
}

void DrogonAdaptor::start()
{
    const static char fname[] = "DrogonAdaptor::start() ";

    if (m_running.exchange(true))
        return;

    setupRoutes();

    m_appThread = std::thread([]()
                              { drogon::app().run(); });

    // quit() is a no-op before the loop runs; joining then would block forever.
    if (!waitForLoopState(true, APP_LOOP_WAIT_MS))
    {
        LOG_ERR << fname << "drogon event loop did not start, service unavailable";
        m_running.store(false); // let a later start() retry instead of no-op
        return;
    }

    LOG_INF << fname << "Drogon service started";
}

bool DrogonAdaptor::waitForLoopState(bool running, int timeoutMs)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (drogon::app().getLoop()->isRunning() != running)
    {
        if (std::chrono::steady_clock::now() >= deadline)
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(APP_LOOP_POLL_MS));
    }
    return true;
}

void DrogonAdaptor::stop()
{
    const static char fname[] = "DrogonAdaptor::stop() ";

    if (!m_running.exchange(false))
        return;

    LOG_INF << fname << "Initiating server shutdown...";

    {
        std::lock_guard<std::mutex> lock(m_connMutex);
        for (const auto &[id, conn] : m_connections)
        {
            if (conn && conn->connected())
                conn->shutdown(drogon::CloseCode::kEndpointGone, "Server shutting down");
        }
        m_connections.clear();
    }

    if (!waitForLoopState(true, APP_LOOP_WAIT_MS))
    {
        LOG_ERR << fname << "drogon event loop never started, skipping quit/join";
        if (m_appThread.joinable())
            m_appThread.detach(); // a joinable thread would terminate at destruction
    }
    else
    {
        drogon::app().quit();
        if (m_appThread.joinable())
            m_appThread.join();
    }

    LOG_INF << fname << "Drogon service stopped.";
}

void DrogonAdaptor::setupRoutes()
{
    auto &app = drogon::app();

    // QuitHandler owns SIGTERM/SIGINT process-wide; drogon must not replace them.
    app.disableSigtermHandling();
    // No framework banner (version leak) and JSON, not drogon's HTML, for errors
    // the daemon never sees (invalid methods, unmatched framework routes).
    app.enableServerHeader(false);
    app.setCustomErrorHandler(
        [](drogon::HttpStatusCode code, const drogon::HttpRequestPtr &)
        {
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setStatusCode(code);
            resp->setContentTypeString("application/json");
            resp->setBody(Utility::text2json(std::string(drogon::statusCodeToString(static_cast<int>(code)))).dump());
            return resp;
        });
    app.setThreadNum(static_cast<size_t>(m_ioThreads));
    app.setIdleConnectionTimeout(WS_IDLE_TIMEOUT_SECONDS);
    // A closed connection stays allocated until its idle-timeout wheel entry
    // expires; keepAlive() drops the entry's weak reference and frees it now.
    app.setConnectionCallback(
        [](const trantor::TcpConnectionPtr &conn)
        {
            if (!conn->connected())
                conn->keepAlive();
        });
    app.setMaxConnectionNum(MAX_WS_CONNECTIONS + 4096); // WS cap + HTTP headroom
    // drogon's 128KB default would drop WSS sessions carrying larger requests.
    app.setClientMaxWebSocketMessageSize(MAX_WS_MESSAGE_SIZE);
    // Stream mode: the upload endpoint reads the body in chunks instead of
    // buffering it. Every other route still receives the complete body.
    app.enableRequestStream();
    // The parser rejects a body above this cap before the handler runs, so the
    // cap must cover the largest endpoint (file upload). The generic REST route
    // re-checks against MAX_HTTP_BODY_SIZE.
    app.setClientMaxBodySize(MAX_UPLOAD_SIZE);
    // Small WSS frames: no Nagle delay; keepalive reaps a peer that died without a FIN.
    app.setAfterAcceptSockOptCallback(
        [](int fd)
        {
            const int on = 1;
            ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&on), static_cast<socklen_t>(sizeof(on)));
            tcpframe::enableKeepAlive(fd);
        });

    // TLS: PEM files, cipher hardening, and client-certificate verification
    // when a CA is configured. "require" also rejects a client without a cert.
    app.addListener(m_host, static_cast<uint16_t>(m_port), true, m_certFile, m_keyFile, false, dgn::tlsHardeningConf(m_caFile));

    // Streaming file endpoints. Exact routes take precedence over the regex
    // catch-all below.
    app.registerHandler(
        "/appmesh/file/download/ws",
        [this](const drogon::HttpRequestPtr &req, drogon::AdviceCallback &&callback)
        { handleDownload(req, std::move(callback)); },
        {drogon::Get});
    app.registerHandler(
        "/appmesh/file/upload/ws",
        [this](const drogon::HttpRequestPtr &req, drogon::RequestStreamPtr &&stream, drogon::AdviceCallback &&callback)
        { handleUpload(req, std::move(stream), std::move(callback)); },
        {drogon::Post});
    // A route without an OPTIONS binder is answered with 403 by drogon. These
    // two exist so browser preflight works either way: drogon answers it when
    // CORS is enabled, this one when the daemon answers CORS itself.
    const auto corsPreflight = [](const drogon::HttpRequestPtr &, drogon::AdviceCallback &&callback)
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k204NoContent);
        callback(resp);
    };
    app.registerHandler("/appmesh/file/download/ws", corsPreflight, {drogon::Options});
    app.registerHandler("/appmesh/file/upload/ws", corsPreflight, {drogon::Options});
    // drogon answers a method mismatch on these routes with an empty 405; answer 404 JSON instead.
    const auto routeNotFound = [](const drogon::HttpRequestPtr &, drogon::AdviceCallback &&callback)
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k404NotFound);
        resp->setContentTypeString("application/json");
        resp->setBody(Utility::text2json("Route not found").dump());
        addCors(resp);
        callback(resp);
    };
    app.registerHandler("/appmesh/file/download/ws", routeNotFound, {drogon::Post, drogon::Put, drogon::Delete, drogon::Patch});
    app.registerHandler("/appmesh/file/upload/ws", routeNotFound, {drogon::Get, drogon::Put, drogon::Delete, drogon::Patch});

    // Dispatched at header time: the body is unread, so an oversized declared length is refused here.
    app.registerPreRoutingAdvice(
        [](const drogon::HttpRequestPtr &req, drogon::AdviceCallback &&callback, drogon::AdviceChainCallback &&chainCallback)
        {
            const auto declaredLength = req->getHeader(web::http::header_names::content_length);
            std::uint64_t declaredBytes = 0;
            std::from_chars(declaredLength.data(), declaredLength.data() + declaredLength.size(), declaredBytes);
            // Only the upload POST streams to disk; every other route is capped.
            const bool isUpload = req->method() == drogon::Post && req->path() == "/appmesh/file/upload/ws";
            if (isUpload || declaredBytes <= MAX_HTTP_BODY_SIZE)
            {
                std::move(chainCallback)();
                return;
            }
            req->attributes()->insert("appmesh.oversizeBody", true);
            auto resp = plainResponse(drogon::k413RequestEntityTooLarge, "Body too large");
            resp->setContentTypeString("text/plain");
            callback(resp);
        });
    // handleResponse() resets closeConnection from keep-alive; re-apply the close here.
    app.registerPreSendingAdvice(
        [](const drogon::HttpRequestPtr &req, const drogon::HttpResponsePtr &resp)
        {
            if (resp && req->attributes()->find("appmesh.oversizeBody"))
                resp->setCloseConnection(true);
        });

    // drogon always answers preflight with CORS headers; hand OPTIONS back to
    // the worker when CORS is disabled so its response stays CORS-free.
    if (Configuration::instance()->getCorsDisabled())
    {
        app.registerPreRoutingAdvice(
            [](const drogon::HttpRequestPtr &req)
            {
                if (req->method() == drogon::Options)
                    req->attributes()->insert("drogon.customCORShandling", true);
            });
    }

    // Generic HTTP catch-all: every request is serialized to a msgpack
    // Request and queued to the shared worker pool. The stream form lets the
    // body be capped while it arrives, so an undeclared (chunked) length
    // cannot buffer past the REST limit.
    app.registerHandlerViaRegex(
        ".*",
        [this](const drogon::HttpRequestPtr &req, drogon::RequestStreamPtr &&stream, drogon::AdviceCallback &&callback)
        { handleHttpRequest(req, std::move(stream), std::move(callback)); });

    // WebSocket catch-all (msgpack-over-WS). The filter authenticates the
    // upgrade request and pins the transport identity.
    app.registerWebSocketControllerRegex(".*", dgn::WsController::registrationName(), {"dgn::WsAuthFilter"});

    // drogon has no server-side sub-protocol API; clients fail the handshake
    // unless the negotiated protocol is echoed on the 101 response.
    app.registerPostHandlingAdvice(
        [](const drogon::HttpRequestPtr &req, const drogon::HttpResponsePtr &resp)
        {
            if (!resp || resp->statusCode() != drogon::k101SwitchingProtocols)
                return;
            const auto accepted = dgn::negotiateWsSubprotocol(req->getHeader(web::http::header_names::sec_websocket_protocol));
            if (!accepted.empty())
                resp->addHeader(web::http::header_names::sec_websocket_protocol, accepted);
        });
}

std::shared_ptr<WSS::ReplyContext> DrogonAdaptor::createHttpReplyContext(drogon::AdviceCallback &&callback)
{
    auto cb = std::make_shared<drogon::AdviceCallback>(std::move(callback));
    return std::make_shared<WSS::ReplyContext>(
        WSS::ReplyContext::ProtocolType::Http,
        [cb](std::string &&data, const std::string &status, const WSS::ReplyContext::Headers &headers, const std::string &contentType, bool /*isLast*/, bool /*isBinary*/)
        {
            // drogon response callbacks may be invoked from any thread; the
            // framework queues the write back to the owning IO loop. If the
            // client already disconnected the response is discarded.
            auto resp = drogon::HttpResponse::newHttpResponse();
            int code = 200;
            try
            {
                code = std::stoi(status);
            }
            catch (...)
            {
            }
            resp->setStatusCode(static_cast<drogon::HttpStatusCode>(code));
            for (const auto &[k, v] : headers)
                resp->addHeader(k, v);
            if (!contentType.empty())
                resp->setContentTypeString(contentType);
            resp->setBody(std::move(data));
            (*cb)(resp);
        });
}

std::shared_ptr<WSS::ReplyContext> DrogonAdaptor::createWebSocketReplyContext(const drogon::WebSocketConnectionPtr &conn,
                                                                              const std::shared_ptr<dgn::WsSession> &session)
{
    auto ctx = std::make_shared<WSS::ReplyContext>(
        WSS::ReplyContext::ProtocolType::Framed,
        [conn](std::string &&data, const std::string &, const WSS::ReplyContext::Headers &, const std::string &, bool /*isLast*/, bool isBinary)
        {
            // WebSocketConnectionPtr is a shared_ptr and send() is safe from
            // any thread; a dead connection is simply skipped.
            if (conn && conn->connected())
            {
                conn->send(std::move(data), isBinary ? drogon::WebSocketMessageType::Binary : drogon::WebSocketMessageType::Text);
            }
        },
        session ? session->connId : std::string(),
        session ? session->numericId : 0,
        session ? session->peerAddress : std::string(),
        session ? session->principalId : std::string());
    // An undecodable frame has no uuid to answer with, so the worker aborts the
    // context; close the connection instead of leaving the peer waiting.
    ctx->setAbortHook(
        [conn]()
        {
            if (conn && conn->connected())
                conn->shutdown(drogon::CloseCode::kProtocolError, "undecodable request");
        });
    return ctx;
}

void DrogonAdaptor::handleHttpRequest(const drogon::HttpRequestPtr &req, drogon::RequestStreamPtr &&stream, drogon::AdviceCallback &&callback)
{
    const auto method = upperMethod(req);
    if (method != "GET" && method != "POST" && method != "PUT" && method != "DELETE" && method != "OPTIONS")
    {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k404NotFound);
        resp->setContentTypeString("application/json");
        resp->setBody(Utility::text2json("Route not found").dump());
        callback(resp);
        return;
    }

    auto state = std::make_shared<HttpBodyState>();
    state->replyCtx = createHttpReplyContext(std::move(callback));
    state->declaredLength = req->getHeader(web::http::header_names::content_length);

    const auto &requestState = state->request = std::make_shared<Request>();
    requestState->uuid = Utility::uuid();
    requestState->http_method = method;
    // originalPath() is the raw, still-encoded path; the daemon unescapes it
    // once, so %-escapes are not decoded twice.
    requestState->request_uri = req->getOriginalPath();

    for (const auto &[k, v] : req->getHeaders())
        requestState->headers.emplace(k, v);
    // Query: only the raw query string, no form-body merge and no '+' decoding.
    const auto &rawQuery = req->query();
    for (size_t pos = 0; pos < rawQuery.size();)
    {
        const auto amp = rawQuery.find('&', pos);
        const auto pair = rawQuery.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        const auto eq = pair.find('=');
        const auto key = pair.substr(0, eq);
        const auto value = eq == std::string::npos ? std::string() : pair.substr(eq + 1);
        requestState->query.emplace(decodeQueryComponent(key), decodeQueryComponent(value));
        if (amp == std::string::npos)
            break;
        pos = amp + 1;
    }

    requestState->client_addr = req->peerAddr().toIp();

    if (stream)
    {
        // The body is counted while it arrives, so a chunked body (no declared
        // length, not covered by the pre-routing advice) is refused at the
        // limit instead of being buffered whole first.
        stream->setStreamReader(drogon::RequestStreamReader::newReader(
            [state](const char *data, size_t length)
            {
                if (state->answered)
                    return; // overflow already answered; drop the rest
                if (state->body.size() + length > MAX_HTTP_BODY_SIZE)
                {
                    state->answered = true;
                    state->replyCtx->replyHTTP("413", "Body too large", {}, "text/plain");
                    return;
                }
                state->body.insert(state->body.end(), data, data + length);
            },
            [state](std::exception_ptr ex)
            {
                if (state->answered)
                    return;
                if (ex)
                {
                    state->answered = true;
                    state->replyCtx->replyHTTP("400", "Request body error", {}, "text/plain");
                    return;
                }
                enqueueHttpRequest(state);
            }));
        return;
    }

    // No body: the request never entered stream mode.
    enqueueHttpRequest(state);
}

void DrogonAdaptor::handleDownload(const drogon::HttpRequestPtr &req, drogon::AdviceCallback &&callback)
{
    const static char fname[] = "DrogonAdaptor::handleDownload() ";

    try
    {
        authorize(req->getHeader(web::http::header_names::authorization), PERMISSION_KEY_file_download);
    }
    catch (const AuthorizationException &)
    {
        callback(plainResponse(drogon::k403Forbidden, "Permission denied"));
        return;
    }
    catch (...)
    {
        auto resp = plainResponse(drogon::k401Unauthorized, "Authentication failed");
        resp->addHeader(web::http::header_names::www_authenticate, "Bearer realm=\"appmesh\"");
        callback(resp);
        return;
    }

    const auto &filePathHeader = req->getHeader(HTTP_HEADER_KEY_file_path);
    if (filePathHeader.empty())
    {
        callback(plainResponse(drogon::k400BadRequest, "Missing X-File-Path header"));
        return;
    }

    std::string filePathStr = Utility::decodeHeaderFilePath(filePathHeader);
    if (!Utility::validateFilePath(filePathStr, Configuration::instance()->getFileAllowedBaseDir()))
    {
        callback(plainResponse(drogon::k403Forbidden, "Invalid file path"));
        return;
    }

    std::filesystem::path filePath(filePathStr);
    std::error_code ec;
    if (!std::filesystem::exists(filePath, ec))
    {
        callback(plainResponse(drogon::k404NotFound, "File not found"));
        return;
    }
    if (!std::filesystem::is_regular_file(filePath, ec))
    {
        callback(plainResponse(drogon::k400BadRequest, "Path is not a regular file"));
        return;
    }

    const std::string rawFileName = filePath.filename().string();
    const std::string fileName = sanitizeFilename(rawFileName);
    // RFC 5987: only filename* carries the real non-ASCII name; the sanitized
    // ASCII filename= stays as fallback for clients that ignore filename*.
    std::string disposition = "attachment; filename=\"" + fileName + "\"";
    if (fileName != rawFileName)
    {
        std::string extValue;
        for (char c : Utility::encodeURIComponent(rawFileName))
        {
            if (c == '\'' || c == '(' || c == ')' || c == '*')
                extValue += Utility::stringFormat("%%%02X", static_cast<unsigned char>(c));
            else
                extValue += c;
        }
        disposition += "; filename*=UTF-8''" + extValue;
    }

    auto resp = drogon::HttpResponse::newFileResponse(filePathStr, "", drogon::CT_APPLICATION_OCTET_STREAM, "", req);
    // newFileResponse answers an unreadable file with a 404 page, not a null pointer.
    if (!resp || resp->statusCode() != drogon::k200OK)
    {
        LOG_ERR << fname << "newFileResponse failed for: " << filePathStr;
        callback(plainResponse(drogon::k500InternalServerError, "Cannot open file for reading"));
        return;
    }
    resp->addHeader(web::http::header_names::content_disposition, disposition);
    addCors(resp);
    callback(resp);
}

void DrogonAdaptor::handleUpload(const drogon::HttpRequestPtr &req, drogon::RequestStreamPtr &&stream, drogon::AdviceCallback &&callback)
{
    const static char fname[] = "DrogonAdaptor::handleUpload() ";

    try
    {
        authorize(req->getHeader(web::http::header_names::authorization), PERMISSION_KEY_file_upload);
    }
    catch (const AuthorizationException &)
    {
        callback(plainResponse(drogon::k403Forbidden, "Permission denied"));
        return;
    }
    catch (...)
    {
        auto resp = plainResponse(drogon::k401Unauthorized, "Authentication failed");
        resp->addHeader(web::http::header_names::www_authenticate, "Bearer realm=\"appmesh\"");
        callback(resp);
        return;
    }

    const auto &filePathHeader = req->getHeader(HTTP_HEADER_KEY_file_path);
    if (filePathHeader.empty())
    {
        callback(plainResponse(drogon::k400BadRequest, "Missing X-File-Path header"));
        return;
    }

    std::string fullPath = Utility::decodeHeaderFilePath(filePathHeader);
    if (!Utility::validateFilePath(fullPath, Configuration::instance()->getFileAllowedBaseDir()))
    {
        callback(plainResponse(drogon::k403Forbidden, "Invalid file path"));
        return;
    }

    std::filesystem::path filePath(fullPath);
    {
        std::error_code ec;
        if (std::filesystem::is_symlink(filePath, ec))
        {
            callback(plainResponse(drogon::k400BadRequest, "Symlinks not allowed"));
            return;
        }
    }
    {
        std::error_code ec;
        if (std::filesystem::exists(filePath, ec))
        {
            callback(plainResponse(drogon::k409Conflict, "File already exists"));
            return;
        }
    }

    HttpHeaderMap attrHeaders;
    auto captureAttr = [&req, &attrHeaders](const char *headerName, const std::string &canonicalName)
    {
        auto value = req->getHeader(headerName);
        if (!value.empty())
            attrHeaders.emplace(canonicalName, std::string(value));
    };
    captureAttr("x-file-mode", HTTP_HEADER_KEY_file_mode);
    captureAttr("x-file-user", HTTP_HEADER_KEY_file_user);
    captureAttr("x-file-group", HTTP_HEADER_KEY_file_group);

    auto parentPath = filePath.parent_path();
    std::error_code ec;
    if (!parentPath.empty() && !std::filesystem::exists(parentPath, ec))
    {
        if (!std::filesystem::create_directories(parentPath, ec))
        {
            LOG_ERR << fname << "Failed to create directory: " << ec.message();
            callback(plainResponse(drogon::k500InternalServerError, "Cannot create directory"));
            return;
        }
    }

    // Stream the body into a temp file beside the destination and rename it on
    // success, so a large upload never sits in memory and the destination only
    // ever exists complete. The body cap is enforced by the parser, so a
    // chunk counter is not needed here.
    const std::string tempPath = fullPath + ".appmesh-upload-" + Utility::uuid();
    auto upload = std::make_shared<FileUploadInfo>(fullPath, tempPath, attrHeaders);
    if (!upload->m_file.is_open())
    {
        LOG_ERR << fname << "Failed to open file for writing: " << tempPath;
        callback(plainResponse(drogon::k500InternalServerError, "Failed to open file for writing"));
        return;
    }

    const std::string fileName = filePath.filename().string();
    auto writeFailed = std::make_shared<std::atomic<bool>>(false);
    stream->setStreamReader(drogon::RequestStreamReader::newReader(
        // IO loop thread, in order, for this connection only.
        [upload, writeFailed](const char *data, size_t length)
        {
            if (writeFailed->load(std::memory_order_relaxed))
                return;
            upload->m_file.write(data, static_cast<std::streamsize>(length));
            if (!upload->m_file.good())
                writeFailed->store(true, std::memory_order_relaxed);
        },
        [upload, writeFailed, fileName, callback = std::move(callback)](std::exception_ptr err) mutable
        {
            const static char fname[] = "DrogonAdaptor::handleUpload() ";

            // An aborted transfer keeps no partial file: the destructor drops the
            // temp file. A parse error (for example a body above the cap) still
            // has a live connection and expects an answer; a disconnected client
            // simply drops it.
            if (err || writeFailed->load())
            {
                LOG_ERR << fname << "Upload of <" << upload->m_filePath << "> did not complete";
                callback(plainResponse(drogon::k400BadRequest, "Upload aborted"));
                return;
            }

            upload->m_file.close();
            std::error_code ec;
            std::filesystem::rename(upload->m_tempPath, upload->m_filePath, ec);
            if (ec)
            {
                LOG_ERR << fname << "Cannot move upload into place: " << ec.message();
                callback(plainResponse(drogon::k500InternalServerError, "File write error"));
                return;
            }
            upload->m_committed = true;

            const auto size = std::filesystem::file_size(upload->m_filePath, ec);
            LOG_INF << fname << "File uploaded successfully: " << upload->m_filePath << " (" << size << " bytes)";

            // Apply caller-supplied POSIX attributes after the file commits,
            // mirroring the REST upload path.
            Utility::applyFilePermission(upload->m_filePath, upload->m_requestHeaders);

            nlohmann::json respJson = {{"status", "success"}, {"file", fileName}, {"size", size}};
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setStatusCode(drogon::k201Created);
            resp->setContentTypeString("application/json");
            addCors(resp);
            // Invalid UTF-8 in the filename makes default dump() throw; 'replace' avoids it.
            resp->setBody(respJson.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
            callback(resp);
        }));
}

void DrogonAdaptor::onWsOpen(const drogon::HttpRequestPtr &req, const drogon::WebSocketConnectionPtr &conn)
{
    const static char fname[] = "DrogonAdaptor::onWsOpen() ";

    auto session = std::make_shared<dgn::WsSession>();
    session->numericId = m_nextConnId.fetch_add(1);
    session->connId = "appmesh-ws-" + std::to_string(session->numericId);
    session->peerAddress = conn->peerAddr().toIp();

    const auto &attrs = req->attributes();
    if (attrs->find("principalId"))
        session->principalId = attrs->get<std::string>("principalId");

    {
        std::lock_guard<std::mutex> lock(m_connMutex);
        if (m_connections.size() >= MAX_WS_CONNECTIONS)
        {
            LOG_WAR << fname << "connection limit reached (" << MAX_WS_CONNECTIONS << "), rejecting connection";
            conn->shutdown(static_cast<drogon::CloseCode>(1013), "connection limit reached");
            return;
        }
        conn->setContext(session);
        m_connections[session->connId] = conn;
    }

    LOG_DBG << fname << "New WebSocket connection: " << session->connId;
}

void DrogonAdaptor::onWsMessage(const drogon::WebSocketConnectionPtr &conn, std::string &&message, drogon::WebSocketMessageType type)
{
    if (type != drogon::WebSocketMessageType::Text && type != drogon::WebSocketMessageType::Binary)
        return;
    // An empty WS frame carries no request payload. Never enqueue it.
    if (message.empty())
        return;

    if (!conn->hasContext())
        return;
    auto session = conn->getContext<dgn::WsSession>();
    if (!session)
        return;

    auto replyCtx = createWebSocketReplyContext(conn, session);
    WORKER::instance()->queueWsRequest(std::move(message), std::move(replyCtx));
}

void DrogonAdaptor::onWsClose(const drogon::WebSocketConnectionPtr &conn)
{
    const static char fname[] = "DrogonAdaptor::onWsClose() ";

    std::string connId;
    uint64_t numericId = 0;
    if (conn->hasContext())
    {
        auto session = conn->getContext<dgn::WsSession>();
        if (session)
        {
            connId = session->connId;
            numericId = session->numericId;
        }
    }
    if (connId.empty())
        return;

    {
        std::lock_guard<std::mutex> lock(m_connMutex);
        m_connections.erase(connId);
    }
    if (numericId > 0)
    {
        EventDispatcher::instance()->removeByConnection(ConnectionKey::wss(numericId));
    }

    LOG_DBG << fname << "Connection " << connId << " closed";
}
