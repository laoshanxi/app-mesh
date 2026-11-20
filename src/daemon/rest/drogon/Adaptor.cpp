// src/daemon/rest/drogon/Adaptor.cpp
#include "Adaptor.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
// S_ISREG for the download content-length probe (UCRT ships it in sys/stat.h).
#include <sys/stat.h>

#ifdef _WIN32
#include <mstcpip.h>
#else
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

#include <json/json.h>

#include "../../../common/DurationParse.h"
#include "../../../common/StreamLogger.h"
#include "../../../common/Utility.h"
#include "../../../common/json.h"
#include "../../Configuration.h"
#include "../../application/Application.h"
#include "../../security/RequestHardening.h"
#include "../../security/Security.h"
#include "../Data.h"
#include "../EventDispatcher.h"
#include "../HttpRequest.h"
#include "../SseSink.h"
#include "../Worker.h"
#include "FileTransferHandler.h" // FileUploadInfo: temp file + atomic rename
#include "FrameCodec.h"          // tcpframe::enableKeepAlive
#include "SseStream.h"
#include "WsController.h"

namespace
{
	constexpr std::size_t MAX_WS_MESSAGE_SIZE = 64 * 1024 * 1024; // 64MB, largest WS request
	constexpr std::size_t MAX_WS_CONNECTIONS = 10000;
	constexpr size_t WS_IDLE_TIMEOUT_SECONDS = 120;
	constexpr int APP_LOOP_WAIT_MS = 5000;
	constexpr int APP_LOOP_POLL_MS = 10;

	// Only %XX decodes; '+' stays literal and a malformed escape keeps its raw value.
	std::string decodeQueryComponent(const std::string &value)
	{
		const static char fname[] = "decodeQueryComponent() ";
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
		if (authorization.empty() || authorization.size() > dgn::MAX_JWT_TOKEN_LENGTH)
			throw std::domain_error("Authentication required");
		const auto principal = Security::authenticateBearerAuthorization(authorization);
		Security::requirePermission(principal.id(), permission);
		return principal.id();
	}

	// Request hardening (replay protection + signature) for the exact-route
	// file endpoints, which bypass the shared worker pipeline. Streamed bodies
	// are not bound into the signature (documented exemption): clients sign
	// these endpoints with the empty-body hash. Returns false after replying.
	bool enforceFileHardening(const drogon::HttpRequestPtr &req, const drogon::AdviceCallback &callback);

	// Same policy for the native SSE routes; the task-stream body arrives
	// streamed, so the empty-body hash exemption applies here too.
	bool enforceSseHardening(const drogon::HttpRequestPtr &req, const drogon::AdviceCallback &callback);

	drogon::HttpResponsePtr plainResponse(drogon::HttpStatusCode code, const std::string &body)
	{
		auto resp = drogon::HttpResponse::newHttpResponse();
		resp->setStatusCode(code);
		resp->setBody(body);
		return resp;
	}

	// CORS is opt-in: no wildcard. The request Origin is echoed only when it is
	// in REST.CorsAllowOrigins; otherwise no CORS headers are sent at all.
	void addCors(const drogon::HttpResponsePtr &resp, const std::string &origin)
	{
		if (Configuration::instance()->getCorsDisabled())
			return;
		if (origin.empty() || Configuration::instance()->getCorsAllowOrigins().count(origin) == 0)
			return;
		resp->addHeader(web::http::header_names::access_control_allow_origin, origin);
		resp->addHeader(web::http::header_names::access_control_allow_methods, "GET, POST, PUT, DELETE, OPTIONS");
		resp->addHeader(web::http::header_names::access_control_allow_headers, "Authorization, Content-Type, X-File-Path");
		resp->addHeader(web::http::header_names::vary, "Origin");
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

	bool enforceFileHardening(const drogon::HttpRequestPtr &req, const drogon::AdviceCallback &callback)
	{
		const static char fname[] = "enforceFileHardening() ";
		RequestHardening::Input input;
		input.method = upperMethod(req);
		input.path = req->getOriginalPath();
		// Parse the raw query with the same %XX-only decoder as the worker path
		// (handleWorkerRequest): getParameters() would decode '+' as space and
		// the two paths would disagree on the canonical query.
		const auto &rawQuery = req->query();
		for (size_t pos = 0; pos < rawQuery.size();)
		{
			const auto amp = rawQuery.find('&', pos);
			const auto pair = rawQuery.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
			const auto eq = pair.find('=');
			const auto key = pair.substr(0, eq);
			const auto value = eq == std::string::npos ? std::string() : pair.substr(eq + 1);
			input.query.emplace(decodeQueryComponent(key), decodeQueryComponent(value));
			if (amp == std::string::npos)
				break;
			pos = amp + 1;
		}
		input.bearer = req->getHeader(web::http::header_names::authorization);
		input.keyId = req->getHeader(HTTP_HEADER_KEY_X_Request_Key);
		input.timestamp = req->getHeader(HTTP_HEADER_KEY_X_Timestamp);
		input.nonce = req->getHeader(HTTP_HEADER_KEY_X_Nonce);
		input.signature = req->getHeader(HTTP_HEADER_KEY_X_Signature);
		// Same canonical file-route view as the worker path (strips the "/ws"
		// channel suffix; streamed bodies hash empty per the exemption).
		input.path = RequestHardening::canonicalFileRoute(input.path, input.body, input.bodySize);

		const auto decision = RequestHardening::instance().evaluate(input);
		if (decision.audit)
			LOG_WAR << fname << "tolerated request hardening violation: " << decision.reason;
		if (decision.action != RequestHardening::Decision::Action::Reject)
			return true;
		LOG_WAR << fname << "rejected file request path <" << input.path << ">: " << decision.reason;
		callback(plainResponse(decision.status == 409 ? drogon::k409Conflict : drogon::k401Unauthorized, decision.reason));
		return false;
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

	bool enforceSseHardening(const drogon::HttpRequestPtr &req, const drogon::AdviceCallback &callback)
	{
		const static char fname[] = "enforceSseHardening() ";
		RequestHardening::Input input;
		input.method = upperMethod(req);
		input.path = req->getOriginalPath();
		const auto &rawQuery = req->query();
		for (size_t pos = 0; pos < rawQuery.size();)
		{
			const auto amp = rawQuery.find('&', pos);
			const auto pair = rawQuery.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
			const auto eq = pair.find('=');
			const auto key = pair.substr(0, eq);
			const auto value = eq == std::string::npos ? std::string() : pair.substr(eq + 1);
			input.query.emplace(decodeQueryComponent(key), decodeQueryComponent(value));
			if (amp == std::string::npos)
				break;
			pos = amp + 1;
		}
		input.bearer = req->getHeader(web::http::header_names::authorization);
		input.keyId = req->getHeader(HTTP_HEADER_KEY_X_Request_Key);
		input.timestamp = req->getHeader(HTTP_HEADER_KEY_X_Timestamp);
		input.nonce = req->getHeader(HTTP_HEADER_KEY_X_Nonce);
		input.signature = req->getHeader(HTTP_HEADER_KEY_X_Signature);

		const auto decision = RequestHardening::instance().evaluate(input);
		if (decision.audit)
			LOG_WAR << fname << "tolerated request hardening violation: " << decision.reason;
		if (decision.action != RequestHardening::Decision::Action::Reject)
			return true;
		LOG_WAR << fname << "rejected stream request path <" << input.path << ">: " << decision.reason;
		callback(plainResponse(decision.status == 409 ? drogon::k409Conflict : drogon::k401Unauthorized, decision.reason));
		return false;
	}

	// App-name segment between the fixed prefix and a known suffix ("/output/stream"
	// or "/task/stream"); the route regexes guarantee one segment without '/'.
	std::string appNameFromStreamPath(const std::string &path, const std::string &suffix)
	{
		const auto decoded = Utility::decodeURIComponent(path);
		constexpr auto prefix = "/appmesh/app/";
		if (decoded.size() <= strlen(prefix) + suffix.size() || decoded.compare(0, strlen(prefix), prefix) != 0)
			return {};
		const auto name = decoded.substr(strlen(prefix), decoded.size() - strlen(prefix) - suffix.size());
		if (name.empty() || name.find('/') != std::string::npos || name.find('*') != std::string::npos)
			return {};
		return name;
	}

	// Query parameters with the same %XX-only decoding as the worker path.
	std::string streamQueryParam(const drogon::HttpRequestPtr &req, const std::string &key)
	{
		const auto &rawQuery = req->query();
		for (size_t pos = 0; pos < rawQuery.size();)
		{
			const auto amp = rawQuery.find('&', pos);
			const auto pair = rawQuery.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
			const auto eq = pair.find('=');
			if (decodeQueryComponent(pair.substr(0, eq)) == key)
				return eq == std::string::npos ? std::string() : decodeQueryComponent(pair.substr(eq + 1));
			if (amp == std::string::npos)
				break;
			pos = amp + 1;
		}
		return {};
	}

	// Bearer gate shared by the native SSE routes: authenticate, check the route
	// permission and the app-owner policy. Replies and returns empty on failure.
	std::string authorizeStreamApp(const drogon::HttpRequestPtr &req, const drogon::AdviceCallback &callback,
								   const std::string &appName, const std::string &permission, bool requireWrite)
	{
		const static char fname[] = "authorizeStreamApp() ";
		try
		{
			const auto principalId = authorize(req->getHeader(web::http::header_names::authorization), permission);
			const auto app = Configuration::instance()->getApp(appName);
			if (!Configuration::instance()->checkOwnerPermission(principalId, app->getOwnerPrincipalId(),
																 app->getOwnerPermission(), requireWrite))
			{
				LOG_WAR << fname << "Principal <" << principalId << "> is not allowed to <"
						<< (requireWrite ? "EDIT" : "VIEW") << "> app <" << appName << ">";
				callback(plainResponse(drogon::k403Forbidden, "Permission denied"));
				return {};
			}
			return appName;
		}
		catch (const AuthorizationException &)
		{
			callback(plainResponse(drogon::k403Forbidden, "Permission denied"));
		}
		catch (const NotFoundException &)
		{
			callback(plainResponse(drogon::k404NotFound, "Application not found"));
		}
		catch (const std::invalid_argument &)
		{
			callback(plainResponse(drogon::k404NotFound, "Application not found"));
		}
		catch (...)
		{
			auto resp = plainResponse(drogon::k401Unauthorized, "Authentication failed");
			resp->addHeader(web::http::header_names::www_authenticate, "Bearer realm=\"appmesh\"");
			callback(resp);
		}
		return {};
	}

	// Starts an SSE response on the callback and returns the sink bound to it.
	std::shared_ptr<SseStream> startSseResponse(const drogon::HttpRequestPtr &req, drogon::AdviceCallback &callback)
	{
		auto sink = std::make_shared<SseStream>(Utility::shortID(), SSE_HEARTBEAT_MILLISECONDS);
		SseStreamRegistry::instance()->emplace(sink, sink->id());
		auto resp = drogon::HttpResponse::newAsyncStreamResponse(
			[sink](drogon::ResponseStreamPtr stream) { sink->attachStream(std::move(stream)); },
			true /* disableKickoffTimeout: LLM streams sit idle for minutes */);
		if (!resp)
		{
			SseStreamRegistry::instance()->erase(sink->id());
			callback(plainResponse(drogon::k500InternalServerError, "Cannot open stream"));
			return nullptr;
		}
		resp->setStatusCode(drogon::k200OK);
		resp->setContentTypeString("text/event-stream");
		resp->addHeader(web::http::header_names::cache_control, "no-cache");
		// Reverse proxies must not buffer event frames.
		resp->addHeader("X-Accel-Buffering", "no");
		addCors(resp, req->getHeader(web::http::header_names::origin));
		callback(resp);
		sink->startTimers();
		return sink;
	}

	// Synthetic ConnectionKey space for SSE subscriptions: disjoint from the
	// wss session ids so removeByConnection() cleanup stays exact.
	uint64_t nextSseConnectionKey()
	{
		static std::atomic<uint64_t> next{1ULL << 63};
		return next.fetch_add(1, std::memory_order_relaxed);
	}

	// Runs once the body is complete (or the request has none).
	void enqueueHttpRequest(const std::shared_ptr<HttpBodyState> &state)
	{
		const static char fname[] = "DrogonAdaptor::enqueueHttpRequest() ";

		// A declared length that does not match the delivered bytes means a
		// truncated body; the parser enforces this, so treat a mismatch as fatal.
		if (!state->declaredLength.empty())
		{
			std::uint64_t declaredBytes = 0;
			std::from_chars(state->declaredLength.data(), state->declaredLength.data() + state->declaredLength.size(),
							declaredBytes);
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

	// One identity for a plain HTTP connection, shared by the requests it carries and its close callback.
	std::string connectionId(const trantor::InetAddress &local, const trantor::InetAddress &peer)
	{
		return local.toIpPort() + "->" + peer.toIpPort();
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

void DrogonAdaptor::initialize(const std::string &host, uint16_t port, const std::string &cert, const std::string &key,
							   const std::string &ca, bool useTLS, int ioThreads)
{
	const static char fname[] = "DrogonAdaptor::initialize() ";

	m_host = host;
	m_port = static_cast<int>(port);
	m_certFile = cert;
	m_keyFile = key;
	m_caFile = ca;
	m_ioThreads = std::max(1, ioThreads);
	m_useTLS = useTLS;

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

	m_appThread = std::thread(
		[]()
		{
			Utility::setThreadName("appmesh-wss");
			drogon::app().run();
		});

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
		std::lock_guard lock(m_connMutex);
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
	// drogon's run() pre-creates 256 upload cache directories under its upload path
	// (default "uploads", relative to the working directory); pin it under work/tmp.
	const auto uploadDir =
		(fs::path(Configuration::instance()->getWorkDir()) / APPMESH_WORK_TMP_DIR / APPMESH_WORK_UPLOAD_DIR).string();
	app.setUploadPath(uploadDir);
	// No framework banner (version leak) and JSON, not drogon's HTML, for errors
	// the daemon never sees (invalid methods, unmatched framework routes).
	app.enableServerHeader(false);
	app.setCustomErrorHandler(
		[](drogon::HttpStatusCode code, const drogon::HttpRequestPtr &)
		{
			auto resp = drogon::HttpResponse::newHttpResponse();
			resp->setStatusCode(code);
			resp->setContentTypeString("application/json");
			resp->setBody(JSON::dump(Utility::text2json(std::string(drogon::statusCodeToString(static_cast<int>(code))))));
			return resp;
		});
	app.setThreadNum(static_cast<size_t>(m_ioThreads));
	app.setIdleConnectionTimeout(WS_IDLE_TIMEOUT_SECONDS);
	// A closed connection stays allocated until its idle-timeout wheel entry
	// expires; keepAlive() drops the entry's weak reference and frees it now. The
	// close also answers output long-polls and stops sync runs held on that
	// connection. drogon (1.9.13) installs this callback on Linux only; elsewhere
	// the long-poll clamp and the run lifecycle are the bounds.
	app.setConnectionCallback(
		[](const trantor::TcpConnectionPtr &conn)
		{
			if (!conn->connected())
			{
				const auto id = connectionId(conn->localAddr(), conn->peerAddr());
				HttpRequestOutputView::onConnectionClosed(id);
				HttpRequestAutoCleanup::onConnectionClosed(id);
				conn->keepAlive();
			}
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
			::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&on),
						 static_cast<socklen_t>(sizeof(on)));
			tcpframe::enableKeepAlive(fd);
		});

	// TLS: PEM files, cipher hardening, and client-certificate verification
	// when a CA is configured. "require" also rejects a client without a cert.
	// useTLS=false serves plaintext HTTP and WebSocket for the TLS-at-gateway
	// deployment shape; the certificate paths are then empty by contract.
	app.addListener(m_host, static_cast<uint16_t>(m_port), m_useTLS, m_certFile, m_keyFile, false,
					m_useTLS ? dgn::tlsHardeningConf(m_caFile) : std::vector<std::pair<std::string, std::string>>{});

	// Streaming file endpoints (exact routes take precedence over the regex
	// catch-all below). The canonical routes are HTTP-native for plain-HTTP
	// clients; the /ws routes are the WSS client's data side channel. TCP and
	// WSS-control transports never reach this HTTP layer.
	app.registerHandler("/appmesh/file/download",
						[this](const drogon::HttpRequestPtr &req, drogon::AdviceCallback &&callback)
						{ handleDownload(req, std::move(callback)); }, {drogon::Get});
	app.registerHandler(
		"/appmesh/file/upload",
		[this](const drogon::HttpRequestPtr &req, drogon::RequestStreamPtr &&stream, drogon::AdviceCallback &&callback)
		{ handleUpload(req, std::move(stream), std::move(callback)); }, {drogon::Post});
	app.registerHandler("/appmesh/file/delete", [this](const drogon::HttpRequestPtr &req, drogon::AdviceCallback &&callback)
						{ handleFileDelete(req, std::move(callback)); }, {drogon::Delete});
	app.registerHandler("/appmesh/file/download/ws",
						[this](const drogon::HttpRequestPtr &req, drogon::AdviceCallback &&callback)
						{ handleDownload(req, std::move(callback)); }, {drogon::Get});
	app.registerHandler(
		"/appmesh/file/upload/ws",
		[this](const drogon::HttpRequestPtr &req, drogon::RequestStreamPtr &&stream, drogon::AdviceCallback &&callback)
		{ handleUpload(req, std::move(stream), std::move(callback)); }, {drogon::Post});
	// Browser preflight for the file routes: answered here (204) because the
	// allowlist below is the daemon's only CORS source.
	const auto corsPreflight = [](const drogon::HttpRequestPtr &req, drogon::AdviceCallback &&callback)
	{
		auto resp = drogon::HttpResponse::newHttpResponse();
		resp->setStatusCode(drogon::k204NoContent);
		addCors(resp, req->getHeader(web::http::header_names::origin));
		callback(resp);
	};
	for (const char *path : {"/appmesh/file/download", "/appmesh/file/upload", "/appmesh/file/delete",
							 "/appmesh/file/download/ws", "/appmesh/file/upload/ws"})
	{
		app.registerHandler(path, corsPreflight, {drogon::Options});
	}
	// drogon answers a method mismatch on these routes with an empty 405; answer 404 JSON instead.
	const auto routeNotFound = [](const drogon::HttpRequestPtr &req, drogon::AdviceCallback &&callback)
	{
		auto resp = drogon::HttpResponse::newHttpResponse();
		resp->setStatusCode(drogon::k404NotFound);
		resp->setContentTypeString("application/json");
		resp->setBody(JSON::dump(Utility::text2json("Route not found")));
		addCors(resp, req->getHeader(web::http::header_names::origin));
		callback(resp);
	};
	app.registerHandler("/appmesh/file/download", routeNotFound, {drogon::Post, drogon::Put, drogon::Delete, drogon::Patch});
	app.registerHandler("/appmesh/file/upload", routeNotFound, {drogon::Get, drogon::Put, drogon::Delete, drogon::Patch});
	app.registerHandler("/appmesh/file/delete", routeNotFound, {drogon::Get, drogon::Post, drogon::Put, drogon::Patch});
	app.registerHandler("/appmesh/file/download/ws", routeNotFound,
						{drogon::Post, drogon::Put, drogon::Delete, drogon::Patch});
	app.registerHandler("/appmesh/file/upload/ws", routeNotFound, {drogon::Get, drogon::Put, drogon::Delete, drogon::Patch});

	// Streaming (SSE) endpoints on the plain HTTP listener: token-level output
	// follow (served here end to end) and the task stream, which opens the
	// chunked response then rides the worker pipeline under the same path.
	app.registerHandlerViaRegex(R"(/appmesh/app/[^/]+/output/stream)",
								[this](const drogon::HttpRequestPtr &req, drogon::AdviceCallback &&callback)
								{ handleOutputStream(req, std::move(callback)); }, {drogon::Get});
	app.registerHandlerViaRegex(
		R"(/appmesh/app/[^/]+/task/stream)",
		[this](const drogon::HttpRequestPtr &req, drogon::RequestStreamPtr &&stream, drogon::AdviceCallback &&callback)
		{ handleTaskStream(req, std::move(stream), std::move(callback)); }, {drogon::Post});
	// Preflights for the regex stream routes fall through to the catch-all
	// below, whose worker reply answers 204 with the allowlist CORS headers.

	// Dispatched at header time: the body is unread, so an oversized declared length is refused here.
	app.registerPreRoutingAdvice(
		[](const drogon::HttpRequestPtr &req, drogon::AdviceCallback &&callback, drogon::AdviceChainCallback &&chainCallback)
		{
			const auto &declaredLength = req->getHeader(web::http::header_names::content_length);
			std::uint64_t declaredBytes = 0;
			std::from_chars(declaredLength.data(), declaredLength.data() + declaredLength.size(), declaredBytes);
			// Only the upload POSTs stream to disk; every other route is capped.
			const bool isUpload = req->method() == drogon::Post &&
								  (req->path() == "/appmesh/file/upload" || req->path() == "/appmesh/file/upload/ws");
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

	// drogon always answers preflight with wildcard-ish CORS headers of its
	// own; take every OPTIONS request out of that path so the daemon's
	// allowlist (REST.CorsAllowOrigins) is the only CORS source.
	app.registerPreRoutingAdvice(
		[](const drogon::HttpRequestPtr &req)
		{
			if (req->method() == drogon::Options)
				req->attributes()->insert("drogon.customCORShandling", true);
		});

	// Generic HTTP catch-all: every request is serialized to a msgpack
	// Request and queued to the shared worker pool. The stream form lets the
	// body be capped while it arrives, so an undeclared (chunked) length
	// cannot buffer past the REST limit.
	app.registerHandlerViaRegex(
		".*", [this](const drogon::HttpRequestPtr &req, drogon::RequestStreamPtr &&stream, drogon::AdviceCallback &&callback)
		{ handleHttpRequest(req, std::move(stream), std::move(callback)); });

	// WebSocket catch-all (msgpack-over-WS). The filter authenticates the
	// upgrade request and pins the transport identity.
	app.registerWebSocketControllerRegex(".*", dgn::WsController::registrationName(), {"dgn::WsAuthFilter"});

	// drogon has no server-side sub-protocol API; clients fail the handshake
	// unless the negotiated protocol is echoed on the 101 response.
	// The same single funnel stamps the CSP on every REST response: the API
	// serves JSON and files, never active content, so 'none' has no side effects.
	// A handler-set CSP (the OAuth relay page's pinned script hash) wins over
	// the default; drogon headers are one value per key, so addHeader would
	// otherwise overwrite it.
	app.registerPostHandlingAdvice(
		[](const drogon::HttpRequestPtr &req, const drogon::HttpResponsePtr &resp)
		{
			if (!resp)
				return;
			if (resp->statusCode() != drogon::k101SwitchingProtocols)
			{
				if (resp->getHeader(web::http::header_names::content_security_policy).empty())
					resp->addHeader(web::http::header_names::content_security_policy,
									"default-src 'none'; frame-ancestors 'none'");
				return;
			}
			const auto accepted =
				dgn::negotiateWsSubprotocol(req->getHeader(web::http::header_names::sec_websocket_protocol));
			if (!accepted.empty())
				resp->addHeader(web::http::header_names::sec_websocket_protocol, accepted);
		});
}

std::shared_ptr<WSS::ReplyContext> DrogonAdaptor::createHttpReplyContext(drogon::AdviceCallback &&callback)
{
	auto cb = std::make_shared<drogon::AdviceCallback>(std::move(callback));
	return std::make_shared<WSS::ReplyContext>(
		WSS::ReplyContext::ProtocolType::Http,
		[cb = std::move(cb)](std::string &&data, const std::string &status, const WSS::ReplyContext::Headers &headers,
							 const std::string &contentType, bool /*isLast*/, bool /*isBinary*/)
		{
			// drogon response callbacks may be invoked from any thread; the
			// framework queues the write back to the owning IO loop. If the
			// client already disconnected the response is discarded.
			auto resp = drogon::HttpResponse::newHttpResponse();
			int code = 200;
			std::from_chars(status.data(), status.data() + status.size(), code);
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
		[conn](std::string &&data, const std::string &, const WSS::ReplyContext::Headers &, const std::string &,
			   bool /*isLast*/, bool isBinary)
		{
			// WebSocketConnectionPtr is a shared_ptr and send() is safe from
			// any thread; a dead connection is simply skipped.
			if (conn && conn->connected())
			{
				conn->send(std::move(data),
						   isBinary ? drogon::WebSocketMessageType::Binary : drogon::WebSocketMessageType::Text);
			}
		},
		session ? session->connId : std::string(), session ? session->numericId : 0,
		session ? session->peerAddress : std::string(), session ? session->principalId : std::string());
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

void DrogonAdaptor::handleHttpRequest(const drogon::HttpRequestPtr &req, drogon::RequestStreamPtr &&stream,
									  drogon::AdviceCallback &&callback)
{
	handleWorkerRequest(req, std::move(stream), std::move(callback), req->getOriginalPath());
}

void DrogonAdaptor::handleWorkerRequest(const drogon::HttpRequestPtr &req, drogon::RequestStreamPtr &&stream,
										drogon::AdviceCallback &&callback, std::string requestPath,
										std::shared_ptr<WSS::ReplyContext> replyCtx,
										std::map<std::string, std::string> extraHeaders)
{
	const auto method = upperMethod(req);
	if (method != "GET" && method != "POST" && method != "PUT" && method != "DELETE" && method != "OPTIONS")
	{
		auto resp = drogon::HttpResponse::newHttpResponse();
		resp->setStatusCode(drogon::k404NotFound);
		resp->setContentTypeString("application/json");
		resp->setBody(JSON::dump(Utility::text2json("Route not found")));
		callback(resp);
		return;
	}

	auto state = std::make_shared<HttpBodyState>();
	state->replyCtx = replyCtx ? std::move(replyCtx) : createHttpReplyContext(std::move(callback));
	state->declaredLength = req->getHeader(web::http::header_names::content_length);

	const auto &requestState = state->request = std::make_shared<Request>();
	requestState->uuid = Utility::uuid();
	requestState->http_method = method;
	// The path must stay raw, still-encoded; the daemon unescapes it once, so
	// %-escapes are not decoded twice.
	requestState->request_uri = std::move(requestPath);
	for (auto &[k, v] : extraHeaders)
		requestState->headers.emplace(std::move(k), std::move(v));

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
	requestState->connection_id = connectionId(req->localAddr(), req->peerAddr());

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

	// A forwarded transfer belongs to the target node: hand it to the shared
	// worker pipeline under the canonical path (the target REST layer knows no
	// /ws route), so this node never serves the file itself.
	if (!req->getHeader(HTTP_HEADER_KEY_Forwarding_Host).empty())
	{
		handleWorkerRequest(req, nullptr, std::move(callback), "/appmesh/file/download");
		return;
	}

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
	if (!enforceFileHardening(req, callback))
		return;

	const auto &filePathHeader = req->getHeader(HTTP_HEADER_KEY_file_path);
	if (filePathHeader.empty())
	{
		callback(plainResponse(drogon::k400BadRequest, "Missing X-File-Path header"));
		return;
	}

	std::string filePathStr = Utility::decodeHeaderFilePath(filePathHeader);
	if (!Utility::validateFilePath(filePathStr, Configuration::instance()->getFileAllowedBaseDir()))
	{
		callback(plainResponse(drogon::k403Forbidden, "File path is not allowed"));
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

	// Open-then-verify: the fd pins the inode whose resolved location passed the
	// jail check; the stream callback below serves only that file, closing the
	// validate-to-open race a swapped symlink component could otherwise win.
	std::string resolvedPath;
	bool jailRejected = false;
	const int fd = Utility::openFileWithinJail(filePathStr, false, Configuration::instance()->getFileAllowedBaseDir(),
											   resolvedPath, &jailRejected);
	if (fd < 0)
	{
		LOG_ERR << fname << (jailRejected ? "resolved path escaped the jail: " : "cannot open file: ") << filePathStr;
		callback(plainResponse(jailRejected ? drogon::k403Forbidden : drogon::k500InternalServerError,
							   jailRejected ? "File path is not allowed" : "Cannot open file for reading"));
		return;
	}
	auto stream = std::make_shared<FdFileStream>(fd);
	// The pinned fd knows the exact length, so clients detect a truncated body.
	struct stat downloadSt
	{
	};
	std::string contentLength;
	if (::fstat(fd, &downloadSt) == 0 && S_ISREG(downloadSt.st_mode))
		contentLength = std::to_string(downloadSt.st_size);
	auto resp = drogon::HttpResponse::newStreamResponse(
			[stream, filePathStr](char *buf, std::size_t size) -> std::size_t
			{
				if (buf == nullptr)
					return 0; // drogon releasing the stream; the shared_ptr closes the fd
				const auto read = stream->read(buf, size);
				if (read == 0 && !stream->good())
					// A read error truncates the body; Content-Length lets the client detect it.
					LOG_ERR << "DrogonAdaptor::handleDownload() read error mid-stream on <" << filePathStr << ">";
				return static_cast<std::size_t>(read);
			},
			"", drogon::CT_APPLICATION_OCTET_STREAM, "", req);
	if (!resp)
	{
		LOG_ERR << fname << "newStreamResponse failed for: " << filePathStr;
		callback(plainResponse(drogon::k500InternalServerError, "Cannot open file for reading"));
		return;
	}
	resp->addHeader(web::http::header_names::content_disposition, disposition);
	if (!contentLength.empty())
		resp->addHeader(web::http::header_names::content_length, contentLength);
	for (const auto &[name, value] : Utility::fileAttributeHeaders(resolvedPath.empty() ? filePathStr : resolvedPath))
		resp->addHeader(name, value);
	addCors(resp, req->getHeader(web::http::header_names::origin));
	callback(resp);
}

void DrogonAdaptor::handleUpload(const drogon::HttpRequestPtr &req, drogon::RequestStreamPtr &&stream,
								 drogon::AdviceCallback &&callback)
{
	const static char fname[] = "DrogonAdaptor::handleUpload() ";

	// A forwarded transfer belongs to the target node: hand it to the shared
	// worker pipeline under the canonical path (the target REST layer knows no
	// /ws route), so this node never buffers the body to disk.
	if (!req->getHeader(HTTP_HEADER_KEY_Forwarding_Host).empty())
	{
		handleWorkerRequest(req, std::move(stream), std::move(callback), "/appmesh/file/upload");
		return;
	}

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
	if (!enforceFileHardening(req, callback))
		return;

	const auto &filePathHeader = req->getHeader(HTTP_HEADER_KEY_file_path);
	if (filePathHeader.empty())
	{
		callback(plainResponse(drogon::k400BadRequest, "Missing X-File-Path header"));
		return;
	}

	std::string fullPath = Utility::decodeHeaderFilePath(filePathHeader);
	if (!Utility::validateFilePath(fullPath, Configuration::instance()->getFileAllowedBaseDir()))
	{
		callback(plainResponse(drogon::k403Forbidden, "File path is not allowed"));
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
		if (std::filesystem::is_directory(filePath, ec))
		{
			callback(plainResponse(drogon::k400BadRequest, "Destination is a directory"));
			return;
		}
	}
	const bool overwrite = req->getHeader(HTTP_HEADER_KEY_file_overwrite) == "true";
	if (!overwrite)
	{
		std::error_code ec;
		if (std::filesystem::exists(filePath, ec))
		{
			callback(plainResponse(drogon::k409Conflict, "File already exists"));
			return;
		}
	}

	// Raw body only; multipart belongs to the agent proxy surface.
	{
		auto contentType = req->getHeader(web::http::header_names::content_type);
		std::transform(contentType.begin(), contentType.end(), contentType.begin(),
					   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
		if (contentType.rfind("MULTIPART/FORM-DATA", 0) == 0)
		{
			callback(plainResponse(drogon::k400BadRequest,
								   "multipart/form-data is not supported on this endpoint; send the raw file body"));
			return;
		}
	}

	HttpHeaderMap attrHeaders;
	auto captureAttr = [&req, &attrHeaders](const char *headerName, const std::string &canonicalName)
	{
		auto value = req->getHeader(headerName);
		if (!value.empty())
			attrHeaders.emplace(canonicalName, std::move(value));
	};
	captureAttr("x-file-mode", HTTP_HEADER_KEY_file_mode);
	captureAttr("x-file-user", HTTP_HEADER_KEY_file_user);
	captureAttr("x-file-group", HTTP_HEADER_KEY_file_group);

	// Stream into a temp file beside the destination and publish it on success
	// (atomically; an overwrite replaces, otherwise an existing destination stays).
	const std::string tempPath = fullPath + ".appmesh-upload-" + Utility::uuid();
	auto upload = std::make_shared<FileUploadInfo>(fullPath, tempPath, attrHeaders, overwrite,
												   Configuration::instance()->getFileAllowedBaseDir());
	if (upload->m_rejected)
	{
		// The fd check saw the resolved temp location leave the jail: a
		// component was swapped between validation and open.
		LOG_ERR << fname << "Resolved upload path escaped the jail: " << fullPath;
		callback(plainResponse(drogon::k403Forbidden, "File path is not allowed"));
		return;
	}
	if (!upload->m_file.is_open())
	{
		LOG_ERR << fname << "Failed to open file for writing: " << tempPath;
		callback(plainResponse(drogon::k500InternalServerError, "Failed to open file for writing"));
		return;
	}

	const std::string fileName = filePath.filename().string();
	const std::string requestOrigin = req->getHeader(web::http::header_names::origin);
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
		[upload, writeFailed, fileName, requestOrigin, callback = std::move(callback)](std::exception_ptr err) mutable
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

			const auto commit = upload->commit();
			if (commit == FileUploadInfo::CommitResult::AlreadyExists)
			{
				LOG_WAR << fname << "Concurrent upload already created: " << upload->m_filePath;
				callback(plainResponse(drogon::k409Conflict, "File already exists"));
				return;
			}
			if (commit == FileUploadInfo::CommitResult::Failed)
			{
				LOG_ERR << fname << "Cannot move upload into place: " << upload->m_filePath;
				callback(plainResponse(drogon::k500InternalServerError, "File write error"));
				return;
			}

			std::error_code ec;
			const auto size = std::filesystem::file_size(upload->m_filePath, ec);
			LOG_INF << fname << "File uploaded successfully: " << upload->m_filePath << " (" << size << " bytes)";

			// Apply caller-supplied POSIX attributes after the file commits,
			// mirroring the REST upload path.
			Utility::applyFilePermission(upload->m_filePath, upload->m_requestHeaders, upload->fd());

			Json::Value respJson;
			respJson["status"] = "success";
			respJson["file"] = fileName;
			respJson["size"] = (Json::UInt64)size;
			auto resp = drogon::HttpResponse::newHttpResponse();
			resp->setStatusCode(drogon::k201Created);
			resp->setContentTypeString("application/json");
			addCors(resp, requestOrigin);
			// Invalid UTF-8 in the filename makes default dump() throw; 'replace' avoids it.
			resp->setBody(JSON::dump(respJson));
			callback(resp);
		}));
}

void DrogonAdaptor::handleFileDelete(const drogon::HttpRequestPtr &req, drogon::AdviceCallback &&callback)
{
	const static char fname[] = "DrogonAdaptor::handleFileDelete() ";

	// A forwarded delete belongs to the target node: hand it to the shared
	// worker pipeline under the canonical path.
	if (!req->getHeader(HTTP_HEADER_KEY_Forwarding_Host).empty())
	{
		handleWorkerRequest(req, nullptr, std::move(callback), "/appmesh/file/delete");
		return;
	}

	try
	{
		authorize(req->getHeader(web::http::header_names::authorization), PERMISSION_KEY_file_delete);
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
	if (!enforceFileHardening(req, callback))
		return;

	const auto &filePathHeader = req->getHeader(HTTP_HEADER_KEY_file_path);
	if (filePathHeader.empty())
	{
		callback(plainResponse(drogon::k400BadRequest, "Missing X-File-Path header"));
		return;
	}

	std::string fullPath = Utility::decodeHeaderFilePath(filePathHeader);
	// Pin-then-verify: unlinkat targets the dirfd-pinned parent re-verified against
	// the jail, so a symlink swap cannot steer the delete outside the jail.
	std::string resolvedPath;
	switch (Utility::unlinkFileWithinJail(fullPath, Configuration::instance()->getFileAllowedBaseDir(), resolvedPath))
	{
	case Utility::JailUnlinkStatus::Removed:
		break;
	case Utility::JailUnlinkStatus::Rejected:
		callback(plainResponse(drogon::k403Forbidden, "File path is not allowed"));
		return;
	case Utility::JailUnlinkStatus::NotFound:
		// Missing leaf or a (never-deletable) directory; a symlink leaf lands in Rejected.
		callback(plainResponse(drogon::k404NotFound, "File not found"));
		return;
	case Utility::JailUnlinkStatus::Failed:
	default:
		callback(plainResponse(drogon::k500InternalServerError, "File remove failed"));
		return;
	}
	LOG_INF << fname << "File deleted: " << (resolvedPath.empty() ? fullPath : resolvedPath);
	auto resp = plainResponse(drogon::k200OK, "success");
	addCors(resp, req->getHeader(web::http::header_names::origin));
	callback(resp);
}

void DrogonAdaptor::handleOutputStream(const drogon::HttpRequestPtr &req, drogon::AdviceCallback &&callback)
{
	const static char fname[] = "DrogonAdaptor::handleOutputStream() ";

	if (!req->getHeader(HTTP_HEADER_KEY_Forwarding_Host).empty())
	{
		callback(plainResponse(drogon::k400BadRequest, "Streaming is not supported through node forwarding"));
		return;
	}
	if (!enforceSseHardening(req, callback))
		return;
	const auto appName = appNameFromStreamPath(req->getOriginalPath(), "/output/stream");
	if (appName.empty() || authorizeStreamApp(req, callback, appName, PERMISSION_KEY_view_app_output, false).empty())
		return;
	const auto app = Configuration::instance()->getApp(appName);

	const auto processUuid = streamQueryParam(req, HTTP_QUERY_KEY_process_uuid);
	const bool follow = streamQueryParam(req, "follow") != "false";
	long position = 0;
	if (const auto posStr = streamQueryParam(req, HTTP_QUERY_KEY_stdout_position); !posStr.empty())
	{
		position = DurationParse::parse(posStr);
		if (position < 0)
		{
			callback(plainResponse(drogon::k400BadRequest, "stdout_position must not be negative"));
			return;
		}
	}
	long timeoutSeconds = DEFAULT_SSE_STREAM_TIMEOUT_SECONDS;
	if (const auto timeoutStr = streamQueryParam(req, HTTP_QUERY_KEY_timeout); !timeoutStr.empty())
	{
		timeoutSeconds = DurationParse::parse(timeoutStr);
		if (timeoutSeconds < 0)
			timeoutSeconds = DEFAULT_SSE_STREAM_TIMEOUT_SECONDS;
		timeoutSeconds = std::min(timeoutSeconds, static_cast<long>(MAX_SSE_STREAM_TIMEOUT_SECONDS));
	}

	auto sink = startSseResponse(req, callback);
	if (!sink)
		return;

	// Shared by the delivery callback, the backfill below and the overall
	// timeout. The position cursor de-duplicates pump events against the
	// backfill read (the race the SDKs used to paper over with sleeps).
	struct FollowState
	{
		std::mutex mutex;
		std::shared_ptr<SseStream> sink;
		std::shared_ptr<Application> app;
		std::string subId;
		long cursor{0};
		bool ended{false};
	};
	const auto state = std::make_shared<FollowState>();
	state->sink = sink;
	state->app = app;
	state->cursor = position;
	// Held weakly: the subscription callback and the sink's close hook keep the
	// state alive, so the timeout timer cannot pin the Application.
	const std::weak_ptr<FollowState> weakState = state;

	// Emits the terminal "end" frame exactly once and tears the stream down.
	const auto endFollow = [weakState](const std::string &reason, const Json::Value &extra)
	{
		const auto state = weakState.lock();
		if (!state)
			return;
		std::string subId;
		{
			std::lock_guard lock(state->mutex);
			if (state->ended)
				return;
			state->ended = true;
			subId = state->subId;
			Json::Value end = extra;
			end["reason"] = reason;
			end["position"] = (Json::Int64)state->cursor;
			state->sink->sendEvent("end", JSON::dump(end));
		}
		// Outside the state lock: close() fires the sink's onClosed hook, which
		// re-enters endFollow for a disconnect and would deadlock under the lock.
		state->sink->close();
		if (!subId.empty())
			EventDispatcher::instance()->unsubscribe(subId);
	};

	// Position-cursor delivery shared by live events and backfill chunks. The
	// cursor counts raw stdout bytes; `output` is the sanitized view whose
	// length can differ, so the raw advance is passed in.
	const auto deliverStdout = [state](long start, const std::string &output, long rawAdvance) -> bool
	{
		std::lock_guard lock(state->mutex);
		if (state->ended)
			return true;
		if (rawAdvance <= 0)
			rawAdvance = static_cast<long>(output.size());
		if (start + rawAdvance <= state->cursor)
			return true; // fully covered by an earlier delivery
		auto text = output;
		if (start < state->cursor && rawAdvance == static_cast<long>(output.size()))
		{
			// Exact prefix trim is only sound when the view is byte-identical
			// to the raw span; a re-encoded chunk is delivered untrimmed rather
			// than slicing the text at a raw-byte boundary.
			text.erase(0, static_cast<std::size_t>(state->cursor - start));
			start = state->cursor;
		}
		Json::Value data;
		data["position"] = (Json::Int64)start;
		data["output"] = std::move(text);
		if (!state->sink->sendEvent("stdout", JSON::dump(data)))
		{
			state->ended = true;
			return false;
		}
		state->cursor = std::max(state->cursor, start + rawAdvance);
		return true;
	};

	// A silent peer is caught by the heartbeat; its close hook ends the follow
	// instead of idling the subscription to the timeout.
	sink->setOnClosed([endFollow]() { endFollow("disconnected", {}); });

	// Subscribe first so the pump starts dispatching, then replay; overlapping
	// deliveries are reconciled by the cursor above.
	const auto subId = EventDispatcher::instance()->subscribe(
		appName,
		static_cast<uint32_t>(AppEventType::STDOUT_OUTPUT) | static_cast<uint32_t>(AppEventType::PROCESS_EXIT) |
			static_cast<uint32_t>(AppEventType::APP_REMOVED),
		"", // owner policy already checked; subscriptions store the principal for unsubscribe only
		[state, deliverStdout, endFollow](const EventEnvelope &envelope) -> bool
		{
			if (envelope.eventType == "STDOUT")
			{
				try
				{
					const auto payload = JSON::parse(*envelope.basePayloadDump);
					const auto &data = payload["data"];
					// raw_size (pre-sanitization byte count) keeps the cursor on
					// raw offsets when the UTF-8 view changed the length.
					long rawAdvance = static_cast<long>(data["output"].asString().size());
					if (data.isMember("raw_size"))
						rawAdvance = data["raw_size"].asInt64();
					return deliverStdout(data["position"].asInt64(), data["output"].asString(), rawAdvance);
				}
				catch (const std::exception &)
				{
					return true; // a malformed frame must not kill the stream
				}
			}
			if (envelope.eventType == "EXIT")
			{
				// Drain [cursor, EOF] so the final position is exact even if the
				// exit-time flush raced this delivery.
				try
				{
					auto app = state->app;
					for (;;)
					{
						long pos = 0;
						{
							std::lock_guard lock(state->mutex);
							pos = state->cursor;
							if (state->ended)
								return false;
						}
						// Same raw-delta rule as the replay path above.
						const auto chunkStart = pos;
						auto output = std::get<0>(app->getOutput(pos, 256 * 1024, "", 0, 0));
						if (output.empty())
							break;
						if (!deliverStdout(chunkStart, output, pos - chunkStart))
							return false;
						if (pos - chunkStart < 256 * 1024)
							break;
					}
				}
				catch (const std::exception &)
				{
				}
				int exitCode = 0;
				try
				{
					const auto payload = JSON::parse(*envelope.basePayloadDump);
					exitCode = payload["data"]["exit_code"].asInt();
				}
				catch (const std::exception &)
				{
				}
				Json::Value extra;
				extra["exit_code"] = exitCode;
				endFollow("exit", extra);
				return false;
			}
			if (envelope.eventType == "REMOVED")
			{
				endFollow("removed", {});
				return false;
			}
			return true;
		},
		ConnectionKey::wss(nextSseConnectionKey()));
	{
		std::lock_guard lock(state->mutex);
		state->subId = subId;
	}

	// Overall lifetime bound; heartbeats inside the sink detect a gone peer.
	if (timeoutSeconds > 0)
	{
		TIMER_MANAGER::instance()->registerTimer(static_cast<std::size_t>(timeoutSeconds) * 1000, 0, "sse-output-timeout",
												 [endFollow]()
												 {
													 endFollow("timeout", {});
													 return false;
												 });
	}

	// Replay [position, EOF]; a finished run ends with its exit code, a live one
	// keeps following (or stops at the tail when follow=false).
	try
	{
		bool finished = false;
		int exitCode = 0;
		for (;;)
		{
			// getOutput advances position to the end of what it read, so the
			// chunk start must be captured first.
			const auto chunkStart = position;
			std::string output;
			std::tie(output, finished, exitCode) = app->getOutput(position, 256 * 1024, processUuid, 0, 0);
			// getOutput returns the sanitized view but advances the cursor over
			// raw bytes; the raw span is the position delta.
			const auto rawAdvance = position - chunkStart;
			if (!output.empty() && !deliverStdout(chunkStart, output, rawAdvance))
				return;
			{
				std::lock_guard lock(state->mutex);
				if (state->ended)
					return;
			}
			if (finished)
			{
				Json::Value extra;
				extra["exit_code"] = exitCode;
				endFollow("exit", extra);
				return;
			}
			if (rawAdvance < 256 * 1024)
			{
				if (!follow)
					endFollow("eof", {});
				return;
			}
		}
	}
	catch (const std::exception &e)
	{
		LOG_WAR << fname << "backfill failed for app <" << appName << ">: " << e.what();
		Json::Value extra;
		extra["message"] = e.what();
		endFollow("error", extra);
	}
}

void DrogonAdaptor::handleTaskStream(const drogon::HttpRequestPtr &req, drogon::RequestStreamPtr &&stream,
									 drogon::AdviceCallback &&callback)
{
	if (!req->getHeader(HTTP_HEADER_KEY_Forwarding_Host).empty())
	{
		callback(plainResponse(drogon::k400BadRequest, "Streaming is not supported through node forwarding"));
		return;
	}
	// No native hardening: the worker pipeline validates replay/signature
	// exactly once against the real body (a pre-check would re-consume the
	// nonce); rejections surface as the terminal "end{error}" frame.
	const auto appName = appNameFromStreamPath(req->getOriginalPath(), "/task/stream");
	if (appName.empty() || authorizeStreamApp(req, callback, appName, PERMISSION_KEY_run_task, true).empty())
		return;
	auto sink = startSseResponse(req, callback);
	if (!sink)
		return;

	// The single final reply of the parked request maps onto terminal SSE
	// events: 200 becomes "final" + "end", anything else (auth races, task
	// timeout, cancellation, queue overflow) becomes an "end" error frame.
	auto replyCtx = std::make_shared<WSS::ReplyContext>(
		WSS::ReplyContext::ProtocolType::Http,
		[sink](std::string &&data, const std::string &status, const WSS::ReplyContext::Headers &, const std::string &,
			   bool /*isLast*/, bool /*isBinary*/)
		{
			int code = 200;
			std::from_chars(status.data(), status.data() + status.size(), code);
			if (code == 200)
			{
				Json::Value result;
				result["result"] = std::move(data);
				sink->sendEvent("final", JSON::dump(result));
				Json::Value end;
				end["reason"] = "final";
				sink->sendEvent("end", JSON::dump(end));
			}
			else
			{
				Json::Value end;
				end["reason"] = code == 408 ? "timeout" : "error";
				end["status"] = code;
				end["message"] = std::move(data);
				sink->sendEvent("end", JSON::dump(end));
			}
			sink->close();
		});

	// The SSE 200 already owns the connection; the pipeline reply rides the
	// sink-bound context above, and the marker header lets the worker-side
	// handler resolve the same sink after the msgpack boundary.
	handleWorkerRequest(req, std::move(stream), drogon::AdviceCallback([](drogon::HttpResponsePtr) {}),
						req->getOriginalPath(), std::move(replyCtx), {{HTTP_HEADER_KEY_X_AppMesh_Sse_Stream, sink->id()}});
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
		std::lock_guard lock(m_connMutex);
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

void DrogonAdaptor::onWsMessage(const drogon::WebSocketConnectionPtr &conn, std::string &&message,
								drogon::WebSocketMessageType type)
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
		std::lock_guard lock(m_connMutex);
		m_connections.erase(connId);
	}
	if (numericId > 0)
	{
		EventDispatcher::instance()->removeByConnection(ConnectionKey::wss(numericId));
	}

	LOG_DBG << fname << "Connection " << connId << " closed";
}
