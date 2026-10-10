// src/common/RestClientDrogon.cpp
// HTTP client backend for the C++17 (drogon) tier. Synchronous requests are
// implemented on top of trantor (drogon's network library) running on a
// dedicated event loop thread, so callers stay blocking as before.
//
// drogon::HttpClient is intentionally not used: it cannot bind a custom CA
// bundle or client certificate to a request, while trantor::TLSPolicy covers
// the full ClientSSLConfig surface (CA path, mTLS cert/key, peer validation).
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <future>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

#include <trantor/net/EventLoop.h>
#include <trantor/net/EventLoopThread.h>
#include <trantor/net/InetAddress.h>
#include <trantor/net/TLSPolicy.h>
#include <trantor/net/TcpClient.h>
#include <trantor/net/TcpConnection.h>
#include <trantor/utils/MsgBuffer.h>

#include "RestClient.h"
#include "UriParser.hpp"
#include "Utility.h"

namespace
{
	constexpr const char *HTTP_USER_AGENT_HEADER = "User-Agent";
	constexpr const char *HTTP_USER_AGENT = "appmesh-daemon";
	constexpr long REQUEST_TIMEOUT_SECONDS = 200L;

	// Process-wide event loop thread driving all outbound HTTP client connections.
	trantor::EventLoop *httpClientLoop()
	{
		static struct LoopHolder
		{
			trantor::EventLoopThread thread;
			trantor::EventLoop *loop;
			LoopHolder() : thread("appmesh-rest"), loop(nullptr)
			{
				thread.run();
				while ((loop = thread.getLoop()) == nullptr)
					std::this_thread::yield();
			}
		} holder;
		return holder.loop;
	}

	struct RequestState
	{
		std::promise<void> donePromise;
		std::shared_ptr<HttpResponse> response = std::make_shared<HttpResponse>();
		std::string requestWire; // fully serialized request, sent on connect
		std::string raw;		 // accumulated response bytes
		size_t bodyStart = 0;
		long contentLength = -1; // -1: body delimited by connection close
		bool headersParsed = false;
		bool chunked = false;
		bool finished = false; // event loop thread only
		trantor::TcpConnectionPtr conn;
		std::shared_ptr<trantor::TcpClient> client;

		// Must run on the event loop thread; the first call wins.
		void finish(const std::string &error)
		{
			if (finished)
				return;
			finished = true;
			if (!error.empty())
				response->text = error;
			donePromise.set_value();
		}
	};

	bool decodeChunkedBody(const std::string &data, std::string &out)
	{
		size_t pos = 0;
		while (true)
		{
			const auto eol = data.find("\r\n", pos);
			if (eol == std::string::npos)
				return false; // need more data
			// chunk extensions (";...") are ignored
			const auto sizeText = data.substr(pos, eol - pos);
			const char *endPtr = nullptr;
			const unsigned long chunkSize = std::strtoul(sizeText.c_str(), const_cast<char **>(&endPtr), 16);
			if (endPtr == sizeText.c_str())
				return false;
			pos = eol + 2;
			if (chunkSize == 0)
			{
				// optional trailer part, terminated by an empty line
				while (true)
				{
					const auto trailerEnd = data.find("\r\n", pos);
					if (trailerEnd == std::string::npos)
						return false; // need more data
					if (trailerEnd == pos)
						return true; // empty line: message complete
					pos = trailerEnd + 2;
				}
			}
			if (data.size() < pos + chunkSize + 2)
				return false; // need more data
			out.append(data, pos, chunkSize);
			pos += chunkSize + 2; // skip trailing CRLF
		}
	}

	// Returns true once the complete response (headers + body) has been received.
	bool tryCompleteResponse(RequestState &state)
	{
		if (!state.headersParsed)
		{
			const auto headerEnd = state.raw.find("\r\n\r\n");
			if (headerEnd == std::string::npos)
				return false;

			// Status line: HTTP/1.1 200 OK
			const auto lineEnd = state.raw.find("\r\n");
			const auto space = state.raw.find(' ');
			if (lineEnd == std::string::npos || space == std::string::npos || space > lineEnd)
			{
				state.finish("malformed HTTP response status line");
				return true;
			}
			state.response->status_code = std::atol(state.raw.c_str() + space + 1);

			size_t pos = lineEnd + 2;
			while (pos < headerEnd)
			{
				const auto eol = state.raw.find("\r\n", pos);
				if (eol == std::string::npos || eol > headerEnd)
					break;
				const auto colon = state.raw.find(':', pos);
				if (colon != std::string::npos && colon < eol)
				{
					auto key = Utility::stdStringTrim(state.raw.substr(pos, colon - pos));
					auto value = Utility::stdStringTrim(state.raw.substr(colon + 1, eol - colon - 1));
					if (!key.empty())
						state.response->header[key] = value;
				}
				pos = eol + 2;
			}

			state.bodyStart = headerEnd + 4;
			state.headersParsed = true;

			const auto transferEncoding = state.response->header.get("transfer-encoding");
			std::string teLower;
			teLower.reserve(transferEncoding.size());
			for (char c : transferEncoding)
				teLower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
			if (teLower.find("chunked") != std::string::npos)
			{
				state.chunked = true;
			}
			else if (state.response->header.count("content-length") > 0)
			{
				state.contentLength = std::atol(state.response->header.get("content-length").c_str());
			}
		}

		const size_t bodyBytes = state.raw.size() - state.bodyStart;
		if (state.chunked)
		{
			std::string body;
			if (!decodeChunkedBody(state.raw.substr(state.bodyStart), body))
				return false;
			state.response->text.swap(body);
			return true;
		}
		if (state.contentLength >= 0)
		{
			if (bodyBytes < static_cast<size_t>(state.contentLength))
				return false;
			state.response->text = state.raw.substr(state.bodyStart, static_cast<size_t>(state.contentLength));
			return true;
		}
		return false; // body delimited by connection close
	}

	std::string buildRequestWire(
		const web::http::method &mtd,
		const std::string &pathWithQuery,
		const std::string &hostHeader,
		const std::map<std::string, std::string> &header,
		const std::string &body)
	{
		// Preserve the legacy transport semantics: a body is sent for POST/PUT only.
		const bool sendBody = !body.empty() && (mtd == web::http::methods::POST || mtd == web::http::methods::PUT);

		std::ostringstream os;
		os << mtd << ' ' << pathWithQuery << " HTTP/1.1\r\n";
		os << "Host: " << hostHeader << "\r\n";
		os << HTTP_USER_AGENT_HEADER << ": " << HTTP_USER_AGENT << "\r\n";
		bool hasContentType = false;
		for (const auto &h : header)
		{
			os << h.first << ": " << h.second << "\r\n";
			if (h.first.size() == std::strlen("Content-Type"))
			{
				std::string lower;
				lower.reserve(h.first.size());
				for (char c : h.first)
					lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
				hasContentType = hasContentType || lower == "content-type";
			}
		}
		if (sendBody)
		{
			if (!hasContentType)
				os << "Content-Type: " << web::http::mime_types::application_json << "\r\n";
			os << "Content-Length: " << body.size() << "\r\n";
		}
		// Ask the peer to close after the response: that also delimits bodies
		// without Content-Length, so no keep-alive bookkeeping is needed.
		os << "Connection: close\r\n\r\n";
		if (sendBody)
			os << body;
		return os.str();
	}
}

std::shared_ptr<HttpResponse> RestClient::request(
	const std::string &host,
	const web::http::method &mtd,
	const std::string &path,
	const std::string &body,
	std::map<std::string, std::string> header,
	std::map<std::string, std::string> query,
	long timeoutSeconds,
	const ClientSSLConfig *sslConfig)
{
	const static char fname[] = "RestClient::request() ";

	auto state = std::make_shared<RequestState>();

	RequestTarget target;
	std::string targetError;
	if (!parseRequestTarget(host, path, query, target, targetError))
	{
		state->response->text = targetError;
		LOG_ERR << fname << state->response->text;
		return state->response;
	}
	const auto ssl = resolveSslConfig(sslConfig);
	state->requestWire = buildRequestWire(mtd, target.target, target.hostHeader, header, body);

	std::string resolveError;
	const std::string ip = Utility::resolveHostAddress(target.host, resolveError);
	if (ip.empty())
	{
		state->response->text = "DNS resolution failed for " + target.host + ": " + resolveError;
		LOG_ERR << fname << state->response->text;
		return state->response;
	}

	auto future = state->donePromise.get_future();
	auto *loop = httpClientLoop();

	loop->runInLoop([state, loop, ip, port = target.port, useSSL = target.useSSL, hostName = target.host, ssl]() mutable
					{
		try
		{
			auto client = std::make_shared<trantor::TcpClient>(loop, trantor::InetAddress(ip, static_cast<uint16_t>(port), ip.find(':') != std::string::npos), "appmesh-rest");

			client->setConnectionCallback([state](const trantor::TcpConnectionPtr &conn)
										  {
				if (state->finished)
					return;
				if (conn->connected())
				{
					state->conn = conn;
					conn->send(state->requestWire);
				}
				else
				{
					// Connection closed: complete from whatever was received.
					if (tryCompleteResponse(*state))
						state->finish(std::string());
					else if (!state->headersParsed)
						state->finish("connection closed before response headers received");
					else if (!state->chunked && state->contentLength < 0)
					{
						state->response->text = state->raw.substr(state->bodyStart);
						state->finish(std::string());
					}
					else
						state->finish("connection closed before response body completed");
				} });
			client->setConnectionErrorCallback([state]()
											   { state->finish("connection to peer failed"); });
			client->setMessageCallback([state](const trantor::TcpConnectionPtr &conn, trantor::MsgBuffer *buf)
									   {
				if (!state->finished)
				{
					state->raw.append(buf->peek(), buf->readableBytes());
					if (tryCompleteResponse(*state))
					{
						state->finish(std::string());
						conn->forceClose();
					}
				}
				buf->retrieveAll(); });

			if (useSSL)
			{
				auto policy = std::make_shared<trantor::TLSPolicy>();
				policy->setValidate(ssl.m_verify_server)
					.setUseOldTLS(false)
					.setUseSystemCertStore(ssl.m_verify_server && ssl.m_ca_location.empty())
					.setHostname(hostName);
				if (ssl.m_verify_server && !ssl.m_ca_location.empty())
					policy->setCaPath(ssl.m_ca_location);
				if (ssl.m_verify_client && !ssl.m_certificate.empty() && !ssl.m_private_key.empty())
				{
					policy->setCertPath(ssl.m_certificate).setKeyPath(ssl.m_private_key);
					if (!ssl.m_private_key_passwd.empty())
						LOG_WAR << fname << "trantor does not support password-protected client keys; the password is ignored";
				}
				client->enableSSL(policy);
			}

			state->client = client;
			client->connect();
		}
		catch (const std::exception &ex)
		{
			state->finish(std::string("failed to set up the connection: ") + ex.what());
		} });

	const long totalTimeout = timeoutSeconds > 0 ? timeoutSeconds : REQUEST_TIMEOUT_SECONDS;
	auto waitStatus = future.wait_for(std::chrono::seconds(totalTimeout));
	if (waitStatus == std::future_status::timeout)
	{
		loop->runInLoop([state]()
						{
			state->finish("request timeout");
			if (state->conn)
				state->conn->forceClose(); });
		// Let the event loop finalize the response object; only the loop thread touches it.
		waitStatus = future.wait_for(std::chrono::seconds(2));
	}

	if (waitStatus == std::future_status::ready)
	{
		future.get();
		if (state->response->status_code == 0)
			LOG_ERR << fname << "request to <" << host << "> failed: " << state->response->text;
		// trantor objects must be released on their event loop thread.
		loop->runInLoop([state]() mutable
					{ state->client.reset(); });
		return state->response;
	}

	// The loop is wedged and still owns the response object; hand the caller a
	// detached timeout answer instead of racing the loop thread for it.
	LOG_ERR << fname << "request to <" << host << "> timed out without a loop response";
	auto timeoutResponse = std::make_shared<HttpResponse>();
	timeoutResponse->status_code = 0;
	timeoutResponse->text = "request timeout";
	loop->runInLoop([state]() mutable
					{ state->client.reset(); });
	return timeoutResponse;
}
