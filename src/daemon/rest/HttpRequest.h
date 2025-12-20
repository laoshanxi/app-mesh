// src/daemon/rest/HttpRequest.h
#pragma once

#include <map>
#include <memory>

#include <nlohmann/json.hpp>

#include "../../common/HttpHeaderMap.h"
#include "../../common/TimerHandler.h"
#include "../../common/Utility.h"
#include "Data.h"

class WebSocketSession;
namespace WSS
{
	class ReplyContext;
}

// HttpRequest is a wrapper of <web::http::http_request>
//   - Used for REST server to forward requests to TCP server and wait for TCP result before responding to REST client
//   - Used for TCP server to send results to REST server
//   - Serializes between RestTcpServer & RestChildObject
//   - Handles cross-domain reply headers
class HttpRequest
{
public:
	// Constructor for deserialization
	// TCP REST Server receives and decodes this
	explicit HttpRequest(Request &&request, int tcpHandlerId);

	virtual ~HttpRequest();

	// Extracts and parses HTTP body as JSON
	// Always use this function to get HTTP body for consistent serialization
	nlohmann::json extractJson() const;

	// Responds to this HTTP request with status only
	bool reply(web::http::status_code status) const;

	// Responds to this HTTP request with JSON body
	bool reply(web::http::status_code status, const nlohmann::json &body_data) const;

	// Responds to this HTTP request with raw bytes
	bool reply(web::http::status_code status, const std::vector<std::uint8_t> &body_data) const;

	// Responds to this HTTP request with JSON body and custom headers
	bool reply(web::http::status_code status, const nlohmann::json &body_data, const std::map<std::string, std::string> &headers) const;

	// Responds to this HTTP request with a string body
	// Callers do NOT need to block waiting for the response to be sent before the body data is destroyed or goes out of scope
	bool reply(web::http::status_code status,
			   std::string &body_data,
			   const std::string &content_type = web::http::mime_types::text_plain_utf8) const;

	// Responds to this HTTP request with string body and custom headers
	bool reply(web::http::status_code status,
			   const std::string &body_data,
			   const std::map<std::string, std::string> &headers,
			   const std::string &content_type = web::http::mime_types::text_plain_utf8) const;

	static std::shared_ptr<HttpRequest> deserialize(const ByteBuffer &input, int tcpHandlerId, const void *wsi, std::shared_ptr<WSS::ReplyContext> ctx);
	std::unique_ptr<msgpack::sbuffer> serialize() const;
	static const nlohmann::json emptyJsonMessage();
	void dump() const;
	void verifyHMAC() const;

	std::string m_uuid;
	web::http::method m_method;
	std::string m_relative_uri;
	std::string m_remote_address;
	std::shared_ptr<std::vector<std::uint8_t>> m_body; // Shared pointer to avoid copying large data
	std::map<std::string, std::string> m_query;
	HttpHeaderMap m_headers;

	// Sends REST response to client through TCP handler
	virtual bool reply(const std::string &requestUri, const std::string &uuid, const std::vector<std::uint8_t> &body,
					   const std::map<std::string, std::string> &headers, const web::http::status_code &status,
					   const std::string &bodyType) const;

private:
	const int m_tcpClientId;
	const void *m_wsSessionId;
	std::shared_ptr<WSS::ReplyContext> m_replyContext;
};

class Application;

// HttpRequest that automatically removes Application when reply finishes
// Used to manage Application lifecycle tied to request completion
class HttpRequestAutoCleanup : public HttpRequest
{
public:
	explicit HttpRequestAutoCleanup(const std::shared_ptr<HttpRequest> &message, const std::shared_ptr<Application> &appObj);
	virtual ~HttpRequestAutoCleanup();

private:
	std::weak_ptr<Application> m_app;
};

// HttpRequest with timeout support
// Automatically responds with timeout status if not replied within specified duration
class HttpRequestWithTimeout : public HttpRequest, public TimerHandler
{
public:
	using HttpRequest::reply;
	explicit HttpRequestWithTimeout(const std::shared_ptr<HttpRequest> &message);
	virtual ~HttpRequestWithTimeout();

	bool initTimer(int timeoutSeconds);

	// Timer callback invoked when timeout expires
	bool onTimerResponse();
	bool replied() const;

	// Interrupts this request with ExpectationFailed status
	bool interrupt();
	void id(int id);
	int id();

protected:
	// Overridden reply to ensure single response by canceling timer and checking reply flag
	virtual bool reply(const std::string &requestUri, const std::string &uuid, const std::vector<std::uint8_t> &body,
					   const std::map<std::string, std::string> &headers, const web::http::status_code &status,
					   const std::string &bodyType) const override;

private:
	mutable std::atomic_long m_timerResponseId;
	mutable std::atomic<bool> m_httpRequestReplyFlag;
	mutable std::atomic_int m_id;
};

// HttpRequest for viewing application output
// Monitors process and responds with output when ready or on timeout
class HttpRequestOutputView : public TimerHandler, public HttpRequest
{
public:
	explicit HttpRequestOutputView(const std::shared_ptr<HttpRequest> &message, const std::shared_ptr<Application> &appObj);
	~HttpRequestOutputView() = default;
	void init();

	// Triggers immediate response with current output
	void response();

	// Timer callback to respond with application output
	bool onTimerResponse();

	// Static method to respond to all pending requests for a process
	// Called when a process exits to respond with final output
	static void onProcessExitResponse(pid_t pid);

private:
	std::atomic_long m_timerResponseId;
	pid_t m_pid;
	std::weak_ptr<Application> m_app;
	std::atomic_flag m_httpRequestReplyFlag = ATOMIC_FLAG_INIT;
};

// Manages task request/response communication between client and server
// Coordinates message flow for bidirectional task handling
class TaskRequest
{
public:
	TaskRequest() = default;
	virtual ~TaskRequest() = default;

	void terminate();

	void sendTask(std::shared_ptr<HttpRequestWithTimeout> &taskRequest);
	bool deleteTask();
	void fetchTask(std::shared_ptr<void> &serverRequest);
	void replyTask(std::shared_ptr<void> &serverRequest);
	std::tuple<int, std::string> taskStatus();

private:
	void cleanupRepliedRequest(std::shared_ptr<HttpRequestWithTimeout> &request);

private:
	std::shared_ptr<HttpRequestWithTimeout> m_taskRequest;
	std::shared_ptr<HttpRequestWithTimeout> m_fetchTask;
	std::shared_ptr<HttpRequestWithTimeout> m_replyTask;
	std::atomic_int m_taskId{0};
};
