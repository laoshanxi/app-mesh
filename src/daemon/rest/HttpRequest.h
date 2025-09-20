#pragma once

#include <map>
#include <memory>

#include <nlohmann/json.hpp>

#include "../../common/TimerHandler.h"
#include "../../common/Utility.h"
#include "protoc/ProtobufHelper.h"

/// <summary>
/// HttpRequest is wrapper of <web::http::http_request>,
///    - used for REST server forward request to TCP server and wait TCP result then response REST client
///    - used for TCP server send result to REST server
/// serialize between RestTcpServer & RestChildObject
/// handle across domain reply (headers)
/// </summary>
class HttpRequest
{
public:
	/// <summary>
	/// Construction for deserialize
	/// TCP REST Server receive and decode this, m_forwardResponse2RestServer always set to true
	/// </summary>
	explicit HttpRequest(Request &&request, int tcpHandlerId);

	virtual ~HttpRequest();

	/// <summary>
	/// Always use this function to get http body
	/// http body will always be extract with string (for serialize purpose) and parse to JSON here
	/// </summary>
	nlohmann::json extractJson() const;

	/// <summary>
	/// Asynchronously responses to this HTTP request.
	/// </summary>
	/// <param name="status">Response status code.</param>
	/// <returns>An asynchronous operation that is completed once response is sent.</returns>
	bool reply(web::http::status_code status) const;

	/// <summary>
	/// Responds to this HTTP request.
	/// </summary>
	/// <param name="status">Response status code.</param>
	/// <param name="body_data">Json value to use in the response body.</param>
	/// <returns>An asynchronous operation that is completed once response is sent.</returns>
	bool reply(web::http::status_code status, const nlohmann::json &body_data) const;

	/// <summary>
	/// Responds to this HTTP request.
	/// </summary>
	/// <param name="status">Response status code.</param>
	/// <param name="body_data">Raw bytes value to use in the response body.</param>
	/// <returns>An asynchronous operation that is completed once response is sent.</returns>
	bool reply(web::http::status_code status, const std::vector<uint8_t> &body_data) const;

	/// <summary>
	/// Responds to this HTTP request.
	/// </summary>
	/// <param name="status">Response status code.</param>
	/// <param name="body_data">Json value to use in the response body.</param>
	/// <param name="headers">Headers value in the response header.</param>
	/// <returns>An asynchronous operation that is completed once response is sent.</returns>
	bool reply(web::http::status_code status, const nlohmann::json &body_data, const std::map<std::string, std::string> &headers) const;

	/// Responds to this HTTP request with a string.
	/// Assumes the character encoding of the string is UTF-8.
	/// </summary>
	/// <param name="status">Response status code.</param>
	/// <param name="body_data">UTF-8 string containing the text to use in the response body.</param>
	/// <param name="content_type">Content type of the body.</param>
	/// <returns>An asynchronous operation that is completed once response is sent.</returns>
	/// <remarks>
	//  Callers of this function do NOT need to block waiting for the response to be
	/// sent to before the body data is destroyed or goes out of scope.
	/// </remarks>
	bool reply(web::http::status_code status,
			   std::string &body_data,
			   const std::string &content_type = web::http::mime_types::text_plain_utf8) const;

	/// <summary>
	/// Responds to this HTTP request.
	/// </summary>
	/// <param name="status">Response status code.</param>
	/// <param name="content_type">A string holding the MIME type of the message body.</param>
	/// <param name="body">An asynchronous stream representing the body data.</param>
	/// <returns>A task that is completed once a response from the request is received.</returns>
	bool reply(web::http::status_code status,
			   const std::string &body_data,
			   const std::map<std::string, std::string> &headers,
			   const std::string &content_type = web::http::mime_types::text_plain_utf8) const;

	static std::shared_ptr<HttpRequest> deserialize(const char *input, int inputSize, int tcpHandlerId);
	static const nlohmann::json emptyJson();
	void dump() const;
	void verifyHMAC() const;

	std::string m_uuid;
	web::http::method m_method;
	std::string m_relative_uri;
	std::string m_remote_address;
	std::shared_ptr<std::vector<uint8_t>> m_body; // use shared_ptr to avoid user string data copy
	std::map<std::string, std::string> m_query;
	std::map<std::string, std::string> m_headers;

protected:
	/// <summary>
	/// Response REST response to client
	/// </summary>
	/// <param name="requestUri"></param>
	/// <param name="uuid"></param>
	/// <param name="body"></param>
	/// <param name="headers"></param>
	/// <param name="status"></param>
	/// <param name="bodyType"></param>
	virtual bool reply(const std::string &requestUri, const std::string &uuid, const std::vector<uint8_t> &body, const std::map<std::string, std::string> &headers, const web::http::status_code &status, const std::string &bodyType) const;

private:
	const int m_tcpHanlerId;
};

class Application;
/// <summary>
/// HttpRequest used to remove Application when finished reply
/// </summary>
class HttpRequestAutoCleanup : public HttpRequest
{
public:
	explicit HttpRequestAutoCleanup(const HttpRequest &message, const std::shared_ptr<Application> &appObj);
	virtual ~HttpRequestAutoCleanup();

private:
	std::shared_ptr<Application> m_app;
};

/// <summary>
/// HttpRequest with timeout
/// </summary>
class HttpRequestWithTimeout : public HttpRequest, public TimerHandler
{
public:
	using HttpRequest::reply;
	explicit HttpRequestWithTimeout(const HttpRequest &message);
	virtual ~HttpRequestWithTimeout();

	bool initTimer(int timeoutSeconds);
	bool onTimerResponse();
	bool replied() const;
	bool interrupt();

protected:
	// called by timer or user
	virtual bool reply(const std::string &requestUri, const std::string &uuid, const std::vector<uint8_t> &body, const std::map<std::string, std::string> &headers, const web::http::status_code &status, const std::string &bodyType) const override;

private:
	mutable std::atomic_long m_timerResponseId;
	mutable std::atomic<bool> m_httpRequestReplyFlag;
};

/// <summary>
/// HttpRequest used to reply app output
/// </summary>
class HttpRequestOutputView : public TimerHandler, public HttpRequest
{
public:
	explicit HttpRequestOutputView(const HttpRequest &message, const std::shared_ptr<Application> &appObj);
	virtual ~HttpRequestOutputView();
	void init();

	void response();
	bool onTimerResponse();

	// response standby request
	static void onProcessExitResponse(pid_t pid);

private:
	std::atomic_long m_timerResponseId;
	pid_t m_pid;
	std::shared_ptr<Application> m_app;
	std::atomic_flag m_httpRequestReplyFlag = ATOMIC_FLAG_INIT;
};

/// <summary>
/// Used to handle message request from client and server
/// </summary>
class TaskRequest
{
public:
	TaskRequest() = default;
	virtual ~TaskRequest();

	void terminate();

	void sendMessage(std::shared_ptr<void> taskRequest);
	void getMessage(std::shared_ptr<void> &serverRequest, std::shared_ptr<HttpRequestWithTimeout> &taskRequest);
	void respMessage(std::shared_ptr<void> &serverRequest, std::shared_ptr<HttpRequestWithTimeout> &taskRequest);

private:
	void cleanupRepliedRequest(std::shared_ptr<HttpRequestWithTimeout> &request);

private:
	std::shared_ptr<HttpRequestWithTimeout> m_getMessage;
	std::shared_ptr<HttpRequestWithTimeout> m_respMessage;
};
