#pragma once

#include <functional>
#include <map>
#include <memory>

#include <ace/CDR_Stream.h>
#include <cpprest/http_client.h>

using namespace web;
using namespace http;

#define CONTENT_TYPE_APPLICATION_JSON "application/json"

/// <summary>
/// HttpRequest is wrapper of <web::http::http_request>,
///    - used for REST server forward request to TCP server and wait TCP result then response REST client
///    - used for TCP server send result to REST server
/// serialize between RestTcpServer & RestChildObject
/// handle across domain reply (headers)
/// </summary>
class HttpRequest : public web::http::http_request
{
private:
	/// <summary>
	/// Construction for deserialize
	/// TCP REST Server receive and decode this, m_forwardResponse2RestServer always set to true
	/// </summary>
	HttpRequest(const std::string &uuid,
				const std::string &method,
				const std::string &uri,
				const std::string &address,
				const std::string &body,
				const std::string &headers,
				const std::string &query);

public:
	HttpRequest(const web::http::http_request &message);

	/// <summary>
	/// Constructor for RestChildObject::sendRequest2Server() save http_request copy
	/// and send the response to REST client after received TCP response
	/// </summary>
	HttpRequest(const HttpRequest &message);
	virtual ~HttpRequest();

	/// <summary>
	/// Always use this function to get http body
	/// http body will always be extract with string (for serialize purpose) and parse to JSON here
	/// </summary>
	web::json::value extractJson() const;

	/// <summary>
	/// Asynchronously responses to this HTTP request.
	/// </summary>
	/// <param name="response">Response to send.</param>
	/// <returns>An asynchronous operation that is completed once response is sent.</returns>
	void reply(http_response &response) const;

	/// <summary>
	/// Asynchronously responses to this HTTP request.
	/// </summary>
	/// <param name="response">Response to send.</param>
	/// <returns>An asynchronous operation that is completed once response is sent.</returns>
	void reply(http_response &response, const std::string &body_data) const;

	/// <summary>
	/// Asynchronously responses to this HTTP request.
	/// </summary>
	/// <param name="status">Response status code.</param>
	/// <returns>An asynchronous operation that is completed once response is sent.</returns>
	void reply(http::status_code status) const;

	/// <summary>
	/// Responds to this HTTP request.
	/// </summary>
	/// <param name="status">Response status code.</param>
	/// <param name="body_data">Json value to use in the response body.</param>
	/// <returns>An asynchronous operation that is completed once response is sent.</returns>
	void reply(http::status_code status, const json::value &body_data) const;

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
	void reply(http::status_code status,
			   utf8string &&body_data,
			   const utf8string &content_type = "text/plain; charset=utf-8") const;

	/// <summary>
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
	void reply(http::status_code status,
			   const utf8string &body_data,
			   const utf8string &content_type = "text/plain; charset=utf-8") const;

	/// <summary>
	/// Responds to this HTTP request with a string. Assumes the character encoding
	/// of the string is UTF-16 will perform conversion to UTF-8.
	/// </summary>
	/// <param name="status">Response status code.</param>
	/// <param name="body_data">UTF-16 string containing the text to use in the response body.</param>
	/// <param name="content_type">Content type of the body.</param>
	/// <returns>An asynchronous operation that is completed once response is sent.</returns>
	/// <remarks>
	//  Callers of this function do NOT need to block waiting for the response to be
	/// sent to before the body data is destroyed or goes out of scope.
	/// </remarks>
	void reply(http::status_code status,
			   const utf16string &body_data,
			   const utf16string &content_type = utility::conversions::to_utf16string("text/plain")) const;

	/// <summary>
	/// Responds to this HTTP request.
	/// </summary>
	/// <param name="status">Response status code.</param>
	/// <param name="content_type">A string holding the MIME type of the message body.</param>
	/// <param name="body">An asynchronous stream representing the body data.</param>
	/// <returns>A task that is completed once a response from the request is received.</returns>
	void reply(status_code status,
			   const concurrency::streams::istream &body,
			   const utility::string_t &content_type = _XPLATSTR("application/octet-stream")) const;

	/// <summary>
	/// Responds to this HTTP request.
	/// </summary>
	/// <param name="status">Response status code.</param>
	/// <param name="content_length">The size of the data to be sent in the body..</param>
	/// <param name="content_type">A string holding the MIME type of the message body.</param>
	/// <param name="body">An asynchronous stream representing the body data.</param>
	/// <returns>A task that is completed once a response from the request is received.</returns>
	void reply(status_code status,
			   const concurrency::streams::istream &body,
			   utility::size64_t content_length,
			   const utility::string_t &content_type = _XPLATSTR("application/octet-stream")) const;

	// serialize header
	static std::map<std::string, std::string> parseHeaders(const std::string &str);
	static std::string serializeHeaders(const std::map<std::string, std::string> &map);
	static std::string serializeHeaders(const web::http::http_headers &map);

	const std::shared_ptr<ACE_OutputCDR> serialize() const;
	static std::shared_ptr<HttpRequest> deserialize(ACE_InputCDR &input);

	// serializeable, always use those variables intead of method(), headers()
	std::string m_uuid;
	web::http::method m_method;
	std::string m_relative_uri;
	std::string m_remote_address;
	std::string m_body;
	std::map<std::string, std::string> m_headers;
	std::string m_query;

	bool m_forwardResponse2RestServer; // not directly reply this endpoint, just forward to child rest side

private:
	// hide bellow extract functions, note extract_X function can only be called once, otherwise will hang
	pplx::task<utf8string> extract_utf8string(bool ignore_content_type = false)
	{
		return web::http::http_request::extract_utf8string(ignore_content_type);
	};
	pplx::task<utility::string_t> extract_string(bool ignore_content_type = false)
	{
		return web::http::http_request::extract_string(ignore_content_type);
	};
	pplx::task<utf16string> extract_utf16string(bool ignore_content_type = false)
	{
		return web::http::http_request::extract_utf16string(ignore_content_type);
	};
	pplx::task<json::value> extract_json(bool ignore_content_type = false) const
	{
		return web::http::http_request::extract_json(ignore_content_type);
	};
};

/// <summary>
/// HttpTcpResponse is the data of REST response used to transfer to REST process
/// </summary>
class HttpTcpResponse
{
public:
	explicit HttpTcpResponse(const std::string &uuid,
					const std::string &body,
					const std::string &bodyType,
					const std::map<std::string, std::string> &headers,
					const http::status_code &status);
	const std::shared_ptr<ACE_OutputCDR> serialize() const;
	static std::shared_ptr<HttpTcpResponse> deserialize(ACE_InputCDR &input);

public:
	const std::string m_uuid;
	const std::string m_body;
	const std::string m_bodyType;
	const std::map<std::string, std::string> m_headers;
	const http::status_code m_status;
};

/// <summary>
/// IoVector used prepare sendout data to header and body
/// </summary>
struct IoVector
{
public:
	explicit IoVector(std::shared_ptr<ACE_OutputCDR> body);

	// length is 2, header and body
	iovec data[2];
	const size_t length() { return data[0].iov_len + data[1].iov_len; };

private:
	ACE_OutputCDR m_headerCdr;
	std::shared_ptr<ACE_OutputCDR> m_bodyCdr;
};

class Application;
/// <summary>
/// HttpRequest used to remove template Application when finished reply
/// </summary>
class HttpRequestWithAppRef : public HttpRequest
{
public:
	HttpRequestWithAppRef(const HttpRequest &message, const std::shared_ptr<Application> &appObj);
	virtual ~HttpRequestWithAppRef();

private:
	const std::shared_ptr<Application> m_app;
};
