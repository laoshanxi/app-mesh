#pragma once

#include <functional>
#include <map>
#include <memory>

#include <cpprest/http_client.h>

using namespace web;
using namespace http;

/// <summary>
/// HttpRequest is used to handle across domain reply
/// </summary>
class HttpRequest : public web::http::http_request
{
public:
	HttpRequest(const web::http::http_request &message);
	HttpRequest(const HttpRequest &message);
	HttpRequest(const std::string &method,
				const std::string &uri,
				const std::string &address,
				const std::string &body,
				const std::string &headers,
				const std::string &query,
				const std::string &uuid);
	virtual ~HttpRequest();

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

	// serializeable, always use those variables intead of method(), headers()
	web::http::method m_method;
	std::string m_relative_uri;
	std::string m_remote_address;
	std::string m_body;
	std::string m_query;
	std::map<std::string, std::string> m_headers;
	std::string m_uuid;
	bool m_reply2child; // not directly reply this endpoint, just forward to child rest side

private:
	// hide bellow extract functions
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
