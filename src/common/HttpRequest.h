#pragma once

#include <functional>
#include <memory>
#include <cpprest/http_client.h>

using namespace web;
using namespace http;

//////////////////////////////////////////////////////////////////////////
/// HttpRequest is used to handle across domain reply
//////////////////////////////////////////////////////////////////////////
class HttpRequest : public web::http::http_request
{
public:
	HttpRequest(const web::http::http_request& message);
	virtual ~HttpRequest();

	/// <summary>
	/// Asynchronously responses to this HTTP request.
	/// </summary>
	/// <param name="response">Response to send.</param>
	/// <returns>An asynchronous operation that is completed once response is sent.</returns>
	pplx::task<void> reply(http_response& response) const;

	/// <summary>
	/// Asynchronously responses to this HTTP request.
	/// </summary>
	/// <param name="status">Response status code.</param>
	/// <returns>An asynchronous operation that is completed once response is sent.</returns>
	pplx::task<void> reply(http::status_code status) const;

	/// <summary>
	/// Responds to this HTTP request.
	/// </summary>
	/// <param name="status">Response status code.</param>
	/// <param name="body_data">Json value to use in the response body.</param>
	/// <returns>An asynchronous operation that is completed once response is sent.</returns>
	pplx::task<void> reply(http::status_code status, const json::value& body_data) const;

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
	pplx::task<void> reply(http::status_code status,
		utf8string&& body_data,
		const utf8string& content_type = "text/plain; charset=utf-8") const;

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
	pplx::task<void> reply(http::status_code status,
		const utf8string& body_data,
		const utf8string& content_type = "text/plain; charset=utf-8") const;

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
	pplx::task<void> reply(http::status_code status,
		const utf16string& body_data,
		const utf16string& content_type = utility::conversions::to_utf16string("text/plain")) const;

	/// <summary>
	/// Responds to this HTTP request.
	/// </summary>
	/// <param name="status">Response status code.</param>
	/// <param name="content_type">A string holding the MIME type of the message body.</param>
	/// <param name="body">An asynchronous stream representing the body data.</param>
	/// <returns>A task that is completed once a response from the request is received.</returns>
	pplx::task<void> reply(status_code status,
		const concurrency::streams::istream& body,
		const utility::string_t& content_type = _XPLATSTR("application/octet-stream")) const;

	/// <summary>
	/// Responds to this HTTP request.
	/// </summary>
	/// <param name="status">Response status code.</param>
	/// <param name="content_length">The size of the data to be sent in the body..</param>
	/// <param name="content_type">A string holding the MIME type of the message body.</param>
	/// <param name="body">An asynchronous stream representing the body data.</param>
	/// <returns>A task that is completed once a response from the request is received.</returns>
	pplx::task<void> reply(status_code status,
		const concurrency::streams::istream& body,
		utility::size64_t content_length,
		const utility::string_t& content_type = _XPLATSTR("application/octet-stream")) const;
};

class HttpRequestWithCallback : public HttpRequest
{
public:
	HttpRequestWithCallback(const web::http::http_request& message, const std::string& appName, std::function<void(std::string)> callBackHandler);
	virtual ~HttpRequestWithCallback();

private:
	std::string m_appName;
	std::function<void(std::string)> m_callBackHandler;
};

class Application;
class HttpRequestWithAppRef : public HttpRequest
{
public:
	HttpRequestWithAppRef(const web::http::http_request& message, const std::shared_ptr<Application>& appObj);
	virtual ~HttpRequestWithAppRef();

private:
	const std::shared_ptr<Application> m_app;
};
