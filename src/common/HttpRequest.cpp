#include "HttpRequest.h"
#include "../daemon/Application.h"

HttpRequest::HttpRequest(const web::http::http_request& message)
	:http_request(message)
{
}

HttpRequest::~HttpRequest()
{
}

pplx::task<void> HttpRequest::reply(http_response& response) const
{
	response.headers().add("Access-Control-Allow-Origin", "*");
	response.headers().add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
	response.headers().add("Access-Control-Allow-Headers", "*");
	return http_request::reply(response);
}

pplx::task<void> HttpRequest::reply(http::status_code status) const
{
	http_response response(status);
	return reply(response);
}

pplx::task<void> HttpRequest::reply(http::status_code status, const json::value& body_data) const
{
	http_response response(status);
	response.set_body(body_data);
	return reply(response);
}

pplx::task<void> HttpRequest::reply(http::status_code status, utf8string&& body_data, const utf8string& content_type) const
{
	http_response response(status);
	response.set_body(std::move(body_data), content_type);
	return reply(response);
}

pplx::task<void> HttpRequest::reply(http::status_code status, const utf8string& body_data, const utf8string& content_type) const
{
	http_response response(status);
	response.set_body(body_data, content_type);
	return reply(response);
}

pplx::task<void> HttpRequest::reply(http::status_code status, const utf16string& body_data, const utf16string& content_type) const
{
	http_response response(status);
	response.set_body(body_data, content_type);
	return reply(response);
}

pplx::task<void> HttpRequest::reply(status_code status, const concurrency::streams::istream& body, const utility::string_t& content_type) const
{
	http_response response(status);
	response.set_body(body, content_type);
	return reply(response);
}

pplx::task<void> HttpRequest::reply(status_code status, const concurrency::streams::istream& body, utility::size64_t content_length, const utility::string_t& content_type) const
{
	http_response response(status);
	response.set_body(body, content_length, content_type);
	return reply(response);
}

////////////////////////////////////////////////////////////////////////////////
// HttpRequestWithCallback
////////////////////////////////////////////////////////////////////////////////
HttpRequestWithCallback::HttpRequestWithCallback(const web::http::http_request& message, const std::string& appName, std::function<void(std::string)> callBackHandler)
	:HttpRequest(message), m_appName(appName), m_callBackHandler(callBackHandler)
{
}

HttpRequestWithCallback::~HttpRequestWithCallback()
{
	if (m_callBackHandler != nullptr)
	{
		m_callBackHandler(m_appName);
	}
}
////////////////////////////////////////////////////////////////////////////////
// HttpRequest with remove app from global map
////////////////////////////////////////////////////////////////////////////////
HttpRequestWithAppRef::HttpRequestWithAppRef(const web::http::http_request& message, const std::shared_ptr<Application>& appObj)
	:HttpRequest(message), m_app(appObj)
{
}

HttpRequestWithAppRef::~HttpRequestWithAppRef()
{
	if (m_app) m_app->onSuicideEvent();
}
