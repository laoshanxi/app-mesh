#include "HttpRequest.h"
#include "../../common/Utility.h"
#include "../../daemon/application/Application.h"
#include "RestTcpServer.h"

HttpRequest::HttpRequest(const web::http::http_request &message)
	: http_request(message), m_uuid(Utility::createUUID()), m_reply2child(false)
{
	this->m_method = message.method();
	this->m_relative_uri = message.relative_uri().path();
	this->m_remote_address = message.remote_address();
	this->m_query = message.relative_uri().query();
	this->m_body = const_cast<web::http::http_request &>(message).extract_utf8string(true).get();
	for (const auto &header : message.headers())
	{
		this->m_headers[header.first] = header.second;
	}
}

HttpRequest::HttpRequest(const HttpRequest &message)
	: http_request(message), m_uuid(message.m_uuid), m_reply2child(message.m_reply2child)
{
	this->m_method = message.m_method;
	this->m_relative_uri = message.m_relative_uri;
	this->m_remote_address = message.m_remote_address;
	this->m_body = message.m_body;
	this->m_query = message.m_query;
	this->m_headers = message.m_headers;
}

HttpRequest::HttpRequest(const std::string &method,
						 const std::string &uri,
						 const std::string &address,
						 const std::string &body,
						 const std::string &headers,
						 const std::string &query,
						 const std::string &uuid)
{
	//const static char fname[] = "HttpRequest::HttpRequest() ";
	this->m_method = method;
	this->m_relative_uri = uri;
	this->m_remote_address = address;
	this->m_body = body;
	this->m_query = query;
	this->m_headers = Utility::parse(headers);
	this->m_uuid = uuid;
	this->m_reply2child = true;
	//LOG_DBG << "HttpRequest headers: " << Utility::serialize(this->m_headers);
}

HttpRequest::~HttpRequest()
{
}

web::json::value HttpRequest::extractJson() const
{
	if (m_body.length())
		return web::json::value::parse(m_body);
	else
		return this->extract_json(true).get();
}

void HttpRequest::reply(http_response &response) const
{
	const static char fname[] = "HttpRequest::reply() ";
	if (m_reply2child)
	{
		LOG_ERR << fname << "unsupported method";
		throw std::runtime_error("not supported");
	}
	else
	{
		response.headers().add("Access-Control-Allow-Origin", "*");
		response.headers().add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
		response.headers().add("Access-Control-Allow-Headers", "*");
		http_request::reply(response).wait();
	}
}

void HttpRequest::reply(http_response &response, const std::string &body_data) const
{
	if (m_reply2child)
	{
		RestTcpServer::instance()->backforwardResponse(m_uuid, body_data, response.headers(), response.status_code(), "text/plain; charset=utf-8");
	}
	else
	{
		response.headers().add("Access-Control-Allow-Origin", "*");
		response.headers().add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
		response.headers().add("Access-Control-Allow-Headers", "*");
		http_request::reply(response).wait();
	}
}

void HttpRequest::reply(http::status_code status) const
{

	if (m_reply2child)
	{
		RestTcpServer::instance()->backforwardResponse(m_uuid, "", {}, status, "text/plain; charset=utf-8");
	}
	else
	{
		http_response response(status);
		return reply(response);
	}
}

void HttpRequest::reply(http::status_code status, const json::value &body_data) const
{
	if (m_reply2child)
	{
		RestTcpServer::instance()->backforwardResponse(m_uuid, body_data.serialize(), {}, status, "application/json");
	}
	else
	{
		http_response response(status);
		response.set_body(body_data);
		return reply(response);
	}
}

void HttpRequest::reply(http::status_code status, utf8string &&body_data, const utf8string &content_type) const
{
	if (m_reply2child)
	{
		RestTcpServer::instance()->backforwardResponse(m_uuid, body_data, {}, status, content_type);
	}
	else
	{
		http_response response(status);
		response.set_body(body_data, content_type);
		return reply(response);
	}
}

void HttpRequest::reply(http::status_code status, const utf8string &body_data, const utf8string &content_type) const
{
	if (m_reply2child)
	{
		RestTcpServer::instance()->backforwardResponse(m_uuid, body_data, {}, status, content_type);
	}
	else
	{
		http_response response(status);
		response.set_body(body_data, content_type);
		return reply(response);
	}
}

void HttpRequest::reply(http::status_code status, const utf16string &body_data, const utf16string &content_type) const
{
	if (m_reply2child)
	{
		RestTcpServer::instance()->backforwardResponse(m_uuid, GET_STD_STRING(body_data), {}, status, GET_STD_STRING(content_type));
	}
	else
	{
		http_response response(status);
		response.set_body(body_data, content_type);
		return reply(response);
	}
}

void HttpRequest::reply(status_code status, const concurrency::streams::istream &body, const utility::string_t &content_type) const
{
	const static char fname[] = "HttpRequest::reply() ";

	if (m_reply2child)
	{
		LOG_ERR << fname << "unsupported method";
		throw std::runtime_error("not supported");
	}
	else
	{
		http_response response(status);
		response.set_body(body, content_type);
		return reply(response);
	}
}

void HttpRequest::reply(status_code status, const concurrency::streams::istream &body, utility::size64_t content_length, const utility::string_t &content_type) const
{
	const static char fname[] = "HttpRequest::reply() ";
	if (m_reply2child)
	{
		LOG_ERR << fname << "unsupported method";
		throw std::runtime_error("not supported");
	}
	else
	{
		http_response response(status);
		response.set_body(body, content_type);
		return reply(response);
	}
}

////////////////////////////////////////////////////////////////////////////////
// HttpRequest with remove app from global map
////////////////////////////////////////////////////////////////////////////////
HttpRequestWithAppRef::HttpRequestWithAppRef(const HttpRequest &message, const std::shared_ptr<Application> &appObj)
	: HttpRequest(message), m_app(appObj)
{
}

HttpRequestWithAppRef::~HttpRequestWithAppRef()
{
	if (m_app)
	{
		m_app->onSuicideEvent();
	}
}
