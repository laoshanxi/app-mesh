#include "HttpRequest.h"
#include "../../common/Utility.h"
#include "../../daemon/application/Application.h"
#include "protoc/ProtobufHelper.h"
#include "protoc/Request.pb.h"

HttpRequest::HttpRequest(const web::http::http_request &message)
	: http_request(message), m_uuid(Utility::createUUID())
{
	this->m_method = message.method();
	this->m_relative_uri = message.relative_uri().path();
	this->m_remote_address = message.remote_address();
	this->m_query = message.relative_uri().query();
	this->m_body = const_cast<web::http::http_request &>(message).extract_utf8string(true).get();
	for (const auto &header : message.headers())
	{
		this->m_headers[header.first] = header.second;
		this->headers().add(header.first, header.second);
	}
}

HttpRequest::HttpRequest(const HttpRequest &message)
	: http_request(message), m_uuid(message.m_uuid)
{
	this->m_method = message.m_method;
	this->m_relative_uri = message.m_relative_uri;
	this->m_remote_address = message.m_remote_address;
	this->m_body = message.m_body;
	this->m_query = message.m_query;
	for (const auto &header : message.m_headers)
	{
		this->m_headers[header.first] = header.second;
		this->headers().add(header.first, header.second);
	}
}

HttpRequest::HttpRequest(const appmesh::Request &request)
{
	this->m_uuid = request.uuid();
	this->m_method = request.http_method();
	this->m_relative_uri = request.request_uri();
	this->m_remote_address = request.client_address();
	this->m_body = request.http_body();
	this->m_query = request.querys();
	for (const auto &header : request.headers())
	{
		this->m_headers[header.first] = header.second;
		this->headers().add(header.first, header.second);
	}
}

HttpRequest::~HttpRequest()
{
}

web::json::value HttpRequest::extractJson() const
{
	return web::json::value::parse(m_body);
}

void HttpRequest::reply(http_response &response) const
{
	persistResponse(m_relative_uri, m_uuid, "", response.headers(), response.status_code(), "");
}

void HttpRequest::reply(http_response &response, const std::string &body_data) const
{
	persistResponse(m_relative_uri, m_uuid, body_data, response.headers(), response.status_code(), "text/plain; charset=utf-8");
}

void HttpRequest::reply(http::status_code status) const
{
	persistResponse(m_relative_uri, m_uuid, "", {}, status, "");
}

void HttpRequest::reply(http::status_code status, const json::value &body_data) const
{
	persistResponse(m_relative_uri, m_uuid, body_data.serialize(), {}, status, CONTENT_TYPE_APPLICATION_JSON);
}

void HttpRequest::reply(http::status_code status, utf8string &&body_data, const utf8string &content_type) const
{
	persistResponse(m_relative_uri, m_uuid, body_data, {}, status, content_type);
}

void HttpRequest::reply(http::status_code status, const utf8string &body_data, const utf8string &content_type) const
{
	persistResponse(m_relative_uri, m_uuid, body_data, {}, status, content_type);
}

void HttpRequest::reply(http::status_code status, const utf16string &body_data, const utf16string &content_type) const
{
	persistResponse(m_relative_uri, m_uuid, GET_STD_STRING(body_data), {}, status, GET_STD_STRING(content_type));
}

void HttpRequest::reply(status_code status, const concurrency::streams::istream &body, const utility::string_t &content_type) const
{
	const static char fname[] = "HttpRequest::reply(status_code status, const concurrency::streams::istream &body, const utility::string_t &content_type) ";
	LOG_ERR << fname << "unsupported method";
	throw std::runtime_error("not supported");
}

void HttpRequest::reply(status_code status, const concurrency::streams::istream &body, utility::size64_t content_length, const utility::string_t &content_type) const
{
	const static char fname[] = "HttpRequest::reply(status_code status, const concurrency::streams::istream &body, utility::size64_t content_length, const utility::string_t &content_type) ";
	LOG_ERR << fname << "unsupported method";
	throw std::runtime_error("not supported");
}

const std::shared_ptr<appmesh::Request> HttpRequest::serialize() const
{
	auto req = std::make_shared<appmesh::Request>();
	// fill data
	req->set_uuid(m_uuid);
	req->set_http_method(m_method);
	req->set_request_uri(m_relative_uri);
	req->set_client_address(m_remote_address);
	req->set_http_body(m_body);
	req->mutable_headers()->insert(m_headers.begin(), m_headers.end());
	req->set_querys(m_query);

	return req;
}

std::shared_ptr<HttpRequest> HttpRequest::deserialize(const char *input)
{
	const static char fname[] = "HttpRequest::deserialize() ";

	// https://blog.csdn.net/u010601662/article/details/78353206
	appmesh::Request req;
	if (ProtobufHelper::deserialize(req, input))
	{
		return std::shared_ptr<HttpRequest>(new HttpRequest(req));
	}
	else
	{
		LOG_ERR << fname << "failed to decode protobuf data";
	}
	return nullptr;
}

const web::json::value HttpRequest::emptyJson()
{
	web::json::value emptyBody;
	emptyBody[REST_TEXT_MESSAGE_JSON_KEY] = web::json::value::string("");
	return emptyBody;
}

void HttpRequest::persistResponse(const std::string &requestUri, const std::string &uuid, const std::string &body,
								  const web::http::http_headers &headers, const http::status_code &status, const std::string &bodyType) const
{
	m_response = std::make_shared<appmesh::Response>();
	// fill data
	m_response->set_uuid(uuid);
	m_response->set_http_body(body);
	m_response->mutable_headers()->insert(headers.begin(), headers.end());
	m_response->set_http_status(status);
	m_response->set_http_body_msg_type(bodyType);
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
		m_app->onSuicide();
	}
}
