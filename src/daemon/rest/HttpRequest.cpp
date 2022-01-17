#include "HttpRequest.h"
#include "../../common/Utility.h"
#include "../../daemon/application/Application.h"
#include "RestTcpServer.h"
#include "protoc/ProtobufHelper.h"
#include "protoc/Request.pb.h"

HttpRequest::HttpRequest(const web::http::http_request &message)
	: http_request(message), m_uuid(Utility::createUUID()), m_forwardResponse2RestServer(false)
{
	this->m_method = message.method();
	this->m_relative_uri = message.relative_uri().path();
	this->m_remote_address = message.remote_address();
	this->m_query = message.relative_uri().query();
	// do not read body for file download/upload
	if (!Utility::startWith(this->m_relative_uri, "/appmesh/file"))
	{
		this->m_body = const_cast<web::http::http_request &>(message).extract_utf8string(true).get();
	}
	for (const auto &header : message.headers())
	{
		this->m_headers[header.first] = header.second;
	}
}

HttpRequest::HttpRequest(const HttpRequest &message)
	: http_request(message), m_uuid(message.m_uuid), m_forwardResponse2RestServer(message.m_forwardResponse2RestServer)
{
	this->m_method = message.m_method;
	this->m_relative_uri = message.m_relative_uri;
	this->m_remote_address = message.m_remote_address;
	this->m_body = message.m_body;
	this->m_headers = message.m_headers;
	this->m_query = message.m_query;
}

HttpRequest::HttpRequest(const appmesh::Request &request)
{
	this->m_uuid = request.uuid();
	this->m_method = request.http_method();
	this->m_relative_uri = request.request_uri();
	this->m_remote_address = request.client_address();
	this->m_body = request.http_body();
	this->m_headers.insert(request.headers().begin(), request.headers().end());
	this->m_query = request.querys();

	this->m_forwardResponse2RestServer = true;
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
	const static char fname[] = "HttpRequest::reply() ";
	if (m_forwardResponse2RestServer)
	{
		LOG_ERR << fname << "unsupported method";
		throw std::runtime_error("not supported");
	}
	else
	{
		addHeaders(response);
		http_request::reply(response).wait();
		this->_get_impl()
	}
}

void HttpRequest::reply(http_response &response, const std::string &body_data) const
{
	if (m_forwardResponse2RestServer)
	{
		RestTcpServer::instance()->backforwardResponse(m_uuid, body_data, response.headers(), response.status_code(), "text/plain; charset=utf-8");
	}
	else
	{
		addHeaders(response);
		http_request::reply(response).wait();
	}
}

void HttpRequest::reply(http::status_code status) const
{
	// give empty JSON str for empty json serialize/deserialize
	const static auto emptyJson = HttpRequest::emptyJson();
	reply(status, emptyJson);
}

void HttpRequest::reply(http::status_code status, const json::value &body_data) const
{
	if (m_forwardResponse2RestServer)
	{
		RestTcpServer::instance()->backforwardResponse(m_uuid, body_data.serialize(), {}, status, CONTENT_TYPE_APPLICATION_JSON);
	}
	else
	{
		const static auto emptyJson = HttpRequest::emptyJson();
		http_response response(status);
		if (body_data != emptyJson)
		{
			response.set_body(body_data);
		}
		return reply(response);
	}
}

void HttpRequest::reply(http::status_code status, utf8string &&body_data, const utf8string &content_type) const
{
	if (m_forwardResponse2RestServer)
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
	if (m_forwardResponse2RestServer)
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
	if (m_forwardResponse2RestServer)
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

	if (m_forwardResponse2RestServer)
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
	if (m_forwardResponse2RestServer)
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

void HttpRequest::addHeaders(http_response &response) const
{
	// TODO: collect http method dynamicly
	// For external origins restrict Access-Control-Allow-Origin to the trusted domains
	response.headers().add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD");
	response.headers().add("Access-Control-Allow-Origin", "*");
	response.headers().add("Access-Control-Allow-Headers", "*");
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
