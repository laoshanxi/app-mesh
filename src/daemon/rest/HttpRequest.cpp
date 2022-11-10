#include <map>
#include <string>

#include "../../common/Utility.h"
#include "../../daemon/application/Application.h"
#include "HttpRequest.h"
#include "TcpServer.h"
#include "protoc/ProtobufHelper.h"
#include "protoc/Request.pb.h"
#include "protoc/Response.pb.h"

HttpRequest::HttpRequest(const appmesh::Request &request, TcpHandler *requestClient)
	: m_requestClient(requestClient)
{
	this->m_uuid = request.uuid();
	this->m_method = request.http_method();
	this->m_relative_uri = request.request_uri();
	this->m_remote_address = request.client_address();
	this->m_body = request.http_body();
	for (const auto &query : request.querys())
	{
		this->m_querys[query.first] = query.second;
	}
	for (const auto &header : request.headers())
	{
		this->m_headers[header.first] = header.second;
	}
}

HttpRequest::~HttpRequest()
{
}

nlohmann::json HttpRequest::extractJson() const
{
	return nlohmann::json::parse(m_body);
}

void HttpRequest::reply(web::http::status_code status) const
{
	reply(m_relative_uri, m_uuid, "", {}, status, "");
}

void HttpRequest::reply(web::http::status_code status, const nlohmann::json &body_data) const
{
	reply(m_relative_uri, m_uuid, body_data.dump(), {}, status, CONTENT_TYPE_APPLICATION_JSON);
}

void HttpRequest::reply(web::http::status_code status, std::string &body_data, const std::string &content_type) const
{
	reply(m_relative_uri, m_uuid, body_data, {}, status, content_type);
}

void HttpRequest::reply(web::http::status_code status, const std::string &body_data, const std::map<std::string, std::string> &headers, const std::string &content_type) const
{
	reply(m_relative_uri, m_uuid, body_data, headers, status, content_type);
}

std::shared_ptr<HttpRequest> HttpRequest::deserialize(const char *input, int inputSize, TcpHandler *clientRequest)
{
	const static char fname[] = "HttpRequest::deserialize() ";

	// https://blog.csdn.net/u010601662/article/details/78353206
	appmesh::Request req;
	if (ProtobufHelper::deserialize(req, input, inputSize))
	{
		return std::make_shared<HttpRequest>(req, clientRequest);
	}
	else
	{
		LOG_ERR << fname << "failed to decode protobuf data";
	}
	return nullptr;
}

const nlohmann::json HttpRequest::emptyJson()
{
	nlohmann::json emptyBody;
	emptyBody[REST_TEXT_MESSAGE_JSON_KEY] = std::string("");
	return emptyBody;
}

void HttpRequest::reply(const std::string &requestUri, const std::string &uuid, const std::string &body,
						const std::map<std::string, std::string> &headers, const web::http::status_code &status, const std::string &bodyType) const
{
	const static char fname[] = "HttpRequest::reply() ";
	LOG_DBG << fname;

	appmesh::Response response;
	// fill data
	response.set_uuid(uuid);
	response.set_request_uri(requestUri);
	response.set_http_body(body);
	response.mutable_headers()->insert(headers.begin(), headers.end());
	response.set_http_status(status);
	response.set_http_body_msg_type(bodyType);

	if (m_requestClient)
	{
		TcpHandler::replyTcp(m_requestClient, response);
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
		m_app->onSuicide();
	}
}
