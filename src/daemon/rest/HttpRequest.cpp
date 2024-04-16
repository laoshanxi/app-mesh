#include <map>
#include <string>

#include "../../common/Utility.h"
#include "../../daemon/application/Application.h"
#include "HttpRequest.h"
#include "TcpServer.h"
#include "protoc/ProtobufHelper.h"

HttpRequest::HttpRequest(const Request &request, int tcpHandlerId)
	: m_tcpHanlerId(tcpHandlerId)
{
	this->m_uuid = request.uuid;
	this->m_method = request.http_method;
	this->m_relative_uri = request.request_uri;
	this->m_remote_address = request.client_addr;
	this->m_body = request.body;
	this->m_querys = request.querys;
	this->m_headers = request.headers;
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

void HttpRequest::reply(web::http::status_code status, const nlohmann::json &body_data, const std::map<std::string, std::string> &headers) const
{
	reply(m_relative_uri, m_uuid, body_data.dump(), headers, status, CONTENT_TYPE_APPLICATION_JSON);
}

void HttpRequest::reply(web::http::status_code status, std::string &body_data, const std::string &content_type) const
{
	reply(m_relative_uri, m_uuid, body_data, {}, status, content_type);
}

void HttpRequest::reply(web::http::status_code status, const std::string &body_data, const std::map<std::string, std::string> &headers, const std::string &content_type) const
{
	reply(m_relative_uri, m_uuid, body_data, headers, status, content_type);
}

std::shared_ptr<HttpRequest> HttpRequest::deserialize(const char *input, int inputSize, int tcpHandlerId)
{
	const static char fname[] = "HttpRequest::deserialize() ";

	// https://blog.csdn.net/u010601662/article/details/78353206
	Request req;
	if (req.deserialize(input, inputSize))
	{
		return std::make_shared<HttpRequest>(req, tcpHandlerId);
	}
	else
	{
		LOG_ERR << fname << "failed to decode tcp raw data";
	}
	return nullptr;
}

const nlohmann::json HttpRequest::emptyJson()
{
	nlohmann::json emptyBody;
	emptyBody[REST_TEXT_MESSAGE_JSON_KEY] = std::string("");
	return emptyBody;
}

void HttpRequest::dump() const
{
	const static char fname[] = "HttpRequest::dump() ";

	LOG_DBG << fname << "m_uuid:" << m_uuid;
	LOG_DBG << fname << "m_method:" << m_method;
	LOG_DBG << fname << "m_relative_uri:" << m_relative_uri;
	LOG_DBG << fname << "m_remote_address:" << m_remote_address;
	LOG_DBG << fname << "m_body:" << m_body;
	for (const auto &q : m_querys)
		LOG_DBG << fname << "m_querys:" << q.first << "=" << q.second;
	// for (const auto &h : m_headers)
	//	LOG_DBG << fname << "m_headers:" << h.first << "=" << h.second;
}

void HttpRequest::reply(const std::string &requestUri, const std::string &uuid, const std::string &body,
						const std::map<std::string, std::string> &headers, const web::http::status_code &status, const std::string &bodyType) const
{
	const static char fname[] = "HttpRequest::reply() ";
	LOG_DBG << fname;

	Response response;
	// fill data
	response.uuid = uuid;
	response.request_uri = requestUri;
	response.body = body;
	response.headers = headers;
	response.http_status = status;
	response.body_msg_type = bodyType;

	if (m_tcpHanlerId > 0)
	{
		TcpHandler::replyTcp(m_tcpHanlerId, response);
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
