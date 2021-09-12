#include <ace/CDR_Stream.h>

#include "../../common/Utility.h"
#include "../../daemon/application/Application.h"
#include "HttpRequest.h"
#include "RestTcpServer.h"

HttpRequest::HttpRequest(const web::http::http_request &message)
	: http_request(message), m_uuid(Utility::createUUID()), m_forwardResponse2RestServer(false)
{
	this->m_method = message.method();
	this->m_relative_uri = message.relative_uri().path();
	this->m_remote_address = message.remote_address();
	this->m_query = message.relative_uri().query();
	// do not read body for file download/upload
	if (this->m_relative_uri.find("/appmesh/file/download") == std::string::npos && this->m_relative_uri.find("/appmesh/file/upload") == std::string::npos)
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

HttpRequest::HttpRequest(const std::string &uuid,
						 const std::string &method,
						 const std::string &uri,
						 const std::string &address,
						 const std::string &body,
						 const std::string &headers,
						 const std::string &query)
{
	//const static char fname[] = "HttpRequest::HttpRequest() ";
	this->m_uuid = uuid;
	this->m_method = method;
	this->m_relative_uri = uri;
	this->m_remote_address = address;
	this->m_body = body;
	this->m_headers = parseHeaders(headers);
	this->m_query = query;

	this->m_forwardResponse2RestServer = true;
	//LOG_DBG << "HttpRequest headers: " << Utility::serializeHeaders(this->m_headers);
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
		http_request::reply(response).wait();
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
		http_request::reply(response).wait();
	}
}

void HttpRequest::reply(http::status_code status) const
{
	// give empty JSON str for client to decode JSON always
	web::json::value emptyBody;
	emptyBody[REST_TEXT_MESSAGE_JSON_KEY] = web::json::value::string("");
	reply(status, emptyBody);
}

void HttpRequest::reply(http::status_code status, const json::value &body_data) const
{
	if (m_forwardResponse2RestServer)
	{
		RestTcpServer::instance()->backforwardResponse(m_uuid, body_data.serialize(), {}, status, CONTENT_TYPE_APPLICATION_JSON);
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

// TODO: assume base 64 have no "|" character
std::map<std::string, std::string> HttpRequest::parseHeaders(const std::string &str)
{
	std::map<std::string, std::string> result;
	const auto headerList = Utility::splitString(str, "||");
	for (const auto &header : headerList)
	{
		auto oneHeader = Utility::splitString(header, "|");
		if (oneHeader.size() == 2)
		{
			result[oneHeader[0]] = oneHeader[1];
		}
	}
	return result;
}

std::string HttpRequest::serializeHeaders(const std::map<std::string, std::string> &map)
{
	std::ostringstream oss;
	for (const auto &pair : map)
	{
		oss << pair.first << "|" << pair.second << "||";
	}
	return oss.str();
}

std::string HttpRequest::serializeHeaders(const web::http::http_headers &map)
{
	std::ostringstream oss;
	for (const auto &pair : map)
	{
		oss << pair.first << "|" << pair.second << "||";
	}
	return oss.str();
}

const std::shared_ptr<ACE_OutputCDR> HttpRequest::serialize() const
{
	// https://github.com/DOCGroup/ACE_TAO/blob/master/ACE/examples/Logger/client/logging_app.cpp
	auto headerStr = serializeHeaders(m_headers);
	const size_t max_payload_size =
		m_uuid.length() +
		m_method.length() +
		m_relative_uri.length() +
		m_remote_address.length() +
		m_body.length() +
		headerStr.length() +
		m_query.length() +
		8 + 7 * ACE_CDR::MAX_ALIGNMENT; // each item need one padding

	// Insert contents into payload stream.
	auto payload = std::make_shared<ACE_OutputCDR>(max_payload_size);
	*payload << m_uuid;
	*payload << m_method;
	*payload << m_relative_uri;
	*payload << m_remote_address;
	*payload << m_body;
	*payload << headerStr;
	*payload << m_query;

	// LOG_DBG << "HttpRequest::serialize() headers: " << headerStr;
	return payload;
}

std::shared_ptr<HttpRequest> HttpRequest::deserialize(ACE_InputCDR &input)
{
	std::string uuid, method, uri, address, body, headerStr, query;
	if (input >> uuid &&
		input >> method &&
		input >> uri &&
		input >> address &&
		input >> body &&
		input >> headerStr &&
		input >> query)
	{
		// use std::make_shared call private constructor will face compile error
		return std::shared_ptr<HttpRequest>(new HttpRequest(uuid, method, uri, address, body, headerStr, query));
	}
	return nullptr;
}

////////////////////////////////////////////////////////////////////////////////
// HttpTcpResponse transfer REST response from RestTcpServer to RestChildObject
////////////////////////////////////////////////////////////////////////////////
HttpTcpResponse::HttpTcpResponse(const std::string &uuid,
								 const std::string &body,
								 const std::string &bodyType,
								 const std::map<std::string, std::string> &headers,
								 const http::status_code &status)
	: m_uuid(uuid), m_body(body), m_bodyType(bodyType), m_headers(headers), m_status(status)
{
}

const std::shared_ptr<ACE_OutputCDR> HttpTcpResponse::serialize() const
{
	auto headerStr = HttpRequest::serializeHeaders(m_headers);
	const size_t max_payload_size =
		m_uuid.length() +
		m_body.length() +
		m_bodyType.length() +
		headerStr.length() +
		8 +
		8 + 5 * ACE_CDR::MAX_ALIGNMENT; // each item need one padding
	// Insert contents into payload stream.
	auto payload = std::make_shared<ACE_OutputCDR>(max_payload_size);
	*payload << m_uuid;
	*payload << m_body;
	*payload << m_bodyType;
	*payload << headerStr;
	*payload << m_status;
	return payload;
}

std::shared_ptr<HttpTcpResponse> HttpTcpResponse::deserialize(ACE_InputCDR &input)
{
	std::string uuid, body, bodyType, headerStr;
	http::status_code status;
	if (input >> uuid &&
		input >> body &&
		input >> bodyType &&
		input >> headerStr &&
		input >> status)
	{
		// use std::make_shared call private constructor will face compile error
		return std::shared_ptr<HttpTcpResponse>(new HttpTcpResponse(uuid, body, bodyType, HttpRequest::parseHeaders(headerStr), status));
	}
	return nullptr;
}

IoVector::IoVector(std::shared_ptr<ACE_OutputCDR> body)
	: m_headerCdr(ACE_CDR::MAX_ALIGNMENT + 8), m_bodyCdr(body)
{
	// Get the number of bytes used by the CDR stream.
	ACE_CDR::ULong length = ACE_Utils::truncate_cast<ACE_CDR::ULong>(body->total_length());

	// Send a header so the receiver can determine the byte order and
	// size of the incoming CDR stream.
	m_headerCdr << ACE_OutputCDR::from_boolean(ACE_CDR_BYTE_ORDER);
	// Store the size of the payload that follows
	m_headerCdr << ACE_CDR::ULong(length);

	// Use an iovec to send both buffer and payload simultaneously.
	// iovec iov[2];
	data[0].iov_base = m_headerCdr.begin()->rd_ptr();
	data[0].iov_len = 8;
	data[1].iov_base = m_bodyCdr->begin()->rd_ptr();
	data[1].iov_len = length;
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
