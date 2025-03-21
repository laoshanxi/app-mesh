#include <map>
#include <string>

#include <ace/Hash_Multi_Map_Manager_T.h>

#include "../../common/Utility.h"
#include "../../common/json.hpp"
#include "../Configuration.h"
#include "../application/Application.h"
#include "../process/AppProcess.h"
#include "../security/HMACVerifier.h"
#include "HttpRequest.h"
#include "RestHandler.h"
#include "TcpServer.h"
#include "protoc/ProtobufHelper.h"

APP_OUT_MULTI_MAP_TYPE APP_OUT_VIEW_MAP;

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
	reply(m_relative_uri, m_uuid, JSON::dump(body_data), {}, status, CONTENT_TYPE_APPLICATION_JSON);
}

void HttpRequest::reply(web::http::status_code status, const nlohmann::json &body_data, const std::map<std::string, std::string> &headers) const
{
	reply(m_relative_uri, m_uuid, JSON::dump(body_data), headers, status, CONTENT_TYPE_APPLICATION_JSON);
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
	if (requestUri == REST_PATH_UPLOAD)
		response.file_upload_request_headers = m_headers;

	if (m_tcpHanlerId > 0)
	{
		TcpHandler::replyTcp(m_tcpHanlerId, response);
	}
}

void HttpRequest::verifyHMAC() const
{

	if (this->m_headers.count(HMAC_HTTP_HEADER) &&
		HMACVerifierSingleton::instance()->verifyHMAC(this->m_uuid, this->m_headers.find(HMAC_HTTP_HEADER)->second))
	{
	}
	else
	{
		throw std::invalid_argument("Verify HMAC failed");
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
	// avoid use Application lock access Configuration
	if (m_app)
		m_app->regSuicideTimer(0);
	m_app.reset();
}

////////////////////////////////////////////////////////////////////////////////
// HttpRequest used to handle view app output
////////////////////////////////////////////////////////////////////////////////
HttpRequestOutputView::HttpRequestOutputView(const HttpRequest &message, const std::shared_ptr<Application> &appObj)
	: HttpRequest(message), m_timerResponseId(INVALID_TIMER_ID), m_pid(ACE_INVALID_PID), m_app(appObj)
{
}
HttpRequestOutputView::~HttpRequestOutputView()
{
}

void HttpRequestOutputView::init()
{
	const static char fname[] = "HttpRequestOutputView::init() ";

	size_t timeout = RestHandler::getHttpQueryValue(*this, HTTP_QUERY_KEY_stdout_timeout, 0, 0, 0);
	m_pid = m_app->getpid();

	if (AppProcess::running(m_pid) && timeout > 0)
	{
		APP_OUT_VIEW_MAP.bind(m_pid, std::static_pointer_cast<HttpRequestOutputView>(TimerHandler::shared_from_this()));
		m_timerResponseId = this->registerTimer(1000L * timeout, 0, std::bind(&HttpRequestOutputView::onTimerResponse, this), fname);

		LOG_DBG << fname << "app <" << m_app->getName() << "> view output with pid <" << m_pid << ">, APP_OUT_VIEW_MAP size = " << APP_OUT_VIEW_MAP.current_size();
	}
	else
	{
		response();
	}
}

void HttpRequestOutputView::response()
{
	this->cancelTimer(m_timerResponseId);
	onTimerResponse();
}

bool HttpRequestOutputView::onTimerResponse()
{
	const static char fname[] = "HttpRequestOutputView::onTimerResponse() ";
	LOG_DBG << fname;
	try
	{
		CLEAR_TIMER_ID(m_timerResponseId);
		if (!m_httpRequestReplyFlag.test_and_set())
		{
			long pos = RestHandler::getHttpQueryValue(*this, HTTP_QUERY_KEY_stdout_position, 0, 0, 0);
			int index = RestHandler::getHttpQueryValue(*this, HTTP_QUERY_KEY_stdout_index, 0, 0, 0);
			long maxSize = RestHandler::getHttpQueryValue(*this, HTTP_QUERY_KEY_stdout_maxsize, APP_STD_OUT_VIEW_DEFAULT_SIZE, 1024, APP_STD_OUT_VIEW_DEFAULT_SIZE);
			size_t timeout = 0; // getHttpQueryValue(message, HTTP_QUERY_KEY_stdout_timeout, 0, 0, 0);
			std::string processUuid = RestHandler::getHttpQueryString(*this, HTTP_QUERY_KEY_process_uuid);
			bool outputHtml = RestHandler::getHttpQueryString(*this, HTTP_QUERY_KEY_html).length();
			bool outputJson = RestHandler::getHttpQueryString(*this, HTTP_QUERY_KEY_json).length();

			auto result = m_app->getOutput(pos, maxSize, processUuid, index, timeout);
			auto output = std::get<0>(result);
			const auto &finished = std::get<1>(result);
			const auto &exitCode = std::get<2>(result);
			if (output.length())
			{
				LOG_INF << fname << "Get application output size <" << output.size() << ">";
			}
			std::map<std::string, std::string> headers;
			if (pos)
				headers[HTTP_HEADER_KEY_output_pos] = std::to_string(pos);
			if (finished)
				headers[HTTP_HEADER_KEY_exit_code] = std::to_string(exitCode);
			if (outputHtml)
			{
				// https://github.com/yesoreyeram/grafana-infinity-datasource/blob/main/testdata/users.html
				// https://sriramajeyam.com/grafana-infinity-datasource/wiki/html
				static const auto html = Utility::readFileCpp("script/grafana_infinity.html");
				auto lines = Utility::splitString(output, "\n");
				std::stringstream ss;
				for (const auto &line : lines)
				{
					ss << line << "</pre>\n<pre>";
				}
				output = Utility::stringFormat(html, m_app->getName().c_str(), ss.str().c_str());
			}
			else if (outputJson)
			{
				auto lines = Utility::splitString(output, "\n");
				auto jsonArray = nlohmann::json::array();
				// Build Json
				for (std::size_t i = 0; i < lines.size(); ++i)
				{
					jsonArray[i] = nlohmann::json{{"index", i + 1}, {"stdout", lines[i]}};
				}
				output = jsonArray.dump();
			}
			HttpRequest::reply(web::http::status_codes::OK, output, headers);
			m_app.reset();
		}
	}
	catch (const std::exception &e)
	{
		HttpRequest::reply(web::http::status_codes::ExpectationFailed);
		m_app.reset();
	}
	return false;
}