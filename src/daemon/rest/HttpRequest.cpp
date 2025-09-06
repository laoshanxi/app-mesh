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

HttpRequest::HttpRequest(Request &&request, int tcpHandlerId)
	: m_uuid(std::move(request.uuid)),
	  m_method(std::move(request.http_method)),
	  m_relative_uri(std::move(request.request_uri)),
	  m_remote_address(std::move(request.client_addr)),
	  m_body(std::make_shared<std::string>(std::move(request.body))),
	  m_querys(std::move(request.querys)),
	  m_headers(std::move(request.headers)),
	  m_tcpHanlerId(tcpHandlerId)
{
}

HttpRequest::~HttpRequest()
{
}

nlohmann::json HttpRequest::extractJson() const
{
	return nlohmann::json::parse(*m_body);
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
		return std::make_shared<HttpRequest>(std::move(req), tcpHandlerId);
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
	LOG_DBG << fname << "m_body:" << *m_body;
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
HttpRequestAutoCleanup::HttpRequestAutoCleanup(const HttpRequest &message, const std::shared_ptr<Application> &appObj)
	: HttpRequest(message), m_app(appObj)
{
}

HttpRequestAutoCleanup::~HttpRequestAutoCleanup()
{
	// avoid use Application lock access Configuration
	if (m_app)
		m_app->regSuicideTimer(0);
	m_app.reset();
}

////////////////////////////////////////////////////////////////////////////////
// HttpRequest with timeout
////////////////////////////////////////////////////////////////////////////////
HttpRequestWithTimeout::HttpRequestWithTimeout(const HttpRequest &message)
	: HttpRequest(message), m_timerResponseId(INVALID_TIMER_ID), m_httpRequestReplyFlag(false)
{
}

bool HttpRequestWithTimeout::initTimer(int timeoutSeconds)
{
	const static char fname[] = "HttpRequestWithTimeout::initTimer() ";

	if (timeoutSeconds <= 0)
	{
		return false;
	}

	m_timerResponseId = this->registerTimer(1000L * timeoutSeconds, 0, std::bind(&HttpRequestWithTimeout::onTimerResponse, this), fname);
	LOG_DBG << fname << "registered timer " << m_timerResponseId << " for request " << this->m_uuid << " with timeout " << timeoutSeconds << " seconds";
	return true;
}

bool HttpRequestWithTimeout::onTimerResponse()
{
	const static char fname[] = "HttpRequestWithTimeout::onTimerResponse() ";
	LOG_DBG << fname;

	CLEAR_TIMER_ID(m_timerResponseId);
	HttpRequest::reply(web::http::status_codes::RequestTimeout);

	return false;
}

bool HttpRequestWithTimeout::replied() const
{
	return m_httpRequestReplyFlag.load();
}

void HttpRequestWithTimeout::reply(const std::string &requestUri, const std::string &uuid, const std::string &body,
								   const std::map<std::string, std::string> &headers, const web::http::status_code &status, const std::string &bodyType) const
{
	const static char fname[] = "HttpRequestWithTimeout::reply() ";
	LOG_DBG << fname;

	const_cast<HttpRequestWithTimeout *>(this)->cancelTimer(m_timerResponseId);
	if (!m_httpRequestReplyFlag.exchange(true))
	{
		HttpRequest::reply(requestUri, uuid, body, headers, status, bodyType);
	}
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

////////////////////////////////////////////////////////////////////////////////
// TaskRequest
////////////////////////////////////////////////////////////////////////////////

TaskRequest::~TaskRequest()
{
	terminate();
}

void TaskRequest::terminate()
{
	terminate(m_getMessage);
	terminate(m_sendMessage);
	terminate(m_respMessage);
}

void TaskRequest::sendMessage(std::shared_ptr<void> asyncHttpRequest)
{
	const static char fname[] = "TaskRequest::sendMessage() ";

	terminate(m_sendMessage);
	m_sendMessage = std::static_pointer_cast<HttpRequestWithTimeout>(asyncHttpRequest);

	// make sure no response pending
	terminate(m_respMessage);

	// if get message request already here, respond it
	checkAvialable(m_getMessage);
	if (m_getMessage)
	{
		LOG_INF << fname << "respond: " << m_getMessage->m_method << " " << m_getMessage->m_relative_uri;
		m_getMessage->reply(web::http::status_codes::OK, *m_sendMessage->m_body);
		m_getMessage = nullptr;
	}
}

void TaskRequest::getMessage(std::shared_ptr<void> asyncHttpRequest)
{
	const static char fname[] = "TaskRequest::getMessage() ";

	terminate(m_getMessage);
	m_getMessage = std::static_pointer_cast<HttpRequestWithTimeout>(asyncHttpRequest);

	// make sure no response pending
	terminate(m_respMessage);

	// get message request may ahead or after send message request
	// respond if send message already here
	checkAvialable(m_sendMessage);
	if (m_sendMessage)
	{
		LOG_INF << fname << "respond: " << m_getMessage->m_method << " " << m_getMessage->m_relative_uri;
		m_getMessage->reply(web::http::status_codes::OK, *m_sendMessage->m_body);
		m_getMessage = nullptr;
		// TODO: allow get same data again?
	}
}

void TaskRequest::respMessage(std::shared_ptr<void> asyncHttpRequest)
{
	const static char fname[] = "TaskRequest::respMessage() ";

	terminate(m_respMessage);
	m_respMessage = std::static_pointer_cast<HttpRequestWithTimeout>(asyncHttpRequest);

	checkAvialable(m_sendMessage);
	if (m_sendMessage)
	{
		LOG_WAR << fname << "no message request from client waiting for response";
		m_respMessage->reply(web::http::status_codes::ExpectationFailed, "no message request from client waiting for response");
		m_respMessage = nullptr;
		return;
	}

	LOG_INF << fname << "respond: " << m_sendMessage->m_method << " " << m_sendMessage->m_relative_uri;

	m_sendMessage->reply(web::http::status_codes::OK, *m_respMessage->m_body);
	m_sendMessage = nullptr;

	m_respMessage->reply(web::http::status_codes::OK);
	m_respMessage = nullptr;
}

void TaskRequest::terminate(std::shared_ptr<HttpRequestWithTimeout> &request)
{
	const static char fname[] = "TaskRequest::terminate() ";

	if (request)
	{
		LOG_DBG << fname << "terminate pending request: " << request->m_uuid << " " << request->m_method << " " << request->m_relative_uri;
		request->reply(web::http::status_codes::ServiceUnavailable);
		request = nullptr;
	}
}

void TaskRequest::checkAvialable(std::shared_ptr<HttpRequestWithTimeout> &request)
{
	const static char fname[] = "TaskRequest::checkAvialable() ";

	if (request && request->replied())
	{
		LOG_WAR << fname << "clean replied request: " << request->m_uuid << " " << request->m_method << " " << request->m_relative_uri;
		request = nullptr;
	}
}
