#include <map>
#include <string>

#include <ace/Hash_Multi_Map_Manager_T.h>

#include "../../common/Utility.h"
#include "../../common/json.h"
#include "../Configuration.h"
#include "../application/Application.h"
#include "../process/AppProcess.h"
#include "../security/HMACVerifier.h"
#include "HttpRequest.h"
#include "RestHandler.h"
#include "TcpServer.h"
#include "protoc/ProtobufHelper.h"

HttpRequest::HttpRequest(Request &&request, int tcpHandlerId)
	: m_uuid(std::move(request.uuid)),
	  m_method(std::move(request.http_method)),
	  m_relative_uri(std::move(request.request_uri)),
	  m_remote_address(std::move(request.client_addr)),
	  m_body(std::make_shared<std::vector<uint8_t>>(std::move(request.body))), // When HttpRequest is copied, m_body only copies the shared_ptr
	  m_query(std::move(request.query)),
	  m_headers(std::move(request.headers)),
	  m_tcpHandlerId(tcpHandlerId)
{
}

HttpRequest::~HttpRequest()
{
}

nlohmann::json HttpRequest::extractJson() const
{
	return nlohmann::json::parse(*m_body);
}

bool HttpRequest::reply(web::http::status_code status) const
{
	return reply(m_relative_uri, m_uuid, {}, {}, status, "");
}

bool HttpRequest::reply(web::http::status_code status, const nlohmann::json &body_data) const
{
	return reply(status, body_data, {});
}

bool HttpRequest::reply(web::http::status_code status, const std::vector<uint8_t> &body_data) const
{
	return reply(m_relative_uri, m_uuid, body_data, {}, status, web::http::mime_types::application_octetstream);
}

bool HttpRequest::reply(web::http::status_code status, const nlohmann::json &body_data, const std::map<std::string, std::string> &headers) const
{
	const auto body = body_data.dump();
	const auto bodyBytes = std::vector<uint8_t>(body.begin(), body.end());
	return reply(m_relative_uri, m_uuid, bodyBytes, headers, status, web::http::mime_types::application_json);
}

bool HttpRequest::reply(web::http::status_code status, std::string &body_data, const std::string &content_type) const
{
	return reply(status, body_data, {}, content_type);
}

bool HttpRequest::reply(web::http::status_code status, const std::string &body_data, const std::map<std::string, std::string> &headers, const std::string &content_type) const
{
	const auto bodyBytes = std::vector<uint8_t>(body_data.begin(), body_data.end());
	return reply(m_relative_uri, m_uuid, bodyBytes, headers, status, content_type);
}

std::shared_ptr<HttpRequest> HttpRequest::deserialize(const char *input, int inputSize, int tcpHandlerId)
{
	const static char fname[] = "HttpRequest::deserialize() ";

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

const nlohmann::json HttpRequest::emptyJsonMessage()
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
	// LOG_DBG << fname << "m_body:" << *m_body;
	for (const auto &q : m_query)
		LOG_DBG << fname << "m_query:" << q.first << "=" << q.second;
	// for (const auto &h : m_headers)
	//	LOG_DBG << fname << "m_headers:" << h.first << "=" << h.second;
}

bool HttpRequest::reply(const std::string &requestUri, const std::string &uuid, const std::vector<uint8_t> &body,
						const std::map<std::string, std::string> &headers, const web::http::status_code &status, const std::string &bodyType) const
{
	const static char fname[] = "HttpRequest::reply() ";
	LOG_DBG << fname;

	Response response;
	// Fill response data
	response.uuid = uuid;
	response.request_uri = requestUri;
	response.body = body;
	response.headers = headers;
	response.http_status = status;
	response.body_msg_type = bodyType;
	if (requestUri == REST_PATH_UPLOAD)
		response.file_upload_request_headers = m_headers;

	if (m_tcpHandlerId > 0)
	{
		return TcpHandler::replyTcp(m_tcpHandlerId, response);
	}

	return false;
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
// HttpRequestAutoCleanup - automatically removes app from global map on cleanup
////////////////////////////////////////////////////////////////////////////////
HttpRequestAutoCleanup::HttpRequestAutoCleanup(const std::shared_ptr<HttpRequest> &message, const std::shared_ptr<Application> &appObj)
	: HttpRequest(*message), m_app(appObj)
{
}

HttpRequestAutoCleanup::~HttpRequestAutoCleanup()
{
	// Trigger suicide timer to remove app (avoid using Application lock to access Configuration)
	if (auto app = m_app.lock())
	{
		app->regSuicideTimer(0);
	}
}

////////////////////////////////////////////////////////////////////////////////
// HttpRequestWithTimeout - HTTP request with timeout support
////////////////////////////////////////////////////////////////////////////////
HttpRequestWithTimeout::HttpRequestWithTimeout(const std::shared_ptr<HttpRequest> &message)
	: HttpRequest(*message), m_timerResponseId(INVALID_TIMER_ID), m_httpRequestReplyFlag(false), m_id(0)
{
}

HttpRequestWithTimeout::~HttpRequestWithTimeout()
{
	// Prevent request leak (helps both C++ and Golang side)
	HttpRequest::reply(web::http::status_codes::ServiceUnavailable);
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

bool HttpRequestWithTimeout::interrupt()
{
	return HttpRequest::reply(web::http::status_codes::ExpectationFailed);
}

void HttpRequestWithTimeout::id(int id)
{
	m_id = id;
}

int HttpRequestWithTimeout::id()
{
	return m_id.load();
}

bool HttpRequestWithTimeout::reply(const std::string &requestUri, const std::string &uuid, const std::vector<uint8_t> &body,
								   const std::map<std::string, std::string> &headers, const web::http::status_code &status, const std::string &bodyType) const
{
	const static char fname[] = "HttpRequestWithTimeout::reply() ";
	LOG_DBG << fname;

	const_cast<HttpRequestWithTimeout *>(this)->cancelTimer(m_timerResponseId);
	if (!m_httpRequestReplyFlag.exchange(true))
	{
		return HttpRequest::reply(requestUri, uuid, body, headers, status, bodyType);
	}
	return false;
}

////////////////////////////////////////////////////////////////////////////////
// HttpRequestOutputView - handles viewing application output with async response
////////////////////////////////////////////////////////////////////////////////
using APP_OUT_MULTI_MAP_TYPE = ACE_Hash_Multi_Map_Manager<pid_t, std::shared_ptr<HttpRequestOutputView>, ACE_Hash<pid_t>, ACE_Equal_To<pid_t>, ACE_Recursive_Thread_Mutex>;
static APP_OUT_MULTI_MAP_TYPE APP_OUT_VIEW_MAP;

HttpRequestOutputView::HttpRequestOutputView(const std::shared_ptr<HttpRequest> &message, const std::shared_ptr<Application> &appObj)
	: HttpRequest(*message), m_timerResponseId(INVALID_TIMER_ID), m_pid(appObj->getpid()), m_app(appObj)
{
}

void HttpRequestOutputView::init()
{
	const static char fname[] = "HttpRequestOutputView::init() ";

	auto app = m_app.lock();
	if (!app)
	{
		HttpRequest::reply(web::http::status_codes::ExpectationFailed);
		return;
	}

	size_t timeout = RestHandler::getHttpQueryValue(*this, HTTP_QUERY_KEY_stdout_timeout, 0, 0, 0);
	if (AppProcess::running(m_pid) && timeout > 0)
	{
		APP_OUT_VIEW_MAP.bind(m_pid, std::static_pointer_cast<HttpRequestOutputView>(shared_from_this()));
		m_timerResponseId = this->registerTimer(1000L * timeout, 0, std::bind(&HttpRequestOutputView::onTimerResponse, this), fname);

		LOG_DBG << fname << "app <" << app->getName() << "> view output with pid <" << m_pid << ">, APP_OUT_VIEW_MAP size = " << APP_OUT_VIEW_MAP.current_size();
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
			auto app = m_app.lock();
			if (!app)
			{
				HttpRequest::reply(web::http::status_codes::ExpectationFailed);
				return false;
			}

			long pos = RestHandler::getHttpQueryValue(*this, HTTP_QUERY_KEY_stdout_position, 0, 0, 0);
			int index = RestHandler::getHttpQueryValue(*this, HTTP_QUERY_KEY_stdout_index, 0, 0, 0);
			long maxSize = RestHandler::getHttpQueryValue(*this, HTTP_QUERY_KEY_stdout_maxsize, APP_STD_OUT_VIEW_DEFAULT_SIZE, 1024, APP_STD_OUT_VIEW_DEFAULT_SIZE);
			size_t timeout = 0;
			std::string processUuid = RestHandler::getHttpQueryString(*this, HTTP_QUERY_KEY_process_uuid);
			bool outputHtml = RestHandler::getHttpQueryString(*this, HTTP_QUERY_KEY_html).length();
			bool outputJson = RestHandler::getHttpQueryString(*this, HTTP_QUERY_KEY_json).length();

			auto result = app->getOutput(pos, maxSize, processUuid, index, timeout);
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
				// Format output as HTML for Grafana Infinity datasource
				// Reference: https://github.com/yesoreyeram/grafana-infinity-datasource/blob/main/testdata/users.html
				// https://sriramajeyam.com/grafana-infinity-datasource/wiki/html
				static const auto html = Utility::readFileCpp("script/grafana_infinity.html");
				auto lines = Utility::splitString(output, "\n");
				std::stringstream ss;
				for (const auto &line : lines)
				{
					ss << line << "</pre>\n<pre>";
				}
				output = Utility::stringFormat(html, app->getName().c_str(), ss.str().c_str());
			}
			else if (outputJson)
			{
				// Convert output lines to JSON array format
				auto lines = Utility::splitString(output, "\n");
				auto jsonArray = nlohmann::json::array();
				for (std::size_t i = 0; i < lines.size(); ++i)
				{
					jsonArray[i] = nlohmann::json{{"index", i + 1}, {"stdout", lines[i]}};
				}
				output = jsonArray.dump();
			}
			HttpRequest::reply(web::http::status_codes::OK, output, headers);
		}
	}
	catch (const std::exception &e)
	{
		HttpRequest::reply(web::http::status_codes::ExpectationFailed);
	}
	return false;
}

void HttpRequestOutputView::onProcessExitResponse(pid_t pid)
{
	const static char fname[] = "HttpRequestOutputView::onProcessExitResponse() ";
	LOG_DBG << fname << (APP_OUT_VIEW_MAP.current_size() > 0 ? " APP_OUT_VIEW_MAP size: " + std::to_string(APP_OUT_VIEW_MAP.current_size()) : "");

	ACE_Unbounded_Set<std::shared_ptr<HttpRequestOutputView>> requests, empty;
	{
		ACE_Guard<ACE_Recursive_Thread_Mutex> guard(APP_OUT_VIEW_MAP.mutex());
		APP_OUT_VIEW_MAP.rebind(pid, empty, requests);
		APP_OUT_VIEW_MAP.unbind(pid);
	}

	if (requests.size() > 0)
	{
		LOG_DBG << fname << "pid <" << pid << "> exit and response output to clients: " << requests.size();
		for (auto &req : requests)
			req->response();
	}
}

////////////////////////////////////////////////////////////////////////////////
// TaskRequest - manages task request/response flow between client and server
////////////////////////////////////////////////////////////////////////////////

void TaskRequest::terminate()
{
	m_fetchTask.reset();
	m_replyTask.reset();
	m_taskRequest.reset();
}

void TaskRequest::sendTask(std::shared_ptr<HttpRequestWithTimeout> &taskRequest)
{
	const static char fname[] = "TaskRequest::sendTask() ";

	m_taskRequest = taskRequest;
	m_taskRequest->id(++m_taskId);

	// Clear any pending response task
	m_replyTask.reset();

	// If fetch request already waiting, respond immediately with the task
	if (m_fetchTask)
	{
		LOG_INF << fname << "respond: " << m_fetchTask->m_method << " " << m_fetchTask->m_relative_uri;
		auto task = std::static_pointer_cast<HttpRequestWithTimeout>(taskRequest);
		m_fetchTask->reply(web::http::status_codes::OK, *task->m_body);
		m_fetchTask.reset();
	}
}

bool TaskRequest::deleteTask()
{
	bool result = false;
	if (m_taskRequest)
	{
		result = m_taskRequest->interrupt();
		m_taskRequest.reset();
	}
	return result;
}

void TaskRequest::fetchTask(std::shared_ptr<void> &serverRequest)
{
	const static char fname[] = "TaskRequest::fetchTask() ";

	m_fetchTask = std::static_pointer_cast<HttpRequestWithTimeout>(serverRequest);

	// Clear any pending response task
	m_replyTask.reset();

	// Fetch request may arrive before or after send request
	// Respond immediately if task is already available
	cleanupRepliedRequest(m_taskRequest);
	if (m_taskRequest)
	{
		LOG_INF << fname << "respond: " << m_fetchTask->m_method << " " << m_fetchTask->m_relative_uri;
		m_fetchTask->reply(web::http::status_codes::OK, *m_taskRequest->m_body);
		m_fetchTask.reset();
		// Allow fetch for multiple times in case process restarted
	}
}

void TaskRequest::replyTask(std::shared_ptr<void> &serverRequest)
{
	const static char fname[] = "TaskRequest::replyTask() ";

	m_replyTask = std::static_pointer_cast<HttpRequestWithTimeout>(serverRequest);

	cleanupRepliedRequest(m_taskRequest);
	if (m_taskRequest == nullptr)
	{
		LOG_WAR << fname << "no message request from client waiting for response";
		m_replyTask->reply(web::http::status_codes::ExpectationFailed, Utility::text2json("no message request from client waiting for response"));
		m_replyTask.reset();
		return;
	}

	LOG_INF << fname << "respond: " << m_taskRequest->m_method << " " << m_taskRequest->m_relative_uri;

	// Forward reply to original client request
	m_taskRequest->reply(web::http::status_codes::OK, *m_replyTask->m_body);
	m_taskRequest.reset();

	// Acknowledge server's reply
	m_replyTask->reply(web::http::status_codes::OK);
	m_replyTask.reset();
}

void TaskRequest::cleanupRepliedRequest(std::shared_ptr<HttpRequestWithTimeout> &request)
{
	const static char fname[] = "TaskRequest::cleanupRepliedRequest() ";

	if (request && request->replied())
	{
		LOG_WAR << fname << "clean replied request: " << request->m_uuid << " " << request->m_method << " " << request->m_relative_uri;
		request = nullptr;
	}
}

std::tuple<int, std::string> TaskRequest::taskStatus()
{
	cleanupRepliedRequest(m_taskRequest);

	if (m_fetchTask)
	{
		return std::make_tuple(m_taskId.load(), "idle"); // Service is ready and waiting for a task
	}

	if (m_taskRequest)
	{
		return std::make_tuple(m_taskRequest->id(), "busy"); // A task has been dispatched and is still processing
	}

	return std::make_tuple(m_taskId.load(), ""); // No active message or task, state unavailable
}
