// src/daemon/rest/HttpRequest.cpp
#include <map>
#include <string>

#include <ace/Hash_Multi_Map_Manager_T.h>

#include "../../common/Utility.h"
#include "../../common/json.h"
#include "../Configuration.h"
#include "../application/Application.h"
#include "../process/AppProcess.h"
#include "../security/HMACVerifier.h"
#include "Data.h"
#include "RestHandler.h"
#include "SocketServer.h"
#include "Worker.h"
#if defined(HAVE_UWEBSOCKETS)
#include "uwebsockets/ReplyContext.h"
#else
#include "../../common/lwsservice/WebSocketService.h"
#endif

#include "HttpRequest.h"

HttpRequest::HttpRequest(Request &&request, int tcpClientId)
	: m_uuid(std::move(request.uuid)),
	  m_method(std::move(request.http_method)),
	  m_relative_uri(std::move(request.request_uri)),
	  m_remote_address(std::move(request.client_addr)),
	  m_body(std::make_shared<std::vector<std::uint8_t>>(std::move(request.body))), // When HttpRequest is copied, m_body only copies the shared_ptr
	  m_query(std::move(request.query)),
	  m_headers(std::move(request.headers)),
	  m_tcpClientId(tcpClientId), m_lwsRef{}, m_uwsReplyContext(nullptr)
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

bool HttpRequest::reply(web::http::status_code status, const std::vector<std::uint8_t> &body_data) const
{
	return reply(m_relative_uri, m_uuid, body_data, {}, status, web::http::mime_types::application_octetstream);
}

bool HttpRequest::reply(web::http::status_code status, const nlohmann::json &body_data, const std::map<std::string, std::string> &headers) const
{
	const auto body = body_data.dump();
	const auto bodyBytes = std::vector<std::uint8_t>(body.begin(), body.end());
	return reply(m_relative_uri, m_uuid, bodyBytes, headers, status, web::http::mime_types::application_json);
}

bool HttpRequest::reply(web::http::status_code status, std::string &body_data, const std::string &content_type) const
{
	return reply(status, body_data, {}, content_type);
}

bool HttpRequest::reply(web::http::status_code status, const std::string &body_data, const std::map<std::string, std::string> &headers, const std::string &content_type) const
{
	const auto bodyBytes = std::vector<std::uint8_t>(body_data.begin(), body_data.end());
	return reply(m_relative_uri, m_uuid, bodyBytes, headers, status, content_type);
}

std::shared_ptr<HttpRequest> HttpRequest::deserialize(const ByteBuffer &input, int tcpClientId, LwsSessionRef lwsRef, std::shared_ptr<WSS::ReplyContext> ctx)
{
	const static char fname[] = "HttpRequest::deserialize() ";

	Request req;
	if (req.deserialize(input))
	{
		auto request = std::make_shared<HttpRequest>(std::move(req), tcpClientId);
		request->m_lwsRef = lwsRef;
		request->m_uwsReplyContext = std::move(ctx);
		return request;
	}
	else
	{
		LOG_ERR << fname << "failed to decode tcp raw data";
	}
	return nullptr;
}

std::unique_ptr<msgpack::sbuffer> HttpRequest::serialize() const
{
	Request req;
	req.body = *m_body;
	req.client_addr = m_remote_address;
	req.http_method = m_method;
	req.request_uri = m_relative_uri;
	req.uuid = m_uuid;
	req.headers = m_headers;
	req.query = m_query;

	return req.serialize();
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

bool HttpRequest::reply(const std::string &requestUri, const std::string &uuid, const std::vector<std::uint8_t> &body,
						const std::map<std::string, std::string> &headers, const web::http::status_code &status, const std::string &bodyType) const
{
	const static char fname[] = "HttpRequest::reply() ";
	LOG_DBG << fname;

	auto response = std::make_unique<Response>();
	// Fill response data
	response->uuid = uuid;
	response->request_uri = requestUri;
	response->body = body;
	response->headers = headers;
	response->http_status = status;
	response->body_msg_type = bodyType;
	if (requestUri == REST_PATH_UPLOAD)
		response->file_upload_request_headers = m_headers;

	if (m_tcpClientId > 0)
	{
		// TCP protocol
		return SocketServer::replyTcp(m_tcpClientId, std::move(response));
	}
#if defined(HAVE_UWEBSOCKETS)
	else if (m_uwsReplyContext)
	{
		if (m_uwsReplyContext->getProtocolType() == WSS::ReplyContext::ProtocolType::Http)
		{
			// HTTP protocol
			response->handleAuthCookies(&m_headers);
			response->applyCorsHeaders();
			response->applySecurityHeaders();
			m_uwsReplyContext->replyHTTP(std::to_string(status), std::string(body.begin(), body.end()), std::move(response->headers), std::string(bodyType));
			return true;
		}
		else if (m_uwsReplyContext->getProtocolType() == WSS::ReplyContext::ProtocolType::WebSocket)
		{
			// WebSocket protocol
			auto data = response->serialize();
			m_uwsReplyContext->replyWebSocket(std::string(data->data(), data->size()), false, true);
			return true;
		}
		else
		{
			LOG_ERR << fname << "Unknown reply context protocol type";
			return false;
		}
	}
#else
	else if (m_lwsRef)
	{
		// WebSocket or HTTP-over-lws: move serialized sbuffer in, no body copy.
		auto resp = std::make_unique<WSResponse>();
		resp->m_session_ref = const_cast<void *>(m_lwsRef.wsi);
		resp->m_req_id = m_lwsRef.reqId;
		resp->m_session_id = m_lwsRef.sessionId;
		resp->m_payload = response->serialize();
		resp->m_is_http = m_headers.get(HTTP_HEADER_KEY_X_LWS_Protocol) == HTTP_HEADER_VALUE_X_LWS_Protocol_HTTP;
		WebSocketService::instance()->enqueueOutgoingResponse(std::move(resp));
		return true;
	}
#endif

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
	// Leak guard via the flag-gated virtual reply() override; no-op if already replied.
	HttpRequest::reply(web::http::status_codes::ServiceUnavailable);
}

bool HttpRequestWithTimeout::initTimer(int timeoutSeconds)
{
	const static char fname[] = "HttpRequestWithTimeout::initTimer() ";

	if (timeoutSeconds <= 0)
	{
		return false;
	}

	m_timerResponseId = this->registerTimer(1000L * timeoutSeconds, 0, fname, std::bind(&HttpRequestWithTimeout::onTimerResponse, this));
	LOG_DBG << fname << "registered timer " << m_timerResponseId << " for request " << this->m_uuid << " with timeout " << timeoutSeconds << " seconds";
	return true;
}

bool HttpRequestWithTimeout::onTimerResponse()
{
	const static char fname[] = "HttpRequestWithTimeout::onTimerResponse() ";
	LOG_DBG << fname;

	CLEAR_TIMER_ID(m_timerResponseId);
	// Flag-gated via the virtual reply() override; no-op if a worker already replied.
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

bool HttpRequestWithTimeout::reply(const std::string &requestUri, const std::string &uuid, const std::vector<std::uint8_t> &body,
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
		m_timerResponseId = this->registerTimer(1000L * timeout, 0, fname, std::bind(&HttpRequestOutputView::onTimerResponse, this));

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
				output = Utility::stringFormat(html.c_str(), app->getName().c_str(), ss.str().c_str());
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
// TaskRequest - manages task request/response flow between clients and server.
// Multiple clients can queue tasks concurrently; the server process fetches
// and replies to them one at a time in FIFO order.
////////////////////////////////////////////////////////////////////////////////

void TaskRequest::terminate()
{
	m_fetchTask.reset();
	m_replyTask.reset();
	m_activeTask.reset();
	while (!m_taskQueue.empty())
	{
		m_taskQueue.front()->interrupt();
		m_taskQueue.pop();
	}
}

void TaskRequest::sendTask(std::shared_ptr<HttpRequestWithTimeout> &taskRequest)
{
	const static char fname[] = "TaskRequest::sendTask() ";

	taskRequest->id(++m_taskId);

	// If the server is already waiting for a task, deliver immediately.
	if (m_fetchTask)
	{
		m_activeTask = taskRequest;
		m_replyTask.reset();
		LOG_INF << fname << "deliver to waiting fetch: " << m_fetchTask->m_method << " " << m_fetchTask->m_relative_uri;
		m_fetchTask->reply(web::http::status_codes::OK, *taskRequest->m_body);
		m_fetchTask.reset();
	}
	else
	{
		if (m_taskQueue.size() >= 512)
		{
			LOG_WAR << fname << "task queue full (" << m_taskQueue.size() << "), rejecting";
			taskRequest->reply(web::http::status_codes::ServiceUnavailable, Utility::text2json("task queue full, try again later"));
			return;
		}
		m_taskQueue.push(taskRequest);
		LOG_INF << fname << "queued task (queue size: " << m_taskQueue.size() << ")";
	}
}

bool TaskRequest::deleteTask()
{
	// Cancel only the in-flight (active) task — the one currently dispatched to
	// the server process. Queued tasks belong to other clients still blocking on
	// their own requests and each carry their own timeout, so they are left
	// intact: one client's cancel must not abort everyone else's pending work.
	// Full teardown of the queue happens in terminate() on app stop/remove.
	if (m_activeTask)
	{
		bool result = m_activeTask->interrupt();
		m_activeTask.reset();
		return result;
	}
	return false;
}

void TaskRequest::fetchTask(std::shared_ptr<void> &serverRequest)
{
	const static char fname[] = "TaskRequest::fetchTask() ";

	m_fetchTask = std::static_pointer_cast<HttpRequestWithTimeout>(serverRequest);
	m_replyTask.reset();

	// If there are queued tasks, deliver the next one immediately.
	if (!m_taskQueue.empty())
	{
		m_activeTask = m_taskQueue.front();
		m_taskQueue.pop();
		LOG_INF << fname << "deliver queued task: " << m_fetchTask->m_method << " " << m_fetchTask->m_relative_uri;
		m_fetchTask->reply(web::http::status_codes::OK, *m_activeTask->m_body);
		m_fetchTask.reset();
		return;
	}

	// Allow re-fetch of active task in case the server process restarted.
	cleanupRepliedRequest(m_activeTask);
	if (m_activeTask)
	{
		LOG_INF << fname << "re-deliver active task: " << m_fetchTask->m_method << " " << m_fetchTask->m_relative_uri;
		m_fetchTask->reply(web::http::status_codes::OK, *m_activeTask->m_body);
		m_fetchTask.reset();
	}
	// Otherwise m_fetchTask stays set — will be satisfied by the next sendTask.
}

void TaskRequest::replyTask(std::shared_ptr<void> &serverRequest)
{
	const static char fname[] = "TaskRequest::replyTask() ";

	m_replyTask = std::static_pointer_cast<HttpRequestWithTimeout>(serverRequest);

	cleanupRepliedRequest(m_activeTask);
	if (m_activeTask == nullptr)
	{
		LOG_WAR << fname << "no client request waiting for response";
		m_replyTask->reply(web::http::status_codes::ExpectationFailed, Utility::text2json("no message request from client waiting for response"));
		m_replyTask.reset();
		return;
	}

	LOG_INF << fname << "respond to client: " << m_activeTask->m_method << " " << m_activeTask->m_relative_uri;

	// Forward the server's reply to the original client request.
	m_activeTask->reply(web::http::status_codes::OK, *m_replyTask->m_body);
	m_activeTask.reset();

	// Acknowledge server's reply.
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
	cleanupRepliedRequest(m_activeTask);

	if (m_fetchTask)
	{
		return std::make_tuple(m_taskId.load(), "idle");
	}

	if (m_activeTask || !m_taskQueue.empty())
	{
		return std::make_tuple(m_taskId.load(), "busy");
	}

	return std::make_tuple(m_taskId.load(), "");
}
