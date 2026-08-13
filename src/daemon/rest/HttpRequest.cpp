// src/daemon/rest/HttpRequest.cpp
#include <map>
#include <string>

#include "../../common/Utility.h"
#include "../../common/json.h"
#include "../Configuration.h"
#include "../application/Application.h"
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

struct HttpReplyMetricState
{
	explicit HttpReplyMetricState(std::function<void(int)> fn) : callback(std::move(fn)) {}

	void notify(int status) noexcept
	{
		if (!notified.exchange(true) && callback)
		{
			try
			{
				callback(status);
			}
			catch (...)
			{
				// Metrics never affect request delivery.
			}
		}
	}
	~HttpReplyMetricState() { notify(0); }

	std::atomic<bool> notified{false};
	std::function<void(int)> callback;
};

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

void HttpRequest::setReplyMetricCallback(std::function<void(int)> callback)
{
	m_replyMetric = std::make_shared<HttpReplyMetricState>(std::move(callback));
}

void HttpRequest::notifyReply(int status) const
{
	if (m_replyMetric)
		m_replyMetric->notify(status);
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
		LOG_ERR << fname << "Failed to decode TCP request data from client <" << tcpClientId << ">";
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
	LOG_DBG << fname << "Replying status <" << status << "> to request <" << uuid << "> for <" << requestUri << ">";

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
		const bool success = SocketServer::replyTcp(m_tcpClientId, std::move(response));
		if (success)
			notifyReply(status);
		return success;
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
			notifyReply(status);
			return true;
		}
		else if (m_uwsReplyContext->getProtocolType() == WSS::ReplyContext::ProtocolType::WebSocket)
		{
			// WebSocket protocol
			auto data = response->serialize();
			m_uwsReplyContext->replyWebSocket(std::string(data->data(), data->size()), false, true);
			notifyReply(status);
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
		notifyReply(status);
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
		app->scheduleRemoval(0);
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

	this->registerTimer(m_timerResponseId, 1000L * timeoutSeconds, 0, fname, std::bind(&HttpRequestWithTimeout::onTimerResponse, this));
	LOG_DBG << fname << "registered timer " << m_timerResponseId << " for request " << this->m_uuid << " with timeout " << timeoutSeconds << " seconds";
	return true;
}

bool HttpRequestWithTimeout::onTimerResponse()
{
	const static char fname[] = "HttpRequestWithTimeout::onTimerResponse() ";
	LOG_DBG << fname << "Request <" << this->m_uuid << "> timed out";

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
	LOG_DBG << fname << "Replying to request <" << uuid << ">";

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
HttpRequestOutputView::HttpRequestOutputView(const std::shared_ptr<HttpRequest> &message, const std::shared_ptr<Application> &appObj)
	: HttpRequest(*message), m_timerResponseId(INVALID_TIMER_ID), m_app(appObj)
{
}

HttpRequestOutputView::~HttpRequestOutputView()
{
	unsubscribeRunCompletion();
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
	const auto requestedRun = RestHandler::getHttpQueryString(*this, HTTP_QUERY_KEY_process_uuid);
	if (timeout > 0)
	{
		auto weakSelf = std::weak_ptr<HttpRequestOutputView>(std::static_pointer_cast<HttpRequestOutputView>(shared_from_this()));
		const auto subscription = app->subscribeRunCompletion(requestedRun, [weakSelf]()
															  {
			if (auto self = weakSelf.lock())
				self->response(); });
		if (subscription == Application::INVALID_RUN_COMPLETION_SUBSCRIPTION)
		{
			response();
			return;
		}
		m_completionSubscription.store(subscription, std::memory_order_release);
		this->registerTimer(m_timerResponseId, 1000L * timeout, 0, fname, std::bind(&HttpRequestOutputView::onTimerResponse, this));
		if (!isValidTimerId(m_timerResponseId))
		{
			unsubscribeRunCompletion();
			response();
			return;
		}
		if (m_responseStarted.load(std::memory_order_acquire))
			this->cancelTimer(m_timerResponseId);

		LOG_DBG << fname << "app <" << app->getName() << "> waiting for run <" << requestedRun << "> completion";
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
	LOG_DBG << fname << "Responding to output request <" << m_uuid << ">";
	// Keep the request alive while timer cancellation and unsubscription release owners.
	auto self = std::static_pointer_cast<HttpRequestOutputView>(shared_from_this());
	unsubscribeRunCompletion();
	try
	{
		if (!m_responseStarted.exchange(true, std::memory_order_acq_rel))
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
				LOG_DBG << fname << "Retrieved application output with size <" << output.size() << ">";
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
		LOG_WAR << fname << "Failed to respond to output request <" << m_uuid << ">: " << e.what();
		HttpRequest::reply(web::http::status_codes::ExpectationFailed);
	}
	return false;
}

void HttpRequestOutputView::unsubscribeRunCompletion()
{
	const auto subscription = m_completionSubscription.exchange(
		Application::INVALID_RUN_COMPLETION_SUBSCRIPTION, std::memory_order_acq_rel);
	if (auto app = m_app.lock())
		app->unsubscribeRunCompletion(subscription);
}

////////////////////////////////////////////////////////////////////////////////
// TaskRequest - manages task request/response flow between clients and server.
// Multiple clients can queue tasks concurrently; the server process fetches
// and replies to them one at a time in FIFO order.
////////////////////////////////////////////////////////////////////////////////

TaskRequest::SupersededRequests TaskRequest::activate(const std::string &processKey)
{
	std::lock_guard<std::mutex> guard(m_mutex);
	if (processKey == m_processKey)
		return {};
	m_processKey = processKey;
	return SupersededRequests{{std::move(m_fetchTask), std::move(m_replyTask)}};
}

void TaskRequest::terminate()
{
	std::queue<std::shared_ptr<HttpRequestWithTimeout>> pending;
	std::shared_ptr<HttpRequestWithTimeout> fetchTask;
	std::shared_ptr<HttpRequestWithTimeout> replyTask;
	std::shared_ptr<HttpRequestWithTimeout> activeTask;
	{
		std::lock_guard<std::mutex> guard(m_mutex);
		m_processKey.clear();
		fetchTask = std::move(m_fetchTask);
		replyTask = std::move(m_replyTask);
		activeTask = std::move(m_activeTask);
		pending.swap(m_taskQueue);
	}
	if (fetchTask)
		fetchTask->interrupt();
	if (replyTask)
		replyTask->interrupt();
	if (activeTask)
		activeTask->interrupt();
	while (!pending.empty())
	{
		pending.front()->interrupt();
		pending.pop();
	}
}

void TaskRequest::sendTask(std::shared_ptr<HttpRequestWithTimeout> &taskRequest)
{
	const static char fname[] = "TaskRequest::sendTask() ";
	std::shared_ptr<HttpRequestWithTimeout> fetchTask;
	std::shared_ptr<HttpRequestWithTimeout> previousReply;
	bool queueFull = false;
	{
		std::lock_guard<std::mutex> guard(m_mutex);
		if (m_processKey.empty())
			throw std::invalid_argument("No process running");
		taskRequest->id(++m_taskId);

		// If the server is already waiting for a task, claim it under the state lock.
		if (m_fetchTask)
		{
			m_activeTask = taskRequest;
			previousReply = std::move(m_replyTask);
			fetchTask = std::move(m_fetchTask);
		}
		else if (m_taskQueue.size() >= 512)
		{
			queueFull = true;
		}
		else
		{
			m_taskQueue.push(taskRequest);
			LOG_DBG << fname << "queued task (queue size: " << m_taskQueue.size() << ")";
		}
	}

	if (fetchTask)
	{
		LOG_DBG << fname << "deliver to waiting fetch: " << fetchTask->m_method << " " << fetchTask->m_relative_uri;
		fetchTask->reply(web::http::status_codes::OK, *taskRequest->m_body);
	}
	else if (queueFull)
	{
		LOG_WAR << fname << "task queue full (512), rejecting";
		taskRequest->reply(web::http::status_codes::ServiceUnavailable, Utility::text2json("task queue full, try again later"));
	}
}

bool TaskRequest::deleteTask()
{
	// Cancel only the in-flight (active) task — the one currently dispatched to
	// the server process. Queued tasks belong to other clients still blocking on
	// their own requests and each carry their own timeout, so they are left
	// intact: one client's cancel must not abort everyone else's pending work.
	// Full teardown of the queue happens in terminate() on app stop/remove.
	std::shared_ptr<HttpRequestWithTimeout> activeTask;
	{
		std::lock_guard<std::mutex> guard(m_mutex);
		activeTask = std::move(m_activeTask);
	}
	return activeTask && activeTask->interrupt();
}

void TaskRequest::fetchTask(const std::string &processKey, std::shared_ptr<void> &serverRequest)
{
	const static char fname[] = "TaskRequest::fetchTask() ";
	std::shared_ptr<HttpRequestWithTimeout> fetchTask;
	std::shared_ptr<HttpRequestWithTimeout> activeTask;
	std::shared_ptr<HttpRequestWithTimeout> previousFetch;
	std::shared_ptr<HttpRequestWithTimeout> previousReply;
	std::shared_ptr<HttpRequestWithTimeout> repliedActive;
	{
		std::lock_guard<std::mutex> guard(m_mutex);
		if (processKey.empty() || processKey != m_processKey)
			throw std::runtime_error("Process key mismatch");
		previousFetch = std::move(m_fetchTask);
		m_fetchTask = std::static_pointer_cast<HttpRequestWithTimeout>(serverRequest);
		previousReply = std::move(m_replyTask);

		// A restarted worker must receive the existing in-flight task before the
		// queued tail; only advance FIFO after that task has replied.
		repliedActive = releaseRepliedRequestLocked(m_activeTask);
		if (!m_activeTask && !m_taskQueue.empty())
		{
			m_activeTask = m_taskQueue.front();
			m_taskQueue.pop();
		}
		if (m_activeTask)
		{
			activeTask = m_activeTask;
			fetchTask = std::move(m_fetchTask);
		}
	}

	if (fetchTask)
	{
		LOG_DBG << fname << "deliver task: " << fetchTask->m_method << " " << fetchTask->m_relative_uri;
		fetchTask->reply(web::http::status_codes::OK, *activeTask->m_body);
	}
	// Otherwise m_fetchTask stays set — will be satisfied by the next sendTask.
}

void TaskRequest::replyTask(const std::string &processKey, std::shared_ptr<void> &serverRequest)
{
	const static char fname[] = "TaskRequest::replyTask() ";
	std::shared_ptr<HttpRequestWithTimeout> replyTask;
	std::shared_ptr<HttpRequestWithTimeout> activeTask;
	std::shared_ptr<HttpRequestWithTimeout> previousReply;
	std::shared_ptr<HttpRequestWithTimeout> repliedActive;
	{
		std::lock_guard<std::mutex> guard(m_mutex);
		if (processKey.empty() || processKey != m_processKey)
			throw std::runtime_error("Process key mismatch");
		previousReply = std::move(m_replyTask);
		m_replyTask = std::static_pointer_cast<HttpRequestWithTimeout>(serverRequest);
		repliedActive = releaseRepliedRequestLocked(m_activeTask);
		replyTask = std::move(m_replyTask);
		activeTask = std::move(m_activeTask);
	}

	if (!activeTask)
	{
		LOG_WAR << fname << "no client request waiting for response";
		replyTask->reply(web::http::status_codes::ExpectationFailed, Utility::text2json("no message request from client waiting for response"));
		return;
	}
	LOG_DBG << fname << "respond to client: " << activeTask->m_method << " " << activeTask->m_relative_uri;

	// Forward the server's reply to the original client request.
	activeTask->reply(web::http::status_codes::OK, *replyTask->m_body);

	// Acknowledge server's reply.
	replyTask->reply(web::http::status_codes::OK);
}

std::shared_ptr<HttpRequestWithTimeout> TaskRequest::releaseRepliedRequestLocked(
	std::shared_ptr<HttpRequestWithTimeout> &request)
{
	const static char fname[] = "TaskRequest::releaseRepliedRequestLocked() ";

	if (request && request->replied())
	{
		LOG_WAR << fname << "clean replied request: " << request->m_uuid << " " << request->m_method << " " << request->m_relative_uri;
		return std::move(request);
	}
	return {};
}

std::tuple<int, std::string> TaskRequest::taskStatus()
{
	std::shared_ptr<HttpRequestWithTimeout> repliedActive;
	std::tuple<int, std::string> result;
	{
		std::lock_guard<std::mutex> guard(m_mutex);
		repliedActive = releaseRepliedRequestLocked(m_activeTask);

		if (m_fetchTask)
			result = std::make_tuple(m_taskId, "idle");
		else if (m_activeTask || !m_taskQueue.empty())
			result = std::make_tuple(m_taskId, "busy");
		else
			result = std::make_tuple(m_taskId, "");
	}
	return result;
}
