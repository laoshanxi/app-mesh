#include <thread>
#include "ConsulConnection.h"
#include <cpprest/http_client.h>
#include "cpprest/json.h"
#include "Configuration.h"
#include "ResourceCollection.h"
#include "../common/Utility.h"

#define BASE_PATH  "/v1/kv/appmgr/"

ConsulConnection::ConsulConnection()
	:m_ssnRenewTimerId(0), m_reportStatusTimerId(0)
{
	// override default reactor
	m_reactor = new ACE_Reactor();
}

ConsulConnection::~ConsulConnection()
{
	// 1. clean old timer
	if (m_ssnRenewTimerId)
	{
		this->cancleTimer(m_ssnRenewTimerId);
		m_ssnRenewTimerId = 0;
	}

	if (m_reportStatusTimerId)
	{
		this->cancleTimer(m_reportStatusTimerId);
		m_reportStatusTimerId = 0;
	}
}

std::shared_ptr<ConsulConnection>& ConsulConnection::instance()
{
	static auto singleton = std::make_shared<ConsulConnection>();
	return singleton;
}

void ConsulConnection::reportStatus(int timerId)
{
	const static char fname[] = "ConsulConnection::reportStatus() ";

	if (Configuration::instance()->getConsul()->m_consulUrl.empty()) return;

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (!m_ssnRenewTimerId)
	{
		// wait for timer request session id
		initTimer();
		return;
	}

	if (m_sessionId.empty())
	{
		// wait for timer request session id
		return;
	}

	try
	{
		std::lock_guard<std::recursive_mutex> guard(m_mutex);

		std::string path = BASE_PATH;
		path.append("status/");
		path.append(ResourceCollection::instance()->getHostName()).append("/");
		path.append("resource");

		auto body = ResourceCollection::instance()->AsJson();

		auto resp = requestHttp(web::http::methods::PUT, path, {}, {}, &body);
		if (resp.status_code() == web::http::status_codes::OK)
		{
			auto result = resp.extract_utf8string(true).get();
			if (result == "true")
			{
				LOG_DBG << fname << "report success";
			}
			else
			{
				LOG_WAR << fname << "report failed with response :" << result;
			}
		}
	}
	catch (const std::exception & ex)
	{
		LOG_WAR << fname << " got exception: " << ex.what();
	}
	catch (...)
	{
		LOG_WAR << fname << " exception";
	}
}

web::http::http_response ConsulConnection::requestHttp(const web::http::method& mtd, const std::string& path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, web::json::value* body)
{
	const static char fname[] = "ConsulConnection::requestHttp() ";

	auto restURL = Configuration::instance()->getConsul()->m_consulUrl;

	LOG_INF << fname << "request :" << path << " to: " << restURL;

	// Create http_client to send the request.
	web::http::client::http_client_config config;
	config.set_timeout(std::chrono::seconds(5));
	config.set_validate_certificates(false);
	web::http::client::http_client client(restURL, config);

	// Build request URI and start the request.
	web::uri_builder builder(GET_STRING_T(path));
	std::for_each(query.begin(), query.end(), [&builder](const std::pair<std::string, std::string>& pair)
		{
			builder.append_query(GET_STRING_T(pair.first), GET_STRING_T(pair.second));
		});

	web::http::http_request request(mtd);
	for (auto h : header)
	{
		request.headers().add(h.first, h.second);
	}
	request.set_request_uri(builder.to_uri());
	if (body != nullptr)
	{
		request.set_body(*body);
	}
	web::http::http_response response = client.request(request).get();
	return std::move(response);
}

std::string ConsulConnection::requestSessionId()
{
	const static char fname[] = "ConsulConnection::requestSessionId() ";

	// https://www.consul.io/api/session.html

	auto node = Configuration::instance()->getConsul()->m_sessionNode;
	if (node.empty()) node = ResourceCollection::instance()->getHostName();

	auto payload = web::json::value::object();
	payload["LockDelay"] = web::json::value::string("15s");
	payload["Name"] = web::json::value::string(std::string("appmgr-lock-") + ResourceCollection::instance()->getHostName());
	payload["Node"] = web::json::value::string(node);
	payload["Behavior"] = web::json::value::string("delete");
	payload["TTL"] = web::json::value::string(std::to_string(Configuration::instance()->getConsul()->m_ttl) + "s");

	auto resp = requestHttp(web::http::methods::PUT, "/v1/session/create", {}, {}, &payload);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto json = resp.extract_json(true).get();
		LOG_DBG << fname << json.serialize();
		if (HAS_JSON_FIELD(json, "ID"))
		{
			auto sessionId = GET_JSON_STR_VALUE(json, "ID");
			LOG_DBG << fname << "sessionId=" << sessionId;
			return sessionId;
		}
	}
	return std::string();
}

std::string ConsulConnection::renewSessionId()
{
	const static char fname[] = "ConsulConnection::renewSessionId() ";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (m_sessionId.length())
	{
		auto resp = requestHttp(web::http::methods::PUT, std::string("/v1/session/renew/").append(m_sessionId), {}, {}, nullptr);
		if (resp.status_code() == web::http::status_codes::OK)
		{
			auto json = resp.extract_json(true).get();
			LOG_DBG << fname << json.serialize();
			if (json.is_array() && json.as_array().size())
			{
				json = json.as_array().at(0);
				auto sessionId = GET_JSON_STR_VALUE(json, "ID");
				LOG_DBG << fname << "sessionId=" << sessionId;
				return sessionId;
			}
		}
	}
	return std::string();
}

std::string ConsulConnection::getSessionId(const web::json::value& json)
{
	const static char fname[] = "ConsulConnection::getSessionId() ";

	LOG_DBG << fname << json.serialize();

	web::json::value jvalue = json;

	if (json.is_array() && json.as_array().size()) jvalue = json.as_array().at(0);

	if (HAS_JSON_FIELD(json, "ID"))
	{
		auto sessionId = GET_JSON_STR_VALUE(json, "ID");
		LOG_DBG << fname << "sessionId=" << sessionId;
		return sessionId;
	}
	return std::string();
}

void ConsulConnection::refreshSession(int timerId)
{
	const static char fname[] = "ConsulConnection::refreshSession() ";
	try
	{
		if (Configuration::instance()->getConsul()->m_consulUrl.empty()) return;

		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		if (m_sessionId.empty())
		{
			m_sessionId = requestSessionId();
		}
		else
		{
			m_sessionId = renewSessionId();
		}
	}
	catch (const std::exception & ex)
	{
		LOG_WAR << fname << " got exception: " << ex.what();
	}
	catch (...)
	{
		LOG_WAR << fname << " exception";
	}
}

void ConsulConnection::initTimer()
{
	if (Configuration::instance()->getConsul()->m_consulUrl.empty()) return;

	// start a single thread for consul timer
	static std::thread timerThread(&TimerHandler::runReactorEvent, std::ref(m_reactor));

	// session renew timer
	if (m_ssnRenewTimerId)
	{
		this->cancleTimer(m_ssnRenewTimerId);
	}
	m_ssnRenewTimerId = this->registerTimer(
		2,
		Configuration::instance()->getConsul()->m_ttl - 3,
		std::bind(&ConsulConnection::refreshSession, this, std::placeholders::_1),
		__FUNCTION__
	);

	// report status timer
	if (m_reportStatusTimerId)
	{
		this->cancleTimer(m_reportStatusTimerId);
	}
	m_reportStatusTimerId = this->registerTimer(
		1,
		Configuration::instance()->getConsul()->m_reportInterval,
		std::bind(&ConsulConnection::reportStatus, this, std::placeholders::_1),
		__FUNCTION__
	);
}
