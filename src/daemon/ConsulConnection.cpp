#include <cpprest/http_client.h>
#include "cpprest/json.h"
#include <thread>

#include "Application.h"
#include "ConsulConnection.h"
#include "Configuration.h"
#include "ResourceCollection.h"
#include "../common/Utility.h"

#define CONSUL_BASE_PATH  "/v1/kv/appmgr/"
extern ACE_Reactor* m_subTimerReactor;

ConsulConnection::ConsulConnection()
	:m_ssnRenewTimerId(0), m_reportStatusTimerId(0)
{
	// override default reactor
	m_reactor = m_subTimerReactor;
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
	// wait for session id
	if (m_sessionId.empty()) return;

	try
	{
		// Consul path: /appmgr/status/myhost
		std::string path = CONSUL_BASE_PATH;
		path.append("status/");
		path.append(ResourceCollection::instance()->getHostName());

		auto consul = std::make_shared<ConsulConnection::ConsulStatus>();
		consul->m_resource = ResourceCollection::instance()->AsJson();
		auto apps = Configuration::instance()->getApps();
		for (auto app : apps)
		{
			consul->m_apps[app->getName()] = app->AsJson(true);
		}
		auto body = consul->AsJson();

		auto resp = requestHttp(web::http::methods::PUT, path, { {"acquire", m_sessionId} }, {}, &body);
		if (resp.status_code() == web::http::status_codes::OK)
		{
			auto result = resp.extract_utf8string(true).get();
			if (result == "true")
			{
				LOG_DBG << fname << "report success";
			}
			else
			{
				LOG_WAR << fname << "report failed with response : " << result;
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

std::map<std::string, web::json::value> ConsulConnection::retrieveTopology()
{
	const static char fname[] = "ConsulConnection::retrieveTopology() ";
	std::map<std::string, web::json::value> result;

	if (Configuration::instance()->getConsul()->m_consulUrl.empty()) return result;
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	// wait for session id
	if (m_sessionId.empty()) return result;

	// get task
	std::shared_ptr<ConsulTask> tasks;
	std::string path = std::string(CONSUL_BASE_PATH).append("task");
	auto resp = requestHttp(web::http::methods::GET, path, {}, {}, nullptr);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		tasks = ConsulTask::FromJson(resp.extract_json(true).get());
	}
	else
	{
		return result;
	}

	path = std::string(CONSUL_BASE_PATH).append("topology");
	resp = requestHttp(web::http::methods::GET, path, { {"recurse","true"} }, {}, nullptr);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto topology = ConsulTopology::FromJson(resp.extract_json(true).get());
		if (topology->m_apps.count(ResourceCollection::instance()->getHostName()))
		{
			for (auto app : topology->m_apps[ResourceCollection::instance()->getHostName()])
			{
				if (tasks->m_apps.count(app))
				{
					result[app] = tasks->m_apps[app];
				}
			}
		}
	}
	for (auto app : result)
	{
		std::shared_ptr<Application> newApp, runningApp;
		try
		{
			// set consul flag for app
			app.second[JSON_KEY_APP_comments] = web::json::value::string(APP_COMMENTS_FROM_CONSUL);

			newApp = Configuration::instance()->parseApp(app.second);
			runningApp = Configuration::instance()->getApp(app.first);

			if (runningApp->getVersion() > newApp->getVersion())
			{
				Configuration::instance()->registerApp(newApp);
			}
		}
		catch (...)
		{
			if (newApp && !runningApp)
			{
				Configuration::instance()->registerApp(newApp);
			}
		}
	}
	return std::move(result);
}

void ConsulConnection::initTimer()
{
	if (Configuration::instance()->getConsul()->m_consulUrl.empty()) return;

	// session renew timer
	if (m_ssnRenewTimerId)
	{
		this->cancleTimer(m_ssnRenewTimerId);
	}
	m_ssnRenewTimerId = this->registerTimer(
		0,
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
		2,
		Configuration::instance()->getConsul()->m_reportInterval,
		std::bind(&ConsulConnection::reportStatus, this, std::placeholders::_1),
		__FUNCTION__
	);
}

web::http::http_response ConsulConnection::requestHttp(const web::http::method& mtd, const std::string& path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, web::json::value* body)
{
	const static char fname[] = "ConsulConnection::requestHttp() ";

	auto restURL = Configuration::instance()->getConsul()->m_consulUrl;

	LOG_DBG << fname << "request :" << path << " to: " << restURL;

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

std::shared_ptr<ConsulConnection::ConsulStatus> ConsulConnection::ConsulStatus::FromJson(const web::json::value& json)
{
	auto consul = std::make_shared<ConsulConnection::ConsulStatus>();
	if (HAS_JSON_FIELD(json, "resource"))
	{
		consul->m_resource = json.at("resource");
	}
	if (HAS_JSON_FIELD(json, "applications"))
	{
		auto apps = json.at("applications").as_object();
		for (auto app : apps)
		{
			consul->m_apps[GET_STD_STRING(app.first)] = app.second;
		}
	}
	return consul;
}

web::json::value ConsulConnection::ConsulStatus::AsJson()
{
	auto result = web::json::value::object();
	result["resource"] = m_resource;
	auto apps = web::json::value::object();
	for (auto app : m_apps)
	{
		apps[app.first] = app.second;
	}
	result["applications"] = apps;
	return result;
}

std::shared_ptr<ConsulConnection::ConsulTask> ConsulConnection::ConsulTask::FromJson(const web::json::value& jobj)
{
	auto consul = std::make_shared<ConsulConnection::ConsulTask>();
	for (auto app : jobj.as_object())
	{
		if (HAS_JSON_FIELD(app.second, "content") && HAS_JSON_FIELD(app.second, "replication") &&
			app.second.at("replication").is_integer() &&
			app.second.at("content").is_object())
		{
			consul->m_apps[app.first] = app.second.at("content");
			consul->m_replications[app.first] = app.second.at("replication").as_integer();
		}
	}
	return consul;
}

web::json::value ConsulConnection::ConsulTask::AsJson()
{
	auto result = web::json::value::object();
	for (auto app : m_apps)
	{
		auto jsonApp = web::json::value::object();
		jsonApp["replication"] = m_replications[app.first];
		jsonApp["content"] = app.second;
		result[app.first] = jsonApp;
	}
	return result;
}

std::shared_ptr<ConsulConnection::ConsulTopology> ConsulConnection::ConsulTopology::FromJson(const web::json::value& jobj)
{
	auto consul = std::make_shared<ConsulConnection::ConsulTopology>();
	for (auto host : jobj.as_object())
	{
		std::set<std::string> apps;
		for (auto app : host.second.as_array())
		{
			apps.insert(app.as_string());
		}
		consul->m_apps[GET_STD_STRING(host.first)] = apps;
	}
	return consul;
}

web::json::value ConsulConnection::ConsulTopology::AsJson()
{
	auto result = web::json::value::object();
	for (auto host : m_apps)
	{
		auto& apps = host.second;
		auto jsonApps = web::json::value::array(apps.size());
		int index = 0;
		for (auto app : apps)
		{
			jsonApps[index++] = web::json::value::string(app);
		}
		result[host.first] = jsonApps;
	}
	return result;
}
