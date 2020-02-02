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
	:m_ssnRenewTimerId(0), m_reportStatusTimerId(0), m_applyTopoTimerId(0)
{
	// override default reactor
	m_reactor = m_subTimerReactor;
}

ConsulConnection::~ConsulConnection()
{
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
	if (m_applyTopoTimerId)
	{
		this->cancleTimer(m_applyTopoTimerId);
		m_applyTopoTimerId = 0;
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

	// check feature enabled
	if (!Configuration::instance()->getConsul()->enabled()) return;

	// check session id ready
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (m_sessionId.empty()) return;

	try
	{
		//report resource: /appmgr/status/myhost/resource
		std::string path = std::string(CONSUL_BASE_PATH).append("status/").append(ResourceCollection::instance()->getHostName()).append("/resource");
		auto body = ResourceCollection::instance()->AsJson();
		auto resp = requestHttp(web::http::methods::PUT, path, { {"acquire", m_sessionId} }, {}, &body);
		if (resp.status_code() == web::http::status_codes::OK)
		{
			auto result = resp.extract_utf8string(true).get();
			if (result == "true")
			{
				LOG_DBG << fname << "report " << path << " success";
			}
			else
			{
				LOG_WAR << fname << "report " << path << " failed with response : " << result;
				return;
			}
		}

		//report resource: /appmgr/status/myhost/applications
		path = std::string(CONSUL_BASE_PATH).append("status/").append(ResourceCollection::instance()->getHostName()).append("/applications");
		auto consul = std::make_shared<ConsulConnection::ConsulStatus>();
		auto apps = Configuration::instance()->getApps();
		for (auto app : apps)
		{
			consul->m_apps[app->getName()] = app->AsJson(true);
		}
		body = consul->AsJson();
		resp = requestHttp(web::http::methods::PUT, path, { {"acquire", m_sessionId} }, {}, &body);
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
				return;
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
		// check feature enabled
		if (!Configuration::instance()->getConsul()->enabled()) return;

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

void ConsulConnection::applyTopology(int timerId)
{
	const static char fname[] = "ConsulConnection::applyTopology() ";
	try
	{
		// check feature enabled
		if (!Configuration::instance()->getConsul()->enabled()) return;
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		// check session id
		if (m_sessionId.empty()) return;

		auto task = retrieveTask();
		auto topology = retrieveTopology(ResourceCollection::instance()->getHostName());
		if (topology.count(ResourceCollection::instance()->getHostName()))
		{
			auto currentAllApps = Configuration::instance()->getApps();
			for (auto topologyAppStr : topology[ResourceCollection::instance()->getHostName()])
			{
				if (task.count(topologyAppStr))
				{
					std::shared_ptr<Application> topologyAppObj;
					topologyAppObj = task[topologyAppStr]->m_app;
					auto it = std::find_if(currentAllApps.begin(), currentAllApps.end(), [&topologyAppStr](std::shared_ptr<Application> const& obj) {
						return obj->getName() == topologyAppStr;
						});
					if (it != currentAllApps.end())
					{
						// Update app
						auto currentRunningApp = *it;
						if (currentRunningApp->getVersion() > topologyAppObj->getVersion())
						{
							Configuration::instance()->registerApp(topologyAppObj);
							LOG_INF << fname << " Consul application <" << topologyAppObj->getName() << "> updated";
						}
					}
					else
					{
						// New add app
						Configuration::instance()->registerApp(topologyAppObj);
						LOG_INF << fname << " Consul application <" << topologyAppObj->getName() << "> added";
					}
				}
			}
			for (auto currentApp : currentAllApps)
			{
				if (currentApp->getComments() == APP_COMMENTS_FROM_CONSUL)
				{
					if (topology.count(ResourceCollection::instance()->getHostName()) && topology[ResourceCollection::instance()->getHostName()].count(currentApp->getName()) == 0)
					{
						// Remove no used topology
						Configuration::instance()->removeApp(currentApp->getName());
					}
				}
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

/*
[
	{
		"CreateIndex": 22935,
		"Flags": 0,
		"Key": "appmgr/topology/",
		"LockIndex": 0,
		"ModifyIndex": 22935,
		"Value": null
	},
	{
		"CreateIndex": 22942,
		"Flags": 0,
		"Key": "appmgr/topology/cents",
		"LockIndex": 0,
		"ModifyIndex": 22942,
		"Value": "WyJteWFwcCJd"
	}
]*/
std::map<std::string, std::set<std::string>> ConsulConnection::retrieveTopology(std::string host)
{
	const static char fname[] = "ConsulConnection::retrieveTopology() ";

	// /appmgr/topology/myhost
	std::map<std::string, std::set<std::string>> topology;
	auto path = std::string(CONSUL_BASE_PATH).append("topology");
	if (host.length()) path.append("/").append(host);
	auto resp = requestHttp(web::http::methods::GET, path, { {"recurse","true"} }, {}, nullptr);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto json = resp.extract_json(true).get();
		if (json.is_array())
		{
			for (auto app : json.as_array())
			{
				if (HAS_JSON_FIELD(app, "Value"))
				{
					auto hostText = Utility::decode64(GET_JSON_STR_VALUE(app, "Value"));
					auto consulKey = GET_JSON_STR_VALUE(app, "Key");
					auto vec = Utility::splitString(consulKey, "/");
					auto hostName = vec[vec.size() - 1];
					auto appJson = web::json::value::parse(hostText).as_array();
					std::set<std::string> apps;
					for (auto app : appJson)
					{
						apps.insert(GET_STD_STRING(app.as_string()));
					}
					topology[hostName] = apps;
				}
			}
		}
	}
	else
	{
		LOG_DBG << fname << "failed with response : " << resp.extract_utf8string(true).get();
	}
	return topology;
}

/*
[
	{
		"CreateIndex": 22168,
		"Flags": 0,
		"Key": "appmgr/task/",
		"LockIndex": 0,
		"ModifyIndex": 22168,
		"Value": null
	},
	{
		"CreateIndex": 22241,
		"Flags": 0,
		"Key": "appmgr/task/myapp",
		"LockIndex": 0,
		"ModifyIndex": 22241,
		"Value": "ewoJCQkJInJlcGxpY2F0aW9uIjogMiwKCQkJCSJjb250ZW50IjogewoJCQkJCSJuYW1lIjogIm15YXBwIiwKCQkJCQkiY29tbWFuZCI6ICJzbGVlcCAzMCIKCQkJCX0KfQ=="
	}
]
*/
std::map<std::string, std::shared_ptr<ConsulConnection::ConsulTask>> ConsulConnection::retrieveTask()
{
	std::map<std::string, std::shared_ptr<ConsulConnection::ConsulTask>> result;
	// /appmgr/task/myapp
	std::string path = std::string(CONSUL_BASE_PATH).append("task");
	auto resp = requestHttp(web::http::methods::GET, path, { {"recurse","true"} }, {}, nullptr);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto json = resp.extract_json(true).get();
		if (json.is_array())
		{
			for (auto app : json.as_array())
			{
				if (HAS_JSON_FIELD(app, "Value"))
				{
					auto appText = Utility::decode64(GET_JSON_STR_VALUE(app, "Value"));
					auto appJson = web::json::value::parse(appText);
					// set flag to mark consul application
					appJson[JSON_KEY_APP_comments] = web::json::value::string(APP_COMMENTS_FROM_CONSUL);
					auto task = ConsulTask::FromJson(appJson);
					if (task->m_app->getName().length()) result[task->m_app->getName()] = task;
				}
			}
		}
	}
	return std::move(result);
}

void ConsulConnection::initTimer()
{
	if (!Configuration::instance()->getConsul()->enabled()) return;

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

	// aply topology timer
	if (m_applyTopoTimerId)
	{
		this->cancleTimer(m_applyTopoTimerId);
	}
	m_applyTopoTimerId = this->registerTimer(
		1,
		Configuration::instance()->getConsul()->m_topologyInterval,
		std::bind(&ConsulConnection::applyTopology, this, std::placeholders::_1),
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
	for (auto app : json.as_object())
	{
		consul->m_apps[GET_STD_STRING(app.first)] = app.second;
	}
	return consul;
}

web::json::value ConsulConnection::ConsulStatus::AsJson()
{
	auto result = web::json::value::object();
	for (auto app : m_apps)
	{
		result[app.first] = app.second;
	}
	return result;
}

std::shared_ptr<ConsulConnection::ConsulTask> ConsulConnection::ConsulTask::FromJson(const web::json::value& jobj)
{
	auto consul = std::make_shared<ConsulConnection::ConsulTask>();
	if (HAS_JSON_FIELD(jobj, "content") && HAS_JSON_FIELD(jobj, "replication") &&
		jobj.at("replication").is_integer() &&
		jobj.at("content").is_object())
	{
		consul->m_app = Configuration::instance()->parseApp(jobj.at("content"));
		consul->m_replication = jobj.at("replication").as_integer();
	}
	return consul;
}

web::json::value ConsulConnection::ConsulTask::AsJson()
{
	auto result = web::json::value::object();
	result["replication"] = web::json::value::number(m_replication);
	result["content"] = m_app->AsJson(false);
	return result;
}


/*
{
	"appmgr": {
		"status": {
			"myhost": {
				"resource": {},
				"applications": {
					"app1": {
						"name": "myapp",
						"health": 0
					}
				}
			}
		},
		"task": {
			"myapp": {
				"replication": 2,
				"content": {
					"name": "myapp",
					"command": "sleep 30"
				}
			}
		},
		"worker": {
			"myapp": ["myhost", "host2"]
		},
		"topology": {
			"myhost": ["myapp", "app2"]
		}
	}
}
*/