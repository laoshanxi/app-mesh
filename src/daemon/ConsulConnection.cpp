#include <algorithm>
#include <thread>
#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include "Application.h"
#include "ConsulConnection.h"
#include "Configuration.h"
#include "ResourceCollection.h"
#include "../common/Utility.h"

#define CONSUL_BASE_PATH  "/v1/kv/appmgr/"
extern ACE_Reactor* m_timerReactor;

ConsulConnection::ConsulConnection()
	:m_ssnRenewTimerId(0), m_reportStatusTimerId(0), m_applyTopoTimerId(0)
{
	// override default reactor
	m_reactor = m_timerReactor;
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

	// Only node need report status
	if (!Configuration::instance()->getConsul()->m_isNode)
	{
		return;
	}

	// check session id ready
	auto sessionId = getSessionId();
	if (sessionId.empty()) return;

	try
	{
		//report resource: /appmgr/status/myhost/resource
		std::string path = std::string(CONSUL_BASE_PATH).append("status/").append(MY_HOST_NAME).append("/resource");
		auto body = ResourceCollection::instance()->AsJson();
		auto resp = requestHttp(web::http::methods::PUT, path, { {"acquire", sessionId} }, {}, &body);
		if (resp.status_code() == web::http::status_codes::OK)
		{
			auto result = resp.extract_utf8string(true).get();
			if (result != "true")
			{
				LOG_WAR << fname << "report resource to " << path << " failed with response : " << result;
				return;
			}
		}
		else
		{
			LOG_WAR << fname << "report resource to " << path << " failed with response : " << resp.extract_utf8string(true).get();
			return;
		}

		//report resource: /appmgr/status/myhost/label
		path = std::string(CONSUL_BASE_PATH).append("status/").append(MY_HOST_NAME).append("/label");
		body = Configuration::instance()->getLabel()->AsJson();
		resp = requestHttp(web::http::methods::PUT, path, { {"acquire", sessionId} }, {}, &body);
		if (resp.status_code() == web::http::status_codes::OK)
		{
			auto result = resp.extract_utf8string(true).get();
			if (result != "true")
			{
				LOG_WAR << fname << "report label to " << path << " failed with response : " << result;
				return;
			}
		}
		else
		{
			LOG_WAR << fname << "report label to " << path << " failed with response : " << resp.extract_utf8string(true).get();
			return;
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

		// check Consul configuration
		if (!Configuration::instance()->getConsul()->m_isMaster &&
			!Configuration::instance()->getConsul()->m_isNode)
		{
			return;
		}

		// get session id
		std::string sessionId = getSessionId();
		if (sessionId.empty())
		{
			sessionId = requestSessionId();
		}
		else
		{
			sessionId = renewSessionId();
		}
		// set session id
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		m_sessionId = sessionId;
		return;
	}
	catch (const std::exception & ex)
	{
		LOG_WAR << fname << " got exception: " << ex.what();
	}
	catch (...)
	{
		LOG_WAR << fname << " exception";
	}
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	m_sessionId.clear();
}

void ConsulConnection::applyTopology(int timerId)
{
	const static char fname[] = "ConsulConnection::applyTopology() ";
	try
	{
		// check feature enabled
		if (!Configuration::instance()->getConsul()->enabled()) return;
		if (getSessionId().empty()) return;

		if (Configuration::instance()->getConsul()->m_isMaster)
		{
			// Leader's job
			leaderSchedule();
		}

		if (Configuration::instance()->getConsul()->m_isNode)
		{
			// Node's job
			nodeSchedule();
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
	std::string sessionId;
	auto node = Configuration::instance()->getConsul()->m_sessionNode;
	if (node.empty()) node = MY_HOST_NAME;

	auto payload = web::json::value::object();
	payload["LockDelay"] = web::json::value::string("15s");
	payload["Name"] = web::json::value::string(std::string("appmgr-lock-") + MY_HOST_NAME);
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
			sessionId = GET_JSON_STR_VALUE(json, "ID");
			LOG_DBG << fname << "sessionId=" << sessionId;
		}
	}
	else
	{
		LOG_WAR << fname << "failed with response : " << resp.extract_utf8string(true).get();
	}
	return sessionId;
}

std::string ConsulConnection::renewSessionId()
{
	const static char fname[] = "ConsulConnection::renewSessionId() ";

	auto sessionId = getSessionId();
	if (sessionId.length())
	{
		auto resp = requestHttp(web::http::methods::PUT, std::string("/v1/session/renew/").append(sessionId), {}, {}, nullptr);
		if (resp.status_code() == web::http::status_codes::OK)
		{
			auto json = resp.extract_json(true).get();
			LOG_DBG << fname << json.serialize();
			if (json.is_array() && json.as_array().size())
			{
				json = json.as_array().at(0);
				sessionId = GET_JSON_STR_VALUE(json, "ID");
				//LOG_DBG << fname << "sessionId=" << sessionId;
			}
		}
		else
		{
			LOG_WAR << fname << "failed with response : " << resp.extract_utf8string(true).get();
			sessionId = requestSessionId();
		}
	}
	return sessionId;
}

std::string ConsulConnection::getSessionId()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_sessionId;
}

void ConsulConnection::leaderSchedule()
{
	const static char fname[] = "ConsulConnection::leaderSchedule() ";

	// leader's responsibility
	if (eletionLeader())
	{
		// prepair
		auto tasksMap = retrieveTask();
		auto nodesMap = retrieveNode();
		auto oldTopology = retrieveTopology("");

		if (nodesMap.empty())
		{
			LOG_DBG << fname << "retrieveNode is empty";
			return;
		}

		// find matched hosts for each task
		findTaskAvialableHost(tasksMap, nodesMap);

		// schedule task
		auto newTopology = scheduleTask(tasksMap, oldTopology);

		// apply schedule result
		compareTopologyAndDispatch(oldTopology, newTopology);
	}
}

void ConsulConnection::nodeSchedule()
{
	const static char fname[] = "ConsulConnection::nodeSchedule() ";

	auto currentAllApps = Configuration::instance()->getApps();
	auto task = retrieveTask();
	auto topology = retrieveTopology(MY_HOST_NAME);
	if (topology.count(MY_HOST_NAME))
	{
		for (auto topologyAppStr : topology[MY_HOST_NAME])
		{
			if (task.count(topologyAppStr))
			{
				std::shared_ptr<Application> topologyAppObj = task[topologyAppStr]->m_app;
				auto it = std::find_if(currentAllApps.begin(), currentAllApps.end(), [&topologyAppStr](std::shared_ptr<Application> const& obj) {
					return obj->getName() == topologyAppStr;
					});
				if (it != currentAllApps.end())
				{
					// Update app
					auto currentRunningApp = *it;
					if (!currentRunningApp->operator==(topologyAppObj))
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
				if (topology.count(MY_HOST_NAME))
				{
					if (!(topology[MY_HOST_NAME].count(currentApp->getName())))
					{
						// Remove no used topology
						Configuration::instance()->removeApp(currentApp->getName());
						LOG_INF << fname << " Consul application <" << currentApp->getName() << "> removed";
					}
				}
			}
		}
	}
	else
	{
		// TODO: if topology missed for some times treat as remove
		for (auto currentApp : currentAllApps)
		{
			if (currentApp->getComments() == APP_COMMENTS_FROM_CONSUL)
			{
				// Remove no used topology
				Configuration::instance()->removeApp(currentApp->getName());
				LOG_INF << fname << " Consul application <" << currentApp->getName() << "> removed";
			}
		}
	}
}

bool ConsulConnection::eletionLeader()
{
	// get session id
	std::string sessionId = getSessionId();
	if (sessionId.empty()) return false;

	// write hostname to leader path : /appmgr/leader
	std::string path = std::string(CONSUL_BASE_PATH).append("leader");
	auto body = web::json::value::string(MY_HOST_NAME);
	auto resp = requestHttp(web::http::methods::PUT, path, { {"acquire", sessionId} }, {}, &body);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto result = resp.extract_utf8string(true).get();
		return (result == "true");
	}
	return false;
}

void ConsulConnection::findTaskAvialableHost(std::map<std::string, std::shared_ptr<ConsulTask>>& taskMap, const std::map<std::string, std::shared_ptr<Label>>& hosts)
{
	const static char fname[] = "ConsulConnection::findTaskAvialableHost() ";

	for (auto task : taskMap)
	{
		auto taskName = task.first;
		task.second->m_matchedHosts.clear();
		for (auto host : hosts)
		{
			auto& hostName = host.first;
			auto& hostLable = host.second;
			auto& taskCondition = task.second->m_condition;
			if (hostLable->match(taskCondition))
			{
				task.second->m_matchedHosts.insert(hostName);
				LOG_DBG << fname << " task <" << taskName << "> match host <" << hostName << ">";
			}
		}
	}
}

std::map<std::string, std::set<std::string>> ConsulConnection::scheduleTask(std::map<std::string, std::shared_ptr<ConsulTask>>& taskMap, const std::map<std::string, std::set<std::string>>& oldTopology)
{
	const static char fname[] = "ConsulConnection::scheduleTask() ";

	std::map<std::string, std::set<std::string>> newTopology;

	struct HostQuata {
		HostQuata(const std::string& n) :quota(0), hostname(n) {};
		int quota;
		std::string hostname;
	};
	std::map<std::string, std::shared_ptr<HostQuata>> hostQuatoMap;

	// fill hostQuatoMap
	for (auto task : taskMap)
	{
		for (auto host : task.second->m_matchedHosts)
		{
			if (!hostQuatoMap.count(host))
			{
				hostQuatoMap[host] = std::make_shared<HostQuata>(host);
			}
		}
	}

	// ignore old schedule
	for (auto task : taskMap)
	{
		auto& taskName = task.first;
		auto& taskDedicateHosts = task.second->m_matchedHosts;
		auto& scheduleHosts = task.second->m_scheduleHosts;
		auto& taskReplication = task.second->m_replication;
		if (taskReplication <= 0) continue;

		scheduleHosts.clear();
		for (auto oldHost : oldTopology)
		{
			auto& oldHostName = oldHost.first;
			auto& oldTaskSet = oldHost.second;
			if (taskDedicateHosts.count(oldHostName) && oldTaskSet.count(taskName))
			{
				// find
				taskDedicateHosts.erase(oldHostName);
				--taskReplication;
				scheduleHosts.insert(oldHostName);

				LOG_DBG << fname << " task <" << taskName << "> already running on host <" << oldHostName << ">";

				// save to topology
				newTopology[oldHostName].insert(taskName);

				// update quato
				std::shared_ptr<HostQuata> hostQ;
				if (hostQuatoMap.count(oldHostName)) hostQuatoMap[oldHostName]->quota++;
			}
		}
	}

	// do schedule
	for (auto task : taskMap)
	{
		// get current task
		auto& taskDedicateHosts = task.second->m_matchedHosts;
		auto& scheduleHosts = task.second->m_scheduleHosts;
		auto& taskReplication = task.second->m_replication;
		auto& taskName = task.first;
		std::vector<std::shared_ptr<HostQuata>> hostQuota4NewTask;

		LOG_DBG << fname << "schedule task <" << taskName << ">";

		if (taskReplication <= 0)
			continue;

		for (auto host : taskDedicateHosts)
		{
			hostQuota4NewTask.push_back(hostQuatoMap[host]);
		}
		// sort hosts
		std::sort(hostQuota4NewTask.begin(), hostQuota4NewTask.end(),
			[](const std::shared_ptr<HostQuata> a, const std::shared_ptr<HostQuata> b)
			{ return a->quota < b->quota; });

		// assign host to task
		for (size_t i = 0; i < taskReplication; i++)
		{
			if (i < hostQuota4NewTask.size())
			{
				auto& selectedHost = hostQuota4NewTask[i];
				selectedHost->quota += 1;
				newTopology[selectedHost->hostname].insert(taskName);
				scheduleHosts.insert(selectedHost->hostname);

				LOG_DBG << fname << " task <" << taskName << "> assigned to host < " << selectedHost->hostname << ">";
			}
		}
	}

	return std::move(newTopology);
}

void ConsulConnection::compareTopologyAndDispatch(std::map<std::string, std::set<std::string>>& oldT, std::map<std::string, std::set<std::string>>& newT)
{
	for (auto newHost : newT)
	{
		if (oldT.count(newHost.first))
		{
			auto equal = true;
			if (newHost.second.size() == oldT[newHost.first].size())
			{
				for (auto app : newHost.second)
				{
					if (!oldT[newHost.first].count(app))
					{
						equal = false;
						break;
					}
				}
				// equal, do nothing here
			}
			else
			{
				equal = false;
			}
			if (!equal)
			{
				// update
				writeTopology(newHost.first, newHost.second);
			}
		}
		else
		{
			// add
			writeTopology(newHost.first, newHost.second);
		}
	}

	for (auto oldHost : oldT)
	{
		if (!newT.count(oldHost.first))
		{
			// delete
			writeTopology(oldHost.first, {});
		}
	}
}

bool ConsulConnection::writeTopology(const std::string& host, const std::set<std::string>& apps)
{
	const static char fname[] = "ConsulConnection::writeTopology() ";

	//topology: /appmgr/topology/myhost
	std::string path = std::string(CONSUL_BASE_PATH).append("topology/host/").append(host);
	web::http::http_response resp;
	if (apps.size())
	{
		auto body = web::json::value::array(apps.size());
		int index = 0;
		for (auto app : apps)
		{
			body[index++] = web::json::value::string(app);
		}
		resp = requestHttp(web::http::methods::PUT, path, {}, {}, &body);
		LOG_INF << fname << "write <" << body.serialize() << "> to <" << host << ">";
	}
	else
	{
		resp = requestHttp(web::http::methods::DEL, path, {}, {}, nullptr);
		LOG_INF << fname << "delete topology for <" << host << ">";
	}
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto result = resp.extract_utf8string(true).get();
		if (result == "true")
		{
			return true;
		}
		else
		{
			LOG_WAR << fname << " PUT " << path << " failed with response : " << result;
		}
	}
	return false;
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
	auto path = std::string(CONSUL_BASE_PATH).append("topology/host");
	if (host.length()) path.append("/").append(host);
	auto resp = requestHttp(web::http::methods::GET, path, { {"recurse","true"} }, {}, nullptr);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto json = resp.extract_json(true).get();
		if (json.is_array())
		{
			for (auto section : json.as_array())
			{
				if (HAS_JSON_FIELD(section, "Value"))
				{
					auto hostText = Utility::decode64(GET_JSON_STR_VALUE(section, "Value"));
					if (hostText.empty()) continue;
					auto consulKey = GET_JSON_STR_VALUE(section, "Key");
					auto vec = Utility::splitString(consulKey, "/");
					auto hostName = vec[vec.size() - 1];
					auto appArrayJson = web::json::value::parse(hostText);
					if (appArrayJson.is_array())
					{
						std::set<std::string> apps;
						for (auto app : appArrayJson.as_array())
						{
							apps.insert(GET_STD_STRING(app.as_string()));
						}
						topology[hostName] = apps;
						LOG_DBG << fname << "get <" << apps.size() << "> task for <" << hostName << ">";
					}
				}
			}
		}
	}
	else
	{
		throw std::invalid_argument(std::string("failed get topology : ") + host);
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
	const static char fname[] = "ConsulConnection::retrieveTask() ";

	std::map<std::string, std::shared_ptr<ConsulConnection::ConsulTask>> result;
	// /appmgr/task/myapp
	std::string path = std::string(CONSUL_BASE_PATH).append("task");
	auto resp = requestHttp(web::http::methods::GET, path, { {"recurse","true"} }, {}, nullptr);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto json = resp.extract_json(true).get();
		if (json.is_array())
		{
			for (auto section : json.as_array())
			{
				if (HAS_JSON_FIELD(section, "Value"))
				{
					auto appText = Utility::decode64(GET_JSON_STR_VALUE(section, "Value"));
					auto appJson = web::json::value::parse(appText);
					auto task = ConsulTask::FromJson(appJson);
					if (task->m_app->getName().length())
					{
						result[task->m_app->getName()] = task;
						LOG_DBG << fname << "get task <" << task->m_app->getName() << ">";
						task->dump();
					}
				}
			}
		}
	}
	return std::move(result);
}
/*
[
	"appmgr/status/cents/applications",
	"appmgr/status/cents/resource"
]
*/
std::map<std::string, std::shared_ptr<Label>> ConsulConnection::retrieveNode()
{
	const static char fname[] = "ConsulConnection::retrieveNode() ";

	std::map<std::string, std::shared_ptr<Label>> result;

	// /appmgr/status
	std::string path = std::string(CONSUL_BASE_PATH).append("status");
	auto resp = requestHttp(web::http::methods::GET, path, { {"recurse","true"} }, {}, nullptr);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto json = resp.extract_json(true).get();
		if (json.is_array())
		{
			for (auto section : json.as_array())
			{
				if (section.has_string_field("Key") && section.has_string_field("Value") && section.at("Value").as_string().length())
				{
					auto key = GET_JSON_STR_VALUE(section, "Key");
					if (Utility::endWith(key, "/label"))
					{
						auto tmp = Utility::stringReplace(key, "appmgr/status/", "");
						auto host = Utility::stringReplace(tmp, "/label", "");
						auto label = Utility::decode64(section.at("Value").as_string());
						if (label.empty()) label = "{}";
						result[host] = Label::FromJson(web::json::value::parse(label));
						LOG_DBG << fname << "get host <" << host << "> with label: " << label;
					}
				}
			}
		}
	}
	return std::move(result);
}

void ConsulConnection::initTimer(const std::string& recoveredConsulSsnId)
{
	const static char fname[] = "ConsulConnection::initTimer() ";
	LOG_DBG << fname;

	if (!Configuration::instance()->getConsul()->enabled()) return;

	if (!recoveredConsulSsnId.empty())
	{
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		m_sessionId = recoveredConsulSsnId;
	}

	// session renew timer
	if (m_ssnRenewTimerId)
	{
		this->cancleTimer(m_ssnRenewTimerId);
		m_ssnRenewTimerId = 0;
	}
	if (Configuration::instance()->getConsul()->m_ttl > 10)
	{
		m_ssnRenewTimerId = this->registerTimer(
			0,
			Configuration::instance()->getConsul()->m_ttl - 3,
			std::bind(&ConsulConnection::refreshSession, this, std::placeholders::_1),
			__FUNCTION__
		);
	}

	// report status timer
	if (m_reportStatusTimerId)
	{
		this->cancleTimer(m_reportStatusTimerId);
		m_reportStatusTimerId = 0;
	}
	if (Configuration::instance()->getConsul()->m_reportInterval > 3)
	{
		m_reportStatusTimerId = this->registerTimer(
			1000L * 2,
			Configuration::instance()->getConsul()->m_reportInterval,
			std::bind(&ConsulConnection::reportStatus, this, std::placeholders::_1),
			__FUNCTION__
		);
	}

	// aply topology timer
	if (m_applyTopoTimerId)
	{
		this->cancleTimer(m_applyTopoTimerId);
		m_applyTopoTimerId = 0;
	}
	if (Configuration::instance()->getConsul()->m_topologyInterval > 1)
	{
		m_applyTopoTimerId = this->registerTimer(
			1000L * 1,
			Configuration::instance()->getConsul()->m_topologyInterval,
			std::bind(&ConsulConnection::applyTopology, this, std::placeholders::_1),
			__FUNCTION__
		);
	}
}

const std::string ConsulConnection::getConsulSessionId()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_sessionId;
}

web::http::http_response ConsulConnection::requestHttp(const web::http::method& mtd, const std::string& path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, web::json::value* body)
{
	const static char fname[] = "ConsulConnection::requestHttp() ";

	auto restURL = Configuration::instance()->getConsul()->m_consulUrl;

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
	// TODO: resp.status_code: 301
	LOG_DBG << fname << path << " return " << response.status_code();
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

ConsulConnection::ConsulTask::ConsulTask()
	:m_replication(0), m_priority(0)
{
	m_condition = std::make_shared<Label>();
}

std::shared_ptr<ConsulConnection::ConsulTask> ConsulConnection::ConsulTask::FromJson(const web::json::value& jobj)
{
	auto consul = std::make_shared<ConsulConnection::ConsulTask>();
	if (HAS_JSON_FIELD(jobj, "content") && HAS_JSON_FIELD(jobj, "replication") &&
		jobj.at("replication").is_integer() &&
		jobj.at("content").is_object())
	{
		auto appJson = jobj.at("content");
		// TODO: use explicit distinguish to identify <consul app> and <native app>
		// set flag to mark consul application
		appJson[JSON_KEY_APP_comments] = web::json::value::string(APP_COMMENTS_FROM_CONSUL);
		consul->m_app = Configuration::instance()->parseApp(appJson);
		consul->m_replication = jobj.at("replication").as_integer();
		SET_JSON_INT_VALUE(jobj, "priority", consul->m_priority);
		if (HAS_JSON_FIELD(jobj, "condition"))
		{
			consul->m_condition = Label::FromJson(jobj.at("condition"));
		}
	}
	return consul;
}

web::json::value ConsulConnection::ConsulTask::AsJson()
{
	auto result = web::json::value::object();
	result["replication"] = web::json::value::number(m_replication);
	result["priority"] = web::json::value::number(m_priority);
	result["content"] = m_app->AsJson(false);
	if (m_condition != nullptr) result["condition"] = m_condition->AsJson();
	return result;
}

void ConsulConnection::ConsulTask::dump()
{
	const static char fname[] = "ConsulConnection::dump() ";
	LOG_DBG << fname << "m_app=" << m_app->getName();
	LOG_DBG << fname << "m_priority=" << m_priority;
	LOG_DBG << fname << "m_replication=" << m_replication;
}
