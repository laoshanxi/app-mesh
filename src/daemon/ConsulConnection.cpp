#include <algorithm>
#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include <thread>

#include "Application.h"
#include "Configuration.h"
#include "ConsulConnection.h"
#include "ResourceCollection.h"
#include "User.h"

#include "../common/Utility.h"
#include "../common/PerfLog.h"

#define CONSUL_BASE_PATH  "/v1/kv/appmgr/"
//extern ACE_Reactor* m_timerReactor;

ConsulConnection::ConsulConnection()
	:m_ssnRenewTimerId(0), m_leader(0)
{
	// override default reactor here
	// m_reactor = m_timerReactor;
}

ConsulConnection::~ConsulConnection()
{
	this->cancleTimer(m_ssnRenewTimerId);
}

std::shared_ptr<ConsulConnection>& ConsulConnection::instance()
{
	static auto singleton = std::make_shared<ConsulConnection>();
	return singleton;
}

// report label and resource to host KV
// report timestamp to Flags attr for KV
void ConsulConnection::reportNode()
{
	const static char fname[] = "ConsulConnection::reportNode() ";

	std::string sessionId = getSessionId();
	if (sessionId.empty()) return;

	// check feature enabled
	if (!Configuration::instance()->getConsul()->consulEnabled()) return;

	// Only node need report status for node (master does not need report)
	if (!Configuration::instance()->getConsul()->m_isNode) return;

	PerfLog perf(fname);
	try
	{
		//report resource: /appmgr/cluster/nodes/myhost
		std::string path = std::string(CONSUL_BASE_PATH).append("cluster/nodes/").append(MY_HOST_NAME);

		static long long lastIndex = 0;
		auto currentIndex = getModifyIndex(path);
		if (currentIndex == lastIndex) return;

		web::json::value body = web::json::value::object();
		body["resource"] = ResourceCollection::instance()->getConsulJson();
		body["label"] = Configuration::instance()->getLabel()->AsJson();
		auto timestamp = std::to_string(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
		auto resp = requestHttp(web::http::methods::PUT, path, { {"acquire", sessionId}, {"flags", timestamp} }, {}, &body);
		if (resp.status_code() == web::http::status_codes::OK)
		{
			auto result = resp.extract_utf8string(true).get();
			if (result == "true")
			{
				auto index = getModifyIndex(path);
				if (index > 0) lastIndex = index;
			}
			else
			{
				LOG_WAR << fname << "report resource to " << path << " failed with response : " << result;
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
		if (!Configuration::instance()->getConsul()->consulEnabled()) return;

		PerfLog perf(fname);
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
		{
			std::lock_guard<std::recursive_mutex> guard(m_mutex);
			m_sessionId = sessionId;
		}
		reportNode();
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

long long ConsulConnection::getModifyIndex(const std::string& path)
{
	const static char fname[] = "ConsulConnection::getModifyIndex() ";

	auto resp = requestHttp(web::http::methods::GET, path, {}, {}, nullptr);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		if (resp.headers().has("X-Consul-Index"))
		{
			auto index = std::atoll(resp.headers().find("X-Consul-Index")->second.c_str());
			LOG_DBG << fname << path << " index : " << index;
			return index;
		}
	}
	return -1;
}

void ConsulConnection::syncSchedule()
{
	const static char fname[] = "ConsulConnection::syncSchedule() ";
	LOG_DBG << fname;

	try
	{
		// check feature enabled
		if (!Configuration::instance()->getConsul()->consulEnabled()) return;
		if (getSessionId().empty())
		{
			std::lock_guard<std::recursive_mutex> guard(m_mutex);
			m_sessionId = requestSessionId();
		}

		PerfLog perf(fname);

		if (Configuration::instance()->getConsul()->m_isMaster)
		{
			// Leader's job
			std::lock_guard<std::recursive_mutex> guard(m_mutex);
			doSchedule();
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

void ConsulConnection::syncSecurity()
{
	const static char fname[] = "ConsulConnection::syncSecurity() ";

	try
	{
		// check feature enabled
		if (!Configuration::instance()->getConsul()->consulSecurityEnabled()) return;

		PerfLog perf(fname);

		std::string path = std::string(CONSUL_BASE_PATH).append("security");
		auto resp = requestHttp(web::http::methods::GET, path, {}, {}, nullptr);
		if (resp.status_code() == web::http::status_codes::OK)
		{
			auto respJson = resp.extract_json(true).get();
			if (!respJson.is_array() || respJson.as_array().size() == 0) return;
			auto securityJson = respJson.as_array().at(0);
			if (!HAS_JSON_FIELD(securityJson, "ModifyIndex") || !HAS_JSON_FIELD(securityJson, "Value")) return;

			auto security = web::json::value::parse(Utility::decode64(GET_JSON_STR_VALUE(securityJson, "Value")));
			auto securityObj = Configuration::JsonSecurity::FromJson(security);
			if (securityObj->m_jwtUsers->getUsers().size())
			{
				Configuration::instance()->updateSecurity(securityObj);
				LOG_DBG << fname << "Security info updated from Consul successfully";
			}
		}
		else
		{
			LOG_WAR << fname << "failed with return code : " << resp.status_code();
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

	auto payload = web::json::value::object();
	payload["LockDelay"] = web::json::value::string("15s");
	payload["Name"] = web::json::value::string(std::string("appmgr-lock-") + MY_HOST_NAME);
	payload["Behavior"] = web::json::value::string("delete");
	payload["TTL"] = web::json::value::string(std::to_string(Configuration::instance()->getConsul()->m_ttl) + "s");

	auto resp = requestHttp(web::http::methods::PUT, "/v1/session/create", {}, {}, &payload);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto json = resp.extract_json(true).get();
		//LOG_DBG << fname << json.serialize();
		if (HAS_JSON_FIELD(json, "ID"))
		{
			sessionId = GET_JSON_STR_VALUE(json, "ID");
			LOG_DBG << fname << "sessionId=" << sessionId;
		}
	}
	return sessionId;
}

void ConsulConnection::releaseSessionId()
{
	auto sessionId = this->getSessionId();
	if (sessionId.length())
	{
		requestHttp(web::http::methods::PUT, std::string("/v1/session/destroy/").append(sessionId), {}, {}, nullptr);
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		m_sessionId.clear();
	}
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
			if (json.is_array() && json.as_array().size())
			{
				json = json.as_array().at(0);
				sessionId = GET_JSON_STR_VALUE(json, "ID");
			}
		}
		else
		{
			LOG_WAR << fname << "failed with return code : " << resp.status_code();
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

void ConsulConnection::doSchedule()
{
	const static char fname[] = "ConsulConnection::doSchedule() ";
	LOG_DBG << fname;

	// leader's job
	if (eletionLeader())
	{
		LOG_DBG << fname << "leader now, do schedule";

		auto taskList = retrieveTask();
		auto oldTopology = retrieveTopology("");
		auto nodes = retrieveNode();
		if (nodes.size())
		{
			// find matched hosts for each task
			findTaskAvialableHost(taskList, nodes);

			// schedule task
			auto newTopology = scheduleTask(taskList, oldTopology);

			// apply schedule result
			compareTopologyAndDispatch(oldTopology, newTopology);
		}
	}
	else
	{
		std::string path = std::string(CONSUL_BASE_PATH).append("leader");
		auto resp = requestHttp(web::http::methods::GET, path, { {"raw", "true"} }, {}, nullptr);
		if (resp.status_code() == web::http::status_codes::OK)
		{
			LOG_DBG << fname << MY_HOST_NAME << " is not leader, leader is : " << resp.extract_utf8string().get();
		}
		else
		{
			LOG_WAR << fname << "no leader now!";
		}
	}
}

void ConsulConnection::syncTopology()
{
	const static char fname[] = "ConsulConnection::syncTopology() ";

	auto currentAllApps = Configuration::instance()->getApps();
	std::shared_ptr<ConsulTopology> newTopology;
	auto topology = retrieveTopology(MY_HOST_NAME);
	auto hostTopologyIt = topology.find(MY_HOST_NAME);
	if (hostTopologyIt != topology.end()) newTopology = hostTopologyIt->second;

	if (newTopology)
	{
		auto task = retrieveTask();
		for (const auto& hostApp : newTopology->m_apps)
		{
			const auto& appName = hostApp;
			if (task.count(appName))
			{
				auto& consulTask = task[appName];
				std::shared_ptr<Application> topologyAppObj = consulTask->m_app;
				auto it = std::find_if(currentAllApps.begin(), currentAllApps.end(), [&appName](std::shared_ptr<Application> const& obj) {
					return obj->getName() == appName;
					});
				if (it != currentAllApps.end())
				{
					// Update app
					auto& currentRunningApp = *it;
					if (!currentRunningApp->operator==(topologyAppObj))
					{
						Configuration::instance()->addApp(topologyAppObj->AsJson(false));
						LOG_INF << fname << " Consul application <" << topologyAppObj->getName() << "> updated";

						registerService(appName, consulTask->m_consulServicePort);
					}
				}
				else
				{
					// New add app
					Configuration::instance()->addApp(topologyAppObj->AsJson(false));
					LOG_INF << fname << " Consul application <" << topologyAppObj->getName() << "> added";

					registerService(appName, consulTask->m_consulServicePort);
				}
			}
		}

		for (const auto& currentApp : currentAllApps)
		{
			if (currentApp->isCloudApp())
			{
				if (!(newTopology && (newTopology->m_apps.count(currentApp->getName()))))
				{
					// Remove no used topology
					Configuration::instance()->removeApp(currentApp->getName());
					LOG_INF << fname << " Consul application <" << currentApp->getName() << "> removed";
					deregisterService(currentApp->getName());
				}
			}
		}
	}
	else
	{
		// retrieveTopology will throw if connection was not reached
		for (const auto& currentApp : currentAllApps)
		{
			if (currentApp->isCloudApp())
			{
				// Remove no used topology
				Configuration::instance()->removeApp(currentApp->getName());
				LOG_INF << fname << " Consul application <" << currentApp->getName() << "> removed";
				deregisterService(currentApp->getName());
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
	auto timestamp = std::to_string(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
	auto resp = requestHttp(web::http::methods::PUT, path, { {"acquire", sessionId}, {"flags", timestamp} }, {}, &body);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto result = resp.extract_utf8string(true).get();
		m_leader = (result == "true");
	}
	else
	{
		m_leader = false;
	}
	return m_leader;
}

bool ConsulConnection::registerService(const std::string& appName, int port)
{
	const static char fname[] = "ConsulConnection::registerService() ";
	// https://www.hashicorp.com/blog/consul-and-external-services/
	//curl -X PUT -d 
	//  '{"Node": "myhost", "Address": "myhost","Service": {"Service": "mysql", "tags": ["master","v1"], "Port": 3306}}'
	//  http://127.0.0.1:8500/v1/catalog/register

	if (port == 0) return false;

	auto body = web::json::value();
	body["ID"] = web::json::value::string(MY_HOST_NAME + ":" + appName);
	body["Name"] = web::json::value::string(appName);
	body["Address"] = web::json::value::string(MY_HOST_NAME);
	body["Port"] = web::json::value::number(port);

	auto check = web::json::value::object();
	check["HTTP"] = web::json::value::string("https://" + MY_HOST_NAME + ":" + std::to_string(Configuration::instance()->getRestListenPort()) + "/app/" + appName + "/health");
	check["Interval"] = web::json::value::string("15s");
	check["Timeout"] = web::json::value::string("5s");
	check["Method"] = web::json::value::string("GET");
	check["TLSSkipVerify"] = web::json::value::boolean(true);
	body["Check"] = check;

	std::string path = "/v1/agent/service/register";
	auto resp = requestHttp(web::http::methods::PUT, path, { {"replace-existing-checks","true"} }, {}, &body);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto result = resp.extract_utf8string(true).get();
		LOG_DBG << fname << " service for task <" << appName << "> registered : " << result;
		return (result == "true");
	}
	return false;
}

bool ConsulConnection::deregisterService(const std::string appName)
{
	const static char fname[] = "ConsulConnection::deregisterService() ";

	auto serviceId = std::string(MY_HOST_NAME).append(":").append(appName);
	std::string path = std::string("/v1/agent/service/deregister/").append(serviceId);
	auto resp = requestHttp(web::http::methods::PUT, path, {}, {}, NULL);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto result = resp.extract_utf8string(true).get();
		LOG_DBG << fname << " service for task <" << appName << "> removed : " << result;
		return (result == "true");
	}
	return false;
}

void ConsulConnection::saveSecurity(bool checkExistance)
{
	const static char fname[] = "ConsulConnection::saveSecurity() ";

	if (!Configuration::instance()->getConsul()->consulSecurityEnabled()) return;

	// /appmgr/security
	std::string path = std::string(CONSUL_BASE_PATH).append("security");
	// if check exist and security KV already exist, do nothing
	if (checkExistance && requestHttp(web::http::methods::GET, path, {}, {}, nullptr).status_code() == web::http::status_codes::OK)
	{
		LOG_WAR << fname << path << " already exist, on need override";
		return;
	}
	auto body = Configuration::instance()->getSecurity()->AsJson(false);
	auto timestamp = std::to_string(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
	web::http::http_response resp = requestHttp(web::http::methods::PUT, path, { {"flags", timestamp} }, {}, &body);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto result = resp.extract_utf8string(true).get();
		if (result != "true")
		{
			LOG_WAR << fname << " PUT " << path << " failed with response : " << result;
		}
	}
}

void ConsulConnection::findTaskAvialableHost(const std::map<std::string, std::shared_ptr<ConsulTask>>& taskMap, const std::map<std::string, std::shared_ptr<ConsulNode>>& hosts)
{
	const static char fname[] = "ConsulConnection::findTaskAvialableHost() ";

	for (const auto& task : taskMap)
	{
		auto taskName = task.first;
		task.second->m_matchedHosts.clear();
		for (const auto& host : hosts)
		{
			auto& hostName = host.first;
			auto& consulHost = host.second;
			auto& taskCondition = task.second->m_condition;
			if (consulHost->m_label->match(taskCondition))
			{
				task.second->m_matchedHosts[hostName] = consulHost;
				LOG_DBG << fname << " task <" << taskName << "> match host <" << hostName << ">";
			}
		}
	}
}

std::map<std::string, std::shared_ptr<ConsulTopology>> ConsulConnection::scheduleTask(const std::map<std::string, std::shared_ptr<ConsulTask>>& taskMap, const std::map<std::string, std::shared_ptr<ConsulTopology>>& oldTopology)
{
	const static char fname[] = "ConsulConnection::scheduleTask() ";
	LOG_DBG << fname;

	// key: hostname, value: task list
	std::map<std::string, std::shared_ptr<ConsulTopology>> newTopology;

	// ignore old schedule
	for (const auto& task : taskMap)
	{
		const auto& taskName = task.first;
		auto& taskDedicateHosts = task.second->m_matchedHosts;
		auto& taskReplication = task.second->m_replication;
		if (taskReplication <= 0) continue;

		for (const auto& oldHost : oldTopology)
		{
			auto& oldHostName = oldHost.first;
			auto& oldTaskSet = oldHost.second->m_apps;
			if (taskDedicateHosts.count(oldHostName) && oldTaskSet.count(taskName))
			{
				auto consulNode = taskDedicateHosts[oldHostName];
				// found app running on old host still match
				taskDedicateHosts.erase(oldHostName);
				--taskReplication;

				LOG_DBG << fname << " task <" << taskName << "> already running on host <" << oldHostName << ">";

				{
					// save to topology
					if (!newTopology.count(oldHostName)) newTopology[oldHostName] = std::make_shared<ConsulTopology>();
					newTopology[oldHostName]->m_apps.insert(taskName);
					consulNode->assignApp(task.second->m_app);
				}
			}
		}
	}

	// do schedule
	for (const auto& task : taskMap)
	{
		// get current task
		const auto& taskDedicateHosts = task.second->m_matchedHosts;
		auto& taskReplication = task.second->m_replication;
		const auto& taskName = task.first;
		std::vector<std::shared_ptr<ConsulNode>> taskDedicateHostsVec;

		LOG_DBG << fname << "schedule task <" << taskName << ">";
		if (taskReplication <= 0)
			continue;

		// copy to vector
		std::transform(taskDedicateHosts.begin(), taskDedicateHosts.end(), std::back_inserter(taskDedicateHostsVec),
			[](const std::pair<std::string, std::shared_ptr<ConsulNode>> host) { return host.second; }
		);
		// sort hosts
		// return left < right is Ascending
		// return left > right is Descending
		std::sort(taskDedicateHostsVec.begin(), taskDedicateHostsVec.end(),
			[](const std::shared_ptr<ConsulNode>& left, const std::shared_ptr<ConsulNode>& right)
			{
				if (left->m_assignedApps.size() < right->m_assignedApps.size())
				{
					return true;
				}
				else if (left->m_assignedApps.size() == right->m_assignedApps.size())
				{
					return (left->getAssignedAppMem() < right->getAssignedAppMem());
				}
				else
				{
					return false;
				}
			});

		if (taskReplication > taskDedicateHostsVec.size())
		{
			LOG_WAR << fname << taskName << " : Replication <" << taskReplication << "> Dedicate Host < " << taskDedicateHostsVec.size() << ">";
		}
		// assign host to task
		for (size_t i = 0; i < taskReplication; i++)
		{
			if (i < taskDedicateHostsVec.size())
			{
				const auto& hostname = taskDedicateHostsVec[i]->m_hostName;
				const auto& consulNode = taskDedicateHostsVec[i];
				// save to topology
				{
					if (!newTopology.count(hostname)) newTopology[hostname] = std::make_shared<ConsulTopology>();
					newTopology[hostname]->m_apps.insert(taskName);
					consulNode->assignApp(task.second->m_app);
				}
				LOG_DBG << fname << " task <" << taskName << "> assigned to host < " << hostname << ">";
				task.second->dump();
			}
			else
			{
				break;
			}
		}
	}

	return std::move(newTopology);
}

void ConsulConnection::compareTopologyAndDispatch(const std::map<std::string, std::shared_ptr<ConsulTopology>>& oldT, const std::map<std::string, std::shared_ptr<ConsulTopology>>& newT)
{
	for (const auto& newHost : newT)
	{
		if (oldT.count(newHost.first))
		{
			auto equal = true;
			if (newHost.second->m_apps.size() == oldT.find(newHost.first)->second->m_apps.size())
			{
				for (const auto& app : newHost.second->m_apps)
				{
					if (!oldT.find(newHost.first)->second->m_apps.count(app))
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

	for (const auto& oldHost : oldT)
	{
		if (!newT.count(oldHost.first))
		{
			// delete
			writeTopology(oldHost.first, nullptr);
		}
	}
}

bool ConsulConnection::writeTopology(std::string hostName, const std::shared_ptr<ConsulTopology> topology)
{
	const static char fname[] = "ConsulConnection::writeTopology() ";

	//topology: /appmgr/topology/myhost
	std::string path = std::string(CONSUL_BASE_PATH).append("topology/").append(hostName);
	web::http::http_response resp;
	if (topology && topology->m_apps.size())
	{
		auto body = topology->AsJson();
		auto timestamp = std::to_string(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
		resp = requestHttp(web::http::methods::PUT, path, { {"flags", timestamp} }, {}, &body);
		LOG_INF << fname << "write <" << body.serialize() << "> to <" << hostName << ">";
	}
	else
	{
		resp = requestHttp(web::http::methods::DEL, path, {}, {}, nullptr);
		LOG_INF << fname << "delete topology for <" << hostName << ">";
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
std::map<std::string, std::shared_ptr<ConsulTopology>> ConsulConnection::retrieveTopology(std::string host)
{
	const static char fname[] = "ConsulConnection::retrieveTopology() ";

	// /appmgr/topology/myhost
	std::map<std::string, std::shared_ptr<ConsulTopology>> topology;
	auto path = std::string(CONSUL_BASE_PATH).append("topology");
	if (host.length()) path.append("/").append(host);
	auto resp = requestHttp(web::http::methods::GET, path, { {"recurse","true"} }, {}, nullptr);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto json = resp.extract_json(true).get();
		if (json.is_array())
		{
			for (const auto& section : json.as_array())
			{
				if (HAS_JSON_FIELD(section, "Value"))
				{
					// int consulIndex = GET_JSON_INT_VALUE(section, "ModifyIndex");
					auto hostText = Utility::decode64(GET_JSON_STR_VALUE(section, "Value"));
					if (hostText.empty()) continue;
					auto consulKey = GET_JSON_STR_VALUE(section, "Key");
					auto vec = Utility::splitString(consulKey, "/");
					auto hostName = vec[vec.size() - 1];
					auto appArrayJson = web::json::value::parse(hostText);
					if (appArrayJson.is_array())
					{
						topology[hostName] = ConsulTopology::FromJson(appArrayJson, hostName);
						LOG_DBG << fname << "get <" << appArrayJson.size() << "> task for <" << hostName << ">";
					}
				}
			}
		}
	}

	LOG_DBG << fname << "get topology size : " << topology.size();
	return std::move(topology);
}

std::map<std::string, std::shared_ptr<ConsulTask>> ConsulConnection::retrieveTask()
{
	const static char fname[] = "ConsulConnection::retrieveTask() ";

	std::map<std::string, std::shared_ptr<ConsulTask>> result;
	// /appmgr/cluster/tasks/myapp
	std::string path = std::string(CONSUL_BASE_PATH).append("cluster/tasks");
	auto resp = requestHttp(web::http::methods::GET, path, { {"recurse","true"} }, {}, nullptr);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto json = resp.extract_json(true).get();
		if (json.is_array())
		{
			for (const auto& section : json.as_array())
			{
				if (HAS_JSON_FIELD(section, "Value") && GET_JSON_STR_VALUE(section, "Key") != "appmgr/cluster/tasks")
				{
					auto appText = Utility::decode64(GET_JSON_STR_VALUE(section, "Value"));
					auto appJson = web::json::value::parse(appText);
					auto task = ConsulTask::FromJson(appJson);
					if (task->m_app && task->m_app->getName().length() && task->m_replication)
					{
						result[task->m_app->getName()] = task;
						LOG_DBG << fname << "get task <" << task->m_app->getName() << ">";
					}
				}
			}
		}
	}
	LOG_DBG << fname << "get tasks size : " << result.size();
	return std::move(result);
}

/*
[
	"appmgr/cluster/nodes/cents"
]
*/
std::map<std::string, std::shared_ptr<ConsulNode>> ConsulConnection::retrieveNode()
{
	const static char fname[] = "ConsulConnection::retrieveNode() ";

	std::map<std::string, std::shared_ptr<ConsulNode>> result;
	// /appmgr/cluster/nodes
	std::string path = std::string(CONSUL_BASE_PATH).append("cluster/nodes");
	auto resp = requestHttp(web::http::methods::GET, path, { {"recurse","true"} }, {}, nullptr);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto json = resp.extract_json(true).get();
		if (json.is_array())
		{
			for (const auto& section : json.as_array())
			{
				if (section.has_string_field("Key") && section.has_string_field("Value") && section.at("Value").as_string().length())
				{
					auto key = GET_JSON_STR_VALUE(section, "Key");
					if (Utility::startWith(key, "appmgr/cluster/nodes/"))
					{
						auto host = Utility::stringReplace(key, "appmgr/cluster/nodes/", "");
						auto value = web::json::value::parse(Utility::decode64(section.at("Value").as_string()));
						result[host] = ConsulNode::FromJson(value, host);
					}
				}
			}
		}
	}
	LOG_DBG << fname << "get nodes size : " << result.size();
	return std::move(result);
}

void ConsulConnection::initTimer()
{
	const static char fname[] = "ConsulConnection::initTimer() ";
	LOG_DBG << fname;

	releaseSessionId();

	if (!Configuration::instance()->getConsul()->consulEnabled()) return;

	// session renew timer
	this->cancleTimer(m_ssnRenewTimerId);
	if (Configuration::instance()->getConsul()->m_ttl > 10 &&
		(Configuration::instance()->getConsul()->m_isMaster || Configuration::instance()->getConsul()->m_isNode))
	{
		m_ssnRenewTimerId = this->registerTimer(
			0,
			Configuration::instance()->getConsul()->m_ttl - 3,
			std::bind(&ConsulConnection::refreshSession, this, std::placeholders::_1),
			__FUNCTION__
		);
	}

	auto consulUrl = Configuration::instance()->getConsul()->m_consulUrl;
	auto consulImg = Configuration::instance()->getConsul()->m_consulDockerImg;
	// security watch
	if (Configuration::instance()->getConsul()->consulSecurityEnabled())
	{
		m_securityWatch = std::make_shared<std::thread>(std::bind(&ConsulConnection::watchSecurityThread, this));
		m_securityWatch->detach();
	}
	// topology watch
	if (Configuration::instance()->getConsul()->m_isNode)
	{
		m_topologyWatch = std::make_shared<std::thread>(std::bind(&ConsulConnection::watchTopologyThread, this));
		m_topologyWatch->detach();
	}
	// schedule nodes watch
	if (Configuration::instance()->getConsul()->m_isMaster)
	{
		m_scheduleWatch = std::make_shared<std::thread>(std::bind(&ConsulConnection::watchScheduleThread, this));
		m_scheduleWatch->detach();
	}
}

web::http::http_response ConsulConnection::requestHttp(const web::http::method& mtd, const std::string& path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, web::json::value* body)
{
	const static char fname[] = "ConsulConnection::requestHttp() ";

	auto restURL = Configuration::instance()->getConsul()->m_consulUrl;

	// Create http_client to send the request.
	web::http::client::http_client_config config;
	//config.set_timeout(std::chrono::seconds(5));
	config.set_validate_certificates(false);
	web::http::client::http_client client(restURL, config);

	// Build request URI and start the request.
	web::uri_builder builder(GET_STRING_T(path));
	std::for_each(query.begin(), query.end(), [&builder](const std::pair<std::string, std::string>& pair)
		{
			builder.append_query(GET_STRING_T(pair.first), GET_STRING_T(pair.second));
		});

	web::http::http_request request(mtd);
	for (const auto& h : header)
	{
		request.headers().add(h.first, h.second);
	}
	request.set_request_uri(builder.to_uri());
	if (body != nullptr)
	{
		request.set_body(Utility::prettyJson(body->serialize()));
	}

	try
	{
		// In case of REST server crash or block query timeout, will throw exception:
		// "Failed to read HTTP status line"
		web::http::http_response response = client.request(request).get();
		LOG_DBG << fname << mtd << " " << path << " return " << response.status_code();
		return std::move(response);
	}
	catch (const std::exception & ex)
	{
		LOG_WAR << fname << path << " got exception: " << ex.what();
	}
	catch (...)
	{
		LOG_WAR << fname << path << " exception";
	}

	web::http::http_response response(web::http::status_codes::ResetContent);
	return std::move(response);
}

long long ConsulConnection::requestLongPullWatch(std::string kvPath, long long lastIndex)
{
	const static char fname[] = "ConsulConnection::requestLongPullWatch() ";

	auto restURL = Configuration::instance()->getConsul()->m_consulUrl;

	// Create http_client to send the request.
	web::http::client::http_client_config config;
	config.set_timeout(std::chrono::seconds(30));	// set block pull to 30s timeout
	config.set_validate_certificates(false);
	web::http::client::http_client client(restURL, config);

	// Build request URI and start the request.
	web::uri_builder builder(kvPath);
	builder.append_query("index", std::to_string(lastIndex));

	web::http::http_request request(web::http::methods::GET);
	request.set_request_uri(builder.to_uri());
	
	try
	{
		web::http::http_response response = client.request(request).get();
		if (response.status_code() == web::http::status_codes::OK)
		{
			return std::atoll(response.headers().find("X-Consul-Index")->second.c_str());
		}
	}
	catch (...)
	{
		// In case of REST server crash or block query timeout, will throw exception:
		// "Failed to read HTTP status line"
		// LOG_DBG << fname << " exception";
	}
	return 0;
}

void ConsulConnection::watchSecurityThread()
{
	const static char fname[] = "ConsulConnection::watchSecurityThread() ";
	LOG_DBG << fname;

	long long index = 0;
	std::string path = std::string(CONSUL_BASE_PATH).append("security");
	while (Configuration::instance()->getConsul()->consulSecurityEnabled())
	{
		auto lastIndex = requestLongPullWatch(path, index);
		if (lastIndex > 0)
		{
			index = lastIndex;
			this->syncSecurity();
		}
		else
		{
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}
	}
	LOG_DBG << fname << "exit";
}

void ConsulConnection::watchTopologyThread()
{
	const static char fname[] = "ConsulConnection::watchTopologyThread() ";
	LOG_DBG << fname;

	long long index = 0;
	auto path = std::string(CONSUL_BASE_PATH).append("topology/").append(MY_HOST_NAME);
	while (Configuration::instance()->getConsul()->m_isNode)
	{
		auto lastIndex = requestLongPullWatch(path, index);
		if (lastIndex > 0)
		{
			index = lastIndex;
			this->syncTopology();
		}
		else
		{
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}
	}
	LOG_DBG << fname << "exit";
}

void ConsulConnection::watchScheduleThread()
{
	const static char fname[] = "ConsulConnection::watchScheduleThread() ";
	LOG_DBG << fname;

	long long index = 0;
	auto path = std::string(CONSUL_BASE_PATH).append("cluster/");
	while (Configuration::instance()->getConsul()->m_isMaster)
	{
		auto lastIndex = requestLongPullWatch(path, index);
		if (lastIndex > 0)
		{
			index = lastIndex;
			this->syncSchedule();
		}
		else
		{
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}
	}
	LOG_DBG << fname << "exit";
}

