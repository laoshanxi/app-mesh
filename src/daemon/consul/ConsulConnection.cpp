#include <algorithm>
#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include <thread>

#include "../../common/DateTime.h"
#include "../../common/PerfLog.h"
#include "../../common/Utility.h"
#include "../../common/os/linux.hpp"
#include "../Configuration.h"
#include "../ResourceCollection.h"
#include "../application/Application.h"
#include "../security/Security.h"
#include "ConsulConnection.h"
#include "Scheduler.h"

#define CONSUL_BASE_PATH "/v1/kv/appmesh/"

ConsulConnection::ConsulConnection()
	: m_ssnRenewTimerId(0), m_leader(0), m_config(std::make_shared<Configuration::JsonConsul>())
{
}

ConsulConnection::~ConsulConnection()
{
	this->cancelTimer(m_ssnRenewTimerId);
}

std::shared_ptr<ConsulConnection> &ConsulConnection::instance()
{
	static auto singleton = std::make_shared<ConsulConnection>();
	return singleton;
}

std::shared_ptr<Configuration::JsonConsul> ConsulConnection::getConfig()
{
	std::lock_guard<std::recursive_mutex> guard(m_consulMutex);
	return m_config;
}

// report label and resource to host KV
// report timestamp to Flags attr for KV
void ConsulConnection::reportNode()
{
	const static char fname[] = "ConsulConnection::reportNode() ";

	std::string sessionId = consulSessionId();
	if (sessionId.empty())
		return;

	// check feature enabled
	if (!getConfig()->consulEnabled())
		return;

	// Only node need report status for node (main does not need report)
	if (!getConfig()->m_isWorker)
		return;

	PerfLog perf(fname);
	try
	{
		//report resource: /appmesh/cluster/nodes/myhost
		std::string path = std::string(CONSUL_BASE_PATH).append("cluster/nodes/").append(MY_HOST_NAME);

		ConsulNode node;
		static auto resource = ResourceCollection::instance()->getHostResource();
		node.m_appmeshProxyUrl = getConfig()->appmeshUrl();
		node.m_hostName = MY_HOST_NAME;
		node.m_label = Configuration::instance()->getLabel();
		node.m_total_bytes = resource.m_total_bytes;
		node.m_cores = resource.m_cores;
		node.m_leader = m_leader;
		web::json::value body = node.AsJson();
		auto cloudBody = this->retrieveNode(MY_HOST_NAME);
		if (cloudBody.serialize() == body.serialize())
		{
			// TODO: mem_free_bytes is always not the same here
			LOG_DBG << fname << "host info " << MY_HOST_NAME << " is the same with server";
			return;
		}

		auto timestamp = std::to_string(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
		auto resp = requestHttp(web::http::methods::PUT, path, {{"acquire", sessionId}, {"flags", timestamp}}, {}, &body);
		if (resp.status_code() == web::http::status_codes::OK)
		{
			auto result = resp.extract_utf8string(true).get();
			if (result == "true")
			{
				LOG_INF << fname << "report resource to " << path << " success";
			}
			else
			{
				LOG_WAR << fname << "report resource to " << path << " failed with response : " << result;
			}
		}
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << fname << "got exception: " << ex.what();
	}
	catch (...)
	{
		LOG_WAR << fname << "exception";
	}
}

void ConsulConnection::refreshSession(int)
{
	const static char fname[] = "ConsulConnection::refreshSession() ";

	try
	{
		// check feature enabled
		if (!getConfig()->consulEnabled())
			return;

		PerfLog perf(fname);
		// get session id
		auto sessionId = this->consulSessionId();
		if (sessionId.empty())
		{
			sessionId = requestSessionId();
		}
		else
		{
			sessionId = renewSessionId();
		}
		this->consulSessionId(sessionId);
		reportNode();
		return;
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << fname << "got exception: " << ex.what();
	}
	catch (...)
	{
		LOG_WAR << fname << "exception";
	}
	this->consulSessionId("");
}

long long ConsulConnection::getModifyIndex(const std::string &path, bool recurse)
{
	const static char fname[] = "ConsulConnection::getModifyIndex() ";

	std::map<std::string, std::string> query;
	if (recurse)
		query["recurse"] = "true";
	auto resp = requestHttp(web::http::methods::GET, path, query, {}, nullptr);
	if (resp.headers().has("X-Consul-Index"))
	{
		auto index = std::atoll(resp.headers().find("X-Consul-Index")->second.c_str());
		LOG_DBG << fname << path << " index : " << index;
		return index;
	}
	return 0;
}

web::json::value ConsulConnection::viewCloudApps()
{
	const static char fname[] = "ConsulConnection::viewCloudApps() ";
	LOG_DBG << fname;

	if (!getConfig()->consulEnabled())
	{
		throw std::runtime_error("Consul not enabled");
	}
	auto topology = retrieveTopology("");
	auto cloudTasks = this->retrieveTask();
	web::json::value result;
	for (auto task : cloudTasks)
	{
		result[task.first] = task.second->AsJson();

		for (auto host : topology)
		{
			if (host.second->m_scheduleApps.count(task.first))
			{
				// health status
				result[task.first]["status"][host.first] = getHealthStatus(host.first, task.first);
			}
		}
	}
	return result;
}

web::json::value ConsulConnection::viewCloudApp(const std::string &app)
{
	const static char fname[] = "ConsulConnection::viewCloudApp() ";
	LOG_DBG << fname;

	if (!getConfig()->consulEnabled())
	{
		throw std::runtime_error("Consul not enabled");
	}
	web::json::value result;
	const auto topology = this->retrieveTopology("");
	const auto cloudTasks = this->retrieveTask();
	const auto iter = cloudTasks.find(app);
	web::json::value scheduleResult;
	if (iter != cloudTasks.end())
	{
		result = iter->second->AsJson();
		for (const auto &node : topology)
		{
			if (node.second->m_scheduleApps.count(app) > 0)
			{
				scheduleResult[node.first] = web::json::value::string(DateTime::formatLocalTime(node.second->m_scheduleApps[app]));
			}
		}
	}
	if (result.is_null())
	{
		throw std::runtime_error("No such cloud application found");
	}
	else
	{
		result["schedule"] = scheduleResult;
	}

	return result;
}

int ConsulConnection::getHealthStatus(const std::string &host, const std::string &app)
{
	const static char fname[] = "ConsulConnection::getHealthStatus() ";

	web::uri_builder baseUri;
	baseUri.set_host(host);
	baseUri.set_port(Configuration::instance()->getRestListenPort());
	baseUri.set_scheme(Configuration::instance()->getSslEnabled() ? "https" : "http");
	auto restPath = Utility::stringFormat("/appmesh/app/%s/health", app.c_str());
	auto resp = requestHttp(baseUri.to_uri(), restPath, web::http::methods::GET);
	if (resp.status_code() != web::http::status_codes::OK)
	{
		LOG_WAR << fname << "failed to get health status: " << resp.status_code() << " with host: " << baseUri.to_string() << restPath << ", app: " << app;
		return 1;
	}
	else
	{
		return (std::stoi(resp.extract_utf8string().get()));
	}
}

void ConsulConnection::deleteCloudApp(const std::string &app)
{
	const static char fname[] = "ConsulConnection::deleteCloudApp() ";
	LOG_DBG << fname;

	if (!getConfig()->consulEnabled())
	{
		throw std::runtime_error("Consul not enabled");
	}

	if (app.empty())
	{
		throw std::runtime_error("application name not specified");
	}

	auto path = std::string(CONSUL_BASE_PATH).append("cluster/tasks/").append(app);
	auto resp = requestHttp(web::http::methods::DEL, path, {}, {}, nullptr);

	if (resp.status_code() != web::http::status_codes::OK)
	{
		throw std::runtime_error(resp.extract_utf8string().get());
	}
}

web::json::value ConsulConnection::addCloudApp(const std::string &app, web::json::value &content)
{
	const static char fname[] = "ConsulConnection::addCloudApp() ";
	LOG_DBG << fname;

	if (!getConfig()->consulEnabled())
	{
		throw std::runtime_error("Consul not enabled");
	}

	if (app.empty())
	{
		throw std::runtime_error("application name not specified");
	}

	// de-serialize to verify the json content
	auto task = ConsulTask::FromJson(content);

	auto path = std::string(CONSUL_BASE_PATH).append("cluster/tasks/").append(app);
	auto resp = requestHttp(web::http::methods::PUT, path, {}, {}, &content);

	if (resp.status_code() != web::http::status_codes::OK)
	{
		throw std::runtime_error(resp.extract_utf8string().get());
	}
	return task->AsJson();
}

web::json::value ConsulConnection::getCloudNodes()
{
	auto nodes = this->retrieveNode();
	web::json::value result;
	for (const auto &node : nodes)
	{
		result[node.first] = node.second->AsJson();
	}
	return result;
}

void ConsulConnection::syncSchedule()
{
	const static char fname[] = "ConsulConnection::syncSchedule() ";
	LOG_DBG << fname;

	try
	{
		// check feature enabled
		if (!getConfig()->consulEnabled())
			return;
		if (consulSessionId().empty())
			this->consulSessionId(requestSessionId());

		PerfLog perf(fname);

		if (getConfig()->m_isMaster)
		{
			// Leader's job
			std::lock_guard<std::recursive_mutex> guard(m_consulMutex);
			doSchedule();
		}
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << fname << "got exception: " << ex.what();
	}
	catch (...)
	{
		LOG_WAR << fname << "exception";
	}
}

void ConsulConnection::syncSecurity()
{
	const static char fname[] = "ConsulConnection::syncSecurity() ";

	try
	{
		// check feature enabled
		if (!getConfig()->consulSecurityEnabled())
			return;

		PerfLog perf(fname);

		std::string path = std::string(CONSUL_BASE_PATH).append("security");
		auto resp = requestHttp(web::http::methods::GET, path, {}, {}, nullptr);
		if (resp.status_code() == web::http::status_codes::OK)
		{
			auto respJson = resp.extract_json(true).get();
			if (!respJson.is_array() || respJson.as_array().size() == 0)
				return;
			auto securityJson = respJson.as_array().at(0);
			if (!HAS_JSON_FIELD(securityJson, "ModifyIndex") || !HAS_JSON_FIELD(securityJson, "Value"))
				return;

			auto security = web::json::value::parse(Utility::decode64(GET_JSON_STR_VALUE(securityJson, "Value")));
			auto securityObj = Security::FromJson(security);
			if (securityObj->getUsers().size())
			{
				Security::instance(securityObj);
				LOG_DBG << fname << "Security info updated from Consul successfully";
			}
		}
		else
		{
			LOG_WAR << fname << "failed with return code : " << resp.status_code();
		}
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << fname << "got exception: " << ex.what();
	}
	catch (...)
	{
		LOG_WAR << fname << "exception";
	}
}

std::string ConsulConnection::requestSessionId()
{
	const static char fname[] = "ConsulConnection::requestSessionId() ";

	// https://www.consul.io/api/session.html
	std::string sessionId;

	auto payload = web::json::value::object();
	payload["LockDelay"] = web::json::value::string("15s");
	payload["Name"] = web::json::value::string(std::string("appmesh-lock-") + MY_HOST_NAME);
	payload["Behavior"] = web::json::value::string("delete");
	payload["TTL"] = web::json::value::string(std::to_string(getConfig()->m_ttl) + "s");

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

void ConsulConnection::releaseSessionId(const std::string &sessionId)
{
	const static char fname[] = "ConsulConnection::releaseSessionId() ";

	if (sessionId.length())
	{
		requestHttp(web::http::methods::PUT, std::string("/v1/session/destroy/").append(sessionId), {}, {}, nullptr);
		LOG_DBG << fname << "release session " << sessionId;
	}
}

std::string ConsulConnection::renewSessionId()
{
	const static char fname[] = "ConsulConnection::renewSessionId() ";

	auto sessionId = consulSessionId();
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

std::string ConsulConnection::consulSessionId()
{
	std::lock_guard<std::recursive_mutex> guard(m_consulMutex);
	return m_sessionId;
}

void ConsulConnection::consulSessionId(const std::string &sessionId)
{
	std::lock_guard<std::recursive_mutex> guard(m_consulMutex);
	m_sessionId = sessionId;
}

void ConsulConnection::doSchedule()
{
	const static char fname[] = "ConsulConnection::doSchedule() ";
	LOG_DBG << fname;

	// leader's job
	if (electionLeader())
	{
		LOG_DBG << fname << "leader now, do schedule";

		auto taskList = retrieveTask();
		auto oldTopology = retrieveTopology("");
		auto nodes = retrieveNode();
		if (nodes.size())
		{
			// find matched hosts for each task
			findTaskAvailableHost(taskList, nodes);

			// schedule task
			auto newTopology = Scheduler::scheduleTask(taskList, oldTopology);

			// apply schedule result
			compareTopologyAndDispatch(oldTopology, newTopology);
		}
	}
	else
	{
		std::string path = std::string(CONSUL_BASE_PATH).append("leader");
		auto resp = requestHttp(web::http::methods::GET, path, {{"raw", "true"}}, {}, nullptr);
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
	if (hostTopologyIt != topology.end())
		newTopology = hostTopologyIt->second;

	if (newTopology)
	{
		auto task = retrieveTask();
		for (const auto &hostApp : newTopology->m_scheduleApps)
		{
			const auto &appName = hostApp.first;
			if (task.count(appName))
			{
				auto &consulTask = task[appName];
				std::shared_ptr<Application> topologyAppObj = consulTask->m_app;
				auto it = std::find_if(currentAllApps.begin(), currentAllApps.end(), [&appName](std::shared_ptr<Application> const &obj)
									   { return obj->getName() == appName; });
				if (it != currentAllApps.end())
				{
					// Update app
					auto &currentRunningApp = *it;
					if (!currentRunningApp->operator==(topologyAppObj))
					{
						Configuration::instance()->addApp(currentRunningApp->AsJson(false))->setUnPersistable();
						LOG_INF << fname << "Consul application <" << currentRunningApp->getName() << "> updated";

						registerService(appName, consulTask->m_consulServicePort);
					}
				}
				else
				{
					// New add app
					Configuration::instance()->addApp(topologyAppObj->AsJson(false))->setUnPersistable();
					LOG_INF << fname << "Consul application <" << topologyAppObj->getName() << "> added";

					registerService(appName, consulTask->m_consulServicePort);
				}
			}
		}

		for (const auto &currentApp : currentAllApps)
		{
			if (currentApp->isCloudApp())
			{
				if (!(newTopology && (newTopology->m_scheduleApps.count(currentApp->getName()))))
				{
					// Remove no used topology
					Configuration::instance()->removeApp(currentApp->getName());
					LOG_INF << fname << "Consul application <" << currentApp->getName() << "> removed";
					deregisterService(currentApp->getName());
				}
			}
		}
	}
	else
	{
		// retrieveTopology will throw if connection was not reached
		for (const auto &currentApp : currentAllApps)
		{
			if (currentApp->isCloudApp())
			{
				// Remove no used topology
				Configuration::instance()->removeApp(currentApp->getName());
				LOG_INF << fname << "Consul application <" << currentApp->getName() << "> removed";
				deregisterService(currentApp->getName());
			}
		}
	}
}

bool ConsulConnection::electionLeader()
{
	const static char fname[] = "ConsulConnection::electionLeader() ";
	// get session id
	std::string sessionId = consulSessionId();
	if (sessionId.empty())
		return false;

	// write hostname to leader path : /appmesh/leader
	std::string path = std::string(CONSUL_BASE_PATH).append("leader");
	auto body = web::json::value::string(MY_HOST_NAME);
	auto timestamp = std::to_string(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
	auto resp = requestHttp(web::http::methods::PUT, path, {{"acquire", sessionId}, {"flags", timestamp}}, {}, &body);
	m_leader = (resp.status_code() == web::http::status_codes::OK);
	LOG_DBG << fname << " m_leader = " << m_leader;
	return m_leader;
}

void ConsulConnection::offlineNode()
{
	const static char fname[] = "ConsulConnection::offlineNode() ";
	LOG_DBG << fname;

	auto path = std::string(CONSUL_BASE_PATH).append("cluster/nodes/").append(MY_HOST_NAME);
	requestHttp(web::http::methods::DEL, path, {}, {}, nullptr);
	path = std::string(CONSUL_BASE_PATH).append("topology/").append(MY_HOST_NAME);
	requestHttp(web::http::methods::DEL, path, {}, {}, nullptr);

	auto currentAllApps = Configuration::instance()->getApps();
	for (const auto &currentApp : currentAllApps)
	{
		if (currentApp->isCloudApp())
		{
			// Remove no used topology
			Configuration::instance()->removeApp(currentApp->getName());
			LOG_INF << fname << "Consul application <" << currentApp->getName() << "> removed";
			deregisterService(currentApp->getName());
		}
	}
}

bool ConsulConnection::registerService(const std::string &appName, int port)
{
	const static char fname[] = "ConsulConnection::registerService() ";
	// https://www.hashicorp.com/blog/consul-and-external-services/
	//curl -X PUT -d
	//  '{"Node": "myhost", "Address": "myhost","Service": {"Service": "mysql", "tags": ["main","v1"], "Port": 3306}}'
	//  http://127.0.0.1:8500/v1/catalog/register

	if (port == 0)
		return false;
	auto serviceId = MY_HOST_NAME + ":" + appName;
	auto body = web::json::value();
	body["ID"] = web::json::value::string(serviceId);
	body["Name"] = web::json::value::string(appName);
	body["Address"] = web::json::value::string(MY_HOST_NAME);
	body["Port"] = web::json::value::number(port);

	auto checkHttpUrl = getConfig()->appmeshUrl() + "/appmesh/app/" + appName + "/health";
	auto check = web::json::value::object();
	check["HTTP"] = web::json::value::string(checkHttpUrl);
	check["Interval"] = web::json::value::string("15s");
	check["Timeout"] = web::json::value::string("5s");
	check["Method"] = web::json::value::string("GET");
	check["TLSSkipVerify"] = web::json::value::boolean(true);
	body["Check"] = check;

	std::string path = "/v1/agent/service/register";
	auto resp = requestHttp(web::http::methods::PUT, path, {{"replace-existing-checks", "true"}}, {}, &body);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		LOG_DBG << fname << "service " << serviceId << " for task <" << appName << "> registered and check URL: " << checkHttpUrl;
		return true;
	}
	return false;
}

bool ConsulConnection::deregisterService(const std::string &appName)
{
	const static char fname[] = "ConsulConnection::deregisterService() ";

	auto serviceId = std::string(MY_HOST_NAME).append(":").append(appName);
	std::string path = std::string("/v1/agent/service/deregister/").append(serviceId);
	auto resp = requestHttp(web::http::methods::PUT, path, {}, {}, NULL);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto result = resp.extract_utf8string(true).get();
		LOG_DBG << fname << "service for task <" << appName << "> removed : " << result;
		return (result == "true");
	}
	return false;
}

void ConsulConnection::saveSecurity(bool checkExistence)
{
	const static char fname[] = "ConsulConnection::saveSecurity() ";

	if (!getConfig()->consulSecurityEnabled())
		return;

	// /appmesh/security
	std::string path = std::string(CONSUL_BASE_PATH).append("security");
	// if check exist and security KV already exist, do nothing
	if (checkExistence && requestHttp(web::http::methods::GET, path, {}, {}, nullptr).status_code() == web::http::status_codes::OK)
	{
		LOG_WAR << fname << path << " already exist, on need override";
		return;
	}
	auto body = Security::instance()->AsJson();
	auto timestamp = std::to_string(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
	web::http::http_response resp = requestHttp(web::http::methods::PUT, path, {{"flags", timestamp}}, {}, &body);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto result = resp.extract_utf8string(true).get();
		if (result != "true")
		{
			LOG_WAR << fname << "PUT " << path << " failed with response : " << result;
		}
	}
}

void ConsulConnection::findTaskAvailableHost(const std::map<std::string, std::shared_ptr<ConsulTask>> &taskMap, const std::map<std::string, std::shared_ptr<ConsulNode>> &hosts)
{
	const static char fname[] = "ConsulConnection::findTaskAvailableHost() ";

	for (const auto &task : taskMap)
	{
		auto taskName = task.first;
		task.second->m_matchedHosts.clear();
		for (const auto &host : hosts)
		{
			auto &hostName = host.first;
			auto &consulHost = host.second;
			auto &taskCondition = task.second->m_condition;
			if (consulHost->m_label->match(taskCondition) && !consulHost->full())
			{
				task.second->m_matchedHosts[hostName] = consulHost;
				LOG_DBG << fname << "task <" << taskName << "> match host <" << hostName << ">";
			}
		}
	}
}

void ConsulConnection::compareTopologyAndDispatch(const std::map<std::string, std::shared_ptr<ConsulTopology>> &oldT, const std::map<std::string, std::shared_ptr<ConsulTopology>> &newT)
{
	for (const auto &newHost : newT)
	{
		if (oldT.count(newHost.first))
		{
			auto equal = true;
			if (newHost.second->m_scheduleApps.size() == oldT.find(newHost.first)->second->m_scheduleApps.size())
			{
				for (const auto &app : newHost.second->m_scheduleApps)
				{
					if (!oldT.find(newHost.first)->second->m_scheduleApps.count(app.first))
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

	for (const auto &oldHost : oldT)
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

	//topology: /appmesh/topology/myhost
	std::string path = std::string(CONSUL_BASE_PATH).append("topology/").append(hostName);
	auto body = web::json::value::object();
	auto timestamp = std::to_string(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
	if (topology && topology->m_scheduleApps.size())
		body = topology->AsJson();
	web::http::http_response resp = requestHttp(web::http::methods::PUT, path, {{"flags", timestamp}}, {}, &body);
	LOG_INF << fname << "write <" << body.serialize() << "> to <" << hostName << ">";

	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto result = resp.extract_utf8string(true).get();
		if (result == "true")
		{
			return true;
		}
		else
		{
			LOG_WAR << fname << "PUT " << path << " failed with response : " << result;
		}
	}
	return false;
}

/*
[
	{
		"CreateIndex": 22935,
		"Flags": 0,
		"Key": "appmesh/topology/",
		"LockIndex": 0,
		"ModifyIndex": 22935,
		"Value": null
	},
	{
		"CreateIndex": 22942,
		"Flags": 0,
		"Key": "appmesh/topology/cents",
		"LockIndex": 0,
		"ModifyIndex": 22942,
		"Value": "WyJteWFwcCJd"
	}
]*/
std::map<std::string, std::shared_ptr<ConsulTopology>> ConsulConnection::retrieveTopology(std::string host)
{
	const static char fname[] = "ConsulConnection::retrieveTopology() ";

	// /appmesh/topology/myhost
	std::map<std::string, std::shared_ptr<ConsulTopology>> topology;
	auto path = std::string(CONSUL_BASE_PATH).append("topology");
	if (host.length())
		path.append("/").append(host);
	auto resp = requestHttp(web::http::methods::GET, path, {{"recurse", "true"}}, {}, nullptr);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto json = resp.extract_json(true).get();
		if (json.is_array())
		{
			for (const auto &section : json.as_array())
			{
				if (HAS_JSON_FIELD(section, "Value"))
				{
					// int consulIndex = GET_JSON_INT_VALUE(section, "ModifyIndex");
					auto hostText = Utility::decode64(GET_JSON_STR_VALUE(section, "Value"));
					if (hostText.empty())
						continue;
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
	return topology;
}

std::map<std::string, std::shared_ptr<ConsulTask>> ConsulConnection::retrieveTask()
{
	const static char fname[] = "ConsulConnection::retrieveTask() ";

	std::map<std::string, std::shared_ptr<ConsulTask>> result;
	// /appmesh/cluster/tasks/myapp
	std::string path = std::string(CONSUL_BASE_PATH).append("cluster/tasks");
	auto resp = requestHttp(web::http::methods::GET, path, {{"recurse", "true"}}, {}, nullptr);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto json = resp.extract_json(true).get();
		if (json.is_array())
		{
			for (const auto &section : json.as_array())
			{
				if (HAS_JSON_FIELD(section, "Value") && GET_JSON_STR_VALUE(section, "Key") != "appmesh/cluster/tasks")
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
	return result;
}

/*
[
	"appmesh/cluster/nodes/cents"
]
*/
std::map<std::string, std::shared_ptr<ConsulNode>> ConsulConnection::retrieveNode()
{
	const static char fname[] = "ConsulConnection::retrieveNode() ";

	std::map<std::string, std::shared_ptr<ConsulNode>> result;
	// /appmesh/cluster/nodes
	std::string path = std::string(CONSUL_BASE_PATH).append("cluster/nodes");
	auto resp = requestHttp(web::http::methods::GET, path, {{"recurse", "true"}}, {}, nullptr);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto json = resp.extract_json(true).get();
		if (json.is_array())
		{
			for (const auto &section : json.as_array())
			{
				if (section.has_string_field("Key") && section.has_string_field("Value") && section.at("Value").as_string().length())
				{
					auto key = GET_JSON_STR_VALUE(section, "Key");
					if (Utility::startWith(key, "appmesh/cluster/nodes/"))
					{
						auto host = Utility::stringReplace(key, "appmesh/cluster/nodes/", "");
						auto value = web::json::value::parse(Utility::decode64(section.at("Value").as_string()));
						result[host] = ConsulNode::FromJson(value, host);
					}
				}
			}
		}
	}
	LOG_DBG << fname << "get nodes size : " << result.size();
	return result;
}

web::json::value ConsulConnection::retrieveNode(const std::string &host)
{
	const static char fname[] = "ConsulConnection::retrieveNode() ";

	// /appmesh/cluster/nodes/myhost
	std::string path = std::string(CONSUL_BASE_PATH).append("cluster/nodes/").append(host);
	auto resp = requestHttp(web::http::methods::GET, path, {{"raw", "true"}}, {}, nullptr);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto json = resp.extract_json(true).get();
		//result = ConsulNode::FromJson(json, host);
		LOG_DBG << fname << "got nodes : " << host;
		return json;
	}
	else
	{
		LOG_DBG << fname << "no node info : " << host;
	}
	return web::json::value();
}

void ConsulConnection::init(std::string recoverSsnId)
{
	const static char fname[] = "ConsulConnection::init() ";
	LOG_DBG << fname;

	{
		std::lock_guard<std::recursive_mutex> guard(m_consulMutex);
		m_config = Configuration::instance()->getConsul();
	}

	if (getConfig()->consulEnabled())
	{
		Utility::initCpprestThreadPool(4); // max threads number is <4> = security + topology + schedule + client

		if (!getConfig()->m_isWorker)
		{
			offlineNode();
		}
		if (recoverSsnId.length())
		{
			releaseSessionId(recoverSsnId);
		}
	}

	// session renew timer
	this->cancelTimer(m_ssnRenewTimerId);
	if (getConfig()->m_ttl > 10 &&
		(getConfig()->m_isMaster || getConfig()->m_isWorker))
	{
		m_ssnRenewTimerId = this->registerTimer(
			0,
			getConfig()->m_ttl - 3,
			std::bind(&ConsulConnection::refreshSession, this, std::placeholders::_1),
			__FUNCTION__);
	}
	else if (getConfig()->consulEnabled())
	{
		releaseSessionId(this->consulSessionId());
		this->consulSessionId("");
	}

	if (getConfig()->consulEnabled())
	{
		// security watch
		if (getConfig()->consulSecurityEnabled())
		{
			m_securityWatch = std::make_shared<std::thread>(std::bind(&ConsulConnection::watchSecurityThread, this));
			m_securityWatch->detach();
		}
		// topology watch
		if (getConfig()->m_isWorker)
		{
			m_topologyWatch = std::make_shared<std::thread>(std::bind(&ConsulConnection::watchTopologyThread, this));
			m_topologyWatch->detach();
		}
		// schedule nodes watch
		if (getConfig()->m_isMaster)
		{
			m_scheduleWatch = std::make_shared<std::thread>(std::bind(&ConsulConnection::watchScheduleThread, this));
			m_scheduleWatch->detach();
		}
	}
}

web::http::http_response ConsulConnection::requestHttp(const web::http::method &mtd, const std::string &path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, web::json::value *body)
{
	const static char fname[] = "ConsulConnection::requestHttp() ";

	auto restURL = getConfig()->m_consulUrl;

	// Create http_client to send the request.
	web::http::client::http_client_config config;
	//config.set_timeout(std::chrono::seconds(5));
	web::credentials cred(getConfig()->m_basicAuthUser, getConfig()->m_basicAuthPass);
	if (getConfig()->m_basicAuthUser.length())
	{
		config.set_credentials(cred);
	}
	config.set_validate_certificates(false);
	web::http::client::http_client client(restURL, config);

	// Build request URI and start the request.
	web::uri_builder builder(GET_STRING_T(path));
	std::for_each(query.begin(), query.end(), [&builder](const std::pair<std::string, std::string> &pair)
				  { builder.append_query(GET_STRING_T(pair.first), GET_STRING_T(pair.second)); });

	web::http::http_request request(mtd);
	for (const auto &h : header)
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
		return response;
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << fname << path << " got exception: " << ex.what();
	}
	catch (...)
	{
		LOG_WAR << fname << path << " exception";
	}

	web::http::http_response response(web::http::status_codes::ResetContent);
	response.set_body(std::string("failed access ").append(restURL));
	return response;
}

web::http::http_response ConsulConnection::requestHttp(const web::uri &baseUri, const std::string &requestPath, const web::http::method &mtd)
{
	const static char fname[] = "ConsulConnection::requestHttp() ";

	// Create http_client to send the request.
	web::http::client::http_client_config config;
	//config.set_timeout(std::chrono::seconds(5));
	config.set_validate_certificates(false);
	web::http::client::http_client client(baseUri, config);
	web::http::http_request request(mtd);
	request.set_request_uri(requestPath);
	try
	{
		// In case of REST server crash or block query timeout, will throw exception:
		// "Failed to read HTTP status line"
		web::http::http_response response = client.request(request).get();
		LOG_DBG << fname << mtd << " " << requestPath << " return " << response.status_code();
		return response;
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << fname << requestPath << " got exception: " << ex.what();
	}
	catch (...)
	{
		LOG_WAR << fname << requestPath << " exception";
	}

	web::http::http_response response(web::http::status_codes::ResetContent);
	response.set_body(std::string("failed access ").append(baseUri.to_string()));
	return response;
}

std::tuple<bool, long long> ConsulConnection::blockWatchKv(const std::string &kvPath, long long lastIndex, bool recurse)
{
	const static char fname[] = "ConsulConnection::blockWatchKv() ";

	auto restURL = getConfig()->m_consulUrl;

	int waitTimeout = 30;
	// Create http_client to send the request.
	web::http::client::http_client_config config;
	web::credentials cred(getConfig()->m_basicAuthUser, getConfig()->m_basicAuthPass);
	if (getConfig()->m_basicAuthUser.length())
	{
		config.set_credentials(cred);
	}
	config.set_timeout(std::chrono::seconds(waitTimeout)); // set block pull to 30s timeout
	config.set_validate_certificates(false);
	web::http::client::http_client client(restURL, config);

	// Build request URI and start the request.
	web::uri_builder builder(GET_STRING_T(kvPath));
	builder.append_query("index", std::to_string(lastIndex));
	builder.append_query("wait", std::to_string(waitTimeout * 1000).append("ms"));
	builder.append_query("stale", "false");
	if (recurse)
	{
		builder.append_query("recurse", "true");
	}

	web::http::http_request request(web::http::methods::GET);
	request.set_request_uri(builder.to_uri());

	try
	{
		web::http::http_response response = client.request(request).get();
		long long index = 0;
		if (response.headers().has("X-Consul-Index"))
		{
			index = std::atoll(response.headers().find("X-Consul-Index")->second.c_str());
		}
		bool success = (response.status_code() == web::http::status_codes::OK);
		LOG_DBG << fname << "watch " << kvPath << " with timeout " << waitTimeout << ", last-index " << lastIndex << " index " << index << " success " << success;
		return std::make_tuple(success, index);
	}
	catch (...)
	{
		// In case of REST server crash or block query timeout, will throw exception:
		// "Failed to read HTTP status line"
		// LOG_DBG << fname << "exception";
	}
	// timeout
	return std::make_tuple(false, 0);
}

void ConsulConnection::watchSecurityThread()
{
	const static char fname[] = "ConsulConnection::watchSecurityThread() ";
	LOG_DBG << fname;

	std::string path = std::string(CONSUL_BASE_PATH).append("security");
	long long index = getModifyIndex(path);
	this->syncSecurity();
	while (getConfig()->consulSecurityEnabled())
	{
		auto result = blockWatchKv(path, index);
		if (std::get<0>(result) || (std::get<1>(result) != index && std::get<1>(result) > 0))
		{
			// watch success
			index = std::get<1>(result);
			this->syncSecurity();
		}
		else
		{
			std::this_thread::sleep_for(std::chrono::seconds(3));
		}
	}
	LOG_DBG << fname << "exit";
}

void ConsulConnection::watchTopologyThread()
{
	const static char fname[] = "ConsulConnection::watchTopologyThread() ";
	LOG_DBG << fname;

	auto path = std::string(CONSUL_BASE_PATH).append("topology/").append(MY_HOST_NAME);
	long long index = getModifyIndex(path);
	this->syncTopology();
	while (getConfig()->m_isWorker)
	{
		auto result = blockWatchKv(path, index);
		if (std::get<0>(result) || (std::get<1>(result) != index && std::get<1>(result) > 0))
		{
			// watch success
			index = std::get<1>(result);
			this->syncTopology();
		}
		else
		{
			std::this_thread::sleep_for(std::chrono::seconds(3));
		}
	}
	LOG_DBG << fname << "exit";
}

void ConsulConnection::watchScheduleThread()
{
	const static char fname[] = "ConsulConnection::watchScheduleThread() ";
	LOG_DBG << fname;

	auto path = std::string(CONSUL_BASE_PATH).append("cluster/");
	long long index = getModifyIndex(path, true);
	this->syncSchedule();
	while (getConfig()->m_isMaster)
	{
		auto result = blockWatchKv(path, index);
		if (std::get<0>(result) || (std::get<1>(result) != index && std::get<1>(result) > 0))
		{
			// watch success
			index = std::get<1>(result);
			this->syncSchedule();
		}
		else
		{
			std::this_thread::sleep_for(std::chrono::seconds(3));
		}
	}
	m_leader = false;
	LOG_DBG << fname << "exit";
}
