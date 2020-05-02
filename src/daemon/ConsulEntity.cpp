#include <algorithm>
#include <thread>
#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include "Application.h"
#include "Label.h"
#include "ConsulConnection.h"
#include "Configuration.h"
#include "ResourceCollection.h"
#include "../common/Utility.h"

std::shared_ptr<ConsulStatus> ConsulStatus::FromJson(const web::json::value& json)
{
	auto consul = std::make_shared<ConsulStatus>();
	for (const auto& app : json.as_object())
	{
		consul->m_apps[GET_STD_STRING(app.first)] = app.second;
	}
	return consul;
}

web::json::value ConsulStatus::AsJson()
{
	auto result = web::json::value::object();
	for (const auto& app : m_apps)
	{
		result[app.first] = app.second;
	}
	return result;
}

ConsulTask::ConsulTask()
	:m_replication(0), m_priority(0), m_consulServicePort(0)
{
	m_condition = std::make_shared<Label>();
}

std::shared_ptr<ConsulTask> ConsulTask::FromJson(const web::json::value& jobj)
{
	auto consul = std::make_shared<ConsulTask>();
	if (HAS_JSON_FIELD(jobj, "content") && HAS_JSON_FIELD(jobj, "replication") &&
		jobj.at("replication").is_integer() &&
		jobj.at("content").is_object())
	{
		auto appJson = jobj.at("content");
		// mark consul application flag
		appJson[JSON_KEY_APP_CLOUD] = web::json::value::boolean(true);
		consul->m_app = Configuration::instance()->parseApp(appJson);
		SET_JSON_INT_VALUE(jobj, "replication", consul->m_replication);
		SET_JSON_INT_VALUE(jobj, "priority", consul->m_priority);
		SET_JSON_INT_VALUE(jobj, "port", consul->m_consulServicePort);
		if (HAS_JSON_FIELD(jobj, "condition"))
		{
			consul->m_condition = Label::FromJson(jobj.at("condition"));
		}
	}
	return consul;
}

web::json::value ConsulTask::AsJson()
{
	auto result = web::json::value::object();
	result["replication"] = web::json::value::number(m_replication);
	result["priority"] = web::json::value::number(m_priority);
	result["port"] = web::json::value::number(m_consulServicePort);
	result["content"] = m_app->AsJson(false);
	if (m_condition != nullptr) result["condition"] = m_condition->AsJson();
	return result;
}

void ConsulTask::dump()
{
	const static char fname[] = "ConsulTask::dump() ";
	LOG_DBG << fname << "m_app=" << m_app->getName();
	LOG_DBG << fname << "m_priority=" << m_priority;
	LOG_DBG << fname << "m_replication=" << m_replication;
	m_app->dump();
}

bool ConsulTask::operator==(const std::shared_ptr<ConsulTask>& task)
{
	if (!task) return false;
	return m_replication == task->m_replication &&
		m_priority == task->m_priority &&
		m_consulServicePort == task->m_consulServicePort &&
		m_app->operator==(task->m_app) &&
		m_condition->operator==(task->m_condition);
}
/*
		"topology": {
			"myhost": [
				{"app": "myapp", "peer_hosts": ["hosts"] },
				{"app": "myapp2" }],
			"host2": ["myapp", "myapp2"]
		}
*/
std::shared_ptr<ConsulTopology> ConsulTopology::FromJson(const web::json::value& jobj, const std::string& hostName)
{
	auto topology = std::make_shared<ConsulTopology>();
	topology->m_hostName = hostName;
	if (jobj.is_array())
	{
		for (const auto& app : jobj.as_array())
		{
			auto appName = GET_JSON_STR_VALUE(app, "app");
			topology->m_apps.insert(appName);
		}
	}
	return std::move(topology);
}

web::json::value ConsulTopology::AsJson()
{
	auto result = web::json::value::array(m_apps.size());
	size_t appIndex = 0;
	for (const auto& app : m_apps)
	{
		auto appJson = web::json::value::object();
		appJson["app"] = web::json::value::string(app);
		result[appIndex++] = appJson;
	}
	return std::move(result);
}

bool ConsulTopology::operator==(const std::shared_ptr<ConsulTopology>& topology)
{
	if (!topology) return false;
	if (m_apps.size() != topology->m_apps.size()) return false;

	for (const auto& app : m_apps)
	{
		if (topology->m_apps.count(app) == 0) return false;
	}
	return true;
}

void ConsulTopology::dump()
{
	const static char fname[] = "ConsulTopology::dump() ";
	for (const auto& app : m_apps)
	{
		LOG_DBG << fname << "app:" << app << " host:" << m_hostName;
	}
}

ConsulNode::ConsulNode()
	:m_label(std::make_shared<Label>()), m_cores(0), m_total_bytes(0), m_free_bytes(0)
{
}

std::shared_ptr<ConsulNode> ConsulNode::FromJson(const web::json::value& jobj, const std::string& hostName)
{
	auto node = std::make_shared<ConsulNode>();
	node->m_hostName = hostName;
	if (HAS_JSON_FIELD(jobj, "label"))
	{
		node->m_label = Label::FromJson(jobj.at("label"));
	}
	if (HAS_JSON_FIELD(jobj, "cpu_cores"))
	{
		node->m_cores = GET_JSON_INT_VALUE(jobj, "cpu_cores");
	}
	if (HAS_JSON_FIELD(jobj, "mem_free_bytes"))
	{
		node->m_free_bytes = GET_JSON_NUMBER_VALUE(jobj, "mem_free_bytes");
	}
	if (HAS_JSON_FIELD(jobj, "mem_total_bytes"))
	{
		node->m_total_bytes = GET_JSON_NUMBER_VALUE(jobj, "mem_total_bytes");
	}
	return node;
}

void ConsulNode::assignApp(const std::shared_ptr<Application>& app)
{
	m_assignedApps[app->getName()] = app;
}

uint64_t ConsulNode::getAssignedAppMem() const
{
	return uint64_t(0);
}
