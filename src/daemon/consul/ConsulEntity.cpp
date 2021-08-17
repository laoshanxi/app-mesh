#include <algorithm>
#include <thread>

#include <cpprest/http_client.h>
#include <cpprest/json.h>

#include "../../common/DateTime.h"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "../Label.h"
#include "../ResourceCollection.h"
#include "../application/Application.h"
#include "ConsulConnection.h"

ConsulTask::ConsulTask()
	: m_replication(0), m_condition(std::make_shared<Label>()), m_priority(0), m_consulServicePort(0), m_requestMemMega(0)
{
}

std::shared_ptr<ConsulTask> ConsulTask::FromJson(const web::json::value &jsonObj)
{
	auto consul = std::make_shared<ConsulTask>();
	if (HAS_JSON_FIELD(jsonObj, "content") && HAS_JSON_FIELD(jsonObj, "replication") &&
		jsonObj.at("replication").is_integer() &&
		jsonObj.at("content").is_object())
	{
		auto appJson = jsonObj.at("content");
		// mark consul application flag
		appJson[JSON_KEY_APP_metadata] = CLOUD_STR_JSON;
		consul->m_app = Configuration::instance()->parseApp(appJson);
		SET_JSON_INT_VALUE(jsonObj, "replication", consul->m_replication);
		SET_JSON_INT_VALUE(jsonObj, "priority", consul->m_priority);
		SET_JSON_INT_VALUE(jsonObj, "port", consul->m_consulServicePort);
		SET_JSON_INT_VALUE(jsonObj, "memoryMB", consul->m_requestMemMega);
		if (HAS_JSON_FIELD(jsonObj, "condition"))
		{
			consul->m_condition = Label::FromJson(jsonObj.at("condition"));
		}
		// for schedule runtime
		for (std::size_t i = 1; i <= consul->m_replication; i++)
		{
			consul->m_tasksSet.insert(i);
		}
	}
	return consul;
}

web::json::value ConsulTask::AsJson() const
{
	auto result = web::json::value::object();
	result["replication"] = web::json::value::number(m_replication);
	result["priority"] = web::json::value::number(m_priority);
	result["port"] = web::json::value::number(m_consulServicePort);
	result["memoryMB"] = web::json::value::number(m_requestMemMega);
	result["content"] = m_app->AsJson(false);
	if (m_condition != nullptr)
		result["condition"] = m_condition->AsJson();
	return result;
}

void ConsulTask::dump()
{
	const static char fname[] = "ConsulTask::dump() ";
	LOG_DBG << fname << "m_app=" << m_app->getName();
	LOG_DBG << fname << "m_priority=" << m_priority;
	LOG_DBG << fname << "m_replication=" << m_replication;
	LOG_DBG << fname << "m_consulServicePort=" << m_consulServicePort;
	LOG_DBG << fname << "m_requestMemMega=" << m_requestMemMega;
	m_app->dump();
}

bool ConsulTask::operator==(const std::shared_ptr<ConsulTask> &task)
{
	if (!task)
		return false;
	return m_replication == task->m_replication &&
		   m_priority == task->m_priority &&
		   m_consulServicePort == task->m_consulServicePort &&
		   m_app->operator==(task->m_app) &&
		   m_condition->operator==(task->m_condition);
}

std::shared_ptr<ConsulTopology> ConsulTopology::FromJson(const web::json::value &jsonObj, const std::string &hostName)
{
	auto topology = std::make_shared<ConsulTopology>();
	topology->m_hostName = hostName;
	if (jsonObj.is_array())
	{
		for (const auto &app : jsonObj.as_array())
		{
			auto appName = GET_JSON_STR_VALUE(app, "app");
			auto appScheduleTime = GET_JSON_STR_VALUE(app, "schedule_time");
			topology->m_scheduleApps[appName] = DateTime::parseISO8601DateTime(appScheduleTime);
		}
	}
	return topology;
}

web::json::value ConsulTopology::AsJson() const
{
	auto result = web::json::value::array(m_scheduleApps.size());
	std::size_t appIndex = 0;
	for (const auto &app : m_scheduleApps)
	{
		auto appJson = web::json::value::object();
		appJson["app"] = web::json::value::string(app.first);
		appJson["schedule_time"] = web::json::value::string(DateTime::formatLocalTime(app.second));
		result[appIndex++] = appJson;
	}
	return result;
}

bool ConsulTopology::operator==(const std::shared_ptr<ConsulTopology> &topology)
{
	if (!topology)
		return false;
	if (m_scheduleApps.size() != topology->m_scheduleApps.size())
		return false;

	for (const auto &app : m_scheduleApps)
	{
		if (topology->m_scheduleApps.count(app.first) == 0)
			return false;
	}
	return true;
}

void ConsulTopology::dump()
{
	const static char fname[] = "ConsulTopology::dump() ";
	for (const auto &app : m_scheduleApps)
	{
		LOG_DBG << fname << "app:" << app.first << " host:" << m_hostName;
	}
}

ConsulNode::ConsulNode()
	: m_label(std::make_shared<Label>()), m_cores(0), m_total_bytes(0), m_occupyMemoryBytes(0), m_leader(false)
{
}

std::shared_ptr<ConsulNode> ConsulNode::FromJson(const web::json::value &jsonObj, const std::string &hostName)
{
	auto node = std::make_shared<ConsulNode>();
	node->m_hostName = hostName;
	if (HAS_JSON_FIELD(jsonObj, "label"))
	{
		node->m_label = Label::FromJson(jsonObj.at("label"));
	}
	if (HAS_JSON_FIELD(jsonObj, "appmesh"))
	{
		node->m_appmeshProxyUrl = GET_JSON_STR_VALUE(jsonObj, "appmesh");
	}
	if (HAS_JSON_FIELD(jsonObj, "leader"))
	{
		node->m_leader = GET_JSON_BOOL_VALUE(jsonObj, "leader");
	}
	if (HAS_JSON_FIELD(jsonObj, "resource"))
	{
		auto resourceJson = jsonObj.at("resource");
		if (HAS_JSON_FIELD(resourceJson, "cpu_cores"))
		{
			node->m_cores = GET_JSON_INT_VALUE(resourceJson, "cpu_cores");
		}
		if (HAS_JSON_FIELD(resourceJson, "mem_total_bytes"))
		{
			node->m_total_bytes = GET_JSON_NUMBER_VALUE(resourceJson, "mem_total_bytes");
		}
	}

	return node;
}

web::json::value ConsulNode::AsJson() const
{
	auto result = web::json::value::object();
	result["appmesh"] = web::json::value::string(m_appmeshProxyUrl);
	result["label"] = m_label->AsJson();
	auto resource = web::json::value::object();
	resource["cpu_cores"] = web::json::value::number(m_cores);
	resource["mem_total_bytes"] = web::json::value::number(m_total_bytes);
	result["resource"] = resource;
	result["leader"] = web::json::value::boolean(m_leader);
	return result;
}

void ConsulNode::dump()
{
	const static char fname[] = "ConsulNode::dump() ";
	LOG_DBG << fname << "m_hostName=" << m_hostName;
	LOG_DBG << fname << "m_leader=" << m_leader;
	LOG_DBG << fname << "m_appmeshProxyUrl=" << m_appmeshProxyUrl;
	LOG_DBG << fname << "m_occupyMemoryBytes=" << m_occupyMemoryBytes;
	LOG_DBG << fname << "m_total_bytes=" << m_total_bytes;
	LOG_DBG << fname << "full=" << full();
	LOG_DBG << fname << "m_cores=" << m_cores;
	for (auto app : m_assignedApps)
	{
		LOG_DBG << fname << "m_assignedApps=" << app.second->getName();
	}
}

void ConsulNode::assignApp(const std::shared_ptr<ConsulTask> &task)
{
	m_assignedApps[task->m_app->getName()] = task->m_app;
	m_occupyMemoryBytes += task->m_requestMemMega * 1024 * 1024;
}

bool ConsulNode::tryAssignApp(const std::shared_ptr<ConsulTask> &task)
{
	const static char fname[] = "ConsulNode::tryAssignApp() ";

	auto result = (m_occupyMemoryBytes + (task->m_requestMemMega * 1024 * 1024)) < m_total_bytes;
	if (!result)
	{
		LOG_INF << fname << "requestMemMega <" << task->m_requestMemMega << "> can not assigned to host <" << m_hostName << ">";
		this->dump();
	}
	return result;
}

bool ConsulNode::full()
{
	return m_occupyMemoryBytes >= m_total_bytes;
}

uint64_t ConsulNode::getAssignedAppMem() const
{
	return m_occupyMemoryBytes;
}
