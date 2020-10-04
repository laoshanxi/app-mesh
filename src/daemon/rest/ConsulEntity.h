#pragma once

#include <memory>
#include <map>
#include <set>
#include <string>
#include <cpprest/json.h>

class Application;
class Label;
struct ConsulStatus
{
	static std::shared_ptr<ConsulStatus> FromJson(const web::json::value &json);
	web::json::value AsJson() const;

	std::map<std::string, web::json::value> m_apps;
};

struct ConsulNode
{
	ConsulNode();
	static std::shared_ptr<ConsulNode> FromJson(const web::json::value &jsonObj, const std::string &hostName);

	/// @brief For schedule sort
	/// @param app
	void assignApp(const std::shared_ptr<Application> &app);
	/// @brief For schedule sort
	/// @return
	uint64_t getAssignedAppMem() const;

	std::shared_ptr<Label> m_label;
	// CPU
	std::size_t m_cores;
	// MEM
	uint64_t m_total_bytes;
	uint64_t m_free_bytes;
	std::string m_hostName;
	std::map<std::string, std::shared_ptr<Application>> m_assignedApps;
};

struct ConsulTask
{
	ConsulTask();
	static std::shared_ptr<ConsulTask> FromJson(const web::json::value &jsonObj);
	web::json::value AsJson() const;
	void dump();
	bool operator==(const std::shared_ptr<ConsulTask> &task);

	std::size_t m_replication;
	std::shared_ptr<Application> m_app;

	// schedule parameters
	std::shared_ptr<Label> m_condition;
	int m_priority;

	// consul service port
	int m_consulServicePort;

	// used for schedule fill
	std::map<std::string, std::shared_ptr<ConsulNode>> m_matchedHosts;
	/// @brief Used for schedule fill, store all index, index start from 1
	std::set<int> m_taskIndexDic;
};

struct ConsulTopology
{
	static std::shared_ptr<ConsulTopology> FromJson(const web::json::value &jsonObj, const std::string &hostName);
	web::json::value AsJson() const;
	bool operator==(const std::shared_ptr<ConsulTopology> &topology);
	void dump();

	/// @brief Topology is organized by host for performance consideration
	std::string m_hostName;
	/// @brief Dispatched tasks on this host
	/// key: app name. value: app index id to identify the unique instance index for one consul task
	std::map<std::string, int> m_scheduleApps;
};
