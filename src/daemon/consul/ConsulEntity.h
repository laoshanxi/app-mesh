#pragma once

#include <chrono>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <tuple>

#include <nlohmann/json.hpp>

class Application;
class Label;

struct ConsulTask;
/// <summary>
/// Consul Node definition
/// </summary>
struct ConsulNode
{
	ConsulNode();
	static std::shared_ptr<ConsulNode> FromJson(const nlohmann::json &jsonObj, const std::string &hostName);
	nlohmann::json AsJson() const;
	void dump();

	/// @brief For schedule sort
	/// @param app
	void assignApp(const std::shared_ptr<ConsulTask> &task);
	bool tryAssignApp(const std::shared_ptr<ConsulTask> &task);
	bool full();
	/// @brief For schedule sort
	/// @return
	uint64_t getAssignedAppMem() const;

	std::shared_ptr<Label> m_label;
	// CPU
	std::size_t m_cores;
	// MEM
	uint64_t m_total_bytes;
	uint64_t m_occupyMemoryBytes;
	std::string m_appmeshProxyUrl;
	std::string m_hostName;
	bool m_leader;
	std::map<std::string, std::shared_ptr<Application>> m_assignedApps;
};

/// <summary>
/// Cluster level application definition with replication and node selector
/// </summary>
struct ConsulTask
{
	ConsulTask();
	static std::shared_ptr<ConsulTask> FromJson(const nlohmann::json &jsonObj);
	nlohmann::json AsJson() const;
	void dump();
	bool operator==(const std::shared_ptr<ConsulTask> &task);

	std::size_t m_replication;
	std::shared_ptr<Application> m_app;

	// schedule parameters
	std::shared_ptr<Label> m_condition;
	int m_priority;

	// consul service port
	int m_consulServicePort;

	// request memory, MB
	uint64_t m_requestMemMega;

	// used for schedule fill
	std::map<std::string, std::shared_ptr<ConsulNode>> m_matchedHosts;
	/// @brief Used for schedule fill, store all index, index start from 1
	/// If one task have 4 replica, the set will have 1,2,3,4
	std::set<int> m_tasksSet;
};

/// <summary>
/// Topology is leader schedule result
/// </summary>
struct ConsulTopology
{
	static std::shared_ptr<ConsulTopology> FromJson(const nlohmann::json &jsonObj, const std::string &hostName);
	nlohmann::json AsJson() const;
	bool operator==(const std::shared_ptr<ConsulTopology> &topology);
	void dump();

	/// @brief Topology is organized by host for performance consideration
	std::string m_hostName;
	/// @brief Dispatched tasks on this host
	/// key: app name. value: <date time>
	std::map<std::string, std::chrono::system_clock::time_point> m_scheduleApps;
};
