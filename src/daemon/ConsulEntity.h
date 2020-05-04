#pragma once

#include <memory>
#include <map>
#include <set>
#include <string>

class Application;
class Label;
struct ConsulStatus {
	static std::shared_ptr<ConsulStatus> FromJson(const web::json::value& json);
	web::json::value AsJson() const;

	std::map<std::string, web::json::value> m_apps;
};

struct ConsulNode {
	ConsulNode();
	static std::shared_ptr<ConsulNode> FromJson(const web::json::value& jobj, const std::string& hostName);
	void assignApp(const std::shared_ptr<Application>& app);
	uint64_t getAssignedAppMem() const;
	std::shared_ptr<Label> m_label;
	// CPU
	size_t m_cores;
	// MEM
	uint64_t m_total_bytes;
	uint64_t m_free_bytes;
	std::string m_hostName;
	std::map<std::string, std::shared_ptr<Application>> m_assignedApps;
};

struct ConsulTask {
	ConsulTask();
	static std::shared_ptr<ConsulTask> FromJson(const web::json::value& jobj);
	web::json::value AsJson() const;
	void dump();
	bool operator==(const std::shared_ptr<ConsulTask>& task);

	size_t m_replication;
	std::shared_ptr<Application> m_app;

	// schedule parameters
	std::shared_ptr<Label> m_condition;
	int m_priority;

	// consul service port
	int m_consulServicePort;

	// used for schedule fill
	std::map<std::string, std::shared_ptr<ConsulNode>> m_matchedHosts;
};

struct ConsulTopology {
	static std::shared_ptr<ConsulTopology> FromJson(const web::json::value& jobj, const std::string& hostName);
	web::json::value AsJson() const;
	bool operator==(const std::shared_ptr<ConsulTopology>& topology);
	void dump();

	// key: application name
	std::set<std::string> m_apps;
	std::string m_hostName;
};
