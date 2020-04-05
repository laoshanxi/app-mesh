#pragma once

#include <memory>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <cpprest/http_msg.h>
#include <cpprest/json.h>
#include "Label.h"
#include "TimerHandler.h"

class Application;
class ConsulConnection :public TimerHandler
{
	struct ConsulStatus {
		static std::shared_ptr<ConsulStatus> FromJson(const web::json::value& json);
		web::json::value AsJson();

		std::map<std::string, web::json::value> m_apps;
	};

	struct ConsulNode {
		ConsulNode();
		static std::shared_ptr<ConsulNode> FromJson(const web::json::value& jobj, const std::string& hostName);
		void assignApp(std::shared_ptr<Application>& app);
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
		web::json::value AsJson();
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
		web::json::value AsJson();
		bool operator==(const std::shared_ptr<ConsulTopology>& topology);
		void dump();

		// key: application name
		std::set<std::string> m_apps;
		std::string m_hostName;
	};

public:
	ConsulConnection();
	virtual ~ConsulConnection();
	static std::shared_ptr<ConsulConnection>& instance();
	void initTimer(const std::string& recoveredConsulSsnId = "");
	const std::string getConsulSessionId();

private:
	virtual void reportStatus(int timerId = 0);
	virtual void refreshSession(int timerId = 0);
	virtual void applyTopology(int timerId = 0);

	web::http::http_response requestHttp(const web::http::method& mtd, const std::string& path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, web::json::value* body);
	std::string requestSessionId();
	std::string renewSessionId();
	std::string getSessionId();
	void leaderSchedule();
	void nodeSchedule();
	bool eletionLeader();
	bool registerService(const std::string appName, int port);
	bool deregisterService(const std::string appName);

	void findTaskAvialableHost(std::map<std::string, std::shared_ptr<ConsulTask>>& task, const std::map<std::string, std::shared_ptr<ConsulNode>>& hosts);
	std::map<std::string, std::shared_ptr<ConsulTopology>> scheduleTask(std::map<std::string, std::shared_ptr<ConsulTask>>& taskMap, const std::map<std::string, std::shared_ptr<ConsulTopology>>& oldTopology);
	void compareTopologyAndDispatch(const std::map<std::string, std::shared_ptr<ConsulTopology>>& oldT, const std::map<std::string, std::shared_ptr<ConsulTopology>>& newT);

	bool writeTopology(std::string hostName, const std::shared_ptr<ConsulTopology> topology);
	// key: host name, value: topology
	std::map<std::string, std::shared_ptr<ConsulTopology>> retrieveTopology(std::string host);
	std::map<std::string, std::shared_ptr<ConsulTask>> retrieveTask();
	bool taskChanged(const std::map<std::string, std::shared_ptr<ConsulTask>>& tasks);
	std::map<std::string, std::shared_ptr<ConsulNode>> retrieveNode();

private:
	std::recursive_mutex m_mutex;
	std::string m_sessionId;
	int m_ssnRenewTimerId;
	int m_reportStatusTimerId;
	int m_applyTopoTimerId;
	
	bool m_leader;
};

#define CONSOL_APP_PEERS "CONSOL_APP_PEERS"
