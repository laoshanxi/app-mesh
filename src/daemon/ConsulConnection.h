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
	enum class Role { Master, Node, All, Nothing };
	struct ConsulStatus {
		static std::shared_ptr<ConsulStatus> FromJson(const web::json::value& json);
		web::json::value AsJson();

		std::map<std::string, web::json::value> m_apps;
	};
	struct ConsulTask {
		ConsulTask();
		static std::shared_ptr<ConsulTask> FromJson(const web::json::value& jobj);
		web::json::value AsJson();
		void dump();

		size_t m_replication;
		std::shared_ptr<Application> m_app;
		
		// schedule parameters
		std::shared_ptr<Label> m_condition;
		int m_priority;

		// used for schedule fill
		std::set<std::string> m_findMatchedHosts;
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

	void findTaskAvialableHost(std::map<std::string, std::shared_ptr<ConsulTask>>& task, const std::map<std::string, std::shared_ptr<Label>>& hosts);
	std::map<std::string, std::set<std::string>> scheduleTask(std::map<std::string, std::shared_ptr<ConsulTask>>& taskMap, const std::map<std::string, std::set<std::string>>& oldTopology);
	void compareTopologyAndDispatch(std::map<std::string, std::set<std::string>>& oldT, std::map<std::string, std::set<std::string>>& newT);

	bool writeTopology(const std::string& host, const std::set<std::string>& apps);
	std::map<std::string, std::set<std::string>> retrieveTopology(std::string host);
	std::map<std::string, std::shared_ptr<ConsulTask>> retrieveTask();
	std::map<std::string, std::shared_ptr<Label>> retrieveNode();

private:
	std::recursive_mutex m_mutex;
	std::string m_consulUrl;
	std::string m_sessionId;
	int m_ssnRenewTimerId;
	int m_reportStatusTimerId;
	int m_applyTopoTimerId;
};

