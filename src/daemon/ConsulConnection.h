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
#include "ConsulEntity.h"

class ConsulConnection :public TimerHandler
{
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
