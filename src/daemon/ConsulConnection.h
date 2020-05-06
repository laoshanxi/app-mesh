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
#include "AppProcess.h"

class ConsulConnection :public TimerHandler
{
public:
	ConsulConnection();
	virtual ~ConsulConnection();
	static std::shared_ptr<ConsulConnection>& instance();
	void initTimer(const std::string& recoveredConsulSsnId = "");
	const std::string getConsulSessionId();
	void saveSecurity(bool checkExistance = false);

	void syncSchedule();
	void syncSecurity();
	void syncTopology();

private:
	virtual void reportNode();
	virtual void refreshSession(int timerId = 0);
	long long getModifyIndex(const std::string& path);

	web::http::http_response requestHttp(const web::http::method& mtd, const std::string& path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, web::json::value* body);
	std::string requestSessionId();
	std::string renewSessionId();
	std::string getSessionId();
	void leaderSchedule();
	void regWatchApp(const std::string& name, const std::string& cmd, const std::string& dockerImg);
	bool eletionLeader();
	bool registerService(const std::string& appName, int port);
	bool deregisterService(const std::string appName);

	void findTaskAvialableHost(const std::map<std::string, std::shared_ptr<ConsulTask>>& task, const std::map<std::string, std::shared_ptr<ConsulNode>>& hosts);
	std::map<std::string, std::shared_ptr<ConsulTopology>> scheduleTask(const std::map<std::string, std::shared_ptr<ConsulTask>>& taskMap, const std::map<std::string, std::shared_ptr<ConsulTopology>>& oldTopology);
	void compareTopologyAndDispatch(const std::map<std::string, std::shared_ptr<ConsulTopology>>& oldT, const std::map<std::string, std::shared_ptr<ConsulTopology>>& newT);

	bool writeTopology(std::string hostName, const std::shared_ptr<ConsulTopology> topology);
	// key: host name, value: topology
	std::map<std::string, std::shared_ptr<ConsulTopology>> retrieveTopology(std::string host);
	std::map<std::string, std::shared_ptr<ConsulTask>> retrieveTask();
	std::map<std::string, std::shared_ptr<ConsulNode>> retrieveNode();

private:
	std::string m_sessionId;
	int m_ssnRenewTimerId;
	bool m_leader;
};
