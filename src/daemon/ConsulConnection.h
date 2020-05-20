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
	void initTimer(std::string recoverSsnId = "");
	void saveSecurity(bool checkExistance = false);
	std::string consulSessionId();

	void syncSchedule();
	void syncSecurity();
	void syncTopology();

private:
	void reportNode();
	long long getModifyIndex(const std::string& path, bool recurse = false);

	web::http::http_response requestHttp(const web::http::method& mtd, const std::string& path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, web::json::value* body);

	std::tuple<bool, long long> blockWatchKv(const std::string& kvPath, long long lastIndex, bool recurse = false);
	void watchSecurityThread();
	void watchTopologyThread();
	void watchScheduleThread();

	void refreshSession(int timerId = 0);
	std::string requestSessionId();
	std::string renewSessionId();
	void consulSessionId(const std::string& sessionId);
	void releaseSessionId(const std::string& sessionId);

	void doSchedule();
	bool eletionLeader();
	void offlineNode();

	bool registerService(const std::string& appName, int port);
	bool deregisterService(const std::string appName);

	void findTaskAvialableHost(const std::map<std::string, std::shared_ptr<ConsulTask>>& task, const std::map<std::string, std::shared_ptr<ConsulNode>>& hosts);
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

	std::shared_ptr<std::thread> m_securityWatch;
	std::shared_ptr<std::thread> m_topologyWatch;
	std::shared_ptr<std::thread> m_scheduleWatch;
};
