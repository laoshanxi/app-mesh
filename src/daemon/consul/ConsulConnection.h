#pragma once

#include <map>
#include <memory>
#include <set>
#include <string>
#include <thread>

#include <cpprest/http_msg.h>
#include <cpprest/json.h>

#include "../../common/TimerHandler.h"
#include "../Configuration.h"
#include "../Label.h"
#include "ConsulEntity.h"

/// <summary>
/// Connect to Consul service
///  1. main node: elect leader and do the scheduler
///  2. work node: watch task dispatch and manage local cloud application accordingly
///  3. sync security: sync consul security to local
/// </summary>
class ConsulConnection : public TimerHandler
{
public:
	ConsulConnection();
	virtual ~ConsulConnection();
	static std::shared_ptr<ConsulConnection> &instance();
	void init(const std::string &recoverSsnId = "");
	void saveSecurity(bool checkExistence = false);
	std::string consulSessionId();
	web::json::value viewCloudApps();
	web::json::value viewCloudApp(const std::string &app);
	web::http::http_response viewCloudAppOutput(const std::string &app, const std::string &hostName, const std::map<std::string, std::string> &query, const web::http::http_headers &headers);
	web::json::value addCloudApp(const std::string &app, web::json::value &content);
	web::json::value getCloudNodes();
	void deleteCloudApp(const std::string &app);
	int getHealthStatus(const std::string &host, const std::string &app);

	void syncSchedule();
	void syncSecurity();
	void syncTopology();

private:
	void reportNode();
	long long getModifyIndex(const std::string &path, bool recurse = false);
	std::shared_ptr<Configuration::JsonConsul> getConfig();

	web::http::http_response requestConsul(const web::http::method &mtd, const std::string &path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, web::json::value *body);
	web::http::http_response requestAppMesh(const web::uri &baseUri, const std::string &requestPath, const web::http::method &mtd, const std::map<std::string, std::string> &query, const web::http::http_headers &headers);

	std::tuple<bool, long long> blockWatchKv(const std::string &kvPath, long long lastIndex, bool recurse = false);
	void watchSecurityThread();
	void watchTopologyThread();
	void watchScheduleThread();

	void refreshSession(int timerId = INVALID_TIMER_ID);
	std::string requestSessionId();
	std::string renewSessionId();
	void consulSessionId(const std::string &sessionId);
	void releaseSessionId(const std::string &sessionId);

	void doSchedule();
	bool electionLeader();
	void offlineNode();

	bool registerService(const std::string &appName, int port);
	bool deregisterService(const std::string &appName);

	void findTaskAvailableHost(const std::map<std::string, std::shared_ptr<ConsulTask>> &task, const std::map<std::string, std::shared_ptr<ConsulNode>> &hosts);
	void compareTopologyAndDispatch(const std::map<std::string, std::shared_ptr<ConsulTopology>> &oldT, const std::map<std::string, std::shared_ptr<ConsulTopology>> &newT);
	bool writeTopology(std::string hostName, const std::shared_ptr<ConsulTopology> topology);
	// key: host name, value: topology
	std::map<std::string, std::shared_ptr<ConsulTopology>> retrieveTopology(std::string host);
	std::map<std::string, std::shared_ptr<ConsulTask>> retrieveTask();
	std::map<std::string, std::shared_ptr<ConsulNode>> retrieveNode();
	web::json::value retrieveNode(const std::string &host);

private:
	mutable std::recursive_mutex m_consulMutex;
	std::string m_sessionId;
	int m_ssnRenewTimerId;
	bool m_leader;
	std::shared_ptr<Configuration::JsonConsul> m_config;

	std::shared_ptr<std::thread> m_securityWatch;
	std::shared_ptr<std::thread> m_topologyWatch;
	std::shared_ptr<std::thread> m_scheduleWatch;
};
