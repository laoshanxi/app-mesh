#pragma once

#include <map>
#include <memory>
#include <set>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

#include "../../common/TimerHandler.h"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "../Label.h"
#include "ConsulEntity.h"

class CurlResponse;

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
	nlohmann::json viewCloudApps();
	nlohmann::json viewCloudApp(const std::string &app);
	std::shared_ptr<CurlResponse> viewCloudAppOutput(const std::string &app, const std::string &hostName, const std::map<std::string, std::string> &query, const std::map<std::string, std::string> &headers);
	nlohmann::json addCloudApp(const std::string &app, nlohmann::json &content);
	nlohmann::json getCloudNodes();
	void deleteCloudApp(const std::string &app);
	int getHealthStatus(const std::string &host, const std::string &app);

	void syncSchedule();
	void syncSecurity();
	void syncTopology();

private:
	void reportNode();
	long long getModifyIndex(const std::string &path, bool recurse = false);
	std::shared_ptr<Configuration::JsonConsul> getConfig();

	std::shared_ptr<CurlResponse> requestConsul(const web::http::method &mtd, const std::string &path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, nlohmann::json *body, int timeoutSec = REST_REQUEST_TIMEOUT_SECONDS);
	std::shared_ptr<CurlResponse> requestAppMesh(const std::string &baseUri, const std::string &requestPath, const web::http::method &mtd, const std::map<std::string, std::string> &query, const std::map<std::string, std::string> &headers);

	std::tuple<bool, long long> blockWatchKv(const std::string &kvPath, long long lastIndex, bool recurse = false);
	void watchSecurityThread();
	void watchTopologyThread();
	void watchScheduleThread();

	void refreshSession();
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
	nlohmann::json retrieveNode(const std::string &host);

private:
	mutable std::recursive_mutex m_consulMutex;
	std::string m_sessionId;
	long m_ssnRenewTimerId;
	bool m_leader;
	std::shared_ptr<Configuration::JsonConsul> m_config;

	std::shared_ptr<std::thread> m_securityWatch;
	std::shared_ptr<std::thread> m_topologyWatch;
	std::shared_ptr<std::thread> m_scheduleWatch;
};
