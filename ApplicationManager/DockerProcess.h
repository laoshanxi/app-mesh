#ifndef APP_DOCKER_PROCESS_H
#define APP_DOCKER_PROCESS_H
#include <map>
#include <string>
#include <algorithm>
#include <chrono>
#include <thread>
#include <ace/Process.h>
#include "AppProcess.h"
#include "MonitoredProcess.h"

//////////////////////////////////////////////////////////////////////////
// Docker Process Object
//////////////////////////////////////////////////////////////////////////
class DockerProcess :public AppProcess
{
public:
	DockerProcess(int cacheOutputLines, std::string dockerImage);
	virtual ~DockerProcess();

	// override with docker behavior
	virtual void killgroup(int timerId = 0) override;
	virtual int spawnProcess(std::string cmd, std::string user, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit) override;
	virtual int syncSpawnProcess(std::string cmd, std::string user, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit);

	virtual std::string containerId() override;
	virtual void containerId(std::string containerId) override;

	// docker logs
	virtual std::string getOutputMsg() override;
	virtual std::string fetchOutputMsg() override;

private:
	std::string getFirstLine(const std::string str);

private:
	std::string m_dockerImage;
	std::string m_containerId;
	std::shared_ptr<std::thread> m_spawnThread;
	std::recursive_mutex m_mutex;

	std::chrono::system_clock::time_point m_lastFetchTime;
};

#endif 