#ifndef APP_DOCKER_PROCESS_H
#define APP_DOCKER_PROCESS_H
#include <map>
#include <string>
#include <algorithm>
#include <chrono>
#include <thread>
#include <ace/Process.h>
#include "Process.h"

//////////////////////////////////////////////////////////////////////////
// Docker Process Object
//////////////////////////////////////////////////////////////////////////
class DockerProcess :public Process
{
public:
	DockerProcess(int cacheOutputLines, std::string dockerImage);
	virtual ~DockerProcess();
	
	// override with docker behavior
	virtual void killgroup(int timerId = 0) override;
	virtual int spawnProcess(std::string cmd, std::string user, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit) override;
	virtual int asyncSpawnProcess(std::string cmd, std::string user, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit);

	// docker logs
	virtual std::string getOutputMsg() override;
	virtual std::string fetchOutputMsg() override;

	void checkStartThreadTimer(int timerId);
private:
	std::string m_dockerImage;
	std::string m_containerId;
	std::shared_ptr<std::thread> m_spawnThread;
	std::recursive_mutex m_mutex;

	std::chrono::system_clock::time_point m_lastFetchTime;
};

#endif 