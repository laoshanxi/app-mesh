#ifndef APP_DOCKER_PROCESS_H
#define APP_DOCKER_PROCESS_H
#include <map>
#include <string>
#include <algorithm>
#include <ace/Process.h>
#include "Process.h"

//////////////////////////////////////////////////////////////////////////
// Docker Process Object
//////////////////////////////////////////////////////////////////////////
class DockerProcess :public Process
{
public:
	DockerProcess(std::string dockerImage);
	virtual ~DockerProcess();
	
	// override with docker behavior
	virtual void killgroup(int timerId = 0) override;
	virtual int spawnProcess(std::string cmd, std::string user, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit) override;
private:
	std::string m_dockerImage;
	std::string m_containerId;
	std::recursive_mutex m_mutex;
};

#endif 