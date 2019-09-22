#ifndef APP_PROCESS_H
#define APP_PROCESS_H
#include <map>
#include <string>
#include <algorithm>

#include <ace/Process.h>

#include "LinuxCgroup.h"
#include "ResourceLimitation.h"
#include "TimerHandler.h"

//////////////////////////////////////////////////////////////////////////
// Process Object
//////////////////////////////////////////////////////////////////////////
class Process :public ACE_Process, public TimerHandler
{
public:
	Process(int cacheOutputLines = 256);
	virtual ~Process();

	void attach(int pid);
	virtual void killgroup(int timerId = 0);
	virtual void setCgroup(std::shared_ptr<ResourceLimitation>& limit);
	const std::string getuuid() const;
	void regKillTimer(size_t timeoutSec, const std::string from);
	virtual std::string containerId() { return std::string(); };
	virtual void containerId(std::string containerId) {};

	virtual int spawnProcess(std::string cmd, std::string user, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit);
	static void getSysProcessList(std::map<std::string, int>& processList, const void* pt = nullptr);

	virtual std::string getOutputMsg();
	virtual std::string fetchOutputMsg();
protected:
	const int m_cacheOutputLines;
private:
	std::shared_ptr<LinuxCgroup> m_cgroup;
	std::shared_ptr<ResourceLimitation> m_resourceLimit;
	std::string m_uuid;
	int m_killTimerId;
};

#endif 

