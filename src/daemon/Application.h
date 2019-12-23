#ifndef APPLICATION_DEFINITION_H
#define APPLICATION_DEFINITION_H

#include <memory>
#include <string>
#include <map>
#include <mutex>
#include <chrono>
#include <cpprest/json.h>

#include "AppProcess.h"
#include "MonitoredProcess.h"
#include "DailyLimitation.h"
#include "ResourceLimitation.h"
#include "TimerHandler.h"
#include "../common/Utility.h"


/**
* @class Application
*
* @brief An Application is used to define and manage a process job.
*
*/
class Application : public TimerHandler
{
public:
	Application();
	virtual ~Application();
	const std::string getName() const;
	bool isEnabled();
	bool isUnAvialable();
	static void FromJson(std::shared_ptr<Application>& app, const web::json::value& obj);

	virtual void refreshPid();
	bool attach(std::map<std::string, int>& process);
	bool attach(int pid);

	// Invoke immediately
	virtual void invokeNow(int timerId);
	// Invoke by scheduler
	virtual void invoke();
	
	virtual void disable();
	virtual void enable();

	// run app in a new process object
	std::string runApp(int timeoutSeconds);
	std::string runAsyncrize(int timeoutSeconds);
	std::string runSyncrize(int timeoutSeconds, void* asyncHttpRequest);
	std::string getAsyncRunOutput(const std::string& processUuid, int& exitCode, bool& finished);
	
	// health: 0-health, 1-unhealth
	void setHealth(bool health) { m_health = health; }
	const std::string& getHealthCheck() { return m_healthCheckCmd; }
	int getHealth() { return 1- m_health; }
	void checkAndUpdateHealth();

	// get normal stdout for running app
	std::string getOutput(bool keepHistory);

	void destroy();
	virtual web::json::value AsJson(bool returnRuntimeInfo);
	virtual void dump();

protected:
	std::shared_ptr<AppProcess> allocProcess(int cacheOutputLines, std::string dockerImage, std::string appName);
	bool isInDailyTimeRange();
	virtual bool avialable();

protected:
	STATUS m_status;
	std::string m_name;
	std::string m_commandLine;
	std::string m_user;
	std::string m_workdir;
	std::string m_comments;
	//the exit code of last instance
	std::shared_ptr<int> m_return;
	std::string m_posixTimeZone;
	bool m_health;
	std::string m_healthCheckCmd;
	
	int m_cacheOutputLines;
	std::shared_ptr<AppProcess> m_process;
	int m_pid;
	std::recursive_mutex m_mutex;
	std::shared_ptr<DailyLimitation> m_dailyLimit;
	std::shared_ptr<ResourceLimitation> m_resourceLimit;
	std::map<std::string, std::string> m_envMap;
	std::string m_dockerImage;
	std::chrono::system_clock::time_point m_procStartTime;
};

#endif 