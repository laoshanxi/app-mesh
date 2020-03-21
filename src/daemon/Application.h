#pragma once

#include <memory>
#include <string>
#include <map>
#include <mutex>
#include <chrono>
#include <cpprest/json.h>
#include "TimerHandler.h"

class CounterPtr;
class GaugePtr;
class PrometheusRest;
class AppProcess;
class DailyLimitation;
class ResourceLimitation;
//////////////////////////////////////////////////////////////////////////
/// An Application is used to define and manage a process job.
//////////////////////////////////////////////////////////////////////////
class Application : public TimerHandler
{
public:
	enum class STATUS : int
	{
		DISABLED,
		ENABLED,
		NOTAVIALABLE,	// used for temp app from RestHandler::apiRunParseApp and destroyed app
		INITIALIZING,
		UNINITIALIZING
	};
	Application();
	virtual ~Application();
	virtual bool operator==(const std::shared_ptr<Application>& app);

	virtual bool avialable();
	const std::string getName() const;
	bool isEnabled();
	bool isWorkingState();
	bool attach(int pid);
	
	static void FromJson(std::shared_ptr<Application>& app, const web::json::value& obj) noexcept(false);
	virtual web::json::value AsJson(bool returnRuntimeInfo);
	virtual void dump();

	// Invoke by scheduler
	virtual void invoke();
	virtual void disable();
	virtual void enable();
	void destroy();
	void onSuicideEvent(int timerId = 0);
	void onFinishEvent(int timerId = 0);
	void onEndEvent(int timerId = 0);

	std::string runAsyncrize(int timeoutSeconds) noexcept(false);
	std::string runSyncrize(int timeoutSeconds, void* asyncHttpRequest) noexcept(false);
	std::string getAsyncRunOutput(const std::string& processUuid, int& exitCode, bool& finished) noexcept(false);

	// health: 0-health, 1-unhealth
	void setHealth(bool health) { m_health = health; }
	const std::string& getHealthCheck() { return m_healthCheckCmd; }
	int getHealth() { return 1 - m_health; }
	pid_t getpid() const;

	// get normal stdout for running app
	std::string getOutput(bool keepHistory);

	void initMetrics(std::shared_ptr<PrometheusRest> prom);
	int getVersion();
	void setVersion(int version);
	const std::string getComments() const { return m_comments; }
	const std::string getInitCmd() const { return m_commandLineInit; }

protected:
	// Invoke immediately
	virtual void invokeNow(int timerId);
	virtual void refreshPid();
	std::shared_ptr<AppProcess> allocProcess(int cacheOutputLines, std::string dockerImage, std::string appName);
	bool isInDailyTimeRange();
	virtual void checkAndUpdateHealth();
	std::string runApp(int timeoutSeconds) noexcept(false);
	void handleEndTimer();

protected:
	STATUS m_status;
	std::string m_name;
	std::string m_commandLine;
	std::string m_commandLineInit;
	std::string m_commandLineFini;
	std::string m_user;
	std::string m_workdir;
	std::string m_comments;
	//the exit code of last instance
	std::unique_ptr<int> m_return;
	std::string m_posixTimeZone;
	std::chrono::system_clock::time_point m_startTime;
	std::chrono::system_clock::time_point m_endTime;
	int m_endTimerId;
	bool m_health;
	std::string m_healthCheckCmd;
	const std::string m_appId;
	unsigned int m_version;
	int m_cacheOutputLines;
	std::shared_ptr<AppProcess> m_process;
	int m_pid;
	std::recursive_mutex m_mutex;
	std::shared_ptr<DailyLimitation> m_dailyLimit;
	std::shared_ptr<ResourceLimitation> m_resourceLimit;
	std::map<std::string, std::string> m_envMap;
	std::string m_dockerImage;
	std::chrono::system_clock::time_point m_procStartTime;

	// Prometheus
	std::shared_ptr<CounterPtr> m_metricStartCount;
	std::shared_ptr<GaugePtr> m_metricMemory;
};
