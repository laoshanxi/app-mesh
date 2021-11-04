#pragma once
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <tuple>

#include <cpprest/json.h>

#include "../TimerHandler.h"
#include "AppBehavior.h"
#include "AppUtils.h"

class AppTimer;
class User;
class CounterMetric;
class GaugeMetric;
class PrometheusRest;
class AppProcess;
class DailyLimitation;
class ResourceLimitation;
namespace prometheus
{
	class Counter;
};
//////////////////////////////////////////////////////////////////////////
/// An Application is used to define and manage a process job.
//////////////////////////////////////////////////////////////////////////
class Application : public TimerHandler, public AppBehavior
{
public:
	Application();
	virtual ~Application();
	virtual bool operator==(const std::shared_ptr<Application> &app);

	const std::string &getName() const;
	pid_t getpid() const;
	void health(bool health);
	int health() const;
	const std::string &healthCheckCmd() const;
	const std::shared_ptr<User> &getOwner() const;
	int getOwnerPermission() const;
	bool isCloudApp() const;
	STATUS getStatus() const;
	bool isPersistAble() const;
	void setUnPersistable();

	bool available(const std::chrono::system_clock::time_point &now = std::chrono::system_clock::now());
	bool isEnabled() const;
	bool attach(int pid);

	static void FromJson(const std::shared_ptr<Application> &app, const web::json::value &obj) noexcept(false);
	virtual web::json::value AsJson(bool returnRuntimeInfo);
	virtual void dump();

	// operate
	void execute(void *ptree = nullptr);
	void enable();
	void disable();
	void destroy();

	// behavior
	std::shared_ptr<std::chrono::system_clock::time_point> scheduleNext(std::chrono::system_clock::time_point now = std::chrono::system_clock::now());
	void regSuicideTimer(int timeoutSeconds);
	void onSuicide(int timerId = 0);
	void onExit(int code);

	std::string runAsyncrize(int timeoutSeconds) noexcept(false);
	std::string runSyncrize(int timeoutSeconds, void *asyncHttpRequest) noexcept(false);
	std::tuple<std::string, bool, int> getOutput(long &position, long maxSize, const std::string &processUuid = "", int index = 0);

	// prometheus
	void initMetrics(std::shared_ptr<PrometheusRest> prom);
	void initMetrics(std::shared_ptr<Application> fromApp);

protected:
	// error
	void setLastError(const std::string &error) noexcept(false);
	const std::string getLastError() const noexcept(false);
	void setInvalidError() noexcept(false);

	// process
	std::shared_ptr<AppProcess> allocProcess(bool monitorProcess, const std::string &dockerImage, const std::string &appName);
	void spawn(int timerId);
	std::shared_ptr<int> refresh(void *ptree = nullptr);
	void healthCheck();

	std::string runApp(int timeoutSeconds) noexcept(false);
	const std::string getExecUser() const;
	const std::string &getCmdLine() const;
	std::map<std::string, std::string> getMergedEnvMap() const;

protected:
	mutable std::recursive_mutex m_appMutex;
	std::shared_ptr<AppTimer> m_timer;
	static ACE_Time_Value m_waitTimeout;
	bool m_persistAble;

	STATUS m_status;
	std::string m_name;
	std::string m_commandLine;
	std::string m_description;
	/// @brief TODO: when user is removed, need remove associated app, otherwise, app invoke will fail
	std::shared_ptr<User> m_owner;
	int m_ownerPermission;
	std::string m_workdir;
	std::string m_stdoutFile;
	web::json::value m_metadata;
	bool m_shellApp;
	int m_stdoutCacheNum;
	std::shared_ptr<ShellAppFileGen> m_shellAppFile;
	std::shared_ptr<LogFileQueue> m_stdoutFileQueue;
	//the exit code of last instance
	std::shared_ptr<int> m_return;
	std::string m_posixTimeZone;
	std::string m_startTime;
	std::string m_endTime;
	std::chrono::system_clock::time_point m_startTimeValue;
	std::chrono::system_clock::time_point m_endTimeValue;

	// short running
	std::string m_startIntervalValue;
	int m_startInterval;
	std::string m_bufferTimeValue;
	int m_bufferTime;
	bool m_startIntervalValueIsCronExpr;
	std::shared_ptr<AppProcess> m_bufferProcess;
	std::shared_ptr<std::chrono::system_clock::time_point> m_nextLaunchTime;
	int m_nextStartTimerId;

	std::chrono::system_clock::time_point m_regTime;
	bool m_health;
	std::string m_healthCheckCmd;
	const std::string m_appId;
	unsigned int m_version;
	std::shared_ptr<AppProcess> m_process;
	pid_t m_pid;
	int m_suicideTimerId;
	std::shared_ptr<DailyLimitation> m_dailyLimit;
	std::shared_ptr<ResourceLimitation> m_resourceLimit;
	std::map<std::string, std::string> m_envMap;
	std::map<std::string, std::string> m_secEnvMap;
	std::string m_dockerImage;
	std::chrono::system_clock::time_point m_procStartTime;
	std::chrono::system_clock::time_point m_procExitTime;

	// Prometheus
	std::shared_ptr<CounterMetric> m_metricStartCount;
	std::shared_ptr<GaugeMetric> m_metricMemory;
	std::shared_ptr<GaugeMetric> m_metricCpu;
	std::shared_ptr<GaugeMetric> m_metricAppPid;
	std::shared_ptr<GaugeMetric> m_metricFileDesc;
	std::shared_ptr<prometheus::Counter> m_starts;

	// error
	mutable std::recursive_mutex m_errorMutex;
	std::string m_lastError;
};
