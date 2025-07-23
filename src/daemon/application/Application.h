#pragma once
#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <tuple>

#include <ace/Event.h>
#include <boost/smart_ptr/shared_ptr.hpp>
#include <boost/thread/synchronized_value.hpp>
#include <nlohmann/json.hpp>

#include "../../common/TimerHandler.h"
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
	STATUS getStatus() const;
	bool isPersistAble() const;
	void setUnPersistable();

	void nextLaunchTime(const std::chrono::system_clock::time_point &time);
	const boost::shared_ptr<std::chrono::system_clock::time_point> nextLaunchTime();

	bool available(const std::chrono::system_clock::time_point &now = std::chrono::system_clock::now());
	bool isEnabled() const;
	bool attach(int pid);

	static void FromJson(const std::shared_ptr<Application> &app, const nlohmann::json &obj) noexcept(false);
	virtual nlohmann::json AsJson(bool returnRuntimeInfo, void *ptree = nullptr);
	virtual void save();
	virtual void remove();
	virtual void dump();
	virtual std::string getYamlPath();

	// operate
	void execute(void *ptree = nullptr);
	void enable();
	void disable();
	void destroy();

	// behavior
	boost::shared_ptr<std::chrono::system_clock::time_point> scheduleNext(std::chrono::system_clock::time_point startFrom = std::chrono::system_clock::now());
	void regSuicideTimer(int timeoutSeconds);
	bool onTimerAppRemove();
	void handleError();
	void onExitUpdate(int code);
	void terminate(std::shared_ptr<AppProcess> &process);

	std::string runAsyncrize(int timeoutSeconds) noexcept(false);
	std::string runSyncrize(int timeoutSeconds, void *asyncHttpRequest) noexcept(false);
	std::tuple<std::string, bool, int> getOutput(long &position, long maxSize, const std::string &processUuid = "", int index = 0, size_t timeout = 0);

	// prometheus
	void initMetrics();
	void initMetrics(std::shared_ptr<Application> fromApp);

protected:
	// error
	void setLastError(const std::string &error) noexcept(false);
	const std::string getLastError() const noexcept(false);
	void setInvalidError() noexcept(false);

	// process
	std::shared_ptr<AppProcess> allocProcess(bool monitorProcess, const std::string &dockerImage, const std::string &appName);
	bool onTimerSpawn();
	void refresh(void *ptree = nullptr);
	void healthCheck();

	std::string runApp(int timeoutSeconds) noexcept(false);
	const std::string getExecUser() const;
	const std::string &getCmdLine() const;
	std::map<std::string, std::string> getMergedEnvMap() const;

protected:
	mutable std::recursive_mutex m_appMutex;
	std::shared_ptr<AppTimer> m_timer;
	bool m_persistAble;

	std::string m_name;
	std::string m_commandLine;
	std::string m_description;
	/// @brief TODO: when user is removed, need remove associated app, otherwise, app invoke will fail
	std::shared_ptr<User> m_owner;
	int m_ownerPermission;
	std::string m_workdir;
	std::string m_stdoutFile;
	nlohmann::json m_metadata;
	bool m_shellApp;
	bool m_sessionLogin;
	int m_stdoutCacheNum;
	int m_stdoutCacheSize;
	std::shared_ptr<ShellAppFileGen> m_shellAppFile;
	std::shared_ptr<LogFileQueue> m_stdoutFileQueue;

	std::chrono::system_clock::time_point m_startTime;
	std::chrono::system_clock::time_point m_endTime;

	// short running
	std::string m_startIntervalValue;
	int m_startInterval;
	std::string m_bufferTimeValue;
	int m_bufferTime;
	bool m_startIntervalValueIsCronExpr;
	std::shared_ptr<AppProcess> m_bufferProcess;

	std::atomic_long m_nextStartTimerId; // use together with m_nextStartTimerIdEvent
	ACE_Event m_nextStartTimerIdEvent;	 // use together with m_nextStartTimerId

	std::chrono::system_clock::time_point m_regTime;
	std::string m_healthCheckCmd;
	const std::string m_appId;
	unsigned int m_version;

	std::atomic_long m_timerRemoveId;
	std::shared_ptr<DailyLimitation> m_dailyLimit;
	std::shared_ptr<ResourceLimitation> m_resourceLimit;
	std::map<std::string, std::string> m_envMap;
	std::map<std::string, std::string> m_secEnvMap;
	std::string m_dockerImage;

	// runtime dynamic variables (which will also be read by API)
	std::shared_ptr<AppProcess> m_process;
	std::atomic<pid_t> m_pid;
	std::atomic<int> m_return; // the exit code of last instance
	std::atomic_bool m_health;
	std::atomic<STATUS> m_status;
	boost::shared_ptr<std::chrono::system_clock::time_point> m_procStartTime;
	boost::shared_ptr<std::chrono::system_clock::time_point> m_procExitTime;
	boost::shared_ptr<std::chrono::system_clock::time_point> m_nextLaunchTime;
	// error
	boost::synchronized_value<std::string> m_lastError;

	// Prometheus
	std::shared_ptr<CounterMetric> m_metricStartCount;
	std::shared_ptr<GaugeMetric> m_metricMemory;
	std::shared_ptr<GaugeMetric> m_metricCpu;
	std::shared_ptr<GaugeMetric> m_metricAppPid;
	std::shared_ptr<GaugeMetric> m_metricFileDesc;
	std::shared_ptr<prometheus::Counter> m_starts;
};
