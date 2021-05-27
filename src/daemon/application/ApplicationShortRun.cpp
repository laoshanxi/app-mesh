#include "ApplicationShortRun.h"
#include "../../common/DateTime.h"
#include "../../common/DurationParse.h"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "../process/AppProcess.h"

ApplicationShortRun::ApplicationShortRun()
	: m_startInterval(0), m_bufferTime(0), m_timerId(0)
{
	const static char fname[] = "ApplicationShortRun::ApplicationShortRun() ";
	LOG_DBG << fname << "Entered.";
}

ApplicationShortRun::~ApplicationShortRun()
{
	const static char fname[] = "ApplicationShortRun::~ApplicationShortRun() ";
	LOG_DBG << fname << "Entered.";
}

void ApplicationShortRun::FromJson(const std::shared_ptr<ApplicationShortRun> &app, const web::json::value &jsonObj)
{
	DurationParse duration;
	std::shared_ptr<Application> fatherApp = app;
	Application::FromJson(fatherApp, jsonObj);
	app->m_startIntervalValue = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_SHORT_APP_start_interval_seconds);
	app->m_startInterval = duration.parse(app->m_startIntervalValue);
	app->m_bufferTimeValue = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_SHORT_APP_start_interval_timeout);
	app->m_bufferTime = duration.parse(app->m_bufferTimeValue);
	assert(app->m_startInterval > 0);
}

void ApplicationShortRun::refreshPid(void *ptree)
{
	// 1. Call parent to get the new pid
	Application::refreshPid();
	// 2. Try to get return code from Buffer process again
	//    If there have buffer process, current process is still running, so get return code from buffer process
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	if (nullptr != m_bufferProcess && m_bufferProcess->running())
	{
		ACE_Time_Value tv;
		tv.msec(10);
		int ret = m_bufferProcess->wait(tv);
		if (ret > 0)
		{
			m_return = std::make_shared<int>(m_bufferProcess->return_value());
		}
	}
}

void ApplicationShortRun::checkAndUpdateHealth()
{
	if (m_healthCheckCmd.empty())
	{
		if (m_pid > 0)
		{
			setHealth(true);
		}
		else
		{
			// if return normally, set to health
			if (m_return && 0 == *m_return)
			{
				setHealth(true);
			}
			else
			{
				setHealth(false);
			}
		}
	}
}

void ApplicationShortRun::invoke(void *ptree)
{
	const static char fname[] = "ApplicationShortRun::invoke() ";
	if (isWorkingState())
	{
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		// 1. kill unexpected process
		if (!this->available() && m_process->running())
		{
			LOG_INF << fname << "Application <" << m_name << "> was not in daily start time";
			m_process->killgroup();
			setInvalidError();
		}
	}
	else
	{
		setLastError("not in working state");
	}
	// Only refresh Pid for short running
	refreshPid(ptree);
}

void ApplicationShortRun::invokeNow(int timerId)
{
	// Check app existence
	if (timerId > 0 && !this->isEnabled())
	{
		this->cancelTimer(timerId);
		setLastError("not enabled");
		return;
	}
	if (!isWorkingState())
	{
		setLastError("not in working state");
		return;
	}
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	// clean old process
	if (m_process->running())
	{
		if (m_bufferTime > 0)
		{
			// give some time for buffer process
			m_bufferProcess = m_process;
			m_bufferProcess->delayKill(m_bufferTime, __FUNCTION__);
		}
		else
		{
			// direct kill old process
			m_process->killgroup();
		}
	}

	// check status and daily range
	if (this->available())
	{
		// Spawn new process
		m_process.reset(); //m_process->killgroup();
		m_process = allocProcess(0, m_dockerImage, m_name);
		m_procStartTime = std::chrono::system_clock::now();
		m_pid = m_process->spawnProcess(getCmdLine(), getExecUser(), m_workdir, getMergedEnvMap(), m_resourceLimit, m_stdoutFile, m_metadata);
		setLastError(m_process->startError());
		m_nextLaunchTime = std::make_unique<std::chrono::system_clock::time_point>(std::chrono::system_clock::now() + std::chrono::seconds(this->getStartInterval()));
	}
	else
	{
		setInvalidError();
	}
}

web::json::value ApplicationShortRun::AsJson(bool returnRuntimeInfo)
{
	const static char fname[] = "ApplicationShortRun::AsJson() ";
	LOG_DBG << fname << "Entered.";
	web::json::value result = Application::AsJson(returnRuntimeInfo);

	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	result[JSON_KEY_SHORT_APP_start_interval_seconds] = web::json::value::string(m_startIntervalValue);
	if (m_bufferTime)
		result[JSON_KEY_SHORT_APP_start_interval_timeout] = web::json::value::string(m_bufferTimeValue);
	if (returnRuntimeInfo)
	{
		if (m_nextLaunchTime != nullptr)
			result[JSON_KEY_SHORT_APP_next_start_time] = web::json::value::string(DateTime::formatLocalTime(*m_nextLaunchTime));
	}
	return result;
}

void ApplicationShortRun::enable()
{
	const static char fname[] = "ApplicationShortRun::enable() ";
	LOG_DBG << fname << "Entered.";

	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	if (m_status == STATUS::DISABLED)
	{
		m_status = STATUS::ENABLED;
		initTimer();
	}
}

void ApplicationShortRun::disable()
{
	Application::disable();
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	// clean old timer
	this->cancelTimer(m_timerId);
	m_nextLaunchTime = nullptr;
}

void ApplicationShortRun::initTimer()
{
	const static char fname[] = "ApplicationShortRun::initTimer() ";

	// std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	// 1. clean old timer
	this->cancelTimer(m_timerId);

	// 2. reg new timer
	const auto now = std::chrono::system_clock::now();
	int64_t firstSleepMilliseconds = 0;
	auto appStartTime = this->getStartTime();
	if (appStartTime == std::chrono::system_clock::time_point() || appStartTime == now)
	{
		// if not set start time, treat start time as now.
		firstSleepMilliseconds = 0;
	}
	else if (appStartTime > now)
	{
		firstSleepMilliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(this->getStartTime() - now).count();
	}
	else
	{
		const auto timeDiffMilliSeconds = std::chrono::duration_cast<std::chrono::milliseconds>(now - this->getStartTime()).count();
		const int64_t startIntervalMiliseconds = 1000L * this->getStartInterval(); // convert to milliseconds
		firstSleepMilliseconds = startIntervalMiliseconds - (timeDiffMilliSeconds % startIntervalMiliseconds);
		assert(firstSleepMilliseconds > 0);
	}
	firstSleepMilliseconds += 2; // add 2 miliseconds buffer to avoid 59:59
	m_timerId = this->registerTimer(firstSleepMilliseconds, this->getStartInterval(), std::bind(&ApplicationShortRun::invokeNow, this, std::placeholders::_1), __FUNCTION__);
	m_nextLaunchTime = std::make_unique<std::chrono::system_clock::time_point>(now + std::chrono::milliseconds(firstSleepMilliseconds));
	LOG_DBG << fname << this->getName() << " m_nextLaunchTime=" << DateTime::formatLocalTime(*m_nextLaunchTime) << ", will sleep " << firstSleepMilliseconds / 1000 << " seconds";
}

int ApplicationShortRun::getStartInterval()
{
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	return m_startInterval;
}

std::chrono::system_clock::time_point ApplicationShortRun::getStartTime()
{
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	return m_startTimeValue;
}

bool ApplicationShortRun::available()
{
	return (Application::available() && std::chrono::system_clock::now() > getStartTime());
}

void ApplicationShortRun::dump()
{
	const static char fname[] = "ApplicationShortRun::dump() ";

	Application::dump();
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	LOG_DBG << fname << "m_startInterval:" << m_startInterval;
	LOG_DBG << fname << "m_bufferTime:" << m_bufferTime;
	if (m_nextLaunchTime != nullptr)
		LOG_DBG << fname << "m_nextLaunchTime:" << DateTime::formatLocalTime(*m_nextLaunchTime);
}
