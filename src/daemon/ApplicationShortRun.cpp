#include "ApplicationShortRun.h"
#include "AppProcess.h"
#include "Configuration.h"
#include "../common/Utility.h"
#include "../common/TimeZoneHelper.h"

ApplicationShortRun::ApplicationShortRun()
	:m_startInterval(0), m_bufferTime(0), m_timerId(0)
{
	const static char fname[] = "ApplicationShortRun::ApplicationShortRun() ";
	LOG_DBG << fname << "Entered.";
}


ApplicationShortRun::~ApplicationShortRun()
{
	const static char fname[] = "ApplicationShortRun::~ApplicationShortRun() ";
	LOG_DBG << fname << "Entered.";
}

void ApplicationShortRun::FromJson(std::shared_ptr<ApplicationShortRun>& app, const web::json::value& jobj)
{
	std::shared_ptr<Application> fatherApp = app;
	Application::FromJson(fatherApp, jobj);
	app->m_startInterval = GET_JSON_INT_VALUE(jobj, JSON_KEY_SHORT_APP_start_interval_seconds);
	assert(app->m_startInterval > 0);
}


void ApplicationShortRun::refreshPid()
{
	// 1. Call parent to get the new pid
	Application::refreshPid();
	// 2. Try to get return code from Buffer process again
	//    If there have buffer process, current process is still running, so get return code from buffer process
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
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

void ApplicationShortRun::invoke()
{
	const static char fname[] = "ApplicationShortRun::invoke() ";
	if (isWorkingState())
	{
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		// 1. kill unexpected process
		if (!this->avialable() && m_process->running())
		{
			LOG_INF << fname << "Application <" << m_name << "> was not in daily start time";
			m_process->killgroup();
		}
	}
	// Only refresh Pid for short running
	refreshPid();
}

void ApplicationShortRun::invokeNow(int timerId)
{
	// Check app existance
	if (timerId > 0 && !this->isEnabled())
	{
		this->cancleTimer(timerId);
		return;
	}
	if (!isWorkingState()) return;
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	// clean old process
	if (m_process->running())
	{
		if (m_bufferTime > 0)
		{
			// give some time for buffer process
			m_bufferProcess = m_process;
			m_bufferProcess->regKillTimer(m_bufferTime, __FUNCTION__);
		}
		else
		{
			// direct kill old process
			m_process->killgroup();
		}
	}
	
	// check status and daily range
	if (this->avialable())
	{
		// Spawn new process
		m_process = allocProcess(m_cacheOutputLines, m_dockerImage, m_name);
		m_procStartTime = std::chrono::system_clock::now();
		m_pid = m_process->spawnProcess(m_commandLine, m_user, m_workdir, m_envMap, m_resourceLimit, m_stdoutFile);
		m_nextLaunchTime = std::make_unique<std::chrono::system_clock::time_point>(std::chrono::system_clock::now() + std::chrono::seconds(this->getStartInterval()));
	}
}

web::json::value ApplicationShortRun::AsJson(bool returnRuntimeInfo)
{
	const static char fname[] = "ApplicationShortRun::AsJson() ";
	LOG_DBG << fname << "Entered.";
	web::json::value result = Application::AsJson(returnRuntimeInfo);

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	result[JSON_KEY_SHORT_APP_start_interval_seconds] = web::json::value::number(m_startInterval);
	if (m_bufferTime) result[JSON_KEY_SHORT_APP_start_interval_timeout] = web::json::value::number(m_bufferTime);
	if (returnRuntimeInfo)
	{
		if (m_nextLaunchTime != nullptr) result[JSON_KEY_SHORT_APP_next_start_time] = web::json::value::string(Utility::convertTime2Str(*m_nextLaunchTime));
	}
	return result;
}

void ApplicationShortRun::enable()
{
	const static char fname[] = "ApplicationShortRun::enable() ";
	LOG_DBG << fname << "Entered.";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (m_status == STATUS::DISABLED)
	{
		m_status = STATUS::ENABLED;
		initTimer();
	}
}

void ApplicationShortRun::disable()
{
	Application::disable();
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	// clean old timer
	if (m_timerId)
	{
		this->cancleTimer(m_timerId);
	}
	m_nextLaunchTime = nullptr;
}

void ApplicationShortRun::initTimer()
{
	const static char fname[] = "ApplicationShortRun::initTimer() ";
	LOG_DBG << fname << "Entered.";

	// std::lock_guard<std::recursive_mutex> guard(m_mutex);
	// 1. clean old timer
	this->cancleTimer(m_timerId);

	// 2. reg new timer
	const auto now = std::chrono::system_clock::now();
	int64_t firstSleepMilliseconds = 0;
	if (this->getStartTime() > now)
	{
		firstSleepMilliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(this->getStartTime() - now).count();
	}
	else if (this->getStartTime() == now)
	{
		firstSleepMilliseconds = 0;
	}
	else
	{
		const auto timeDiffMilliSeconds = std::chrono::duration_cast<std::chrono::milliseconds>(now - this->getStartTime()).count();
		const int64_t startIntervalMiliseconds = 1000L * this->getStartInterval();	// convert to milliseconds
		firstSleepMilliseconds = startIntervalMiliseconds - (timeDiffMilliSeconds % startIntervalMiliseconds);
		assert(firstSleepMilliseconds > 0);
	}
	firstSleepMilliseconds += 2;	// add 2 miliseconds buffer to avoid 59:59
	m_timerId = this->registerTimer(firstSleepMilliseconds, this->getStartInterval(), std::bind(&ApplicationShortRun::invokeNow, this, std::placeholders::_1), __FUNCTION__);
	m_nextLaunchTime = std::make_unique<std::chrono::system_clock::time_point>(now + std::chrono::milliseconds(firstSleepMilliseconds));
	LOG_DBG << fname << this->getName() << " m_nextLaunchTime=" << Utility::convertTime2Str(*m_nextLaunchTime) << ", will sleep " << firstSleepMilliseconds/1000 << " seconds";
}

int ApplicationShortRun::getStartInterval()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_startInterval;
}

std::chrono::system_clock::time_point ApplicationShortRun::getStartTime()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_startTime;
}

bool ApplicationShortRun::avialable()
{
	return (Application::avialable() && std::chrono::system_clock::now() > getStartTime());
}

void ApplicationShortRun::dump()
{
	const static char fname[] = "ApplicationShortRun::dump() ";

	Application::dump();
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	LOG_DBG << fname << "m_startInterval:" << m_startInterval;
	LOG_DBG << fname << "m_bufferTime:" << m_bufferTime;
	if (m_nextLaunchTime != nullptr) LOG_DBG << fname << "m_nextLaunchTime:" << Utility::convertTime2Str(*m_nextLaunchTime);
}
