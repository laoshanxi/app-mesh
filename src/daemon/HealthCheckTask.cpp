#include "HealthCheckTask.h"
#include "../common/Utility.h"
#include "Configuration.h"
#include "AppProcess.h"
#include "Application.h"

extern ACE_Reactor* m_timerReactor;
HealthCheckTask::HealthCheckTask()
	:m_timerId(0)
{
	// override default reactor
	m_reactor = m_timerReactor;
}

HealthCheckTask::~HealthCheckTask()
{
	if (m_timerId)
	{
		this->cancleTimer(m_timerId);
		m_timerId = 0;
	}
}

void HealthCheckTask::initTimer()
{
	if (m_timerId)
	{
		this->cancleTimer(m_timerId);
	}
	m_timerId = this->registerTimer(
		2,
		DEFAULT_HEALTH_CHECK_INTERVAL,
		std::bind(&HealthCheckTask::healthCheckTimer, this, std::placeholders::_1),
		__FUNCTION__
	);
}

void HealthCheckTask::healthCheckTimer(int timerId)
{
	const static char fname[] = "HealthCheckTask::healthCheckTimer() ";

	auto apps = Configuration::instance()->getApps();
	for (auto& app : apps)
	{
		if (app->getHealthCheck().empty()) continue;
		try
		{
			if (app->avialable())
			{
				auto proc = std::make_shared<AppProcess>(0);
				proc->spawnProcess(app->getHealthCheck(), "", "", {}, nullptr);
				proc->regKillTimer(DEFAULT_HEALTH_CHECK_INTERVAL, fname);
				ACE_exitcode exitCode;
				proc->wait(&exitCode);
				app->setHealth(0 == exitCode);
				// proc->killgroup();
				LOG_DBG << fname << app->getName() << " health check :" << app->getHealthCheck() << " return " << exitCode;
			}
			else
			{
				app->setHealth(false);
			}
		}
		catch (const std::exception & ex)
		{
			LOG_WAR << fname << app->getName() << "check got exception: " << ex.what();
		}
		catch (...)
		{
			LOG_WAR << fname << app->getName() << " exception";
		}
	}
}

std::shared_ptr<HealthCheckTask>& HealthCheckTask::instance()
{
	static auto singleton = std::make_shared<HealthCheckTask>();
	return singleton;
}
