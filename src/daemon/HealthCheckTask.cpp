#include "Application.h"
#include "AppProcess.h"
#include "Configuration.h"
#include "HealthCheckTask.h"
#include "../common/Utility.h"
#include "../common/PerfLog.h"

HealthCheckTask::HealthCheckTask()
	:m_timerId(0)
{
}

HealthCheckTask::~HealthCheckTask()
{
	this->cancleTimer(m_timerId);
}

void HealthCheckTask::initTimer()
{
	this->cancleTimer(m_timerId);
	m_timerId = this->registerTimer(
		1000L * 2,
		DEFAULT_HEALTH_CHECK_INTERVAL,
		std::bind(&HealthCheckTask::healthCheckTimer, this, std::placeholders::_1),
		__FUNCTION__
	);
}

void HealthCheckTask::healthCheckTimer(int timerId)
{
	const static char fname[] = "HealthCheckTask::healthCheckTimer() ";
	PerfLog perf(fname);
	auto apps = Configuration::instance()->getApps();
	for (auto& app : apps)
	{
		if (app->getHealthCheck().empty()) continue;
		try
		{
			if (app->avialable())
			{
				auto proc = std::make_shared<AppProcess>(0);
				proc->spawnProcess(app->getHealthCheck(), "", "", {}, nullptr, "");
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
