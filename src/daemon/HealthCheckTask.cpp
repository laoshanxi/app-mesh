#include "HealthCheckTask.h"
#include "../common/Utility.h"
#include "Configuration.h"
#include "AppProcess.h"
#include "Application.h"

HealthCheckTask::HealthCheckTask()
{
}

HealthCheckTask::~HealthCheckTask()
{
}

void HealthCheckTask::healthCheckAllApp() const
{
	const static char fname[] = "HealthCheckTask::healthCheckAllApp() ";

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

std::unique_ptr<HealthCheckTask>& HealthCheckTask::instance()
{
	static auto singleton = std::make_unique<HealthCheckTask>();
	return singleton;
}
