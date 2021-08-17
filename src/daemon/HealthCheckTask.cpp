#include "HealthCheckTask.h"
#include "../common/PerfLog.h"
#include "../common/Utility.h"
#include "Configuration.h"
#include "application/Application.h"
#include "process/AppProcess.h"

HealthCheckTask::HealthCheckTask()
{
}

HealthCheckTask::~HealthCheckTask()
{
}

void HealthCheckTask::doHealthCheck()
{
	const static char fname[] = "HealthCheckTask::doHealthCheck() ";
	PerfLog perf(fname);
	auto apps = Configuration::instance()->getApps();
	for (auto &app : apps)
	{
		if (app->getHealthCheck().empty())
			continue;
		try
		{
			if (app->available())
			{
				auto proc = std::make_shared<AppProcess>();
				proc->spawnProcess(app->getHealthCheck(), "", "", {}, nullptr, "", EMPTY_STR_JSON, 0);
				proc->delayKill(DEFAULT_HEALTH_CHECK_INTERVAL, fname);
				ACE_exitcode exitCode;
				proc->wait(&exitCode);
				app->setHealth(0 == exitCode);
				// proc->killgroup();
				LOG_DBG << fname << app->getName() << " health check :" << app->getHealthCheck() << ", return " << exitCode << ", last error: " << proc->startError();
			}
			else
			{
				app->setHealth(false);
			}
		}
		catch (const std::exception &ex)
		{
			LOG_WAR << fname << app->getName() << "check got exception: " << ex.what();
		}
		catch (...)
		{
			LOG_WAR << fname << app->getName() << " exception";
		}
	}
}

std::shared_ptr<HealthCheckTask> &HealthCheckTask::instance()
{
	static auto singleton = std::make_shared<HealthCheckTask>();
	return singleton;
}
