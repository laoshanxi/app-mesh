#include "HealthCheckTask.h"
#include "../common/Utility.h"
#include "Configuration.h"

HealthCheckTask::HealthCheckTask()
	:m_exit(false)
{
}

HealthCheckTask::~HealthCheckTask()
{
}

std::unique_ptr<HealthCheckTask>& HealthCheckTask::instance()
{
	static std::unique_ptr<HealthCheckTask> singleton = std::make_unique<HealthCheckTask>();
	return singleton;
}

int HealthCheckTask::svc(void)
{
	const static char fname[] = "HealthCheckTask::svc() ";
	LOG_INF << fname << "Entered";

	while (!m_exit)
	{
		try
		{
			std::this_thread::sleep_for(std::chrono::seconds(5));
			auto apps = Configuration::instance()->getApps();
			for (auto app : apps)
			{
				if (app->getHealthCheck().length())
				{
					try
					{
						auto proc = std::make_shared<AppProcess>(0);
						proc->spawnProcess(app->getHealthCheck(), "", "", {}, nullptr);
						proc->regKillTimer(DEFAULT_HEALTH_CHECK_SCRIPT_TIMEOUT, fname);
						ACE_exitcode exitCode;
						proc->wait(&exitCode);
						app->setHealth(exitCode != 0);
						LOG_WAR << fname << app->getName() << " health check :" << app->getHealthCheck() << " return " << exitCode;
					}
					catch (const std::exception& ex)
					{
						LOG_WAR << fname << app->getName() << "check got exception: " << ex.what();
					}
					catch (...)
					{
						LOG_WAR << fname << app->getName() << " exception";
					}
				}
			}
		}
		catch (...)
		{
			LOG_WAR << fname << " exception";
		}
	}

	LOG_WAR << fname << " thread exit";
	return 0;
}

int HealthCheckTask::open(void* args)
{
	return activate(THR_NEW_LWP | THR_JOINABLE | THR_CANCEL_ENABLE | THR_CANCEL_ASYNCHRONOUS, 1);
}

int HealthCheckTask::close(u_long flags)
{
	m_exit = true;
	return ACE_Task_Base::close(flags);
}
