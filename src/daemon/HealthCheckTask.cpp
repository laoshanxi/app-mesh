// src/daemon/HealthCheckTask.cpp
#include "HealthCheckTask.h"
#include "../common/QuitHandler.h"
#include "../common/Utility.h"
#include "Configuration.h"
#include "application/Application.h"
#include "process/AppProcess.h"

#include <thread>

HealthCheckTask::HealthCheckTask() {}

HealthCheckTask::~HealthCheckTask() {}

void HealthCheckTask::doHealthCheck()
{
	const static char fname[] = "HealthCheckTask::doHealthCheck() ";
	auto apps = Configuration::instance()->getApps();
	for (auto &app : apps)
	{
		if (app->healthCheckCmd().empty())
			continue;
		try
		{
			if (app->available())
			{
				auto proc = std::make_shared<AppProcess>(std::weak_ptr<Application>());
				const auto pid = proc->start(app->healthCheckCmd(), "", "", {}, nullptr, "", EMPTY_STR_JSON, 0).pid;
				int exitCode = 1;
				pid_t waited = 0;
				if (pid > 1)
				{
					// Wait in slices so a shutdown request cannot ride out the
					// full DEFAULT_HEALTH_CHECK_INTERVAL.
					const auto deadline =
						std::chrono::steady_clock::now() + std::chrono::seconds(DEFAULT_HEALTH_CHECK_INTERVAL);
					do
					{
						waited = proc->wait(std::chrono::milliseconds(200), &exitCode);
					} while (waited == 0 && !QuitHandler::instance()->shouldExit() &&
							 std::chrono::steady_clock::now() < deadline);
				}
				if (pid > 1 && waited <= 0)
				{
					proc->terminate();
					exitCode = proc->returnValue();
				}
				app->health(0 == exitCode);
				LOG_DBG << fname << "Health check for <" << app->getName() << "> command <" << app->healthCheckCmd()
						<< "> returned <" << exitCode << ">, last error: " << proc->startError();
			}
			else
			{
				app->health(false);
			}
		}
		catch (const std::exception &ex)
		{
			LOG_WAR << fname << "Health check for <" << app->getName() << "> got exception: " << ex.what();
		}
		catch (...)
		{
			LOG_WAR << fname << "Health check for <" << app->getName() << "> got unknown exception";
		}
	}
}

std::shared_ptr<HealthCheckTask> &HealthCheckTask::instance()
{
	static auto singleton = std::make_shared<HealthCheckTask>();
	return singleton;
}

void HealthCheckTask::runAsync()
{
	const static char fname[] = "HealthCheckTask::runAsync() ";
	// Each check spawns processes and waits up to DEFAULT_HEALTH_CHECK_INTERVAL
	// per application; running that inline would stall application scheduling,
	// so the schedule loop hands it to a short-lived thread and moves on. The
	// flag collapses overlapping rounds instead of queueing them.
	if (m_checkRunning.test_and_set())
	{
		LOG_DBG << fname << "previous health check round still running, skipping";
		return;
	}
	std::thread([this]()
				{
					try
					{
						doHealthCheck();
					}
					catch (const std::exception &ex)
					{
						LOG_WAR << "HealthCheckTask::runAsync() health check round failed: " << ex.what();
					}
					catch (...)
					{
						LOG_WAR << "HealthCheckTask::runAsync() health check round failed with unknown exception";
					}
					m_checkRunning.clear();
				})
		.detach();
}
