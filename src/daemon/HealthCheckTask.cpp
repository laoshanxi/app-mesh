// src/daemon/HealthCheckTask.cpp
#include "HealthCheckTask.h"
#include "../common/QuitHandler.h"
#include "../common/Utility.h"
#include "Configuration.h"
#include "application/Application.h"
#include "process/AppProcess.h"

#include <chrono>
#include <thread>

HealthCheckTask::HealthCheckTask()
{
}

HealthCheckTask::~HealthCheckTask()
{
	// The daemon's normal shutdown ends with ACE_OS::_exit(), so this dtor
	// rarely runs; when it does, the worker exits once the exit flag is set
	// (each round and each sleep slice checks it).
	if (m_worker.joinable())
		m_worker.join();
}

void HealthCheckTask::start()
{
	if (m_worker.joinable())
		return;
	m_worker = std::thread(&HealthCheckTask::run, this);
}

void HealthCheckTask::run()
{
	const static char fname[] = "HealthCheckTask::run() ";
	LOG_INF << fname << "health check worker started";
	while (!QuitHandler::instance()->shouldExit())
	{
		// doHealthCheck() waits in exit-checked slices, so a shutdown request
		// ends a running round promptly.
		try
		{
			doHealthCheck();
		}
		catch (const std::exception &ex)
		{
			LOG_WAR << fname << "health check round failed: " << ex.what();
		}
		catch (...)
		{
			LOG_WAR << fname << "health check round failed with unknown exception";
		}
		// Fixed sleep after each round: a slow round pushes the next one back
		// instead of shortening the gap. 30 schedule ticks keeps the
		// process-spawning rounds sparse (60s at the default interval).
		const auto deadline = std::chrono::steady_clock::now() +
							  std::chrono::seconds(Configuration::instance()->getScheduleInterval() * 30);
		while (!QuitHandler::instance()->shouldExit() && std::chrono::steady_clock::now() < deadline)
			std::this_thread::sleep_for(std::chrono::milliseconds(200));
	}
	LOG_INF << fname << "health check worker exited";
}

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
				ACE_exitcode exitCode = 1;
				pid_t waited = 0;
				if (pid > 1)
				{
					// Wait in slices: the completion notice is dispatched by the process
					// reactor, which the signal path stops first (QuitHandler). Without an
					// exit check this wait rides out the full DEFAULT_HEALTH_CHECK_INTERVAL.
					const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(DEFAULT_HEALTH_CHECK_INTERVAL);
					do
					{
						waited = proc->wait(ACE_Time_Value(0, 200 * 1000), &exitCode);
					} while (waited == 0 && !QuitHandler::instance()->shouldExit() && std::chrono::steady_clock::now() < deadline);
				}
				if (pid > 1 && waited <= 0)
				{
					proc->terminate();
					exitCode = proc->returnValue();
				}
				app->health(0 == exitCode);
				LOG_DBG << fname << "Health check for <" << app->getName() << "> command <" << app->healthCheckCmd() << "> returned <" << exitCode << ">, last error: " << proc->startError();
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
