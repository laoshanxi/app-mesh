// src/daemon/HealthCheckTask.cpp
#include "HealthCheckTask.h"
#include "../common/QuitHandler.h"
#include "../common/Utility.h"
#include "Configuration.h"
#include "application/Application.h"
#include "process/AppProcess.h"

#include <thread>

void HealthCheckTask::doHealthCheck()
{
	const static char fname[] = "HealthCheckTask::doHealthCheck() ";
	auto apps = Configuration::instance()->getApps();
	for (auto &app : apps)
	{
		// Native apps need an explicit command; container apps may rely on the
		// image HEALTHCHECK alone.
		if (!app->isContainerized() && app->healthCheckCmd().empty())
			continue;
		try
		{
			if (app->available())
			{
				int exitCode = 1;
				// Container verdict first: the image HEALTHCHECK status Docker
				// already maintains, else health_check_cmd executed inside the
				// container. A channel failure is fail-closed (not provably
				// healthy), never a host probe.
				const auto containerVerdict = app->probeContainerHealth();
				if (containerVerdict)
				{
					exitCode = *containerVerdict;
					LOG_DBG << fname << "Container health for <" << app->getName() << "> verdict <" << exitCode << ">";
				}
				else if (!app->isContainerized())
				{
					auto proc = std::make_shared<AppProcess>(std::weak_ptr<Application>());
					const auto pid = proc->start(app->healthCheckCmd(), "", "", {}, nullptr, "", EMPTY_STR_JSON, 0).pid;
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
					LOG_DBG << fname << "Health check for <" << app->getName() << "> command <" << app->healthCheckCmd()
							<< "> returned <" << exitCode << ">, last error: " << proc->startError();
				}
				else if (app->healthCheckCmd().empty())
				{
					// Container without an image HEALTHCHECK and without a command:
					// no health semantics, leave the current state untouched.
					continue;
				}
				else
				{
					LOG_WAR << fname << "Container health check for <" << app->getName()
							<< "> could not reach the container; marking unhealthy";
				}
				app->health(0 == exitCode);
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

HealthCheckTask::HealthCheckTask() {}

HealthCheckTask::~HealthCheckTask()
{
	// A teardown path may skip the exit signal; marking it bounds the join to
	// the current wait slice instead of hanging on a still-looping worker.
	QuitHandler::instance()->markExit();
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
		// doHealthCheck() waits in QuitHandler-aware slices, so a shutdown
		// request ends a running round promptly.
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
		QuitHandler::instance()->waitForExit(
			std::chrono::seconds(Configuration::instance()->getScheduleInterval() * 30));
	}
	LOG_INF << fname << "health check worker exited";
}
