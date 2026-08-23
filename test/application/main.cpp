// test/application/main.cpp
//
// Characterization tests for the application run-lifecycle semantics.
//
// History: this file originally pinned the former RunState latch
// (updateRunState/consumePendingExit) through a subclass harness that reached
// protected members. That internal state was replaced by the private
// Application::Runtime phase machine (lifecycleGeneration + restartEvaluationPending),
// which is intentionally hidden from the Application interface, so the same
// intent is now pinned through the public API (FromJson/enable/disable/execute/
// getpid/getStatus/health):
//   - a DISABLED app never auto-starts on a scheduler tick (the isEnabled gate
//     that also blocks auto-handling of exits),
//   - an ENABLED app starts on the first tick and turns healthy once RUNNING,
//   - a natural exit drives exactly ONE restart: the once-per-exit latch is
//     consumed on the first reconciling tick and later ticks over the same
//     exited state do nothing (no per-tick re-firing),
//   - disable() kills the current run and clears the latch; the killed run's
//     (possibly late) exit report is a stale reporter and must not churn the
//     fresh run started after re-enable.
// The AppTimer scheduling-math tests are unchanged: that API is stable.
#define CATCH_CONFIG_RUNNER
#include <catch.hpp>

#include <ace/Init_ACE.h>
#include <ace/OS.h>
#include <ace/Reactor.h>
#include <ace/TP_Reactor.h>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#include "../../src/common/Utility.h"
#include "../../src/daemon/Configuration.h"
#include "../../src/daemon/application/AppTimer.h"
#include "../../src/daemon/application/AppUtils.h"
#include "../../src/daemon/application/Application.h"
#include "../../src/daemon/process/ProcessManager.h"

using Clock = std::chrono::system_clock;
using TimePoint = Clock::time_point;

namespace
{
	void globalInit()
	{
		ACE::init();
		Utility::initLogging("test_application");
		Utility::setLogLevel("DEBUG");

		auto config = std::make_shared<Configuration>();
		Configuration::instance(config);

		boost::filesystem::create_directories(config->getWorkDir() + "/tmp");
		boost::filesystem::create_directories(config->getWorkDir() + "/stdout");

		auto *tp = new ACE_TP_Reactor();
		ACE_Reactor::instance(new ACE_Reactor(tp, true), true);

		Process_Manager::instance()->open(ACE_Process_Manager::DEFAULT_SIZE,
										   ACE_Reactor::instance());
		// TimerManager lazily spawns its own queue thread; touch it up front like
		// the daemon does so worker races cannot hit an unconstructed singleton.
		TIMER_MANAGER::instance();

		static std::thread reactorThread([]()
										  { ACE_Reactor::instance()->run_reactor_event_loop(); });
		reactorThread.detach();
	}

	// Fixed, timezone-independent base instant (2023-11-14T22:13:20Z) for deterministic math.
	TimePoint base() { return Clock::from_time_t(1700000000); }

	std::string tmpDir() { return Configuration::instance()->getWorkDir() + "/tmp"; }

	std::string stdoutFileFor(const std::string &name)
	{
		return Configuration::instance()->getWorkDir() + "/stdout/appmesh." + name + ".out";
	}

	void writeTextFile(const std::string &path, const std::string &content)
	{
		std::ofstream out(path, std::ios::trunc);
		out << content;
	}

	int lineCount(const std::string &path)
	{
		std::ifstream in(path);
		int count = 0;
		std::string line;
		while (std::getline(in, line))
			++count;
		return count;
	}

	// Build an Application through the public registration path (FromJson).
	std::shared_ptr<Application> makeApp(const std::string &name, const std::string &command,
										bool enabled, bool restartOnExit)
	{
		nlohmann::json def = {
			{"name", name},
			{"command", command},
			{"owner_principal_id", "test-owner"},
			{"status", enabled},
			{"behavior", {{"exit", restartOnExit ? "restart" : "standby"}}}};
		auto app = std::make_shared<Application>();
		Application::FromJson(app, def);
		return app;
	}

	// Poll `pred` until true or timeout, driving the scheduler tick (execute) each
	// iteration like the daemon's periodic pass would.
	bool waitFor(int timeoutMs, const std::function<void()> &drive, const std::function<bool()> &pred)
	{
		const auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
		while (Clock::now() < deadline)
		{
			if (drive)
				drive();
			if (pred())
				return true;
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
		if (drive)
			drive();
		return pred();
	}

	void tick(Application &app) { app.execute(); }

	void tickAndRequireStablePid(Application &app, pid_t expected, int iterations)
	{
		for (int i = 0; i < iterations; ++i)
		{
			tick(app);
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			REQUIRE(app.getpid() == expected);
		}
	}
}

int main(int argc, char *argv[])
{
	globalInit();
	int result = Catch::Session().run(argc, argv);
	_exit(result == 0 ? 0 : 1);
}

// =============================================================================
// Configuration::loadApps() feeds Utility::yamlToJson() output straight into
// FromJson(): a quoted env value (auth-dex DEX_CLIENT_CREDENTIAL_GRANT_
// ENABLED_BY_DEFAULT: "true") must survive as a string, or app recovery
// aborts daemon startup with json type_error.302.
// =============================================================================
TEST_CASE("fromJson_01_quoted_yaml_env_stays_string", "[application]")
{
	const auto def = Utility::yamlToJson(YAML::Load(
		"name: auth-dex\n"
		"command: /usr/bin/true\n"
		"owner_principal_id: system:appmesh\n"
		"env:\n"
		"  DEX_CLIENT_CREDENTIAL_GRANT_ENABLED_BY_DEFAULT: \"true\"\n"));
	auto app = std::make_shared<Application>();
	Application::FromJson(app, def);
	REQUIRE(app->AsJson(false).at("env").at("DEX_CLIENT_CREDENTIAL_GRANT_ENABLED_BY_DEFAULT") == "true");
}

// The unquoted form of the same file is a type error against the env string
// contract; it must be rejected (loadApps refuses partial recovery) instead of
// being silently coerced.
TEST_CASE("fromJson_02_unquoted_yaml_env_rejected", "[application]")
{
	const auto def = Utility::yamlToJson(YAML::Load(
		"name: auth-dex\n"
		"command: /usr/bin/true\n"
		"owner_principal_id: system:appmesh\n"
		"env:\n"
		"  DEX_FLAG: true\n"));
	auto app = std::make_shared<Application>();
	REQUIRE_THROWS_AS(Application::FromJson(app, def), std::invalid_argument);
}

// =============================================================================
// Run lifecycle through the public API (successor of the former RunState latch
// tests: consume_01_no_pending_exit / consume_02_disabled_status_blocks /
// consume_03_fires_exactly_once).
// =============================================================================

TEST_CASE("lifecycle_01_disabled_app_never_auto_starts", "[application]")
{
	// Boundary: the isEnabled gate — scheduler ticks must never start a run for a
	// DISABLED app (the same gate keeps a non-ENABLED app from auto-handling exits).
	auto app = makeApp("lifecycle_01", "sleep 30", /*enabled*/ false, /*restartOnExit*/ false);
	REQUIRE(app->getStatus() == STATUS::DISABLED);

	for (int i = 0; i < 10; ++i)
	{
		tick(*app);
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	REQUIRE(app->getStatus() == STATUS::DISABLED);
	REQUIRE(app->getpid() <= 1); // ACE_INVALID_PID: no run was ever started
}

TEST_CASE("lifecycle_02_enabled_app_starts_on_tick_and_turns_healthy", "[application]")
{
	// Basic transition: ENABLED + first tick -> run starts (valid pid), and once
	// the phase is Running the health check reports healthy.
	auto app = makeApp("lifecycle_02", "sleep 30", /*enabled*/ true, /*restartOnExit*/ false);
	REQUIRE(app->getStatus() == STATUS::ENABLED);

	tick(*app);
	REQUIRE(waitFor(10000, [&app]() { tick(*app); }, [&app]() { return app->getpid() > 1; }));
	// health() == 0 means healthy (m_health true once the run phase is Running).
	REQUIRE(waitFor(10000, [&app]() { tick(*app); }, [&app]() { return app->health() == 0; }));
	REQUIRE(app->getStatus() == STATUS::ENABLED);
}

TEST_CASE("lifecycle_03_natural_exit_restarts_exactly_once", "[application]")
{
	// The once-per-exit latch: a natural exit arms exactly one restart (after the
	// crash-loop backoff); every later tick over the already-reconciled state is a
	// no-op. Regressions here re-introduce per-tick re-firing of the exit policy.
	const auto script = tmpDir() + "/lifecycle_03.sh";
	const auto marker = tmpDir() + "/lifecycle_03_go";
	const auto runlog = tmpDir() + "/lifecycle_03_runs.log";
	::remove(marker.c_str());
	::remove(runlog.c_str());
	// First run: record itself then exit immediately. Once the marker exists, the
	// restarted run stays alive so pid stability is observable.
	writeTextFile(script, "#!/bin/sh\n"
						  "echo run >> \"" + runlog + "\"\n"
						  "if [ -f \"" + marker + "\" ]; then\n"
						  "  sleep 30\n"
						  "fi\n");

	auto app = makeApp("lifecycle_03", "sh " + script, /*enabled*/ true, /*restartOnExit*/ true);

	tick(*app); // starts run #1, which exits naturally right away
	REQUIRE(waitFor(10000, [&app]() { tick(*app); }, [&runlog]() { return lineCount(runlog) >= 1; }));
	// Let the reactor deliver the exit report (run pid resets to invalid).
	REQUIRE(waitFor(5000, nullptr, [&app]() { return app->getpid() <= 1; }));

	// Arm the long-lived second run, then drive ticks until the latched restart
	// fires (first crash-loop backoff step is 1s).
	writeTextFile(marker, "");
	REQUIRE(waitFor(10000, [&app]() { tick(*app); }, [&app]() { return app->getpid() > 1; }));
	const auto restarted = app->getpid();

	// The exit was consumed exactly once: no further relaunch from the same exit.
	tickAndRequireStablePid(*app, restarted, 30);
}

TEST_CASE("lifecycle_04_disable_kills_run_and_reenable_starts_fresh", "[application]")
{
	// Boundary: disable() bumps the lifecycle generation, kills the run and clears
	// the latch, so the killed run's exit report is a stale reporter: it must not
	// start anything while disabled and must not churn the fresh run after
	// re-enable.
	auto app = makeApp("lifecycle_04", "sleep 30", /*enabled*/ true, /*restartOnExit*/ true);

	tick(*app);
	REQUIRE(waitFor(10000, [&app]() { tick(*app); }, [&app]() { return app->getpid() > 1; }));
	const auto first = app->getpid();

	app->disable();
	REQUIRE(app->getStatus() == STATUS::DISABLED);
	// The killed run's exit lands (possibly from the reactor thread): pid invalid.
	REQUIRE(waitFor(8000, [&app]() { tick(*app); }, [&app]() { return app->getpid() <= 1; }));

	// Ticks while disabled never auto-start (the non-ENABLED gate).
	for (int i = 0; i < 10; ++i)
	{
		tick(*app);
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		REQUIRE(app->getpid() <= 1);
	}

	app->enable();
	REQUIRE(app->getStatus() == STATUS::ENABLED);
	REQUIRE(waitFor(10000, [&app]() { tick(*app); }, [&app]() { return app->getpid() > 1; }));
	const auto second = app->getpid();
	REQUIRE(second != first);

	// A late exit report from the killed first run must not disturb the fresh run.
	tickAndRequireStablePid(*app, second, 30);
}

// =============================================================================
// AppTimer nextTime() — start-form scheduling math (long-running / periodic).
// =============================================================================

TEST_CASE("appTimer_long_returns_request_time_when_after_start", "[apptimer]")
{
	AppTimer timer(base(), Clock::time_point::max(), nullptr);
	const auto from = base() + std::chrono::seconds(5);
	REQUIRE(timer.nextTime(from) == from);
}

TEST_CASE("appTimer_period_aligns_to_interval_grid", "[apptimer]")
{
	AppTimerPeriod timer(base(), Clock::time_point::max(), nullptr, /*intervalSeconds*/ 10);
	// 3s past the grid origin -> next grid point is +7s -> base+10s.
	const auto next = timer.nextTime(base() + std::chrono::seconds(3));
	REQUIRE(next == base() + std::chrono::seconds(10));
}

TEST_CASE("appTimer_cron_preserves_next_second_occurrence", "[apptimer]")
{
	const auto from = base();
	const auto nextSecond = (Clock::to_time_t(from) + 1) % 60;
	const auto expression = std::to_string(nextSecond) + " * * * * *";
	AppTimerCron timer(base(), Clock::time_point::max(), nullptr, expression, /*intervalSeconds*/ 0);

	REQUIRE(timer.nextTime(from) == from + std::chrono::seconds(1));
}
