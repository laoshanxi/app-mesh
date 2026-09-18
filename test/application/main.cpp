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

	void writeTextFile(const std::string &path, const std::string &content)
	{
		std::ofstream out(path, std::ios::trunc);
		out << content;
	}

	// Count completed lines. On CentOS 7 a signal landing during the read makes
	// the older libstdc++ throw instead of retrying; that transient error means
	// "no complete line yet" here, so waitFor() keeps polling.
	int lineCount(const std::string &path)
	{
		std::ifstream in(path);
		int count = 0;
		std::string line;
		try
		{
			while (std::getline(in, line))
				++count;
		}
		catch (const std::ios_base::failure &)
		{
		}
		return count;
	}

	// Build an Application through the public registration path (FromJson).
	std::shared_ptr<Application> makeApp(const std::string &name, const std::string &command,
										bool enabled, bool restartOnExit,
										const std::vector<std::string> &dependsOn = {})
	{
		nlohmann::json def = {
			{"name", name},
			{"command", command},
			{"owner_principal_id", "test-owner"},
			{"enabled", enabled},
			{"behavior", {{"exit", restartOnExit ? "restart" : "standby"}}}};
		if (!dependsOn.empty())
			def["depends_on"] = dependsOn;
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
// depends_on — dependency gate for managed starts.
// =============================================================================

TEST_CASE("depends_01_from_json_parses_and_serializes", "[application]")
{
	// The persisted/REST contract: names are trimmed and de-duplicated, and a
	// malformed definition must be rejected instead of silently dropping edges.
	nlohmann::json def = {
		{"name", "depends_01"},
		{"command", "sleep 30"},
		{"owner_principal_id", "test-owner"},
		{"depends_on", {"dep-a", "dep-b", "dep-a ", "  "}}};
	auto app = std::make_shared<Application>();
	Application::FromJson(app, def);
	REQUIRE(app->dependsOn() == std::vector<std::string>{"dep-a", "dep-b"});
	REQUIRE(app->AsJson(false).at("depends_on") == nlohmann::json::array({"dep-a", "dep-b"}));

	def["depends_on"] = "dep-a";
	REQUIRE_THROWS_AS(Application::FromJson(std::make_shared<Application>(), def), std::invalid_argument);
	def["depends_on"] = nlohmann::json::array({1});
	REQUIRE_THROWS_AS(Application::FromJson(std::make_shared<Application>(), def), std::invalid_argument);
	def["depends_on"] = nlohmann::json::array({"depends_01"});
	REQUIRE_THROWS_AS(Application::FromJson(std::make_shared<Application>(), def), std::invalid_argument);
}

TEST_CASE("depends_02_gate_holds_until_dependency_healthy", "[application]")
{
	// The core promise: a dependent never starts while its dependency is not
	// running and healthy, exposes waiting_for so the block is observable, and
	// starts on its own once the dependency recovers (no manual wakeup).
	auto config = Configuration::instance();
	auto dep = makeApp("depends_02_dep", "sleep 30", /*enabled*/ false, /*restartOnExit*/ false);
	auto dependent = makeApp("depends_02_app", "sleep 30", /*enabled*/ true, /*restartOnExit*/ false,
							 {"depends_02_dep"});
	config->registerRecoveredApp(dep);
	config->registerRecoveredApp(dependent);

	for (int i = 0; i < 10; ++i)
	{
		tick(*dependent);
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		REQUIRE(dependent->getpid() <= 1);
	}
	REQUIRE(dependent->waitingFor() == std::vector<std::string>{"depends_02_dep"});
	REQUIRE(dependent->AsJson(true).at("waiting_for") == nlohmann::json::array({"depends_02_dep"}));

	// Dependency becomes enabled, then running, then healthy: the gate opens on
	// the next scheduler pass.
	dep->enable();
	const auto driveBoth = [&]() {
		tick(*dep);
		tick(*dependent);
	};
	REQUIRE(waitFor(10000, driveBoth, [&dep]() { return dep->getpid() > 1 && dep->health() == 0; }));
	REQUIRE(waitFor(10000, driveBoth, [&dependent]() { return dependent->getpid() > 1; }));
	REQUIRE(dependent->waitingFor().empty());
}

TEST_CASE("depends_03_dependency_stop_does_not_stop_dependent", "[application]")
{
	// Compose semantics: a dependency going down must never kill an already
	// running dependent — only the NEXT start is gated. Stopping both would
	// turn one failure into a cascade.
	auto config = Configuration::instance();
	auto dep = makeApp("depends_03_dep", "sleep 30", /*enabled*/ true, /*restartOnExit*/ false);
	auto dependent = makeApp("depends_03_app", "sleep 30", /*enabled*/ true, /*restartOnExit*/ false,
							 {"depends_03_dep"});
	config->registerRecoveredApp(dep);
	config->registerRecoveredApp(dependent);

	tick(*dep);
	REQUIRE(waitFor(10000, [&]() { tick(*dep); }, [&dep]() { return dep->getpid() > 1 && dep->health() == 0; }));
	tick(*dependent);
	REQUIRE(waitFor(10000, [&]() { tick(*dependent); }, [&dependent]() { return dependent->getpid() > 1; }));
	const auto dependentPid = dependent->getpid();

	dep->disable();
	REQUIRE(waitFor(8000, [&]() { tick(*dependent); }, [&dep]() { return dep->getpid() <= 1; }));
	tickAndRequireStablePid(*dependent, dependentPid, 20);
	REQUIRE(dependent->waitingFor() == std::vector<std::string>{"depends_03_dep"});
}

TEST_CASE("depends_04_restart_blocked_while_dependency_down", "[application]")
{
	// Restart convergence: a natural exit arms a restart, but the armed start
	// must stay held while the dependency is down and fire once it is healthy
	// again. Without the gate a crash-looping dependent would spin against a
	// dead dependency forever.
	const auto script = tmpDir() + "/depends_04.sh";
	const auto marker = tmpDir() + "/depends_04_go";
	const auto runlog = tmpDir() + "/depends_04_runs.log";
	::remove(marker.c_str());
	::remove(runlog.c_str());
	writeTextFile(script, "#!/bin/sh\n"
						  "echo run >> \"" + runlog + "\"\n"
						  "if [ -f \"" + marker + "\" ]; then\n"
						  "  sleep 30\n"
						  "fi\n");

	auto config = Configuration::instance();
	auto dep = makeApp("depends_04_dep", "sleep 30", /*enabled*/ true, /*restartOnExit*/ false);
	auto dependent = makeApp("depends_04_app", "sh " + script, /*enabled*/ true, /*restartOnExit*/ true,
							 {"depends_04_dep"});
	config->registerRecoveredApp(dep);
	config->registerRecoveredApp(dependent);

	// Dependency healthy, dependent starts and exits immediately (run #1).
	tick(*dep);
	REQUIRE(waitFor(10000, [&]() { tick(*dep); }, [&dep]() { return dep->getpid() > 1 && dep->health() == 0; }));
	tick(*dependent);
	REQUIRE(waitFor(10000, [&]() { tick(*dependent); }, [&runlog]() { return lineCount(runlog) >= 1; }));

	// Dependency goes down: the latched restart must not fire even after the
	// 1s crash-loop backoff expires.
	dep->disable();
	REQUIRE(waitFor(8000, [&]() { tick(*dependent); }, [&dependent]() { return dependent->getpid() <= 1; }));
	for (int i = 0; i < 20; ++i)
	{
		tick(*dependent);
		std::this_thread::sleep_for(std::chrono::milliseconds(150));
		REQUIRE(lineCount(runlog) == 1);
		REQUIRE(dependent->getpid() <= 1);
	}

	// Dependency recovers: the held restart fires without any manual action.
	dep->enable();
	writeTextFile(marker, "");
	REQUIRE(waitFor(15000, [&]() {
		tick(*dep);
		tick(*dependent);
	}, [&runlog]() { return lineCount(runlog) >= 2; }));
	REQUIRE(waitFor(10000, [&]() { tick(*dependent); }, [&dependent]() { return dependent->getpid() > 1; }));
}

TEST_CASE("depends_05_registration_validation", "[application]")
{
	// Registration is the only place the graph stays consistent: recurring
	// schedules (no delay/skip/fire answer at fire time), dangling references,
	// and cycles are all rejected before any state is replaced.
	auto config = Configuration::instance();

	// On-demand applications never converge through the scheduler.
	auto onDemand = makeApp("depends_05_on_demand", "sleep 30", true, false, {"depends_05_dep"});
	REQUIRE_THROWS_AS(config->validateDependencies(onDemand, /*persistable*/ false), std::invalid_argument);

	// Recurring applications fire at fixed instants; gating has no defined meaning.
	nlohmann::json recurringDef = {
		{"name", "depends_05_interval"},
		{"command", "true"},
		{"owner_principal_id", "test-owner"},
		{"interval", "10"},
		{"depends_on", nlohmann::json::array({"depends_05_dep"})}};
	auto recurring = std::make_shared<Application>();
	Application::FromJson(recurring, recurringDef);
	REQUIRE_THROWS_AS(config->validateDependencies(recurring, /*persistable*/ true), std::invalid_argument);

	// Unknown dependency name.
	auto dangling = makeApp("depends_05_dangling", "sleep 30", true, false, {"depends_05_no_such_app"});
	REQUIRE_THROWS_AS(config->validateDependencies(dangling, /*persistable*/ true), std::invalid_argument);

	// Cycle: existing A -> B (bypassing registration simulates a hand-loaded
	// definition), candidate B -> A must be rejected even though A exists.
	auto a = makeApp("depends_05_a", "sleep 30", true, false, {"depends_05_b"});
	config->registerRecoveredApp(a);
	auto cyclic = makeApp("depends_05_b", "sleep 30", true, false, {"depends_05_a"});
	REQUIRE_THROWS_AS(config->validateDependencies(cyclic, /*persistable*/ true), std::invalid_argument);

	// Valid: dependency registered, chain acyclic.
	auto valid = makeApp("depends_05_valid", "sleep 30", true, false, {"depends_05_a"});
	REQUIRE_NOTHROW(config->validateDependencies(valid, /*persistable*/ true));
}

TEST_CASE("depends_06_missing_dependency_does_not_gate", "[application]")
{
	// A dependency name with no registered application (deleted dependency, or
	// a dangling persisted reference) must not hold the dependent forever:
	// deleting a dependency may not brick the applications behind it.
	auto config = Configuration::instance();
	auto dependent = makeApp("depends_06_app", "sleep 30", /*enabled*/ true, /*restartOnExit*/ false,
							 {"depends_06_never_registered"});
	config->registerRecoveredApp(dependent);

	tick(*dependent);
	REQUIRE(waitFor(10000, [&]() { tick(*dependent); }, [&dependent]() { return dependent->getpid() > 1; }));
	REQUIRE(dependent->waitingFor().empty());
}

TEST_CASE("depends_07_recovery_validation", "[application]")
{
	// Recovery loads YAML without REST validation, then validates the whole
	// graph once: a persisted cycle must refuse partial recovery (boot fails
	// loud instead of wedging readiness), while a dangling reference must load
	// and not gate (removing a dependency may not brick recovery).
	auto config = Configuration::instance();
	const auto appDir = tmpDir() + "/depends_07_apps";
	boost::filesystem::remove_all(appDir);
	boost::filesystem::create_directories(appDir);

	writeTextFile(appDir + "/x.yaml",
				  "name: depends_07_x\ncommand: sleep 30\nowner_principal_id: test-owner\n"
				  "enabled: 1\ndepends_on:\n  - depends_07_y\n");
	writeTextFile(appDir + "/y.yaml",
				  "name: depends_07_y\ncommand: sleep 30\nowner_principal_id: test-owner\n"
				  "enabled: 1\ndepends_on:\n  - depends_07_x\n");
	config->loadApps(appDir);
	REQUIRE_THROWS_AS(config->validateRecoveredDependencies(), std::runtime_error);
	// Drop the cyclic pair from the shared map so the second half validates clean.
	config->removeApp("depends_07_x");
	config->removeApp("depends_07_y");

	// Dangling reference: loads, validates clean, and does not gate at runtime.
	boost::filesystem::remove_all(appDir);
	boost::filesystem::create_directories(appDir);
	writeTextFile(appDir + "/z.yaml",
				  "name: depends_07_z\ncommand: sleep 30\nowner_principal_id: test-owner\n"
				  "enabled: 1\ndepends_on:\n  - depends_07_ghost\n");
	config->loadApps(appDir);
	REQUIRE_NOTHROW(config->validateRecoveredDependencies());
	const auto dependent = config->getApp("depends_07_z", false);
	REQUIRE(dependent);
	tick(*dependent);
	REQUIRE(waitFor(10000, [&]() { tick(*dependent); }, [&dependent]() { return dependent->getpid() > 1; }));
}

TEST_CASE("depends_08_multiple_dependencies_all_must_be_ready", "[application]")
{
	// systemd-style AND semantics: with two dependencies, one healthy and one
	// disabled, the dependent stays gated and waiting_for names only the unmet
	// one; it starts only after every dependency is healthy.
	auto config = Configuration::instance();
	auto depA = makeApp("depends_08_a", "sleep 30", /*enabled*/ true, /*restartOnExit*/ false);
	auto depB = makeApp("depends_08_b", "sleep 30", /*enabled*/ false, /*restartOnExit*/ false);
	auto dependent = makeApp("depends_08_app", "sleep 30", /*enabled*/ true, /*restartOnExit*/ false,
							 {"depends_08_a", "depends_08_b"});
	config->registerRecoveredApp(depA);
	config->registerRecoveredApp(depB);
	config->registerRecoveredApp(dependent);

	const auto driveAll = [&]() {
		tick(*depA);
		tick(*depB);
		tick(*dependent);
	};
	REQUIRE(waitFor(10000, driveAll, [&depA]() { return depA->getpid() > 1 && depA->health() == 0; }));
	for (int i = 0; i < 10; ++i)
	{
		driveAll();
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		REQUIRE(dependent->getpid() <= 1);
	}
	REQUIRE(dependent->waitingFor() == std::vector<std::string>{"depends_08_b"});

	depB->enable();
	REQUIRE(waitFor(10000, driveAll, [&depB]() { return depB->getpid() > 1 && depB->health() == 0; }));
	REQUIRE(waitFor(10000, driveAll, [&dependent]() { return dependent->getpid() > 1; }));
	REQUIRE(dependent->waitingFor().empty());
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
