// test/application/main.cpp
//
// Characterization tests for the application lifecycle detection logic that the
// RunState refactor touches. These pin the CURRENT behavior so the upcoming
// changes (removing hasExited's magic +1s buffer, reworking the periodic
// first-schedule path) are explicit and reviewable rather than silent.
#define CATCH_CONFIG_RUNNER
#include <catch.hpp>

#include <ace/Init_ACE.h>
#include <ace/OS.h>
#include <ace/Reactor.h>
#include <ace/TP_Reactor.h>
#include <chrono>
#include <memory>
#include <thread>

#include <boost/make_shared.hpp>

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

		auto *tp = new ACE_TP_Reactor();
		ACE_Reactor::instance(new ACE_Reactor(tp, true), true);

		Process_Manager::instance()->open(ACE_Process_Manager::DEFAULT_SIZE,
										   ACE_Reactor::instance());

		static std::thread reactorThread([]()
										  { ACE_Reactor::instance()->run_reactor_event_loop(); });
		reactorThread.detach();
	}

	// Fixed, timezone-independent base instant (2023-11-14T22:13:20Z) for deterministic math.
	TimePoint base() { return Clock::from_time_t(1700000000); }
}

int main(int argc, char *argv[])
{
	globalInit();
	int result = Catch::Session().run(argc, argv);
	_exit(result == 0 ? 0 : 1);
}

// =============================================================================
// consumePendingExit() — the once-per-exit latch that drives handleError().
// =============================================================================

// Subclass to reach protected state/methods. Application uses enable_shared_from_this,
// so it must be heap-allocated via make_shared.
struct ExitHarness : public Application
{
	void setStatus(STATUS s) { m_status.store(s); }

	// Seed the run-state as if a process started and exited, latching exitPending.
	void seedExit(int code)
	{
		updateRunState([&](RunState &r) {
			r.returnCode = code;
			r.startTime = boost::make_shared<TimePoint>(base());
			r.exitTime = boost::make_shared<TimePoint>(base());
			r.exitPending = true;
		});
	}

	bool callConsume() { return consumePendingExit(); }
};

static std::shared_ptr<ExitHarness> makeApp() { return std::make_shared<ExitHarness>(); }

TEST_CASE("consume_01_no_pending_exit", "[application]")
{
	auto app = makeApp(); // fresh: nothing latched
	REQUIRE(app->callConsume() == false);
}

TEST_CASE("consume_02_disabled_status_blocks", "[application]")
{
	auto app = makeApp();
	app->setStatus(STATUS::DISABLED);
	app->seedExit(0);
	// A non-ENABLED app never auto-handles an exit.
	REQUIRE(app->callConsume() == false);
}

TEST_CASE("consume_03_fires_exactly_once", "[application]")
{
	auto app = makeApp();
	app->seedExit(0);
	// The latch is consumed once -> handleError runs once per exit; subsequent reconciles
	// over the same exited state do nothing (this is what fixed the REMOVE re-arm and the
	// former per-tick re-firing).
	REQUIRE(app->callConsume() == true);
	REQUIRE(app->callConsume() == false);
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
