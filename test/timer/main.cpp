// test/timer/main.cpp
#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include <catch.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

#include "../../src/common/TimerHandler.h"

namespace
{
	// Poll until the predicate holds or the budget expires, so timing-sensitive
	// assertions do not depend on a fixed sleep being long enough.
	bool waitUntil(const std::function<bool()> &pred, int timeoutMs)
	{
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
		while (std::chrono::steady_clock::now() < deadline)
		{
			if (pred())
				return true;
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
		}
		return pred();
	}

	// Blocks the timer-dispatch thread inside a callback until open(), so a test
	// can deterministically overlap a running callback with registration or
	// cancellation from the test thread. Opens itself after a bounded wait so a
	// failing test cannot wedge the dispatch thread.
	class Gate
	{
	public:
		void wait()
		{
			std::unique_lock<std::mutex> lock(m_mutex);
			m_cv.wait_for(lock, std::chrono::seconds(5), [this]() { return m_open; });
		}

		void open()
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			m_open = true;
			m_cv.notify_all();
		}

	private:
		std::mutex m_mutex;
		std::condition_variable m_cv;
		bool m_open{false};
	};

	// Runs after every handler already queued on the dispatch thread, so a test
	// can observe the effect of a posted arm/cancel without racing it.
	void drainDispatchThread()
	{
		std::atomic<int> sentinel{0};
		TIMER_MANAGER::instance()->registerTimer(0, 0, "sentinel", [&sentinel]()
												{
			sentinel++;
			return false; });
		REQUIRE(waitUntil([&sentinel]() { return sentinel.load() == 1; }, 2000));
	}

	class Probe : public TimerHandler
	{
	public:
		std::atomic_long m_slot{INVALID_TIMER_ID};
		std::atomic<int> m_fired{0};
	};
}

TEST_CASE("one_shot_fires_and_resets_slot", "[timer]")
{
	// HttpRequestWithTimeout's reply-vs-timeout race relies on the slot being
	// atomically reset once a one-shot timer fires.
	auto probe = std::make_shared<Probe>();
	const long token = probe->registerTimer(probe->m_slot, 30, 0, "test", [probe]() {
		probe->m_fired++;
		return false;
	});
	REQUIRE(isValidTimerId(token));
	REQUIRE(isValidTimerId(probe->m_slot));
	REQUIRE(waitUntil([&]() { return probe->m_fired.load() == 1; }, 2000));
	REQUIRE(!isValidTimerId(probe->m_slot));
}

TEST_CASE("one_shot_cancel_prevents_fire", "[timer]")
{
	auto probe = std::make_shared<Probe>();
	REQUIRE(isValidTimerId(probe->registerTimer(probe->m_slot, 10000, 0, "test", [probe]() {
		probe->m_fired++;
		return false;
	})));
	REQUIRE(probe->cancelTimer(probe->m_slot));
	REQUIRE(!isValidTimerId(probe->m_slot));
	std::this_thread::sleep_for(std::chrono::milliseconds(200));
	REQUIRE(probe->m_fired.load() == 0);
}

TEST_CASE("recurring_stops_when_callback_returns_false", "[timer]")
{
	// AppProcess::onTimerCheckStdout stops its polling loop by returning false;
	// the slot must be reset so the process does not keep a stale token.
	auto probe = std::make_shared<Probe>();
	REQUIRE(isValidTimerId(probe->registerTimer(probe->m_slot, 20, 20, "test", [probe]() {
		return ++probe->m_fired < 3;
	})));
	REQUIRE(waitUntil([&]() { return probe->m_fired.load() >= 3; }, 2000));
	REQUIRE(waitUntil([&]() { return !isValidTimerId(probe->m_slot); }, 2000));
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	REQUIRE(probe->m_fired.load() == 3);
}

TEST_CASE("slot_replacement_cancels_previous_timer", "[timer]")
{
	// HttpRequestOutputView::init re-registers into the same slot; the replaced
	// timer must never fire and must not erase the replacement's token.
	auto probe = std::make_shared<Probe>();
	auto oldFired = std::make_shared<std::atomic<int>>(0);
	auto newFired = std::make_shared<std::atomic<int>>(0);
	// The old timer would fire at 100ms if the replacement failed to cancel it.
	REQUIRE(isValidTimerId(probe->registerTimer(probe->m_slot, 100, 0, "test", [oldFired]() {
		(*oldFired)++;
		return false;
	})));
	REQUIRE(isValidTimerId(probe->registerTimer(probe->m_slot, 30, 0, "test", [newFired]() {
		(*newFired)++;
		return false;
	})));
	REQUIRE(waitUntil([&]() { return newFired->load() == 1; }, 2000));
	// Past the old timer's deadline: canceled, not just delayed.
	std::this_thread::sleep_for(std::chrono::milliseconds(300));
	REQUIRE(oldFired->load() == 0);
}

TEST_CASE("lambda_only_registration_via_timer_manager", "[timer]")
{
	auto fired = std::make_shared<std::atomic<int>>(0);
	const long token = TIMER_MANAGER::instance()->registerTimer(30, 0, "test", [fired]() {
		(*fired)++;
		return false;
	});
	REQUIRE(isValidTimerId(token));
	REQUIRE(waitUntil([&]() { return fired->load() == 1; }, 2000));

	// A token that already fired is reported as released, not as an error.
	REQUIRE(!TIMER_MANAGER::instance()->cancelTimer(token));
}

TEST_CASE("cancel_from_own_callback_stops_recurring_timer", "[timer]")
{
	// Callbacks run without any queue lock held, so self-cancellation is
	// deterministic: the current invocation completes, the re-arm is canceled.
	auto probe = std::make_shared<Probe>();
	REQUIRE(isValidTimerId(probe->registerTimer(probe->m_slot, 20, 20, "test", [probe]() {
		probe->m_fired++;
		probe->cancelTimer(probe->m_slot);
		return true;
	})));
	REQUIRE(waitUntil([&]() { return probe->m_fired.load() == 1; }, 2000));
	std::this_thread::sleep_for(std::chrono::milliseconds(150));
	REQUIRE(probe->m_fired.load() == 1);
}

TEST_CASE("concurrent_register_and_cancel_is_safe", "[timer]")
{
	// Timer registration and cancellation race in production (disable vs.
	// destroy, reply vs. timeout); churn must never crash or corrupt the manager.
	std::shared_ptr<std::atomic<int>> fired = std::make_shared<std::atomic<int>>(0);
	std::vector<std::thread> threads;
	for (int t = 0; t < 4; ++t)
	{
		threads.emplace_back([fired]() {
			for (int i = 0; i < 50; ++i)
			{
				const long token = TIMER_MANAGER::instance()->registerTimer(100000, 0, "test", [fired]() {
					(*fired)++;
					return false;
				});
				if (isValidTimerId(token))
					TIMER_MANAGER::instance()->cancelTimer(token);
			}
		});
	}
	for (auto &thread : threads)
		thread.join();
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	REQUIRE(fired->load() == 0);
}

TEST_CASE("one_shot_ignores_callback_true_return", "[timer]")
{
	// The callback return value only means "continue" for a recurring timer. A
	// one-shot must never re-arm, or the exit finalizer and HTTP timeout would
	// replay forever.
	auto probe = std::make_shared<Probe>();
	REQUIRE(isValidTimerId(probe->registerTimer(probe->m_slot, 20, 0, "test", [probe]() {
		probe->m_fired++;
		return true;
	})));
	REQUIRE(waitUntil([&]() { return probe->m_fired.load() == 1; }, 2000));
	std::this_thread::sleep_for(std::chrono::milliseconds(150));
	REQUIRE(probe->m_fired.load() == 1);
	REQUIRE(!isValidTimerId(probe->m_slot));
}

TEST_CASE("zero_delay_one_shot_fires_without_interval", "[timer]")
{
	// AppProcess::onTimerExit is registered with delay 0 from the process upcall:
	// cleanup must run on the next dispatch, not one interval later.
	auto fired = std::make_shared<std::atomic<int>>(0);
	REQUIRE(isValidTimerId(TIMER_MANAGER::instance()->registerTimer(0, 0, "test", [fired]() {
		(*fired)++;
		return false;
	})));
	REQUIRE(waitUntil([&]() { return fired->load() == 1; }, 2000));
}

TEST_CASE("zero_delay_recurring_fires_before_first_interval", "[timer]")
{
	// TimerStdoutStrategy registers delay 0 with interval 1000ms; the first
	// dispatch must not wait a whole interval, and cancellation must stop it
	// even when the next fire is far away.
	auto probe = std::make_shared<Probe>();
	REQUIRE(isValidTimerId(probe->registerTimer(probe->m_slot, 0, 1000, "test", [probe]() {
		probe->m_fired++;
		return true;
	})));
	REQUIRE(waitUntil([&]() { return probe->m_fired.load() == 1; }, 500));
	REQUIRE(probe->cancelTimer(probe->m_slot));
	REQUIRE(!isValidTimerId(probe->m_slot));
	const int settled = probe->m_fired.load();
	std::this_thread::sleep_for(std::chrono::milliseconds(200));
	REQUIRE(probe->m_fired.load() == settled);
}

TEST_CASE("recurring_callback_exception_stops_timer", "[timer]")
{
	// A throwing callback must unwind to a stopped, released timer; a recurring
	// timer that kept re-arming after an exception would throw on every tick.
	auto probe = std::make_shared<Probe>();
	REQUIRE(isValidTimerId(probe->registerTimer(probe->m_slot, 10, 10, "test", [probe]() -> bool {
		if (++probe->m_fired >= 2)
			throw std::runtime_error("callback failure");
		return true;
	})));
	REQUIRE(waitUntil([&]() { return probe->m_fired.load() >= 2; }, 2000));
	REQUIRE(waitUntil([&]() { return !isValidTimerId(probe->m_slot); }, 2000));
	std::this_thread::sleep_for(std::chrono::milliseconds(150));
	REQUIRE(probe->m_fired.load() == 2);
}

TEST_CASE("recurring_callback_unknown_exception_stops_timer", "[timer]")
{
	// A non-std exception must not escape the dispatch thread; it stops the timer
	// like any other failure instead of terminating the daemon.
	auto probe = std::make_shared<Probe>();
	REQUIRE(isValidTimerId(probe->registerTimer(probe->m_slot, 10, 10, "test", [probe]() -> bool {
		probe->m_fired++;
		throw 42;
	})));
	REQUIRE(waitUntil([&]() { return probe->m_fired.load() == 1; }, 2000));
	REQUIRE(waitUntil([&]() { return !isValidTimerId(probe->m_slot); }, 2000));
	std::this_thread::sleep_for(std::chrono::milliseconds(150));
	REQUIRE(probe->m_fired.load() == 1);
}

TEST_CASE("finished_callback_does_not_clear_replacement_slot", "[timer]")
{
	// HttpRequestOutputView re-registers into the same slot while an older timer
	// is still winding down. The older timer clears the slot with a CAS on its own
	// token, so it must not erase the replacement token.
	auto probe = std::make_shared<Probe>();
	auto gate = std::make_shared<Gate>();
	auto oldRunning = std::make_shared<std::atomic<bool>>(false);
	REQUIRE(isValidTimerId(probe->registerTimer(probe->m_slot, 10, 10, "test", [gate, oldRunning]() {
		oldRunning->store(true);
		gate->wait();
		return false;
	})));
	REQUIRE(waitUntil([&]() { return oldRunning->load(); }, 2000));

	const long replacement = probe->registerTimer(probe->m_slot, 30000, 0, "test", [probe]() {
		probe->m_fired++;
		return false;
	});
	REQUIRE(isValidTimerId(replacement));
	REQUIRE(probe->m_slot.load() == replacement);

	// Let the replaced timer finish and release, then prove it left the slot alone.
	gate->open();
	drainDispatchThread();
	REQUIRE(probe->m_slot.load() == replacement);
	REQUIRE(probe->m_fired.load() == 0);
	REQUIRE(probe->cancelTimer(probe->m_slot));
}

TEST_CASE("cancel_while_callback_running_stops_recurring_timer", "[timer]")
{
	// TimerStdoutStrategy::teardown cancels a timer that may be mid-dispatch. The
	// running invocation completes, but the re-arm must be discarded so the timer
	// does not survive its own cancellation.
	auto probe = std::make_shared<Probe>();
	auto gate = std::make_shared<Gate>();
	auto running = std::make_shared<std::atomic<bool>>(false);
	REQUIRE(isValidTimerId(probe->registerTimer(probe->m_slot, 10, 10, "test", [probe, gate, running]() {
		probe->m_fired++;
		running->store(true);
		gate->wait();
		return true;
	})));
	REQUIRE(waitUntil([&]() { return running->load(); }, 2000));
	REQUIRE(probe->cancelTimer(probe->m_slot));
	REQUIRE(!isValidTimerId(probe->m_slot));

	gate->open();
	drainDispatchThread();
	std::this_thread::sleep_for(std::chrono::milliseconds(150));
	REQUIRE(probe->m_fired.load() == 1);
}

TEST_CASE("register_from_timer_callback_is_allowed", "[timer]")
{
	// Finalization chains one timer from another; a lock held across callbacks
	// would deadlock the dispatch thread here.
	auto probe = std::make_shared<Probe>();
	auto chained = std::make_shared<std::atomic<int>>(0);
	REQUIRE(isValidTimerId(probe->registerTimer(probe->m_slot, 10, 0, "test", [probe, chained]() {
		probe->m_fired++;
		TIMER_MANAGER::instance()->registerTimer(10, 0, "test", [chained]() {
			(*chained)++;
			return false;
		});
		return false;
	})));
	REQUIRE(waitUntil([&]() { return chained->load() == 1; }, 2000));
	REQUIRE(probe->m_fired.load() == 1);
}

TEST_CASE("cancel_by_raw_token_releases_slot", "[timer]")
{
	// The raw-token overload is what replaces a timer in the same slot. It clears
	// the published slot from the dispatch thread, so the slot converges to
	// invalid shortly after the call returns.
	auto probe = std::make_shared<Probe>();
	const long token = probe->registerTimer(probe->m_slot, 5000, 0, "test", [probe]() {
		probe->m_fired++;
		return false;
	});
	REQUIRE(isValidTimerId(token));
	REQUIRE(TIMER_MANAGER::instance()->cancelTimer(token));
	REQUIRE(waitUntil([&]() { return !isValidTimerId(probe->m_slot); }, 2000));
	std::this_thread::sleep_for(std::chrono::milliseconds(150));
	REQUIRE(probe->m_fired.load() == 0);
}

TEST_CASE("concurrent_slot_churn_leaves_no_live_timer", "[timer]")
{
	// Reply-vs-timeout paths register and cancel the same slot from different
	// threads. Whatever wins, no timer may keep firing after the churn stops.
	std::vector<std::shared_ptr<Probe>> probes;
	for (int t = 0; t < 4; ++t)
		probes.push_back(std::make_shared<Probe>());

	std::vector<std::thread> threads;
	for (int t = 0; t < 4; ++t)
	{
		threads.emplace_back([&probes, t]() {
			auto probe = probes[t];
			for (int i = 0; i < 50; ++i)
			{
				const long token = probe->registerTimer(probe->m_slot, 5, 0, "test", [probe]() {
					probe->m_fired++;
					return false;
				});
				if (isValidTimerId(token) && i % 2 == 0)
					probe->cancelTimer(probe->m_slot);
			}
		});
	}
	for (auto &thread : threads)
		thread.join();

	std::this_thread::sleep_for(std::chrono::milliseconds(300));
	for (auto &probe : probes)
	{
		const int settled = probe->m_fired.load();
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		REQUIRE(probe->m_fired.load() == settled);
		REQUIRE(settled <= 50);
	}
}
