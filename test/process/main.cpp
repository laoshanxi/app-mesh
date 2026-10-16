// test/process/main.cpp
// Regression test for the StdoutPump EINTR drain retry, which black-box
// reproduction cannot reach (signals are not deterministically deliverable
// through the daemon).
#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include "../../src/daemon/process/StdoutPump.h"
#include <catch.hpp>

#include <atomic>
#include <csignal>
#include <cstdio>
#include <memory>
#include <mutex>
#include <unistd.h>

namespace
{
	std::atomic<int> g_alarmDeliveries{0};
	int g_signalWriteFd = -1;

	// No SA_RESTART: the read fails with EINTR. First delivery releases the
	// drain (write + close are async-signal-safe).
	extern "C" void alarmSignalHandler(int)
	{
		if (g_alarmDeliveries.fetch_add(1) == 0 && g_signalWriteFd >= 0)
		{
			const char byte = 'x';
			::write(g_signalWriteFd, &byte, 1); // best effort; close still gives EOF
			::close(g_signalWriteFd);
			g_signalWriteFd = -1;
		}
	}
} // namespace

// The drain must retry after EINTR. A blocking read is interrupted by a
// repeating timer; the handler delivers the byte and EOF. With the retry
// acceptedBytes == 1; without it 0.
TEST_CASE("StdoutPump stop drains through an EINTR interruption", "[process]")
{
	int pipeFds[2];
	REQUIRE(::pipe(pipeFds) == 0);
	// Blocking read end: the drain blocks and the interrupt is deterministic.

	char diskTemplate[] = "/tmp/appmesh-eintr-test-XXXXXX";
	const int diskFd = ::mkstemp(diskTemplate);
	REQUIRE(diskFd >= 0);
	::unlink(diskTemplate);

	struct sigaction installed{};
	installed.sa_handler = alarmSignalHandler;
	sigemptyset(&installed.sa_mask);
	installed.sa_flags = 0; // no SA_RESTART: the read must return EINTR
	struct sigaction previous;
	REQUIRE(::sigaction(SIGALRM, &installed, &previous) == 0);

	g_alarmDeliveries = 0;
	g_signalWriteFd = pipeFds[1];
	struct itimerval timer{};
	timer.it_interval.tv_usec = 300 * 1000; // keep interrupting retries too
	timer.it_value.tv_usec = 300 * 1000;    // fires while blocked in read()
	REQUIRE(::setitimer(ITIMER_REAL, &timer, nullptr) == 0);

	auto diskMutex = std::make_shared<std::mutex>();
	auto pump = std::make_shared<StdoutPump>("eintr-test", pipeFds[0], diskFd, diskMutex);
	pump->stop();

	struct itimerval off{};
	::setitimer(ITIMER_REAL, &off, nullptr);
	::sigaction(SIGALRM, &previous, nullptr);
	g_signalWriteFd = -1;
	::close(diskFd);

	REQUIRE(g_alarmDeliveries.load() >= 1); // an interrupt was delivered
	REQUIRE(pump->acceptedBytes() == 1);    // and the drain retried through it
}
