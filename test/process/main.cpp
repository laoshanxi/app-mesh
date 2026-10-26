// test/process/main.cpp
// Regression tests for the StdoutPump data path, which black-box reproduction
// cannot reach deterministically (signals and poller wakeups are not reliably
// deliverable through the daemon).
#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include "../../src/daemon/process/ForkExec.h"
#include "../../src/daemon/process/StdoutPump.h"
#include <catch.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <string>
#include <sys/time.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

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

// The poller must capture bytes written right after activation and bytes
// written much later through the same pipe (the concurrent-run loss signature:
// early bytes arrived, late bytes vanished), and reach EOF on writer close.
TEST_CASE("StdoutPump poller captures early and late bytes through EOF", "[process]")
{
	int pipeFds[2];
	REQUIRE(::pipe(pipeFds) == 0);
	const int flags = ::fcntl(pipeFds[0], F_GETFL, 0);
	REQUIRE(::fcntl(pipeFds[0], F_SETFL, flags | O_NONBLOCK) == 0); // as the daemon creates it

	char diskTemplate[] = "/tmp/appmesh-poller-test-XXXXXX";
	const int diskFd = ::mkstemp(diskTemplate);
	REQUIRE(diskFd >= 0);
	::unlink(diskTemplate);

	const std::string early = "PROBE\n";
	const std::string late = "hi-late\n";
	auto diskMutex = std::make_shared<std::mutex>();
	auto pump = std::make_shared<StdoutPump>("poller-test", pipeFds[0], diskFd, diskMutex);
	pump->activate();

	REQUIRE(::write(pipeFds[1], early.data(), early.size()) == static_cast<ssize_t>(early.size()));
	std::this_thread::sleep_for(std::chrono::milliseconds(300)); // several poll cycles
	REQUIRE(::write(pipeFds[1], late.data(), late.size()) == static_cast<ssize_t>(late.size()));
	::close(pipeFds[1]);

	// The poller processes EOF on writer close; the daemon's teardown waits
	// for it, and so does this test.
	const std::string expected = early + late;
	for (int i = 0; i < 100 && pump->acceptedBytes() < static_cast<long>(expected.size()); ++i)
		std::this_thread::sleep_for(std::chrono::milliseconds(20));
	pump->stop();

	REQUIRE(pump->acceptedBytes() == static_cast<long>(expected.size()));
	std::string disk(expected.size(), '\0');
	REQUIRE(::pread(diskFd, disk.data(), disk.size(), 0) == static_cast<ssize_t>(expected.size()));
	REQUIRE(disk == expected);
	::close(diskFd);
}

// A pump destroyed while registered (writer still open, no EOF) must detach
// cleanly through the destructor path, and the poller must keep serving later
// pumps — the lost-stop-race regression that would otherwise leave a closed
// fd spinning the poll set.
TEST_CASE("poller survives a pump destroyed while registered", "[process]")
{
	auto diskMutex = std::make_shared<std::mutex>();

	int pipeFds[2];
	REQUIRE(::pipe(pipeFds) == 0);
	const int flags = ::fcntl(pipeFds[0], F_GETFL, 0);
	REQUIRE(::fcntl(pipeFds[0], F_SETFL, flags | O_NONBLOCK) == 0);
	{
		char diskTemplate[] = "/tmp/appmesh-poller-drop-test-XXXXXX";
		const int diskFd = ::mkstemp(diskTemplate);
		REQUIRE(diskFd >= 0);
		::unlink(diskTemplate);
		auto pump = std::make_shared<StdoutPump>("drop-test", pipeFds[0], diskFd, diskMutex);
		pump->activate();
		// No stop(), no EOF: destroy while the poller holds the registration.
		pump.reset();
		::close(diskFd);
	}

	// One full poll cycle: the poller observes the closed fd (POLLNVAL) and
	// drops the retired pump before the next pump allocates fresh fds.
	std::this_thread::sleep_for(std::chrono::milliseconds(400));

	// The destructor closed the read fd; the poller must drop it and keep
	// working for the next pump.
	REQUIRE(::close(pipeFds[1]) == 0);

	int pipe2[2];
	REQUIRE(::pipe(pipe2) == 0);
	const int flags2 = ::fcntl(pipe2[0], F_GETFL, 0);
	REQUIRE(::fcntl(pipe2[0], F_SETFL, flags2 | O_NONBLOCK) == 0);
	char diskTemplate2[] = "/tmp/appmesh-poller-after-test-XXXXXX";
	const int disk2 = ::mkstemp(diskTemplate2);
	REQUIRE(disk2 >= 0);
	::unlink(diskTemplate2);
	auto pump2 = std::make_shared<StdoutPump>("after-drop", pipe2[0], disk2, diskMutex);
	pump2->activate();
	const std::string payload = "still-alive\n";
	REQUIRE(::write(pipe2[1], payload.data(), payload.size()) == static_cast<ssize_t>(payload.size()));
	::close(pipe2[1]);
	for (int i = 0; i < 100 && pump2->acceptedBytes() < static_cast<long>(payload.size()); ++i)
		std::this_thread::sleep_for(std::chrono::milliseconds(20));
	pump2->stop();
	REQUIRE(pump2->acceptedBytes() == static_cast<long>(payload.size()));
	::close(disk2);
}

// ---------------------------------------------------------------------------
// forkExec: the daemon's launch primitive. The child side is raw system calls
// only; these pin the contract AppProcess relies on.
// ---------------------------------------------------------------------------
namespace
{
	int waitExit(pid_t pid)
	{
		int status = 0;
		REQUIRE(::waitpid(pid, &status, 0) == pid);
		return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	}

	ForkExecRequest shellRequest(const std::string &script)
	{
		ForkExecRequest request;
		request.executable = "/bin/sh";
		request.argv = {"/bin/sh", "-c", script};
		request.environment = {"PATH=/usr/bin:/bin"};
		return request;
	}
} // namespace

TEST_CASE("forkExec execs with the requested argv, environment, directory and process group", "[process]")
{
	// The test's own environment stands in for anything that could leak past
	// the explicit environment.
	::setenv("APPMESH_TEST_CANARY", "leak", 1);
	auto request = shellRequest("test \"$1\" = hello && test -z \"$APPMESH_TEST_CANARY\" && test \"$FOO\" = bar"
								" && test \"$(pwd -P)\" = \"$(cd /tmp && pwd -P)\""
								" && test \"$(ps -o pgid= -p $$ | tr -d ' ')\" = \"$$\" && exit 7");
	request.argv.push_back("sh");
	request.argv.push_back("hello");
	request.environment.push_back("FOO=bar");
	request.workingDirectory = "/tmp";
	const auto result = forkExec(request);
	REQUIRE(result.pid > 0);
	REQUIRE(waitExit(result.pid) == 7);
}

TEST_CASE("forkExec hands the child nothing beyond stdin, stdout and stderr", "[process]")
{
	// Many open descriptors in the parent; none may reach the child.
	std::vector<int> held;
	for (int i = 0; i < 50; ++i)
	{
		int fds[2];
		REQUIRE(::pipe(fds) == 0);
		held.push_back(fds[0]);
		held.push_back(fds[1]);
	}
	char outTemplate[] = "/tmp/appmesh-forkexec-XXXXXX";
	const int outFd = ::mkstemp(outTemplate);
	REQUIRE(outFd >= 0);
	auto request = shellRequest("echo /dev/fd/*");
	request.stdoutFd = outFd;
	request.stderrFd = outFd;
	const auto result = forkExec(request);
	REQUIRE(result.pid > 0);
	REQUIRE(waitExit(result.pid) == 0);
	for (int fd : held)
		::close(fd);
	std::string output(4096, '\0');
	const ssize_t n = ::pread(outFd, output.data(), output.size(), 0);
	::close(outFd);
	::unlink(outTemplate);
	REQUIRE(n > 0);
	output.resize(static_cast<std::size_t>(n));
	// Every token is /dev/fd/N; the shell's own glob scan holds /dev/fd open as
	// descriptor 3, so nothing above 3 may appear.
	REQUIRE(output.rfind("/dev/fd/0 /dev/fd/1 /dev/fd/2", 0) == 0);
	int highest = -1;
	for (std::size_t pos = output.find("/dev/fd/"); pos != std::string::npos; pos = output.find("/dev/fd/", pos + 8))
		highest = std::max(highest, std::atoi(output.c_str() + pos + 8));
	REQUIRE(highest <= 3);
}

TEST_CASE("forkExec reports a failed step synchronously, before any run exists", "[process]")
{
	auto missing = shellRequest("exit 0");
	missing.executable = "/nonexistent/program";
	missing.argv[0] = "/nonexistent/program";
	auto result = forkExec(missing);
	REQUIRE(result.pid < 0);
	REQUIRE(result.error == ENOENT);
	REQUIRE(std::string(result.stage) == "execve");

	auto badDir = shellRequest("exit 0");
	badDir.workingDirectory = "/nonexistent/dir";
	result = forkExec(badDir);
	REQUIRE(result.pid < 0);
	REQUIRE(result.error == ENOENT);
	REQUIRE(std::string(result.stage) == "chdir");

	auto badCgroup = shellRequest("exit 0");
	badCgroup.cgroupProcsFiles = {"/nonexistent/cgroup.procs"};
	result = forkExec(badCgroup);
	REQUIRE(result.pid < 0);
	REQUIRE(std::string(result.stage) == "cgroup");

	if (::geteuid() != 0)
	{
		// A non-root parent cannot take another identity; root can (and does).
		auto other = shellRequest("exit 0");
		other.uid = 1;
		other.gid = 1;
		result = forkExec(other);
		REQUIRE(result.pid < 0);
		REQUIRE(result.error == EPERM);
		REQUIRE(std::string(result.stage) == "setgid");
	}
	// Switching to the identity the parent already has is permitted everywhere.
	auto self = shellRequest("exit 0");
	self.uid = ::geteuid();
	self.gid = ::getegid();
	result = forkExec(self);
	REQUIRE(result.pid > 0);
	REQUIRE(waitExit(result.pid) == 0);
}
