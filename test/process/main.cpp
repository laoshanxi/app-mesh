// test/process/main.cpp
#define CATCH_CONFIG_RUNNER
#include <catch.hpp>

#include <ace/Init_ACE.h>
#include <ace/OS.h>
#include <ace/Reactor.h>
#include <ace/TP_Reactor.h>
#include <chrono>
#include <fstream>
#include <thread>

#include "../../src/common/Utility.h"
#include "../../src/daemon/Configuration.h"
#include "../../src/daemon/process/AppProcess.h"
#include "../../src/daemon/process/StdoutStrategy.h"

namespace
{
	void globalInit()
	{
		ACE::init();
		Utility::initLogging("test_process");
		Utility::setLogLevel("DEBUG");

		auto config = std::make_shared<Configuration>();
		Configuration::instance(config);

		boost::filesystem::create_directories(config->getWorkDir() + "/tmp");
		auto stdinDir = boost::filesystem::path(config->getWorkDir()) / "stdin";
		boost::filesystem::create_directories(stdinDir);

		auto *tp = new ACE_TP_Reactor();
		ACE_Reactor::instance(new ACE_Reactor(tp, true), true);

		Process_Manager::instance()->open(ACE_Process_Manager::DEFAULT_SIZE,
										  ACE_Reactor::instance());

		static std::thread reactorThread([]()
										 { ACE_Reactor::instance()->run_reactor_event_loop(); });
		reactorThread.detach();

		LOG_INF << "Test initialized, pid=" << ACE_OS::getpid();
	}
}

int main(int argc, char *argv[])
{
	fprintf(stderr, ">>> main entered\n");
	globalInit();
	fprintf(stderr, ">>> init done, running Catch\n");
	int result = Catch::Session().run(argc, argv);
	fprintf(stderr, ">>> Catch returned %d\n", result);
	_exit(result == 0 ? 0 : 1);
}

// =============================================================================
// Helpers
// =============================================================================

static std::shared_ptr<AppProcess> makeProcess()
{
	return std::make_shared<AppProcess>(std::weak_ptr<Application>());
}

static std::string tmpFile()
{
	static std::atomic<int> counter{0};
	return "/tmp/appmesh_ut_" + std::to_string(ACE_OS::getpid()) + "_" + std::to_string(++counter) + ".out";
}

// =============================================================================
// 01-02: Construction / destruction basics
// =============================================================================

TEST_CASE("AppProcess_01_defaults", "[process]")
{
	auto p = makeProcess();
	REQUIRE(p->getpid() == ACE_INVALID_PID);
	REQUIRE(p->returnValue() == -1);
	REQUIRE_FALSE(p->running());
	REQUIRE_FALSE(p->getuuid().empty());
	REQUIRE(p->stdoutDispatchedBytes() == 0);
	REQUIRE(p->startError().empty());
}

TEST_CASE("AppProcess_02_destroy_without_spawn", "[process]")
{
	{ auto p = makeProcess(); }
	SUCCEED("~AppProcess without spawn");
}

TEST_CASE("AppProcess_03_uuid_uniqueness", "[process]")
{
	auto a = makeProcess(), b = makeProcess(), c = makeProcess();
	REQUIRE(a->getuuid() != b->getuuid());
	REQUIRE(b->getuuid() != c->getuuid());
	REQUIRE(a->getkey() != b->getkey());
}

// =============================================================================
// 10-11: Invalid command / spawn failure
// =============================================================================

TEST_CASE("AppProcess_10_invalid_command", "[process]")
{
	auto p = makeProcess();
	auto f = tmpFile();
	REQUIRE(p->spawnProcess("/no/such/binary", "", "", {}, nullptr, f) == ACE_INVALID_PID);
	REQUIRE_FALSE(p->startError().empty());
	REQUIRE_FALSE(p->running());
	Utility::removeFile(f);
}

TEST_CASE("AppProcess_11_no_exec_permission", "[process]")
{
	auto p = makeProcess();
	auto f = tmpFile();
	REQUIRE(p->spawnProcess("/etc/passwd", "", "", {}, nullptr, f) == ACE_INVALID_PID);
	REQUIRE_FALSE(p->startError().empty());
	Utility::removeFile(f);
}

// =============================================================================
// 20-23: Spawn + natural exit (various durations)
// =============================================================================

TEST_CASE("AppProcess_20_echo_exit", "[process]")
{
	auto p = makeProcess();
	auto f = tmpFile();
	REQUIRE(p->spawnProcess("echo hello_ut", "", "", {}, nullptr, f) > 0);

	p->wait(ACE_Time_Value(5));
	std::this_thread::sleep_for(std::chrono::milliseconds(500));

	REQUIRE_FALSE(p->running());
	REQUIRE(p->returnValue() == 0);

	std::ifstream ifs(f);
	std::string content((std::istreambuf_iterator<char>(ifs)), {});
	REQUIRE(content.find("hello_ut") != std::string::npos);
	Utility::removeFile(f);
}

TEST_CASE("AppProcess_21_nonzero_exit", "[process]")
{
	auto p = makeProcess();
	auto f = tmpFile();
	REQUIRE(p->spawnProcess("sh -c 'exit 42'", "", "", {}, nullptr, f) > 0);
	p->wait(ACE_Time_Value(5));
	std::this_thread::sleep_for(std::chrono::milliseconds(500));
	REQUIRE(p->returnValue() == 42);
	Utility::removeFile(f);
}

TEST_CASE("AppProcess_22_ultra_short_true", "[process]")
{
	auto p = makeProcess();
	auto f = tmpFile();
	REQUIRE(p->spawnProcess("true", "", "", {}, nullptr, f) > 0);
	std::this_thread::sleep_for(std::chrono::seconds(2));
	REQUIRE_FALSE(p->running());
	REQUIRE(p->returnValue() == 0);
	Utility::removeFile(f);
}

TEST_CASE("AppProcess_23_ultra_short_stdout", "[process]")
{
	auto p = makeProcess();
	auto f = tmpFile();
	REQUIRE(p->spawnProcess("seq 1 20", "", "", {}, nullptr, f) > 0);
	std::this_thread::sleep_for(std::chrono::seconds(2));

	// finalSyncDrain should have captured pipe data to disk
	std::ifstream ifs(f);
	std::string content((std::istreambuf_iterator<char>(ifs)), {});
	REQUIRE(content.find("20") != std::string::npos);
	Utility::removeFile(f);
}

// =============================================================================
// 30-33: Terminate + delayKill
// =============================================================================

TEST_CASE("AppProcess_30_terminate_running", "[process]")
{
	auto p = makeProcess();
	auto f = tmpFile();
	REQUIRE(p->spawnProcess("sleep 300", "", "", {}, nullptr, f) > 0);
	REQUIRE(p->running());
	p->terminate();
	REQUIRE_FALSE(p->running());
	REQUIRE(p->returnValue() == 9);
	Utility::removeFile(f);
}

TEST_CASE("AppProcess_31_terminate_already_exited", "[process]")
{
	auto p = makeProcess();
	auto f = tmpFile();
	REQUIRE(p->spawnProcess("true", "", "", {}, nullptr, f) > 0);
	std::this_thread::sleep_for(std::chrono::seconds(2));
	// CAS guard: no double onExit
	p->terminate();
	REQUIRE_FALSE(p->running());
	Utility::removeFile(f);
}

TEST_CASE("AppProcess_32_double_terminate", "[process]")
{
	auto p = makeProcess();
	auto f = tmpFile();
	REQUIRE(p->spawnProcess("sleep 300", "", "", {}, nullptr, f) > 0);
	p->terminate();
	p->terminate(); // second terminate must not crash / double event
	REQUIRE_FALSE(p->running());
	Utility::removeFile(f);
}

TEST_CASE("AppProcess_33_delay_kill", "[process]")
{
	auto p = makeProcess();
	auto f = tmpFile();
	REQUIRE(p->spawnProcess("sleep 300", "", "", {}, nullptr, f) > 0);
	p->delayKill(1, "ut_33");
	REQUIRE(p->running());
	std::this_thread::sleep_for(std::chrono::seconds(3));
	REQUIRE_FALSE(p->running());
	Utility::removeFile(f);
}

// =============================================================================
// 40-41: Zombie prevention
// =============================================================================

TEST_CASE("AppProcess_40_no_zombie_natural", "[process]")
{
	pid_t child = 0;
	{
		auto p = makeProcess();
		auto f = tmpFile();
		child = p->spawnProcess("echo zombie_check", "", "", {}, nullptr, f);
		REQUIRE(child > 0);
		std::this_thread::sleep_for(std::chrono::seconds(2));
		Utility::removeFile(f);
	}
	REQUIRE_FALSE(AppProcess::running(child));
}

TEST_CASE("AppProcess_41_no_zombie_terminate", "[process]")
{
	pid_t child = 0;
	{
		auto p = makeProcess();
		auto f = tmpFile();
		child = p->spawnProcess("sleep 300", "", "", {}, nullptr, f);
		REQUIRE(child > 0);
		p->terminate();
		Utility::removeFile(f);
	}
	REQUIRE_FALSE(AppProcess::running(child));
}

// =============================================================================
// 50-52: Memory / FD leak checks
// =============================================================================

static int countFds()
{
#if defined(__APPLE__)
	int n = 0;
	for (int fd = 0; fd < 1024; ++fd)
		if (fcntl(fd, F_GETFD) != -1) ++n;
	return n;
#else
	namespace fs = boost::filesystem;
	return static_cast<int>(std::distance(
		fs::directory_iterator("/proc/self/fd"), fs::directory_iterator()));
#endif
}

TEST_CASE("AppProcess_50_no_fd_leak", "[process]")
{
	// Warm up (lazy resources)
	for (int i = 0; i < 3; ++i)
	{
		auto p = makeProcess();
		auto f = tmpFile();
		p->spawnProcess("true", "", "", {}, nullptr, f);
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
		Utility::removeFile(f);
	}
	std::this_thread::sleep_for(std::chrono::seconds(2));
	const int baseline = countFds();

	for (int i = 0; i < 10; ++i)
	{
		auto p = makeProcess();
		auto f = tmpFile();
		p->spawnProcess("echo fd_test", "", "", {}, nullptr, f);
		std::this_thread::sleep_for(std::chrono::milliseconds(300));
		Utility::removeFile(f);
	}
	std::this_thread::sleep_for(std::chrono::seconds(3));
	REQUIRE(countFds() - baseline < 5);
}

TEST_CASE("AppProcess_51_no_fd_leak_terminate", "[process]")
{
	for (int i = 0; i < 3; ++i)
	{
		auto p = makeProcess();
		auto f = tmpFile();
		p->spawnProcess("sleep 300", "", "", {}, nullptr, f);
		p->terminate();
		Utility::removeFile(f);
	}
	std::this_thread::sleep_for(std::chrono::seconds(2));
	const int baseline = countFds();

	for (int i = 0; i < 10; ++i)
	{
		auto p = makeProcess();
		auto f = tmpFile();
		p->spawnProcess("sleep 300", "", "", {}, nullptr, f);
		p->terminate();
		Utility::removeFile(f);
	}
	std::this_thread::sleep_for(std::chrono::seconds(2));
	REQUIRE(countFds() - baseline < 5);
}

TEST_CASE("AppProcess_52_shared_ptr_release", "[process]")
{
	std::weak_ptr<AppProcess> weakRef;
	{
		auto p = makeProcess();
		weakRef = p;
		auto f = tmpFile();
		p->spawnProcess("echo release_test", "", "", {}, nullptr, f);
		std::this_thread::sleep_for(std::chrono::seconds(2));
		Utility::removeFile(f);
		// p goes out of scope — should trigger ~AppProcess
	}
	// The weak_ptr should be expired — AppProcess fully released
	std::this_thread::sleep_for(std::chrono::seconds(1));
	REQUIRE(weakRef.expired());
}

TEST_CASE("AppProcess_53_shared_ptr_release_terminate", "[process]")
{
	std::weak_ptr<AppProcess> weakRef;
	{
		auto p = makeProcess();
		weakRef = p;
		auto f = tmpFile();
		p->spawnProcess("sleep 300", "", "", {}, nullptr, f);
		p->terminate();
		Utility::removeFile(f);
	}
	std::this_thread::sleep_for(std::chrono::seconds(2));
	REQUIRE(weakRef.expired());
}

// =============================================================================
// 60-64: Stdout / stdin / env
// =============================================================================

TEST_CASE("AppProcess_60_stdout_content", "[process]")
{
	auto p = makeProcess();
	auto f = tmpFile();
	REQUIRE(p->spawnProcess("echo stdout_content", "", "", {}, nullptr, f) > 0);
	std::this_thread::sleep_for(std::chrono::seconds(2));

	long pos = 0;
	auto out = p->getOutputMsg(&pos);
	REQUIRE(out.find("stdout_content") != std::string::npos);
	REQUIRE(pos > 0);
	Utility::removeFile(f);
}

TEST_CASE("AppProcess_61_no_stdout_file", "[process]")
{
	auto p = makeProcess();
	REQUIRE(p->spawnProcess("echo no_file", "", "", {}, nullptr, "") > 0);
	std::this_thread::sleep_for(std::chrono::seconds(1));
	REQUIRE(p->stdoutDispatchedBytes() == 0);
}

TEST_CASE("AppProcess_62_incremental_read", "[process]")
{
	auto p = makeProcess();
	auto f = tmpFile();
	REQUIRE(p->spawnProcess("seq 1 100", "", "", {}, nullptr, f) > 0);
	std::this_thread::sleep_for(std::chrono::seconds(2));

	long pos = 0;
	auto r1 = p->getOutputMsg(&pos, 32);
	REQUIRE_FALSE(r1.empty());
	REQUIRE(pos > 0);
	auto r2 = p->getOutputMsg(&pos, 32);
	if (!r2.empty())
		REQUIRE(r1.substr(0, 8) != r2.substr(0, 8));
	Utility::removeFile(f);
}

TEST_CASE("AppProcess_63_stdin", "[process]")
{
	auto p = makeProcess();
	auto f = tmpFile();
	nlohmann::json stdinData = "hello_stdin_ut";
	REQUIRE(p->spawnProcess("cat", "", "", {}, nullptr, f, stdinData) > 0);
	std::this_thread::sleep_for(std::chrono::seconds(2));

	long pos = 0;
	auto out = p->getOutputMsg(&pos);
	REQUIRE(out.find("hello_stdin_ut") != std::string::npos);
	Utility::removeFile(f);
}

TEST_CASE("AppProcess_64_env_vars", "[process]")
{
	auto p = makeProcess();
	auto f = tmpFile();
	std::map<std::string, std::string> env = {{"UT_VAR", "ut_value_789"}};
	REQUIRE(p->spawnProcess("sh -c 'echo $UT_VAR'", "", "", env, nullptr, f) > 0);
	std::this_thread::sleep_for(std::chrono::seconds(2));

	long pos = 0;
	REQUIRE(p->getOutputMsg(&pos).find("ut_value_789") != std::string::npos);
	Utility::removeFile(f);
}

// =============================================================================
// 70: Attach / Detach
// =============================================================================

TEST_CASE("AppProcess_70_attach_detach", "[process]")
{
	auto p = makeProcess();
	REQUIRE(p->getpid() == ACE_INVALID_PID);
	p->attach(1);
	REQUIRE(p->getpid() == 1);
	p->detach();
	REQUIRE(p->getpid() == ACE_INVALID_PID);
}

// =============================================================================
// 80-81: Stress
// =============================================================================

TEST_CASE("AppProcess_80_serial_stress", "[process][stress]")
{
	for (int i = 0; i < 20; ++i)
	{
		auto p = makeProcess();
		auto f = tmpFile();
		if (p->spawnProcess("echo stress", "", "", {}, nullptr, f) > 0)
			p->terminate();
		Utility::removeFile(f);
	}
	SUCCEED("20 serial spawn+terminate OK");
}

TEST_CASE("AppProcess_81_concurrent_stress", "[process][stress]")
{
	const int N = 4;
	std::atomic<int> errors{0};
	std::vector<std::thread> threads;
	for (int i = 0; i < N; ++i)
	{
		threads.emplace_back([&errors]()
							 {
			for (int j = 0; j < 5; ++j)
			{
				auto p = makeProcess();
				auto f = tmpFile();
				if (p->spawnProcess("echo concurrent", "", "", {}, nullptr, f) <= 0)
					errors++;
				else
					p->terminate();
				Utility::removeFile(f);
			} });
	}
	for (auto &t : threads)
		t.join();
	REQUIRE(errors == 0);
}

// =============================================================================
// 90-91: Working directory
// =============================================================================

TEST_CASE("AppProcess_90_workdir", "[process]")
{
	auto p = makeProcess();
	auto f = tmpFile();
	REQUIRE(p->spawnProcess("pwd", "", "/tmp", {}, nullptr, f) > 0);
	std::this_thread::sleep_for(std::chrono::seconds(2));

	long pos = 0;
	auto out = p->getOutputMsg(&pos);
	REQUIRE((out.find("/tmp") != std::string::npos || out.find("/private/tmp") != std::string::npos));
	Utility::removeFile(f);
}

TEST_CASE("AppProcess_91_invalid_workdir", "[process]")
{
	auto p = makeProcess();
	auto f = tmpFile();
	REQUIRE(p->spawnProcess("echo wd_test", "", "/nonexistent_xyz", {}, nullptr, f) > 0);
	std::this_thread::sleep_for(std::chrono::seconds(2));
	REQUIRE_FALSE(p->running());
	Utility::removeFile(f);
}
