// test/process/main.cpp
// Regression tests for the StdoutPump data path, which black-box reproduction
// cannot reach deterministically (signals and poller wakeups are not reliably
// deliverable through the daemon).
#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include "../../src/daemon/Configuration.h"
#include "../../src/daemon/process/DockerApiProcess.h"
#include "../../src/daemon/process/ForkExec.h"
#include "../../src/daemon/process/StdoutPump.h"
#include "../../src/daemon/rest/drogon/FileTransferHandler.h"
#include <catch.hpp>

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
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

#if !defined(_WIN32)
// Overwrite publishes a fresh inode: the replaced attributes must survive and the payload must hit disk before the rename.
TEST_CASE("FileUploadInfo overwrite commit", "[rest][security]")
{
	namespace fs = std::filesystem;
	const std::string jail = "/tmp/appmesh_upload_commit_jail";
	const std::string dest = jail + "/tmp/dest.txt";
	std::error_code ec;
	fs::remove_all(jail, ec);
	REQUIRE(Utility::createDirectory(jail + "/tmp"));
	auto statMode = [&dest](struct stat &st) { REQUIRE(::stat(dest.c_str(), &st) == 0); };

	SECTION("overwrite replays the replaced file's mode and owner")
	{
		{
			std::ofstream f(dest, std::ios::binary | std::ios::trunc);
			f << "OLD";
		}
		REQUIRE(::chmod(dest.c_str(), 0640) == 0);
		struct stat before
		{
		};
		statMode(before);

		HttpHeaderMap headers; // no attribute headers: the original attributes win
		FileUploadInfo upload(dest, dest + ".part", headers, true, jail);
		REQUIRE(upload.m_file.is_open());
		upload.m_file.write("NEW!", 4);
		REQUIRE(upload.m_file.good());
		REQUIRE(upload.commit() == FileUploadInfo::CommitResult::Committed);

		struct stat after
		{
		};
		statMode(after);
		REQUIRE((after.st_mode & 07777) == 0640); // replayed, not the temp default 0644
		REQUIRE(after.st_uid == before.st_uid);
		REQUIRE(after.st_gid == before.st_gid);
		std::ifstream in(dest, std::ios::binary);
		std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
		REQUIRE(content == "NEW!");
		REQUIRE_FALSE(fs::exists(dest + ".part", ec)); // the temp name is gone
	}

	SECTION("explicit client attribute headers beat the replay")
	{
		{
			std::ofstream f(dest, std::ios::binary | std::ios::trunc);
			f << "OLD";
		}
		REQUIRE(::chmod(dest.c_str(), 0600) == 0);
		HttpHeaderMap headers;
		headers.emplace(HTTP_HEADER_KEY_file_mode, "416"); // 0640 in decimal, as fileAttributeHeaders sends it
		FileUploadInfo upload(dest, dest + ".part", headers, true, jail);
		upload.m_file.write("NEW", 3);
		REQUIRE(upload.commit() == FileUploadInfo::CommitResult::Committed);
		// The faces apply explicit headers after the commit on the still-open fd.
		Utility::applyFilePermission(dest, headers, upload.fd());

		struct stat after
		{
		};
		statMode(after);
		REQUIRE((after.st_mode & 07777) == 0640);
	}

	SECTION("a fresh (non-overwrite) commit keeps the temp default mode")
	{
		HttpHeaderMap headers;
		FileUploadInfo upload(dest, dest + ".part", headers, false, jail);
		upload.m_file.write("FRESH", 5);
		REQUIRE(upload.commit() == FileUploadInfo::CommitResult::Committed);
		struct stat after
		{
		};
		statMode(after);
		REQUIRE((after.st_mode & 07777) == 0644);
	}

	fs::remove_all(jail, ec);
}
#endif

#if !defined(_WIN32)
// Container ownership must carry the node: nodes sharing one Docker engine are
// otherwise indistinguishable (mutual delete/adopt/sweep of same-named apps).
TEST_CASE("Docker container naming carries the node identity", "[docker]")
{
	REQUIRE_FALSE(dockerNodeIdentity().empty());
	REQUIRE(DockerApiProcess::namespacedContainerName("demo") ==
			"appmesh-" + dockerNodeIdentity() + "-demo");
}

// Shell mode's generated script travels inside the command, never as a host
// bind a sibling dockerd cannot resolve.
TEST_CASE("inlineShellScriptCmd inlines the shell-mode script bind", "[docker]")
{
	namespace fs = std::filesystem;
	const auto jail = fs::temp_directory_path() / "appmesh_inline_shell";
	std::error_code ec;
	fs::remove_all(jail, ec);
	fs::create_directories(jail);
	const auto scriptPath = (jail / "appmesh.demo.x1.sh").string();
	const std::string scriptBody = "#!/bin/bash\nset -e\ncd /tmp\necho hi\n";
	{
		std::ofstream out(scriptPath, std::ios::binary);
		out << scriptBody;
	}

	SECTION("bash <script> plus the same-path bind is inlined as bash -c")
	{
		Json::Value body;
		body["Cmd"][0] = "bash";
		body["Cmd"][1] = scriptPath;
		body["HostConfig"]["Binds"][0] = scriptPath + ":" + scriptPath + ":ro";
		body["HostConfig"]["Binds"][1] = "vol:/data";

		inlineShellScriptCmd(body);

		REQUIRE(body["Cmd"].size() == 3);
		REQUIRE(body["Cmd"][0].asString() == "bash");
		REQUIRE(body["Cmd"][1].asString() == "-c");
		// multi-line content, no re-escaping; the generated header cd is made
		// tolerant so a generic image without the daemon path still boots
		REQUIRE(body["Cmd"][2].asString() ==
				"#!/bin/bash\nset -e\ncd /tmp 2>/dev/null || echo 'App Mesh: working dir </tmp> not present in this "
				"container, using the image default' >&2\necho hi\n");
		REQUIRE(body["HostConfig"]["Binds"].size() == 1); // only the user bind remains
		REQUIRE(body["HostConfig"]["Binds"][0].asString() == "vol:/data");
	}

	SECTION("a user cd line outside the generated header stays untouched")
	{
		const std::string userScript = "#!/bin/bash\nset -e\ncd /opt\ncd /tmp\necho hi\n";
		{
			std::ofstream out(scriptPath, std::ios::binary);
			out << userScript;
		}
		Json::Value body;
		body["Cmd"][0] = "bash";
		body["Cmd"][1] = scriptPath;
		body["HostConfig"]["Binds"][0] = scriptPath + ":" + scriptPath + ":ro";

		inlineShellScriptCmd(body);

		REQUIRE(body["Cmd"][2].asString() ==
				"#!/bin/bash\nset -e\ncd /opt 2>/dev/null || echo 'App Mesh: working dir </opt> not present in this "
				"container, using the image default' >&2\ncd /tmp\necho hi\n"); // the user's own cd survives
	}

	SECTION("a longer bash argv keeps its shape")
	{
		Json::Value body;
		body["Cmd"][0] = "bash";
		body["Cmd"][1] = scriptPath;
		body["Cmd"][2] = "-x";
		body["HostConfig"]["Binds"][0] = scriptPath + ":" + scriptPath + ":ro";

		inlineShellScriptCmd(body);

		REQUIRE(body["Cmd"].size() == 3);
		REQUIRE(body["Cmd"][1].asString() == scriptPath);
	}

	SECTION("a bash script without its own bind stays untouched")
	{
		Json::Value body;
		body["Cmd"][0] = "bash";
		body["Cmd"][1] = scriptPath;
		body["HostConfig"]["Binds"][0] = "vol:/data";

		inlineShellScriptCmd(body);

		REQUIRE(body["Cmd"].size() == 2);
		REQUIRE(body["Cmd"][1].asString() == scriptPath);
	}

	SECTION("a bind whose script is missing locally stays untouched")
	{
		const auto missing = (jail / "nope.sh").string();
		Json::Value body;
		body["Cmd"][0] = "bash";
		body["Cmd"][1] = missing;
		body["HostConfig"]["Binds"][0] = missing + ":" + missing + ":ro";

		inlineShellScriptCmd(body);

		REQUIRE(body["Cmd"].size() == 2);
		REQUIRE(body["HostConfig"]["Binds"].size() == 1);
	}

	SECTION("a create body without a command gains no members")
	{
		Json::Value body;
		body["Image"] = "alpine:3.21"; // ENTRYPOINT-only image: no Cmd, no Binds

		inlineShellScriptCmd(body);

		REQUIRE(body.isMember("Image"));
		REQUIRE_FALSE(body.isMember("Cmd"));      // no null members inserted
		REQUIRE_FALSE(body.isMember("HostConfig"));
	}

	fs::remove_all(jail, ec);
}
#endif

#if !defined(_WIN32)
namespace
{
	// Answers the container-service calls one run needs, so the output path can
	// be exercised without a Docker engine or the Go agent.
	class FakeContainerAgent
	{
	public:
		FakeContainerAgent()
		{
			m_listenFd = ::socket(AF_INET, SOCK_STREAM, 0);
			REQUIRE(m_listenFd >= 0);
			int reuse = 1;
			::setsockopt(m_listenFd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
			struct sockaddr_in address
			{
			};
			address.sin_family = AF_INET;
			address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			REQUIRE(::bind(m_listenFd, reinterpret_cast<struct sockaddr *>(&address), sizeof(address)) == 0);
			REQUIRE(::listen(m_listenFd, 16) == 0);
			socklen_t length = sizeof(address);
			REQUIRE(::getsockname(m_listenFd, reinterpret_cast<struct sockaddr *>(&address), &length) == 0);
			m_port = ntohs(address.sin_port);
			m_thread = std::thread([this] { serve(); });
		}

		~FakeContainerAgent()
		{
			::shutdown(m_listenFd, SHUT_RDWR);
			::close(m_listenFd);
			if (m_thread.joinable())
				m_thread.join();
		}

		int port() const { return m_port; }

	private:
		void serve()
		{
			for (;;)
			{
				const int client = ::accept(m_listenFd, nullptr, nullptr);
				if (client < 0)
					return;
				handle(client);
				::close(client);
			}
		}

		static void handle(int client)
		{
			std::string request;
			char buffer[4096];
			while (request.find("\r\n\r\n") == std::string::npos)
			{
				const auto bytes = ::read(client, buffer, sizeof(buffer));
				if (bytes <= 0)
					return;
				request.append(buffer, static_cast<size_t>(bytes));
			}
			const auto headerEnd = request.find("\r\n\r\n");
			const auto headerText = request.substr(0, headerEnd);
			size_t contentLength = 0;
			if (const auto lengthKey = headerText.find("Content-Length:"); lengthKey != std::string::npos)
				contentLength = std::strtoul(headerText.c_str() + lengthKey + std::strlen("Content-Length:"), nullptr, 10);
			while (request.size() < headerEnd + 4 + contentLength)
			{
				const auto bytes = ::read(client, buffer, sizeof(buffer));
				if (bytes <= 0)
					return;
				request.append(buffer, static_cast<size_t>(bytes));
			}

			std::istringstream requestLine(headerText.substr(0, headerText.find("\r\n")));
			std::string method;
			std::string target;
			requestLine >> method >> target;

			std::string status = "200 OK";
			std::string body;
			if (target.rfind("/appmesh/container/image", 0) == 0)
				body = R"({"present":true})";
			else if (method == "POST" && target == "/appmesh/container/run")
				body = R"({"id":"cid1","pid":999999,"running":true,"exitCode":0,"replacedLogs":""})";
			else if (target.rfind("/appmesh/container/cid1/logs", 0) == 0)
				body = R"({"lines":[{"ns":1764100000000000000,"text":"hello"}]})";
			else if (method == "GET" && target == "/appmesh/container/cid1")
				body = R"({"id":"cid1","pid":999999,"running":false,"exitCode":0})";
			else if (target.rfind("/appmesh/container/cid1/stop", 0) == 0 ||
					 target.rfind("/appmesh/container/cid1/kill", 0) == 0 ||
					 (method == "DELETE" && target == "/appmesh/container/cid1"))
				body = R"({"ok":true})";
			else
				status = "404 Not Found";

			const auto response = "HTTP/1.1 " + status + "\r\nContent-Type: application/json\r\nContent-Length: " +
								  std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
			size_t sent = 0;
			while (sent < response.size())
			{
				const auto bytes = ::send(client, response.data() + sent, response.size() - sent, 0);
				if (bytes <= 0)
					return;
				sent += static_cast<size_t>(bytes);
			}
		}

		int m_listenFd{-1};
		int m_port{0};
		std::thread m_thread;
	};
} // namespace

// The sync-run completion reads output after the run is torn down. For a
// container that is the terminate-time log archive in the run's stdout slot:
// reading the base fallback's cleared path would drop the output entirely.
TEST_CASE("Docker run output survives container teardown through the stdout archive", "[docker][process]")
{
	namespace fs = std::filesystem;
	FakeContainerAgent agent;

	Json::Value root;
	root["REST"]["RestListenAddress"] = "127.0.0.1";
	root["REST"]["RestListenPort"] = agent.port();
	root["REST"]["SSL"]["SSLEnabled"] = false; // the request client speaks plaintext to the fake
	Configuration::instance(Configuration::FromJson(root, false));
	// The endpoint gate checks DOCKER_HOST before any engine call.
	::setenv("DOCKER_HOST", "tcp://127.0.0.1:1", 1);

	const auto stdoutFile =
		(fs::temp_directory_path() / ("appmesh-docker-archive-" + Utility::shortID() + ".out")).string();
	{
		auto process = std::make_shared<DockerApiProcess>(std::weak_ptr<Application>(), "archive-test", "alpine:3.19");
		const auto started = process->start("echo hello", "", "", {}, nullptr, stdoutFile, Json::Value(Json::objectValue));
		REQUIRE(started.accepted);

		// While the container exists, the agent's demultiplexed log projection is the source.
		long position = 0;
		REQUIRE(process->getOutputMsg(&position) == "hello\n");
		REQUIRE(position == 1764100000000000000LL);

		// Teardown deletes the container after archiving its logs into the run's
		// own stdout slot; the completion read must return that archive.
		process->terminate();
		long archivePosition = 0;
		REQUIRE(process->getOutputMsg(&archivePosition) == "hello\n");
		REQUIRE(archivePosition == 6); // a byte cursor, not the container's nanosecond stamp

		// A cursor handed back from the container path restarts the archive read
		// instead of failing on an out-of-range byte offset.
		long stalePosition = 1764100000000000000LL;
		REQUIRE(process->getOutputMsg(&stalePosition) == "hello\n");
		REQUIRE(stalePosition == 6);
	}

	::unsetenv("DOCKER_HOST");
	std::error_code ec;
	fs::remove(stdoutFile, ec);
	Configuration::instance(std::make_shared<Configuration>());
}
#endif
