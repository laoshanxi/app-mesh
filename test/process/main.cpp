// test/process/main.cpp
// Container-backend unit surfaces that run without a live agent: the node
// identity naming and the shell-script inlining the create path applies.
#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include "../../src/daemon/Configuration.h"
#include "../../src/daemon/application/Application.h"
#include "../../src/daemon/process/DockerApiProcess.h"
#include <catch.hpp>

#include <boost/filesystem.hpp>
#include <nlohmann/json.hpp>

#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <memory>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <thread>

namespace fs = boost::filesystem;

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
	const auto jail = fs::temp_directory_path() / "appmesh_inline_shell";
	boost::system::error_code ec;
	fs::remove_all(jail, ec);
	fs::create_directories(jail);
	const auto scriptPath = (jail / "appmesh.demo.x1.sh").string();
	const std::string scriptBody = "#!/bin/bash\nset -e\ncd /tmp\necho hi\n";
	{
		std::ofstream out(scriptPath.c_str(), std::ios::binary);
		out << scriptBody;
	}

	SECTION("bash <script> plus the same-path bind is inlined as bash -c")
	{
		nlohmann::json body;
		body["Cmd"][0] = "bash";
		body["Cmd"][1] = scriptPath;
		body["HostConfig"]["Binds"][0] = scriptPath + ":" + scriptPath + ":ro";
		body["HostConfig"]["Binds"][1] = "vol:/data";

		inlineShellScriptCmd(body);

		REQUIRE(body["Cmd"].size() == 3);
		REQUIRE(body["Cmd"][0].get<std::string>() == "bash");
		REQUIRE(body["Cmd"][1].get<std::string>() == "-c");
		// multi-line content, no re-escaping; the generated header cd is made
		// tolerant so a generic image without the daemon path still boots
		REQUIRE(body["Cmd"][2].get<std::string>() ==
				"#!/bin/bash\nset -e\ncd /tmp 2>/dev/null || echo 'App Mesh: working dir </tmp> not present in this "
				"container, using the image default' >&2\necho hi\n");
		REQUIRE(body["HostConfig"]["Binds"].size() == 1); // only the user bind remains
		REQUIRE(body["HostConfig"]["Binds"][0].get<std::string>() == "vol:/data");
	}

	SECTION("a user cd line outside the generated header stays untouched")
	{
		const std::string userScript = "#!/bin/bash\nset -e\ncd /opt\ncd /tmp\necho hi\n";
		{
			std::ofstream out(scriptPath.c_str(), std::ios::binary);
			out << userScript;
		}
		nlohmann::json body;
		body["Cmd"][0] = "bash";
		body["Cmd"][1] = scriptPath;
		body["HostConfig"]["Binds"][0] = scriptPath + ":" + scriptPath + ":ro";

		inlineShellScriptCmd(body);

		REQUIRE(body["Cmd"][2].get<std::string>() ==
				"#!/bin/bash\nset -e\ncd /opt 2>/dev/null || echo 'App Mesh: working dir </opt> not present in this "
				"container, using the image default' >&2\ncd /tmp\necho hi\n"); // the user's own cd survives
	}

	SECTION("a longer bash argv keeps its shape")
	{
		nlohmann::json body;
		body["Cmd"][0] = "bash";
		body["Cmd"][1] = scriptPath;
		body["Cmd"][2] = "-x";
		body["HostConfig"]["Binds"][0] = scriptPath + ":" + scriptPath + ":ro";

		inlineShellScriptCmd(body);

		REQUIRE(body["Cmd"].size() == 3);
		REQUIRE(body["Cmd"][1].get<std::string>() == scriptPath);
	}

	SECTION("a bash script without its own bind stays untouched")
	{
		nlohmann::json body;
		body["Cmd"][0] = "bash";
		body["Cmd"][1] = scriptPath;
		body["HostConfig"]["Binds"][0] = "vol:/data";

		inlineShellScriptCmd(body);

		REQUIRE(body["Cmd"].size() == 2);
		REQUIRE(body["Cmd"][1].get<std::string>() == scriptPath);
	}

	SECTION("a bind whose script is missing locally stays untouched")
	{
		const auto missing = (jail / "nope.sh").string();
		nlohmann::json body;
		body["Cmd"][0] = "bash";
		body["Cmd"][1] = missing;
		body["HostConfig"]["Binds"][0] = missing + ":" + missing + ":ro";

		inlineShellScriptCmd(body);

		REQUIRE(body["Cmd"].size() == 2);
		REQUIRE(body["HostConfig"]["Binds"].size() == 1);
	}

	SECTION("a create body without a command gains no members")
	{
		nlohmann::json body;
		body["Image"] = "alpine:3.21"; // ENTRYPOINT-only image: no Cmd, no Binds

		inlineShellScriptCmd(body);

		REQUIRE(body.contains("Image"));
		REQUIRE_FALSE(body.contains("Cmd"));      // no null members inserted
		REQUIRE_FALSE(body.contains("HostConfig"));
	}

	fs::remove_all(jail, ec);
}

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

// A missing working_dir would start the process in the share directory; recovery keeps the definition.
TEST_CASE("Registration refuses a working_dir that is not a directory", "[process]")
{
	Configuration::instance(std::make_shared<Configuration>());

	const auto define = [](const nlohmann::json &definition) {
		auto app = std::make_shared<Application>();
		Application::FromJson(app, definition);
	};

	const auto missing = nlohmann::json{{"name", "wd-check"}, {"owner_principal_id", "oidc:test"},
										{"command", "echo hi"}, {"working_dir", "/srv/data"}};
	REQUIRE_THROWS_AS(define(missing), std::invalid_argument);

	const auto base = fs::temp_directory_path() / ("appmesh-wd-check-" + Utility::shortID());
	boost::system::error_code ec;
	fs::create_directories(base, ec);
	const auto existingFile = (base / "working_dir_file").string();
	{
		std::ofstream(existingFile) << "not a directory";
	}
	auto fileWorkdir = missing;
	fileWorkdir["working_dir"] = existingFile;
	REQUIRE_THROWS_AS(define(fileWorkdir), std::invalid_argument);

	// A path the daemon cannot inspect (permission denied) stays accepted: the start
	// answers for it, and the daemon cannot tell it is not a directory.
	auto nowWrite = missing;
	nowWrite["working_dir"] = base.string();
	REQUIRE_NOTHROW(define(nowWrite));

	auto recovered = missing;
	recovered["from_recover"] = true;
	REQUIRE_NOTHROW(define(recovered));

	fs::remove_all(base, ec);
}

// The sync-run completion reads output after the run is torn down. For a
// container that is the terminate-time log archive in the run's stdout slot:
// reading the base fallback's cleared path would drop the output entirely.
TEST_CASE("Docker run output survives container teardown through the stdout archive", "[docker][process]")
{
	FakeContainerAgent agent;

	nlohmann::json root;
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
		const auto started = process->start("echo hello", "", "", {}, nullptr, stdoutFile);
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
	boost::system::error_code ec;
	fs::remove(stdoutFile, ec);
	Configuration::instance(std::make_shared<Configuration>());
}
#endif
