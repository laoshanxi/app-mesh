// test/process/main.cpp
// Container-backend unit surfaces that run without a live agent: the node
// identity naming and the shell-script inlining the create path applies.
#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include "../../src/daemon/process/DockerApiProcess.h"
#include <catch.hpp>

#include <boost/filesystem.hpp>
#include <nlohmann/json.hpp>

#include <fstream>
#include <iterator>
#include <string>

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
