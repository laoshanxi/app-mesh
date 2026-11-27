// test/process/sandbox.cpp
// Landlock ruleset construction and the application-level sandbox decision.
#include "../../src/common/Utility.h"
#include "../../src/daemon/Configuration.h"
#include "../../src/daemon/application/Application.h"
#include "../../src/daemon/process/AppProcess.h"
#include "../../src/daemon/process/ForkExec.h"
#include "../../src/daemon/process/LandlockPolicy.h"
#include <catch.hpp>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <pwd.h>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace
{
	constexpr const char *OWNER = "oidc:owner";

	// One work tree for the whole binary: Application fixes its stdout directory
	// at the first definition it parses.
	struct WorkTree
	{
		std::string path;
		WorkTree() : path((fs::temp_directory_path() / ("appmesh-sandbox-" + Utility::shortID())).string())
		{
			// The daemon creates these at startup.
			for (const auto *leaf : {"runtime/stdout", "runtime/shell", "share"})
				fs::create_directories(fs::path(path) / leaf);
		}
		// Leave a default configuration behind for the tests that follow.
		~WorkTree() { Configuration::instance(std::make_shared<Configuration>()); }
	};
	const WorkTree g_workTree;

	void configure(const std::string &workDir, const std::string &mode, bool enabled = true)
	{
		Json::Value root;
		root["BaseConfig"]["WorkingDirectory"] = workDir;
		root["Sandbox"]["Enable"] = enabled;
		root["Sandbox"]["Mode"] = mode;
		Configuration::instance(Configuration::FromJson(root));
	}

	// A JSON object of one or two string members.
	Json::Value object(std::pair<std::string, std::string> first, std::pair<std::string, std::string> second = {})
	{
		Json::Value value(Json::objectValue);
		value[first.first] = first.second;
		if (!second.first.empty())
			value[second.first] = second.second;
		return value;
	}

	// A native application owned by OWNER; `overrides` replaces definition fields.
	std::shared_ptr<Application> define(const Json::Value &overrides = Json::Value(Json::objectValue))
	{
		auto definition = object({"name", "sandbox-app"}, {"command", "true"});
		definition["owner_principal_id"] = OWNER;
		for (const auto &key : overrides.getMemberNames())
			definition[key] = overrides[key];
		auto app = std::make_shared<Application>();
		Application::FromJson(app, definition);
		return app;
	}

	std::string workspaceOf(const std::string &key)
	{
		return (fs::path(g_workTree.path) / "workspaces" / Utility::sha256Hex(OWNER).substr(0, 16) / key).string();
	}

	mode_t modeOf(const std::string &path)
	{
		struct stat st;
		REQUIRE(::stat(path.c_str(), &st) == 0);
		return st.st_mode & 0777;
	}

	// A directory the sandboxed run user owns outside its sandbox.
	std::string ownedLeakDir(const std::string &name)
	{
		const auto path = (fs::path(g_workTree.path) / name).string();
		REQUIRE(fs::create_directories(path));
		if (::geteuid() == 0)
		{
			const auto *nobody = ::getpwnam("nobody");
			REQUIRE(nobody != nullptr);
			REQUIRE(::chown(path.c_str(), nobody->pw_uid, nobody->pw_gid) == 0);
		}
		return path;
	}
} // namespace

// A bit the kernel does not know fails the whole ruleset: every handled access
// must stay within the probed ABI.
TEST_CASE("Landlock handled access follows the kernel ABI", "[process][sandbox]")
{
	constexpr std::uint64_t EXECUTE = 1ull << 0, READ_FILE = 1ull << 2, READ_DIR = 1ull << 3;
	constexpr std::uint64_t REFER = 1ull << 13, TRUNCATE = 1ull << 14;
	// Every ABI v1 write right, without EXECUTE and the reads.
	constexpr auto WRITE_V1 = 0x1FF2;

	REQUIRE(LandlockPolicy::handledAccess(SandboxMode::Write, 1) == WRITE_V1);
	REQUIRE(LandlockPolicy::handledAccess(SandboxMode::Write, 2) == (WRITE_V1 | REFER));
	REQUIRE(LandlockPolicy::handledAccess(SandboxMode::Write, 3) == (WRITE_V1 | REFER | TRUNCATE));
	REQUIRE(LandlockPolicy::handledAccess(SandboxMode::Write, 8) == (WRITE_V1 | REFER | TRUNCATE));

	REQUIRE(LandlockPolicy::handledAccess(SandboxMode::Strict, 1) == (WRITE_V1 | READ_FILE | READ_DIR));
	REQUIRE(LandlockPolicy::handledAccess(SandboxMode::Strict, 4) == (WRITE_V1 | REFER | TRUNCATE | READ_FILE | READ_DIR));
	// Programs stay executable: EXECUTE is never handled.
	REQUIRE((LandlockPolicy::handledAccess(SandboxMode::Strict, 8) & EXECUTE) == 0);

	// A kernel without Landlock, or a missing directory, rejects the start with a reason.
	std::string error;
	REQUIRE(LandlockPolicy::buildRuleset(SandboxMode::Write, "/nonexistent/workspace", "/nonexistent/share", {}, 0,
										  error) == -1);
	REQUIRE_FALSE(error.empty());
	if (const auto abi = LandlockPolicy::detectAbi(); abi > 0)
	{
		REQUIRE(LandlockPolicy::buildRuleset(SandboxMode::Write, "/nonexistent/workspace", "/nonexistent/share", {}, abi,
											  error) == -1);
		REQUIRE(error.find("/nonexistent/workspace") != std::string::npos);
	}
}

TEST_CASE("Sandbox modes parse, name and order", "[process][sandbox]")
{
	REQUIRE(parseSandboxMode(" Strict ", SandboxMode::Off) == SandboxMode::Strict);
	REQUIRE(parseSandboxMode("write", SandboxMode::Strict) == SandboxMode::Write);
	REQUIRE(parseSandboxMode("off", SandboxMode::Strict) == SandboxMode::Off);
	// An unknown text keeps the caller's default.
	REQUIRE(parseSandboxMode("enforce", SandboxMode::Write) == SandboxMode::Write);
	REQUIRE(std::string(sandboxModeName(SandboxMode::Off)) == "off");
	REQUIRE(std::string(sandboxModeName(SandboxMode::Write)) == "write");
	REQUIRE(std::string(sandboxModeName(SandboxMode::Strict)) == "strict");

	REQUIRE(stricterSandboxMode(SandboxMode::Off, SandboxMode::Off) == SandboxMode::Off);
	REQUIRE(stricterSandboxMode(SandboxMode::Off, SandboxMode::Write) == SandboxMode::Write);
	REQUIRE(stricterSandboxMode(SandboxMode::Strict, SandboxMode::Off) == SandboxMode::Strict);
	REQUIRE(stricterSandboxMode(SandboxMode::Write, SandboxMode::Strict) == SandboxMode::Strict);
}

// The node switch gates everything; containers and system applications stay out;
// the runtime view names the workspace an application will get.
TEST_CASE("The application sandbox follows the node policy", "[process][sandbox]")
{
	const auto &dir = g_workTree;
	SECTION("switch off: no application is confined")
	{
		configure(dir.path, "write", false);
		REQUIRE(define()->effectiveSandboxMode() == SandboxMode::Off);
		REQUIRE_FALSE(define()->AsJson(true).isMember("sandbox_workdir"));
	}

	SECTION("the node default applies to native applications")
	{
		configure(dir.path, "strict");
		const auto app = define();
		REQUIRE(app->effectiveSandboxMode() == SandboxMode::Strict);
		const auto view = app->AsJson(true);
		REQUIRE(view["sandbox_mode"].asString() == "strict");
		REQUIRE(view["sandbox_workdir"].asString() == workspaceOf("sandbox-app"));
		// Runtime-only: the persisted definition carries neither field.
		REQUIRE_FALSE(app->AsJson(false).isMember("sandbox_mode"));
		REQUIRE_FALSE(app->AsJson(false).isMember("sandbox_workdir"));
	}

	SECTION("containers and system applications are never sandboxed")
	{
		configure(dir.path, "write");
		const auto container = define(object({"docker_image", "alpine:3.19"}));
		REQUIRE(container->effectiveSandboxMode() == SandboxMode::Off);
		REQUIRE_FALSE(container->AsJson(true).isMember("sandbox_mode"));

		auto system = object({"owner_principal_id", "system:appmesh"});
		system["system"] = true;
		REQUIRE(define(system)->effectiveSandboxMode() == SandboxMode::Off);
		REQUIRE_FALSE(define(system)->AsJson(true).isMember("sandbox_mode"));
	}

	SECTION("a run instance works in a workspace named after its base application")
	{
		configure(dir.path, "write");
		const auto instance = define(object({"run_base", "base-app"}));
		REQUIRE(instance->AsJson(true)["sandbox_workdir"].asString() == workspaceOf("base-app"));
	}

	SECTION("an idle application reports off and names no workspace")
	{
		configure(dir.path, "off");
		const auto view = define()->AsJson(true);
		REQUIRE(view["sandbox_mode"].asString() == "off");
		REQUIRE_FALSE(view.isMember("sandbox_workdir"));
	}
}

// Registration refuses a definition that could never start; recovery keeps it so
// that enabling the sandbox cannot block the daemon boot.
TEST_CASE("A sandboxed application refuses working_dir at registration only", "[process][sandbox]")
{
	const auto &dir = g_workTree;
	const auto withDir = object({"working_dir", "/srv/data"});

	configure(dir.path, "strict");
	REQUIRE_THROWS_AS(define(withDir), std::invalid_argument);

	auto recovered = withDir;
	recovered["from_recover"] = true;
	REQUIRE_NOTHROW(define(recovered));

	configure(dir.path, "off");
	REQUIRE_NOTHROW(define(withDir));
}

// A sandboxed on-demand run starts inside its private workspace with TMPDIR and
// HOME pointing at it, and cannot write outside it. On a host without Landlock the
// same run is refused instead of starting unrestricted.
TEST_CASE("A sandboxed run gets a private workspace", "[process][sandbox]")
{
	const auto &dir = g_workTree;
	configure(dir.path, "write");

	const auto workspace = workspaceOf("sandbox-app");
	// $1 = workspace, $2 = a directory the run user owns outside the sandbox.
	const auto outside = ownedLeakDir("outside");
	const auto script = (fs::path(dir.path) / "probe.sh").string();
	{
		std::ofstream out(script);
		out << "echo x > \"$1/file\" && cat \"$1/file\" > /dev/null && echo x > \"$TMPDIR/cache\" && echo inside-ok\n"
			<< "echo x > /dev/null && echo null-ok\n"
			<< "echo x > \"$2/file\" 2>/dev/null && echo outside-LEAK || echo outside-denied\n"
			<< "echo \"pwd=$PWD\"\n"
			<< "echo \"home=$HOME\"\n"
			<< "echo \"tmp=$TMPDIR\"\n";
	}
	auto definition = object({"command", "sh " + script + " " + workspace + " " + outside});
	// A root daemon must hand the workspace to an unprivileged user.
	if (::geteuid() == 0)
		definition["execution_user"] = "nobody";
	const auto app = define(definition);
	app->setUnPersistable();

	if (LandlockPolicy::detectAbi() <= 0)
	{
		REQUIRE_THROWS_WITH(app->runAsync(0), Catch::Contains("cannot be applied"));
		// The scratch workspace still goes with the anonymous run.
		REQUIRE(fs::exists(workspace));
		app->removeScratchWorkspace();
		REQUIRE_FALSE(fs::exists(workspace));
		return;
	}

	REQUIRE_FALSE(app->runAsync(0).empty());
	long position = 0;
	const auto output = std::get<0>(app->getOutput(position, 1 << 20, "", 0, 20));
	REQUIRE(output.find("inside-ok") != std::string::npos);
	REQUIRE(output.find("null-ok") != std::string::npos);
	REQUIRE(output.find("outside-denied") != std::string::npos);
	REQUIRE(output.find("LEAK") == std::string::npos);
	REQUIRE(output.find("pwd=" + workspace) != std::string::npos);
	REQUIRE(output.find("home=" + workspace) != std::string::npos);
	REQUIRE(output.find("tmp=" + workspace + "/tmp") != std::string::npos);

	REQUIRE(fs::exists(fs::path(workspace) / "file"));
	REQUIRE(fs::exists(fs::path(workspace) / "tmp" / "cache"));
	REQUIRE_FALSE(fs::exists(fs::path(outside) / "file"));
	REQUIRE(modeOf(workspace) == 0700);
	REQUIRE(modeOf(workspace + "/tmp") == 0700);
	REQUIRE(modeOf(fs::path(workspace).parent_path().string()) == 0711);
	REQUIRE(app->AsJson(true)["sandbox_workdir"].asString() == workspace);

	// The scratch workspace goes with the anonymous run.
	app->removeScratchWorkspace();
	REQUIRE_FALSE(fs::exists(workspace));
}

// A run instance shares its workspace with its base application, and a run outside
// the sandbox has none: neither takes a workspace along.
TEST_CASE("Only an anonymous sandboxed run takes its workspace along", "[process][sandbox]")
{
	const auto &dir = g_workTree;
	configure(dir.path, "write");
	const auto instance = define(object({"run_base", "base-app"}));
	instance->setUnPersistable();
	REQUIRE(instance->effectiveSandboxMode() == SandboxMode::Write);
	instance->removeScratchWorkspace();
	REQUIRE_FALSE(fs::exists(workspaceOf("base-app")));

	configure(dir.path, "off");
	const auto legacy = workspaceOf("legacy-app");
	REQUIRE(fs::create_directories(legacy));
	const auto plain = define(object({"name", "legacy-app"}));
	plain->setUnPersistable();
	plain->removeScratchWorkspace();
	REQUIRE(fs::exists(legacy));
}

// A deleted definition takes every workspace named after it, under every Principal,
// and nothing else.
TEST_CASE("A deleted definition takes the workspaces named after it", "[process][sandbox]")
{
	const auto &dir = g_workTree;
	configure(dir.path, "write");
	const auto own = workspaceOf("definition-app");
	const auto caller = (fs::path(dir.path) / "workspaces" / "0123456789abcdef" / "definition-app").string();
	const auto other = (fs::path(dir.path) / "workspaces" / "0123456789abcdef" / "other-app").string();
	const auto empty = (fs::path(dir.path) / "workspaces" / "fedcba9876543210").string();
	for (const auto &path : {own, caller, other, std::string(empty)})
		REQUIRE(fs::create_directories(path));

	const auto app = define(object({"name", "definition-app"}));
	REQUIRE(app->isPersistAble());
	app->removeDefinitionWorkspaces();
	REQUIRE_FALSE(fs::exists(own));
	REQUIRE_FALSE(fs::exists(caller));
	REQUIRE(fs::exists(other));
	REQUIRE_FALSE(fs::exists(empty)); // a Principal directory left empty goes too
	REQUIRE(fs::exists(fs::path(dir.path) / "workspaces"));

	// A run instance never takes the workspace it shares with its base application.
	const auto instance = define(object({"run_base", "other-app"}));
	instance->removeDefinitionWorkspaces();
	REQUIRE(fs::exists(other));
}

TEST_CASE("A deleted Principal takes its workspace directory", "[process][sandbox]")
{
	const auto &dir = g_workTree;
	const auto principal = (fs::path(dir.path) / "workspaces" / Utility::sha256Hex(OWNER).substr(0, 16)).string();
	const auto neighbour = (fs::path(dir.path) / "workspaces" / "1111111111111111").string();
	REQUIRE(fs::create_directories(fs::path(principal) / "app"));
	REQUIRE(fs::create_directories(fs::path(neighbour) / "app"));
	Application::removePrincipalWorkspaces(OWNER);
	REQUIRE_FALSE(fs::exists(principal));
	REQUIRE(fs::exists(neighbour));
	REQUIRE(fs::exists(fs::path(dir.path) / "workspaces"));
}

// A run that finds its workspace already there leaves the data in it alone.
TEST_CASE("A run keeps a workspace it did not create", "[process][sandbox]")
{
	const auto &dir = g_workTree;
	configure(dir.path, "write");
	const auto kept = workspaceOf("sbx-kept");
	REQUIRE(fs::create_directories(fs::path(kept) / "tmp"));
	std::ofstream(fs::path(kept) / "earlier.txt") << "earlier data";

	const auto app = define(object({"name", "sbx-kept"}));
	app->setUnPersistable();
	try
	{
		app->runAsync(0);
	}
	catch (const std::invalid_argument &)
	{
		// A refused run counts too: the workspace was there before it.
	}
	app->removeScratchWorkspace();
	REQUIRE(fs::exists(fs::path(kept) / "earlier.txt"));
}

// The health probe of a sandboxed application runs under the same user and sandbox.
TEST_CASE("A sandboxed application is probed inside its sandbox", "[process][sandbox]")
{
	const auto &dir = g_workTree;
	configure(dir.path, "write");
	const auto leak = ownedLeakDir("probe-leak");
	// Exit 0 only when the probe can write its workspace and /dev/null, and not outside.
	const auto script = (fs::path(dir.path) / "health.sh").string();
	{
		std::ofstream out(script);
		out << "echo x > \"$HOME/healthy\" || exit 2\n"
			<< "echo x > /dev/null || exit 3\n"
			<< "echo x > \"$1/file\" 2>/dev/null && exit 4\n"
			<< "exit 0\n";
	}
	auto definition = object({"command", "true"}, {"health_check_cmd", "sh " + script + " " + leak});
	if (::geteuid() == 0)
		definition["execution_user"] = "nobody";
	const auto app = define(definition);

	if (LandlockPolicy::detectAbi() <= 0)
	{
		const auto refused = app->startHealthCheck();
		REQUIRE(refused->getpid() == INVALID_PID);
		REQUIRE(refused->startError().find("cannot be applied") != std::string::npos);
		return;
	}
	const auto probe = app->startHealthCheck();
	int exitCode = -1;
	REQUIRE(probe->wait(std::chrono::seconds(20), &exitCode) != 0);
	REQUIRE(exitCode == 0);
	REQUIRE(fs::exists(fs::path(workspaceOf("sandbox-app")) / "healthy"));
	REQUIRE_FALSE(fs::exists(fs::path(leak) / "file"));
}

#if defined(__linux__)
namespace
{
	int waitExit(pid_t pid)
	{
		int status = 0;
		REQUIRE(::waitpid(pid, &status, 0) == pid);
		return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	}
} // namespace

// forkExec is the last point before exec: the child must enter the Landlock
// domain there, in write and in strict mode.
TEST_CASE("forkExec confines a sandboxed child to its workspace and share", "[process][sandbox]")
{
	const auto abi = LandlockPolicy::detectAbi();
	if (abi <= 0)
		return; // kernel without Landlock: nothing to exercise

	const auto &dir = g_workTree;
	const auto workspace = (fs::path(dir.path) / "fork-workspace").string();
	const auto share = (fs::path(dir.path) / "fork-share").string();
	const auto outside = (fs::path(dir.path) / "fork-outside").string();
	REQUIRE(fs::create_directories(workspace));
	REQUIRE(fs::create_directories(share));
	REQUIRE(fs::create_directories(outside));

	// $0 = workspace, $1 = share, $2 = outside.
	const char *const script = "echo x > \"$0/file\" && cat \"$0/file\" > /dev/null && ls \"$0\" > /dev/null && echo "
							   "workspace-ok || echo workspace-DENIED\n"
							   "echo x > \"$1/file\" && echo share-ok || echo share-DENIED\n"
							   "echo x > \"$2/file\" 2>/dev/null && echo outside-LEAK || echo outside-denied\n"
							   "echo x > /dev/null && echo null-ok || echo null-DENIED\n"
							   "cat /etc/passwd > /dev/null && echo passwd-ok || echo passwd-DENIED\n"
							   "cat /etc/hostname > /dev/null 2>&1 && echo hostname-READ || echo hostname-NOREAD\n";
	for (const auto mode : {SandboxMode::Write, SandboxMode::Strict})
	{
		std::string error;
		const int ruleset = LandlockPolicy::buildRuleset(mode, workspace, share, {}, abi, error);
		REQUIRE(ruleset >= 3);

		char outTemplate[] = "/tmp/appmesh-landlock-XXXXXX";
		const int outFd = ::mkstemp(outTemplate);
		REQUIRE(outFd >= 0);
		ForkExecRequest request;
		request.executable = "/bin/sh";
		request.argv = {"/bin/sh", "-c", script, workspace, share, outside};
		request.environment = {"PATH=/usr/bin:/bin"};
		request.stdoutFd = outFd;
		request.stderrFd = outFd;
		request.landlockRulesetFd = ruleset;
		const auto result = forkExec(request);
		::close(ruleset);
		REQUIRE(result.pid > 0);
		REQUIRE(waitExit(result.pid) == 0);
		std::string output(4096, '\0');
		const ssize_t size = ::pread(outFd, output.data(), output.size(), 0);
		::close(outFd);
		::unlink(outTemplate);
		output.resize(static_cast<std::size_t>(size));
		// Both modes write inside the sandbox and nowhere else; /dev/null and the
		// password database stay reachable, and strict can still read its workspace.
		REQUIRE(output.find("workspace-ok") != std::string::npos);
		REQUIRE(output.find("share-ok") != std::string::npos);
		REQUIRE(output.find("outside-denied") != std::string::npos);
		REQUIRE(output.find("null-ok") != std::string::npos);
		REQUIRE(output.find("passwd-ok") != std::string::npos);
		REQUIRE(output.find("DENIED") == std::string::npos);
		REQUIRE(output.find("LEAK") == std::string::npos);
		// Reads are free in write mode and limited to the baseline in strict mode.
		REQUIRE(output.find(mode == SandboxMode::Write ? "hostname-READ" : "hostname-NOREAD") != std::string::npos);
	}

	// A broken ruleset descriptor fails at the landlock stage, before exec.
	ForkExecRequest broken;
	broken.executable = "/bin/sh";
	broken.argv = {"/bin/sh", "-c", "exit 0"};
	broken.landlockRulesetFd = 1 << 20;
	const auto result = forkExec(broken);
	REQUIRE(result.pid < 0);
	REQUIRE(result.error == EBADF);
	REQUIRE(std::string(result.stage) == "landlock");
}
#endif
