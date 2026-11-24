// src/daemon/process/DockerApiProcess.cpp
#include "DockerApiProcess.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <utility>
#include <vector>

#include <json/json.h>

#include "../../common/RestClient.h"
#include "../../common/Utility.h"
#include "../../common/json.h"
#include "../Configuration.h"
#include "../ResourceLimitation.h"
#include "../application/Application.h"
#include "../security/HMACVerifier.h"

namespace
{
	constexpr long DOCKER_REQUEST_TIMEOUT_SECONDS = 15;
	constexpr int DEFAULT_PULL_TIMEOUT_SECONDS = 300;
	// The pull request outlives its window by the regular call timeout so the
	// agent's bounded pull, not the transport, decides the outcome.
	constexpr long PULL_REQUEST_TIMEOUT_MARGIN_SECONDS = 15;

	constexpr const char *const CONTAINER_SERVICE_BASE = "/appmesh/container";

	// Daemon-only registry credentials never reach the container environment.
	bool isDaemonOnlyDockerEnv(const std::string &name)
	{
		return name == ENV_APPMESH_DOCKER_REGISTRY_SERVER || name == ENV_APPMESH_DOCKER_REGISTRY_USER ||
			   name == ENV_APPMESH_DOCKER_REGISTRY_PASSWORD;
	}

	// PSK headers shared by every daemon->agent container call, signed with
	// the agent's current process proof.
	void signContainerRequest(std::map<std::string, std::string> &header)
	{
		auto uuid = Utility::shortID();
		header["X-Request-ID"] = uuid;
		if (const auto agent = Configuration::instance()->getApp(SEPARATE_AGENT_APP_NAME, false))
			header[HMAC_HTTP_HEADER] = agent->signProcessProof(uuid);
	}

	std::string dockerAgentBaseUrl()
	{
		// The agent shares the REST listener and serves plaintext when SSL is off; no hardcoded https://.
		const auto scheme = Configuration::instance()->getSslEnabled() ? "https://" : "http://";
		return std::string(scheme) + Configuration::instance()->getRestListenAddress() + ":" +
			   std::to_string(Configuration::instance()->getRestListenPort());
	}

	// Why container applications cannot run here: the Docker.Enable switch,
	// then a Docker endpoint. Mirrors the agent's own gates.
	std::string dockerUnavailableReason()
	{
		if (!Configuration::instance()->getDockerEnabled())
			return "Docker support is disabled by configuration (Docker.Enable: false)";
		if (::getenv("DOCKER_HOST") == nullptr && !Utility::isFileExist("/var/run/docker.sock"))
			return "no Docker endpoint on this node (no /var/run/docker.sock, no DOCKER_HOST)";
		return {};
	}

	std::string upperCase(std::string text)
	{
		std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
		return text;
	}

	std::string lowerCase(std::string text)
	{
		std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		return text;
	}
} // namespace

// High-risk host-facing settings the Docker.HostSecurityPolicy gate looks for.
std::vector<std::string> dockerHostSecurityFindings(const Json::Value &createBody)
{
	std::vector<std::string> findings;
	if (!createBody.isObject())
		return findings;
	const auto &hostConfig = createBody["HostConfig"];
	if (!hostConfig.isObject())
		return findings;
	if (hostConfig["Privileged"].isBool() && hostConfig["Privileged"].asBool())
		findings.push_back("privileged container");
	const auto pidMode = upperCase(GET_JSON_STR_VALUE(hostConfig, "PidMode"));
	if (pidMode == "HOST")
		findings.push_back("host PID namespace (pid=host)");
	const auto ipcMode = upperCase(GET_JSON_STR_VALUE(hostConfig, "IpcMode"));
	if (ipcMode == "HOST" || ipcMode == "SHAREABLE")
		findings.push_back("shared host IPC namespace (ipc=" + lowerCase(ipcMode) + ")");
	// docker network semantics: host/none/container:<id> bypass the bridge.
	const auto networkMode = lowerCase(GET_JSON_STR_VALUE(hostConfig, "NetworkMode"));
	if (networkMode == "host")
		findings.push_back("host network namespace (network=host)");
	// Binds and Mounts are two spellings of the same host-path exposure; normalize so '//' and '/./' cannot disguise '/'.
	const auto riskyBindSource = [](std::string source)
	{
		std::string normalized;
		for (size_t i = 0; i < source.size(); i++)
		{
			if (source[i] == '/' && !normalized.empty() && normalized.back() == '/')
				continue;
			normalized += source[i];
		}
		// Collapse '/./' segments and a trailing '/.'.
		const auto dotSlash = normalized.find("/./");
		if (dotSlash != std::string::npos)
			normalized = normalized.substr(0, dotSlash) + normalized.substr(dotSlash + 2);
		if (Utility::endWith(normalized, "/."))
			normalized.resize(normalized.size() - 2);
		return normalized == "/" || normalized == "/var/run" || normalized == "/run" ||
			   Utility::endWith(normalized, "/docker.sock");
	};
	if (hostConfig["Binds"].isArray())
	{
		for (const auto &bind : hostConfig["Binds"])
		{
			if (!bind.isString())
				continue;
			const auto source = bind.asString().substr(0, bind.asString().find(':'));
			if (riskyBindSource(source))
				findings.push_back("bind of host path <" + source + ">");
		}
	}
	if (hostConfig["Mounts"].isArray())
	{
		for (const auto &mount : hostConfig["Mounts"])
		{
			// Read-only mounts still expose host content; every bind type counts.
			if (!mount.isObject() || lowerCase(GET_JSON_STR_VALUE(mount, "Type")) != "bind")
				continue;
			const auto source = GET_JSON_STR_VALUE(mount, "Source");
			if (riskyBindSource(source))
				findings.push_back("Mount of host path <" + source + ">");
		}
	}
	// Volumes-from or raw host-device mapping is a host-facing capability by construction.
	if (hostConfig["VolumesFrom"].isArray() && hostConfig["VolumesFrom"].size() > 0)
		findings.push_back("volumes inherited from another container (volumes-from)");
	if (hostConfig["Devices"].isArray() && hostConfig["Devices"].size() > 0)
		findings.push_back("host device mapping (device)");
	if (hostConfig["SecurityOpt"].isArray())
	{
		for (const auto &opt : hostConfig["SecurityOpt"])
		{
			// apparmor/seccomp/systempaths "unconfined" and label disabling are the profile-escape spellings.
			if (opt.isString())
			{
				const auto text = lowerCase(opt.asString());
				if (text.find("unconfined") != std::string::npos || text.find("label=disable") == 0 ||
					text.find("label:disable") != std::string::npos)
					findings.push_back("security opt <" + opt.asString() + ">");
			}
		}
	}
	if (hostConfig["CapAdd"].isArray())
	{
		for (const auto &cap : hostConfig["CapAdd"])
		{
			if (!cap.isString())
				continue;
			const auto name = upperCase(cap.asString());
			if (name == "ALL" || name == "SYS_ADMIN" || name == "SYS_PTRACE")
				findings.push_back("CapAdd " + cap.asString());
		}
	}
	return findings;
}

// The OS hostname: the daemon and the embedded agent run on the same host, so
// both derive the identical ownership identity, and nodes sharing one Docker
// engine (sibling containers, a common docker.sock) stay distinguishable.
std::string dockerNodeIdentity()
{
	char host[256] = {};
	if (::gethostname(host, sizeof(host) - 1) != 0 || host[0] == '\0')
		return "unknown-node";
	return host;
}

// Namespaced by node and app so an App Mesh container can never collide with an
// operator container, nor with the same-named application of another node.
std::string DockerApiProcess::namespacedContainerName(const std::string &appName)
{
	return "appmesh-" + dockerNodeIdentity() + "-" + appName;
}

void inlineShellScriptCmd(Json::Value &createBody)
{
	// Presence checks first: operator[] would insert null members and pollute
	// the create body of an ENTRYPOINT-only image.
	if (!HAS_JSON_FIELD(createBody, "Cmd") || !HAS_JSON_FIELD(createBody, "HostConfig"))
		return;
	const auto &cmd = createBody["Cmd"];
	// The exact shape Application::getCmdLine() produces for shell mode: `bash <script>`.
	if (!cmd.isArray() || cmd.size() != 2 || !cmd[0].isString() || cmd[0].asString() != "bash" || !cmd[1].isString())
		return;
	const auto script = cmd[1].asString();

	// Only inline when this very script is the compile step's same-path read-only bind.
	auto &hostConfig = createBody["HostConfig"];
	if (!hostConfig.isObject() || !hostConfig["Binds"].isArray())
		return;
	const auto bindSpec = script + ":" + script + ":ro";
	bool bound = false;
	for (const auto &bind : hostConfig["Binds"])
		if (bind.isString() && bind.asString() == bindSpec)
			bound = true;
	if (!bound)
		return;

	std::ifstream in(script, std::ios::binary);
	if (!in.is_open())
		return; // unreadable here would be unreadable in the container; keep the old shape
	std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

	// The generated header's cd (its 4th line) targets a daemon-host path; a
	// generic image lacks it and set -e would kill the script before the user
	// command. appmesh-based images still cd successfully, keeping the
	// working-dir behavior unchanged; user lines are never touched.
	{
		const auto cdPrefix = std::string("cd ");
		auto lineStart = content.find("set -e");
		if (lineStart != std::string::npos)
		{
			lineStart = content.find('\n', lineStart);
			if (lineStart != std::string::npos)
			{
				++lineStart;
				const auto lineEnd = content.find('\n', lineStart);
				if (lineEnd != std::string::npos && content.compare(lineStart, cdPrefix.length(), cdPrefix) == 0)
				{
					const auto dir = content.substr(lineStart + cdPrefix.length(), lineEnd - lineStart - cdPrefix.length());
					content.replace(lineStart, lineEnd - lineStart,
						cdPrefix + dir + " 2>/dev/null || echo 'App Mesh: working dir <" + dir +
							"> not present in this container, using the image default' >&2");
				}
			}
		}
	}

	Json::Value inlined(Json::arrayValue);
	inlined.append("bash");
	inlined.append("-c");
	inlined.append(std::move(content));
	createBody["Cmd"] = std::move(inlined);

	Json::Value kept(Json::arrayValue);
	for (const auto &bind : hostConfig["Binds"])
		if (!bind.isString() || bind.asString() != bindSpec)
			kept.append(bind);
	hostConfig["Binds"] = std::move(kept);
}

// Event-push liveness: the scheduler demotes the poll only while markers stay fresh.
namespace
{
	std::atomic<int64_t> g_containerEventsAliveMs{0};
	constexpr int64_t CONTAINER_EVENTS_FRESH_MS = 90 * 1000;
	// Backstop inspect interval while markers stay fresh.
	constexpr int64_t CONTAINER_EVENTS_BACKSTOP_MS = 60 * 1000;
} // namespace

void DockerApiProcess::noteContainerEventsAlive()
{
	g_containerEventsAliveMs.store(
		std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
			.count(),
		std::memory_order_release);
}

bool DockerApiProcess::containerEventsFresh()
{
	const auto last = g_containerEventsAliveMs.load(std::memory_order_acquire);
	if (last == 0)
		return false;
	const auto now =
		std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
			.count();
	return now - last < CONTAINER_EVENTS_FRESH_MS;
}

// SIGTERM grace before SIGKILL, docker's own default when the app sets none.
int DockerApiProcess::stopGraceSeconds() const
{
	if (const auto ownerApplication = owner().lock())
	{
		const auto grace = ownerApplication->stopGraceSeconds();
		if (grace > 0)
			return grace;
	}
	return 10;
}

DockerApiProcess::DockerApiProcess(std::weak_ptr<Application> owner, const std::string &appName,
								   const std::string &dockerImage)
	: AppProcess(std::move(owner)),
	  // A namespaced name implies its pre-namespacing original; the legacy name
	  // only exists to clean up containers created by an older App Mesh version.
	  m_containerName(namespacedContainerName(appName)), m_dockerImage(dockerImage),
	  m_legacyContainerName(appName)
{
	const static char fname[] = "DockerApiProcess::DockerApiProcess() ";
	LOG_DBG << fname << "Entered";
}

DockerApiProcess::~DockerApiProcess()
{
	const static char fname[] = "DockerApiProcess::~DockerApiProcess() ";
	LOG_DBG << fname << "Entered";

	// Destructors must not throw: cleanup is best-effort during teardown.
	try
	{
		// Destruction has no shared owner; skip lifecycle callbacks.
		DockerApiProcess::terminateImpl();
	}
	catch (...)
	{
	}
}

bool DockerApiProcess::running() const
{
	// The pull thread keeps this run alive exactly like a real child did.
	if (m_pullInFlight.load(std::memory_order_acquire))
		return true;
	{
		std::lock_guard guard(m_dockerMutex);
		if (!m_containerId.empty() && !m_hostPidVisible.load(std::memory_order_acquire))
			return m_containerRunning.load(std::memory_order_acquire);
	}
	return AppProcess::running();
}

pid_t DockerApiProcess::getpid() const
{
	// Return invalid PID if process ID is 1 (init/systemd)
	if (AppProcess::getpid() == 1)
	{
		return INVALID_PID;
	}
	return AppProcess::getpid();
}

std::string DockerApiProcess::containerId() const
{
	std::lock_guard guard(m_dockerMutex);
	return m_containerId;
}

void DockerApiProcess::setContainerId(const std::string &containerId)
{
	std::lock_guard guard(m_dockerMutex);
	m_containerId = containerId;
}

std::string DockerApiProcess::takeContainerId()
{
	std::lock_guard guard(m_dockerMutex);
	auto containerId = std::move(m_containerId);
	m_containerId.clear();
	return containerId;
}

bool DockerApiProcess::needsAlwaysExitPoll() const
{
	std::lock_guard guard(m_dockerMutex);
	return !m_containerId.empty() && !m_hostPidVisible.load(std::memory_order_acquire);
}

bool DockerApiProcess::backendLivenessPollDue() const
{
	if (!needsAlwaysExitPoll())
		return false;
	const auto now =
		std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
			.count();
	return now - m_lastBackendPollMs.load(std::memory_order_acquire) >= CONTAINER_EVENTS_BACKSTOP_MS;
}

void DockerApiProcess::reportBackendExit()
{
	const auto containerId = this->containerId();
	if (containerId.empty())
	{
		// A pull thread owns its own exit; native fallback takes the OS answer.
		onExit(returnValue());
		return;
	}

	// The marker demotion may suppress the next poll until this ages past the backstop.
	m_lastBackendPollMs.store(
		std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
			.count(),
		std::memory_order_release);

	// Docker decides; a channel failure never fabricates an exit.
	const auto state = this->inspectState(containerId);
	if (!state)
	{
		LOG_WAR << "DockerApiProcess::reportBackendExit() inspect failed for <" << containerId << ">";
		return;
	}
	if ((*state)["running"].asBool())
	{
		m_containerRunning.store(true, std::memory_order_release);
		return;
	}
	m_containerRunning.store(false, std::memory_order_release);
	onExit((*state)["exitCode"].asInt());
}

std::optional<int> DockerApiProcess::containerHealthVerdict()
{
	const static char fname[] = "DockerApiProcess::containerHealthVerdict() ";
	const auto containerId = this->containerId();
	if (containerId.empty())
		return std::nullopt;

	// Health exists only when the image defines a HEALTHCHECK.
	const auto state = this->inspectState(containerId);
	if (!state)
	{
		// Fail closed: a channel failure is not proof of health.
		LOG_WAR << fname << "container inspect failed, marking unhealthy";
		return 1;
	}
	// A stopped container keeps its last Health; reading it would bounce a dead app back to healthy.
	if (!(*state)["running"].asBool())
		return 1;
	if (!HAS_JSON_FIELD(*state, "health"))
		return std::nullopt; // no image HEALTHCHECK to read

	const auto status = GET_JSON_STR_VALUE(*state, "health");
	if (status == "healthy")
		return 0;
	if (status == "unhealthy")
		return 1;
	if (status == "starting")
		return 0; // docker's own start-period leniency
	LOG_WAR << fname << "unknown HEALTHCHECK status <" << status << ">";
	return std::nullopt;
}

std::optional<int> DockerApiProcess::execHealthProbe(const std::string &cmd)
{
	const static char fname[] = "DockerApiProcess::execHealthProbe() ";
	const auto containerId = this->containerId();
	if (containerId.empty() || cmd.empty())
		return std::nullopt;

	// The agent owns the exec protocol; the daemon sends the parsed argv.
	Json::Value body;
	auto cmdArray = Json::Value(Json::arrayValue);
	for (const auto &arg : Utility::str2argv(cmd))
		cmdArray.append(std::string(arg));
	body["cmd"] = std::move(cmdArray);

	auto resp = this->requestContainer(web::http::methods::POST,
									   Utility::stringFormat("/%s/exec", containerId.c_str()), {}, &body);
	if (resp->statusCode != web::http::status_codes::OK)
	{
		LOG_WAR << fname << "exec probe failed <" << resp->statusCode << ">: " << resp->text.substr(0, 200);
		return std::nullopt;
	}
	const auto result = JSON::parse(resp->text, nullptr);
	if (HAS_JSON_FIELD(result, "exitCode") && result["exitCode"].isIntegral())
		return result["exitCode"].asInt();
	LOG_WAR << fname << "exec result unavailable: " << resp->text.substr(0, 200);
	return std::nullopt;
}

std::string DockerApiProcess::stdoutArchiveFile() const
{
	std::lock_guard guard(m_dockerMutex);
	return m_stdoutFile;
}

void DockerApiProcess::archiveContainerLogs(const std::string &containerId)
{
	const static char fname[] = "DockerApiProcess::archiveContainerLogs() ";
	const auto stdoutFile = this->stdoutArchiveFile();
	if (stdoutFile.empty() || containerId.empty())
		return;
	try
	{
		auto resp = this->requestContainer(web::http::methods::GET,
											Utility::stringFormat("/%s/logs", containerId.c_str()), {{"tail", "2000"}}, nullptr);
		if (resp->statusCode == web::http::status_codes::OK)
		{
			const auto output = joinLogLines(JSON::parse(resp->text, nullptr));
			if (!output.empty())
			{
				std::ofstream out(stdoutFile, std::ios::app);
				out << output;
			}
		}
		else
			LOG_WAR << fname << "log fetch failed <" << resp->statusCode << ">, archive skipped";
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << fname << "failed: " << ex.what();
	}
}

void DockerApiProcess::sweepOrphanContainers()
{
	const static char fname[] = "DockerApiProcess::sweepOrphanContainers() ";
	if (const auto unavailable = dockerUnavailableReason(); !unavailable.empty())
	{
		LOG_DBG << fname << "skipped: " << unavailable;
		return;
	}

	const auto sweepMode = ::getenv("APPMESH_DOCKER_ORPHAN_SWEEP");
	const bool deleteOrphans = sweepMode != nullptr && ::strcmp(sweepMode, "delete") == 0;

	try
	{
		std::map<std::string, std::string> header;
		signContainerRequest(header);
		const auto resp = RestClient::request(dockerAgentBaseUrl(), web::http::methods::GET,
											  std::string(CONTAINER_SERVICE_BASE) + "/list", "", header, {}, 15);
		if (resp->statusCode != web::http::status_codes::OK)
		{
			LOG_WAR << fname << "labeled container list failed <" << resp->statusCode << ">, skipping sweep";
			return;
		}
		const auto containers = JSON::parse(resp->text, nullptr);
		if (!containers.isArray())
			return;

		for (const auto &container : containers)
		{
			const auto labels = container["labels"];
			const auto appName = labels.isObject() ? GET_JSON_STR_VALUE(labels, DOCKER_LABEL_APP) : std::string();
			if (appName.empty())
				continue;
			// Another node's container on the shared engine is not ours to judge;
			// the node that owns it runs its own sweep.
			if (!labels.isObject() || GET_JSON_STR_VALUE(labels, DOCKER_LABEL_NODE) != dockerNodeIdentity())
				continue;
			const auto app = Configuration::instance()->getApp(appName, false);
			if (app && app->isContainerized())
				continue;

			const auto containerId = GET_JSON_STR_VALUE(container, "id");
			LOG_WAR << fname << "orphan container <" << containerId << "> of removed application <" << appName << ">"
					<< (deleteOrphans ? ", deleting" : "; set APPMESH_DOCKER_ORPHAN_SWEEP=delete to remove it");
			if (deleteOrphans && !containerId.empty())
			{
				std::map<std::string, std::string> deleteHeader;
				signContainerRequest(deleteHeader);
				const auto deleted = RestClient::request(dockerAgentBaseUrl(), web::http::methods::DEL,
														 Utility::stringFormat("%s/%s", CONTAINER_SERVICE_BASE, containerId.c_str()),
														 "", deleteHeader, {{"force", "1"}}, 15);
				if (deleted->statusCode >= web::http::status_codes::BadRequest &&
					deleted->statusCode != web::http::status_codes::NotFound)
					LOG_WAR << fname << "delete of orphan container <" << containerId << "> failed <" << deleted->text
							<< ">";
			}
		}
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << fname << "sweep failed: " << ex.what();
	}
}

void DockerApiProcess::selfCheckDockerAgent()
{
	const static char fname[] = "DockerApiProcess::selfCheckDockerAgent() ";
	if (const auto unavailable = dockerUnavailableReason(); !unavailable.empty())
	{
		LOG_INF << fname << "Docker support inactive on this node: " << unavailable;
		return;
	}

	// A short retry covers the agent's boot race after the PSK hand-over.
	for (int attempt = 1; attempt <= 3; attempt++)
	{
		try
		{
			std::map<std::string, std::string> header;
			signContainerRequest(header);
			const auto resp = RestClient::request(dockerAgentBaseUrl(), web::http::methods::GET,
												  std::string(CONTAINER_SERVICE_BASE) + "/ping", "", header, {}, 10);
			if (resp->statusCode == web::http::status_codes::OK)
			{
				LOG_INF << fname << "Docker agent channel verified";
				return;
			}
			LOG_ERR << fname << "Docker agent self-check got status <" << resp->statusCode
					<< ">: Docker applications will fail to start until the agent serves the container service again <"
					<< resp->text.substr(0, 200) << ">";
			return;
		}
		catch (const std::exception &ex)
		{
			if (attempt == 3)
			{
				LOG_ERR << fname << "Docker agent self-check failed: " << ex.what()
						<< "; Docker applications will fail to start until the agent is reachable on the REST listen port";
				return;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
		}
	}
}

void DockerApiProcess::adoptRecoveredContainer()
{
	const static char fname[] = "DockerApiProcess::adoptRecoveredContainer() ";
	if (!containerId().empty())
		return;

	// Same ownership proof the agent's run operation applies: only a container
	// labeled for this app is adopted.
	auto resp = this->requestContainer(web::http::methods::GET,
									   Utility::stringFormat("/%s", m_containerName.c_str()), {}, nullptr);
	if (resp->statusCode != web::http::status_codes::OK)
		return;
	const auto inspect = JSON::parse(resp->text, nullptr);
	if (!inspect.isObject() || !HAS_JSON_FIELD(inspect, "labels") || !inspect["labels"].isObject())
		return;
	const auto &labels = inspect["labels"];
	if (GET_JSON_STR_VALUE(labels, DOCKER_LABEL_MANAGED) != "true" ||
		GET_JSON_STR_VALUE(labels, DOCKER_LABEL_APP) != legacyContainerName() ||
		GET_JSON_STR_VALUE(labels, DOCKER_LABEL_NODE) != dockerNodeIdentity())
		return;
	if (!HAS_JSON_FIELD(inspect, "running") || !inspect["running"].isBool())
		return;

	const auto running = GET_JSON_BOOL_VALUE(inspect, "running");
	setContainerId(HAS_JSON_FIELD(inspect, "id") && inspect["id"].isString() ? GET_JSON_STR_VALUE(inspect, "id")
																			 : m_containerName);
	m_containerRunning.store(running, std::memory_order_release);
	m_hostPidVisible.store(AppProcess::running(), std::memory_order_release);
	LOG_INF << fname << "adopted recovered container <" << m_containerName << "> (running: <" << running
			<< ">) for application <" << legacyContainerName() << ">";
}

void DockerApiProcess::terminateImpl()
{
	const static char fname[] = "DockerApiProcess::terminateImpl() ";

	// A pull in flight has no container; cancel ends its bounded request silently.
	m_pullCancelled.store(true, std::memory_order_release);

	auto containerId = takeContainerId();
	if (containerId.empty())
	{
		// Image pulls are native child processes owned by AppProcess.
		AppProcess::terminateImpl();
		return;
	}

	// Graceful stop — SIGTERM first; docker returns as soon as the container exits.
	const auto grace = stopGraceSeconds();
	Json::Value stopBody;
	stopBody["graceSeconds"] = grace;
	auto resp = this->requestContainer(web::http::methods::POST,
									   Utility::stringFormat("/%s/stop", containerId.c_str()), {}, &stopBody,
									   grace + DOCKER_REQUEST_TIMEOUT_SECONDS);
	if (resp->statusCode >= web::http::status_codes::BadRequest && resp->statusCode != web::http::status_codes::NotFound)
	{
		LOG_WAR << fname << "Graceful stop of container <" << containerId << "> failed <" << resp->text << ">";
		// Never fall back to the host PID (exit handling may have reused it); the kill + delete below is the backstop.
	}

	// Persist the container's final logs before the delete removes them.
	archiveContainerLogs(containerId);

	// Kill — unless the container already exited (every stop of a completed run
	// would otherwise log docker's "cannot kill ... is not running" noise).
	const auto state = this->inspectState(containerId);
	if (!state || (*state)["running"].asBool())
	{
		resp = this->requestContainer(web::http::methods::POST, Utility::stringFormat("/%s/kill", containerId.c_str()),
									  {}, nullptr);

		if (resp->statusCode >= web::http::status_codes::BadRequest && resp->statusCode != web::http::status_codes::NotFound)
		{
			LOG_WAR << fname << "Kill container <" << containerId << "> failed <" << resp->text << ">";
		}
	}

	// Delete
	resp = this->requestContainer(web::http::methods::DEL, Utility::stringFormat("/%s", containerId.c_str()),
								  {{"force", "1"}, {"volumes", "1"}}, nullptr);

	if (resp->statusCode >= web::http::status_codes::BadRequest && resp->statusCode != web::http::status_codes::NotFound)
	{
		LOG_WAR << fname << "Delete container <" << containerId << "> failed <" << resp->text << ">";
	}

	// Detach manually
	this->detach();
}

pid_t DockerApiProcess::startImpl(std::string cmd, std::string execUser, std::string workDir,
								  std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
								  const std::string &stdoutFile, const Json::Value &stdinFileContent, int maxStdoutSize,
								  bool stdinPipe)
{
	const static char fname[] = "DockerApiProcess::startImpl() ";
	LOG_DBG << fname << "Entered";
	(void)stdinPipe; // registration rejects pipe stdin for container apps
	{
		std::lock_guard guard(m_dockerMutex);
		m_stdoutFile = stdoutFile;
	}

	// Fail here: with the service off, the forwarded 404 would read as "image missing".
	if (const auto unavailable = dockerUnavailableReason(); !unavailable.empty())
	{
		LOG_WAR << fname << "cannot start container application: " << unavailable;
		setStartError(unavailable + " — this application runs in a Docker container");
		return INVALID_PID;
	}

	// Image presence: on-demand runs never pull, managed applications arm the pull as an intermediate run.
	auto resp = this->requestContainer(web::http::methods::GET, "/image", {{"ref", m_dockerImage}}, nullptr);
	if (resp->statusCode == web::http::status_codes::NotFound)
	{
		if (const auto ownerApplication = owner().lock(); ownerApplication && ownerApplication->isOneShot())
		{
			auto msg = std::string("image <") + m_dockerImage +
					   "> is not present locally; an on-demand run does not pull — register the application to "
					   "pull first or pre-pull the image";
			LOG_WAR << fname << msg;
			setStartError(msg);
			return INVALID_PID;
		}
		int pullTimeout = DEFAULT_PULL_TIMEOUT_SECONDS;
		if (const auto timeoutSetting = envMap.find(ENV_APPMESH_DOCKER_IMG_PULL_TIMEOUT); timeoutSetting != envMap.end())
		{
			try
			{
				const auto parsed = std::stoi(timeoutSetting->second);
				if (parsed > 0)
					pullTimeout = parsed;
			}
			catch (const std::exception &)
			{
				LOG_WAR << fname << "ignored invalid " << ENV_APPMESH_DOCKER_IMG_PULL_TIMEOUT << " <" << timeoutSetting->second
						<< ">, using default <" << pullTimeout << "> seconds";
			}
		}
		startApiImagePull(std::move(envMap), pullTimeout, stdoutFile);
		return INVALID_PID;
	}
	if (resp->statusCode != web::http::status_codes::OK)
	{
		LOG_WAR << fname << "Docker image check failed with status <" << resp->statusCode << ">: " << resp->text;
		setStartError(resp->text.empty() ? "Docker container service is unavailable" : resp->text);
		return INVALID_PID;
	}

	// Validate input metadata format
	if (!stdinFileContent.isNull() && !stdinFileContent.isObject())
	{
		auto msg = std::string("input error format of metadata, should be a JSON format for Docker container definition: ") +
				   JSON::dump(stdinFileContent);
		LOG_WAR << fname << msg;
		setStartError(msg);
		return INVALID_PID;
	}

	// First-class fields were compiled into metadata by the application; labels are stamped agent-side.
	auto createBody = stdinFileContent.isObject() ? stdinFileContent : Json::Value(Json::objectValue);

	// Set command
	if (cmd.length())
	{
		auto argv = Utility::str2argv(cmd);
		auto array = Json::Value(Json::arrayValue);
		for (size_t i = 0; i < argv.size(); i++)
		{
			array.append(std::string(argv[i]));
		}
		createBody["Cmd"] = std::move(array);
	}

	// Set image
	if (m_dockerImage.length())
	{
		createBody["Image"] = std::string(m_dockerImage);
	}

	// Container user follows the application's execution_user, the intuitive
	// mapping; an explicit metadata User still wins.
	if (execUser.length() && !HAS_JSON_FIELD(createBody, "User"))
	{
		createBody["User"] = execUser;
	}

	// Set working directory
	if (workDir.length())
	{
		createBody["WorkingDir"] = workDir;
	}

	// Set environment variables
	if (envMap.size())
	{
		auto array = Json::Value(Json::arrayValue);
		for (const auto &[key, value] : envMap)
		{
			if (isDaemonOnlyDockerEnv(key))
				continue;
			array.append(key + "=" + value);
		}
		createBody["Env"] = array;
	}

	// Configure host settings
	if (HAS_JSON_FIELD(createBody, "HostConfig") && !createBody["HostConfig"].isObject())
	{
		setStartError("Docker HostConfig must be a JSON object");
		return INVALID_PID;
	}
	auto hostConfig = HAS_JSON_FIELD(createBody, "HostConfig") ? createBody["HostConfig"] : Json::Value(Json::objectValue);

	if (limit)
	{
		constexpr int64_t MB = 1024LL * 1024LL;
		if (limit->m_memoryMb > 0)
			hostConfig["Memory"] = static_cast<int64_t>(limit->m_memoryMb) * MB;
		if (limit->m_memoryVirtSpecified)
			hostConfig["MemorySwap"] = static_cast<int64_t>(limit->m_memoryVirtMb) * MB;
		if (limit->m_cpuShares > 0)
			hostConfig["CpuShares"] = (limit->m_cpuShares);
		if (limit->m_cpuCores > 0)
			hostConfig["NanoCPUs"] = static_cast<int64_t>(limit->m_cpuCores * 1e9);
	}

	// Keep the stopped container until its final state/logs are inspected.
	hostConfig["AutoRemove"] = false;
	Json::Value restartPolicy;
	restartPolicy["Name"] = "no";
	hostConfig["RestartPolicy"] = restartPolicy;
	createBody["HostConfig"] = hostConfig;

	// Shell mode's generated script never travels as a host bind (invisible to a
	// docker.sock / sibling dockerd): it is inlined into the command instead.
	inlineShellScriptCmd(createBody);

	// Docker.HostSecurityPolicy: audited or rejected before the container exists.
	{
		const auto policy = Configuration::instance()->getDockerHostSecurityPolicy();
		if (policy != "off")
		{
			const auto findings = dockerHostSecurityFindings(createBody);
			if (!findings.empty())
			{
				std::string joined;
				for (const auto &f : findings)
					joined += (joined.empty() ? "" : "; ") + f;
				if (policy == "enforce")
				{
					setStartError("Docker.HostSecurityPolicy=enforce rejected the container definition: " + joined);
					LOG_WAR << fname << startError();
					this->detach();
					return INVALID_PID;
				}
				LOG_WAR << fname << "Docker.HostSecurityPolicy=audit: container <" << m_containerName << "> uses "
						<< joined;
			}
		}
	}

	// One signed call: owned leftovers removed, container created, started, inspected.
	// A managed application re-binds to a still-running orphan of its own instead
	// of replacing it, so a node crash keeps the container and its in-container state.
	const auto ownerApplication = owner().lock();
	Json::Value runRequest;
	runRequest["name"] = m_containerName;
	runRequest["app"] = legacyContainerName();
	runRequest["legacyName"] = legacyContainerName();
	runRequest["adoptRunning"] = ownerApplication && !ownerApplication->isOneShot();
	runRequest["graceSeconds"] = stopGraceSeconds();
	runRequest["createBody"] = createBody;
	resp = this->requestContainer(web::http::methods::POST, "/run", {}, &runRequest);
	if (resp->statusCode != web::http::status_codes::OK)
	{
		LOG_WAR << fname << "container run failed <" << resp->text << ">";
		setStartError(resp->text);
		this->detach();
		terminate();
		return this->getpid();
	}

	const auto runResponse = JSON::parse(resp->text, nullptr);
	// The replaced leftover's final logs precede this run's own output.
	const auto replacedLogs = GET_JSON_STR_VALUE(runResponse, "replacedLogs");
	if (!m_stdoutFile.empty() && !replacedLogs.empty())
	{
		std::ofstream out(m_stdoutFile, std::ios::app);
		out << replacedLogs;
	}

	const auto containerId = GET_JSON_STR_VALUE(runResponse, "id");
	setContainerId(containerId.empty() ? m_containerName : containerId);
	if (GET_JSON_BOOL_VALUE(runResponse, "adopted"))
		LOG_INF << fname << "adopted running orphan container <" << m_containerName << "> for application <"
				<< legacyContainerName() << ">";

	if (!GET_JSON_BOOL_VALUE(runResponse, "running"))
	{
		const int exitCode = HAS_JSON_FIELD(runResponse, "exitCode") && runResponse["exitCode"].isIntegral()
								 ? runResponse["exitCode"].asInt()
								 : DOCKER_COMMAND_ERROR;
		LOG_INF << fname << "container <" << m_containerName
				<< "> completed before host PID inspection, exit code <" << exitCode << ">";
		reportEarlyExit(exitCode);
		return INVALID_PID;
	}

	const auto pid = runResponse["pid"].isIntegral() ? runResponse["pid"].asInt64() : 0;
	if (pid > 1 && pid <= std::numeric_limits<pid_t>::max())
	{
		this->attach(static_cast<pid_t>(pid));
		// A containerized daemon cannot see sibling containers' host PIDs;
		// Docker's own state becomes the liveness authority
		// (needsAlwaysExitPoll / reportBackendExit).
		m_hostPidVisible.store(AppProcess::running(), std::memory_order_release);
		m_containerRunning.store(true, std::memory_order_release);
		LOG_INF << fname << "started pid <" << pid << "> (visible: " << m_hostPidVisible.load(std::memory_order_acquire)
				<< ") for container: " << m_containerName;
		return this->getpid();
	}

	setStartError("container reported running without a valid host pid");
	LOG_WAR << fname << startError();
	this->detach();
	terminate();
	return this->getpid();
}

void DockerApiProcess::startApiImagePull(std::map<std::string, std::string> envMap, int pullTimeoutSeconds,
										 const std::string &stdoutFile)
{
	const static char fname[] = "DockerApiProcess::startApiImagePull() ";

	LOG_INF << fname << "pulling image <" << m_dockerImage << "> via the agent, timeout <" << pullTimeoutSeconds
			<< ">s";

	m_pullCancelled.store(false, std::memory_order_release);
	m_pullInFlight.store(true, std::memory_order_release);
	// Accepted run without a PID — the early-exit handshake; the pull thread owns the report.
	resolveStart(true, INVALID_PID);

	// The thread holds the only strong self reference until its request ends.
	auto self = std::dynamic_pointer_cast<DockerApiProcess>(shared_from_this());
	std::thread(
		[self, envMap = std::move(envMap), pullTimeoutSeconds, stdoutFile]() mutable
		{
			const static char pullName[] = "DockerApiProcess::imagePullThread ";

			// A stop that raced this thread must not launch the pull; the exit report still fires.
			if (self->m_pullCancelled.load(std::memory_order_acquire))
			{
				self->setStartError("image pull cancelled");
				self->onExit(1);
				self->m_pullInFlight.store(false, std::memory_order_release);
				return;
			}

			std::string pullError;
			std::string progressDump;
			try
			{
				// Daemon-side secrets in the body; same-reference pulls collapse agent-side.
				Json::Value body;
				body["ref"] = self->m_dockerImage;
				body["timeoutSeconds"] = pullTimeoutSeconds;
				if (const auto user = envMap.find(ENV_APPMESH_DOCKER_REGISTRY_USER); user != envMap.end() && !user->second.empty())
				{
					Json::Value auth;
					auth["username"] = user->second;
					if (const auto password = envMap.find(ENV_APPMESH_DOCKER_REGISTRY_PASSWORD); password != envMap.end())
						auth["password"] = password->second;
					if (const auto server = envMap.find(ENV_APPMESH_DOCKER_REGISTRY_SERVER); server != envMap.end() && !server->second.empty())
						auth["server"] = server->second;
					body["auth"] = auth;
				}

				const auto resp = self->requestContainer(web::http::methods::POST, "/image/ensure", {}, &body,
														 pullTimeoutSeconds + PULL_REQUEST_TIMEOUT_MARGIN_SECONDS);
				if (resp->statusCode != web::http::status_codes::OK)
				{
					pullError = Utility::stringFormat("image pull failed with status <%ld>: %s", resp->statusCode,
													  resp->text.substr(0, 512).c_str());
				}
				else
				{
					const auto result = JSON::parse(resp->text, nullptr);
					progressDump = GET_JSON_STR_VALUE(result, "progress");
					if (HAS_JSON_FIELD(result, "ok") && !result["ok"].asBool())
						pullError = "image pull failed: " + GET_JSON_STR_VALUE(result, "error");
				}
			}
			catch (const std::exception &ex)
			{
				pullError = std::string("image pull request failed: ") + ex.what();
			}
			catch (...)
			{
				pullError = "image pull request failed with an unknown exception";
			}

			if (!stdoutFile.empty() && !progressDump.empty() && !self->m_pullCancelled.load(std::memory_order_acquire))
			{
				std::ofstream out(stdoutFile, std::ios::app);
				out << progressDump;
			}

			const int exitCode = pullError.empty() ? 0 : 1;
			if (!pullError.empty())
			{
				LOG_WAR << pullName << pullError;
				self->setStartError(pullError);
			}
			else
				LOG_INF << pullName << "image <" << self->m_dockerImage << "> pulled, progress bytes <"
						<< progressDump.size() << ">, stdout file <" << (stdoutFile.empty() ? "<none>" : stdoutFile) << ">";

			// The only exit report this PID-less run ever gets.
			self->onExit(exitCode);
			self->m_pullInFlight.store(false, std::memory_order_release);
		})
		.detach();
}

const std::string DockerApiProcess::getOutputMsg(long *position, int maxSize, bool readLine)
{
	const auto containerId = this->containerId();
	if (!containerId.empty())
	{
		std::map<std::string, std::string> query{{"tail", readLine ? "1" : "all"}};
		if (position && *position > 0)
			query["sinceNs"] = std::to_string(*position);
		auto resp = this->requestContainer(web::http::methods::GET,
											Utility::stringFormat("/%s/logs", containerId.c_str()), std::move(query),
											nullptr);
		if (resp->statusCode != web::http::status_codes::OK)
		{
			// An error body is not application output; fall back to the archived stdout file.
			LOG_WAR << "DockerApiProcess::getOutputMsg() log fetch failed <" << resp->statusCode << ">";
			return AppProcess::getOutputMsg(position, maxSize, readLine);
		}

		// The cursor advances only to fully delivered lines; truncated ones re-deliver on the next poll.
		std::vector<std::tuple<std::string, long, size_t, size_t>> lines; // payload, epoch ns, start, payload end
		const auto parsed = JSON::parse(resp->text, nullptr);
		if (parsed.isObject() && parsed["lines"].isArray())
		{
			for (const auto &line : parsed["lines"])
			{
				if (!line.isObject() || !HAS_JSON_FIELD(line, "text"))
					continue;
				const auto ns = HAS_JSON_FIELD(line, "ns") && line["ns"].isIntegral() ? line["ns"].asInt64() : -1;
				lines.emplace_back(GET_JSON_STR_VALUE(line, "text"), static_cast<long>(ns), 0, 0);
			}
		}
		std::string output;
		for (auto &[payload, nanos, start, payloadEnd] : lines)
		{
			start = output.size();
			output += payload;
			payloadEnd = output.size();
			output += '\n';
		}
		size_t frontCut = 0;
		if (readLine)
		{
			const auto newline = output.find('\n');
			if (newline != std::string::npos)
				output.resize(newline);
		}
		else if (maxSize > 0 && output.size() > static_cast<size_t>(maxSize))
			output.resize(static_cast<size_t>(maxSize));
		else if (maxSize < 0 && output.size() > static_cast<size_t>(-maxSize))
		{
			frontCut = output.size() - static_cast<size_t>(-maxSize);
			output.erase(0, frontCut);
		}
		if (position)
		{
			for (const auto &[payload, nanos, start, payloadEnd] : lines)
			{
				if (nanos < 0 || nanos <= *position)
					continue;
				// Fully delivered: neither end truncated nor beginning cut into.
				if (start >= frontCut && payloadEnd <= output.size())
					*position = nanos;
			}
		}
		return output;
	}

	// No container is left (the run was stopped and its container removed, or it
	// never created one): the output lives in this run's stdout slot, written by
	// the terminate-time log archive. The base fallback reads the path attach()
	// left behind, which is empty for container runs, and drops the archive.
	if (const auto archiveFile = this->stdoutArchiveFile(); !archiveFile.empty())
	{
		try
		{
			return Utility::readFileCpp(archiveFile, position, maxSize, readLine);
		}
		catch (const std::invalid_argument &)
		{
			// A container-log cursor is a nanosecond stamp, not a byte offset:
			// restart the archive read instead of failing the output request.
			if (position)
				*position = 0;
			return Utility::readFileCpp(archiveFile, position, maxSize, readLine);
		}
	}

	return AppProcess::getOutputMsg(position, maxSize, readLine);
}

int DockerApiProcess::returnValue() const
{
	const static char fname[] = "DockerApiProcess::returnValue() ";

	const auto containerId = this->containerId();
	if (!containerId.empty())
	{
		const auto state = this->inspectState(containerId);
		if (state)
			return (*state)["exitCode"].asInt();

		LOG_WAR << fname << "Failed to get exit code for container <" << containerId << ">";
		return DOCKER_COMMAND_ERROR;
	}
	return AppProcess::returnValue();
}

const std::shared_ptr<HttpResponse> DockerApiProcess::requestContainer(const web::http::method &mtd, const std::string &path,
																	   std::map<std::string, std::string> query,
																	   Json::Value *body, long timeoutSeconds) const
{
	const static char fname[] = "DockerApiProcess::requestContainer() ";

	auto wrapperPath = std::string(CONTAINER_SERVICE_BASE) + path;
	std::map<std::string, std::string> header;
	signContainerRequest(header);

	std::string bodyContent;
	if (body)
	{
		bodyContent = JSON::dump(*body);
		// Mask container Env in the logged copy.
		auto logBody = *body;
		if (logBody.isMember("createBody") && logBody["createBody"].isObject() && logBody["createBody"].isMember("Env"))
			logBody["createBody"]["Env"] = "***";
		LOG_DBG << fname << path << " " << JSON::dump(logBody);
	}

	const auto restURL = dockerAgentBaseUrl();
	auto response = std::make_shared<HttpResponse>();
	std::string errorMsg = std::string("exception caught: ").append(path);
	const long effectiveTimeout = timeoutSeconds > 0 ? timeoutSeconds : DOCKER_REQUEST_TIMEOUT_SECONDS;

	// Idempotent GETs retry once (agent restart window); mutations never retry.
	const int maxAttempts = (mtd == web::http::methods::GET) ? 2 : 1;
	const auto requestStart = std::chrono::steady_clock::now();
	for (int attempt = 1; attempt <= maxAttempts; attempt++)
	{
		try
		{
			response = RestClient::request(restURL, mtd, wrapperPath, bodyContent, header, query, effectiveTimeout);
			// A transport failure returns normally with status 0 (the error callback never raises); retry like the exception path.
			if (response->statusCode != 0 || attempt == maxAttempts)
				break;
		}
		catch (const std::exception &ex)
		{
			errorMsg = ex.what();
			LOG_ERR << fname << path << " got exception: " << ex.what();
			if (attempt < maxAttempts)
				continue;
			response->statusCode = web::http::status_codes::ServiceUnavailable;
			response->text = errorMsg;
		}
		catch (...)
		{
			LOG_ERR << fname << "Unknown exception on request <" << path << ">";
			if (attempt < maxAttempts)
				continue;
			response->statusCode = web::http::status_codes::ServiceUnavailable;
			response->text = errorMsg;
		}
	}
	if (response->statusCode == 0)
	{
		// Never leave a fake status 0 success behind.
		response->statusCode = web::http::status_codes::ServiceUnavailable;
		response->text = "connection to the agent container service failed";
	}
	// Make a full-timeout stall visible with its duration.
	LOG_DBG << fname << path << " status <" << response->statusCode << "> took <"
			<< std::chrono::duration<double>(std::chrono::steady_clock::now() - requestStart).count() << "s>";
	return response;
}

// The agent's inspect projection: {id, pid, running, exitCode, health, labels}.
std::optional<Json::Value> DockerApiProcess::inspectState(const std::string &idOrName) const
{
	auto resp = this->requestContainer(web::http::methods::GET, Utility::stringFormat("/%s", idOrName.c_str()), {}, nullptr);
	if (resp->statusCode != web::http::status_codes::OK)
		return std::nullopt;
	auto state = JSON::parse(resp->text, nullptr);
	if (!state.isObject() || !HAS_JSON_FIELD(state, "running") || !state["running"].isBool())
	{
		LOG_WAR << "DockerApiProcess::inspectState() unparseable inspect response for <" << idOrName << ">";
		return std::nullopt;
	}
	if (!HAS_JSON_FIELD(state, "exitCode") || !state["exitCode"].isIntegral())
		state["exitCode"] = DOCKER_COMMAND_ERROR;
	return state;
}

// The agent's log projection joined back into plain text (timestamps dropped).
std::string DockerApiProcess::joinLogLines(const Json::Value &logs)
{
	if (!logs.isObject() || !logs["lines"].isArray())
		return {};
	std::string output;
	for (const auto &line : logs["lines"])
	{
		if (!line.isObject() || !HAS_JSON_FIELD(line, "text"))
			continue;
		output += GET_JSON_STR_VALUE(line, "text");
		output += '\n';
	}
	return output;
}
