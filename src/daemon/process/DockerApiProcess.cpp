// src/daemon/process/DockerApiProcess.cpp
#include "DockerApiProcess.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <sstream>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

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
		header[DOCKER_REQUEST_ID_HEADER] = uuid;
		if (const auto agent = Configuration::instance()->getApp(SEPARATE_AGENT_APP_NAME, false))
			header[HMAC_HTTP_HEADER] = agent->signProcessProof(uuid);
	}

	std::string dockerAgentBaseUrl()
	{
		// The agent shares the REST listener and serves plaintext when SSL is off; no hardcoded https://.
		const auto scheme = Configuration::instance()->getSslEnabled() ? "https://" : "http://";
		return scheme + Configuration::instance()->getRestListenAddress() + ":" +
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

	// A string field read that never throws: wrong shapes read as empty.
	std::string jsonStringField(const nlohmann::json &obj, const char *key)
	{
		return HAS_JSON_FIELD(obj, key) && obj.at(key).is_string() ? obj.at(key).get<std::string>() : std::string();
	}
} // namespace

// High-risk host-facing settings the Docker.HostSecurityPolicy gate looks for.
std::vector<std::string> dockerHostSecurityFindings(const nlohmann::json &createBody)
{
	std::vector<std::string> findings;
	if (!createBody.is_object())
		return findings;
	if (!HAS_JSON_FIELD(createBody, "HostConfig") || !createBody.at("HostConfig").is_object())
		return findings;
	const auto &hostConfig = createBody.at("HostConfig");
	if (HAS_JSON_FIELD(hostConfig, "Privileged") && hostConfig.at("Privileged").is_boolean() &&
		hostConfig.at("Privileged").get<bool>())
		findings.push_back("privileged container");
	const auto pidMode = upperCase(jsonStringField(hostConfig, "PidMode"));
	if (pidMode == "HOST")
		findings.push_back("host PID namespace (pid=host)");
	const auto ipcMode = lowerCase(jsonStringField(hostConfig, "IpcMode"));
	if (ipcMode == "host" || ipcMode == "shareable")
		findings.push_back("shared host IPC namespace (ipc=" + ipcMode + ")");
	// docker network semantics: host/none/container:<id> bypass the bridge.
	const auto networkMode = lowerCase(jsonStringField(hostConfig, "NetworkMode"));
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
	if (HAS_JSON_FIELD(hostConfig, "Binds") && hostConfig.at("Binds").is_array())
	{
		for (const auto &bind : hostConfig.at("Binds"))
		{
			if (!bind.is_string())
				continue;
			const auto value = bind.get<std::string>();
			const auto source = value.substr(0, value.find(':'));
			if (riskyBindSource(source))
				findings.push_back("bind of host path <" + source + ">");
		}
	}
	if (HAS_JSON_FIELD(hostConfig, "Mounts") && hostConfig.at("Mounts").is_array())
	{
		for (const auto &mount : hostConfig.at("Mounts"))
		{
			// Read-only mounts still expose host content; every bind type counts.
			if (!mount.is_object() || lowerCase(jsonStringField(mount, "Type")) != "bind")
				continue;
			const auto source = jsonStringField(mount, "Source");
			if (riskyBindSource(source))
				findings.push_back("Mount of host path <" + source + ">");
		}
	}
	// Volumes-from or raw host-device mapping is a host-facing capability by construction.
	if (HAS_JSON_FIELD(hostConfig, "VolumesFrom") && hostConfig.at("VolumesFrom").is_array() &&
		!hostConfig.at("VolumesFrom").empty())
		findings.push_back("volumes inherited from another container (volumes-from)");
	if (HAS_JSON_FIELD(hostConfig, "Devices") && hostConfig.at("Devices").is_array() && !hostConfig.at("Devices").empty())
		findings.push_back("host device mapping (device)");
	if (HAS_JSON_FIELD(hostConfig, "SecurityOpt") && hostConfig.at("SecurityOpt").is_array())
	{
		for (const auto &opt : hostConfig.at("SecurityOpt"))
		{
			// apparmor/seccomp/systempaths "unconfined" and label disabling are the profile-escape spellings.
			if (opt.is_string())
			{
				const auto text = lowerCase(opt.get<std::string>());
				if (text.find("unconfined") != std::string::npos || text.find("label=disable") == 0 ||
					text.find("label:disable") != std::string::npos)
					findings.push_back("security opt <" + opt.get<std::string>() + ">");
			}
		}
	}
	if (HAS_JSON_FIELD(hostConfig, "CapAdd") && hostConfig.at("CapAdd").is_array())
	{
		for (const auto &cap : hostConfig.at("CapAdd"))
		{
			if (!cap.is_string())
				continue;
			const auto name = upperCase(cap.get<std::string>());
			if (name == "ALL" || name == "SYS_ADMIN" || name == "SYS_PTRACE")
				findings.push_back("CapAdd " + cap.get<std::string>());
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

void inlineShellScriptCmd(nlohmann::json &createBody)
{
	// Presence checks first: operator[] would insert null members and pollute
	// the create body of an ENTRYPOINT-only image.
	if (!HAS_JSON_FIELD(createBody, "Cmd") || !HAS_JSON_FIELD(createBody, "HostConfig"))
		return;
	const auto &cmd = createBody.at("Cmd");
	// The exact shape Application::getCmdLine() produces for shell mode: `bash <script>`.
	if (!cmd.is_array() || cmd.size() != 2 || !cmd[0].is_string() || cmd[0].get<std::string>() != "bash" ||
		!cmd[1].is_string())
		return;
	const auto script = cmd[1].get<std::string>();

	// Only inline when this very script is the compile step's same-path read-only bind.
	if (!HAS_JSON_FIELD(createBody, "HostConfig") || !createBody.at("HostConfig").is_object())
		return;
	auto &hostConfig = createBody.at("HostConfig");
	if (!HAS_JSON_FIELD(hostConfig, "Binds") || !hostConfig.at("Binds").is_array())
		return;
	const auto bindSpec = script + ":" + script + ":ro";
	bool bound = false;
	for (const auto &bind : hostConfig.at("Binds"))
		if (bind.is_string() && bind.get<std::string>() == bindSpec)
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

	nlohmann::json inlined = nlohmann::json::array();
	inlined.push_back("bash");
	inlined.push_back("-c");
	inlined.push_back(std::move(content));
	createBody["Cmd"] = std::move(inlined);

	nlohmann::json kept = nlohmann::json::array();
	for (const auto &bind : hostConfig.at("Binds"))
		if (!bind.is_string() || bind.get<std::string>() != bindSpec)
			kept.push_back(bind);
	hostConfig["Binds"] = std::move(kept);
}

// Event-push liveness: the scheduler demotes the poll only while markers stay fresh.
namespace
{
	std::atomic<int64_t> g_containerEventsAliveMs(0);
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
		std::lock_guard<std::mutex> guard(m_dockerMutex);
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
		return ACE_INVALID_PID;
	}
	return AppProcess::getpid();
}

std::string DockerApiProcess::containerId() const
{
	std::lock_guard<std::mutex> guard(m_dockerMutex);
	return m_containerId;
}

void DockerApiProcess::setContainerId(const std::string &containerId)
{
	std::lock_guard<std::mutex> guard(m_dockerMutex);
	m_containerId = containerId;
}

std::string DockerApiProcess::takeContainerId()
{
	std::lock_guard<std::mutex> guard(m_dockerMutex);
	auto containerId = std::move(m_containerId);
	m_containerId.clear();
	return containerId;
}

bool DockerApiProcess::needsAlwaysExitPoll() const
{
	std::lock_guard<std::mutex> guard(m_dockerMutex);
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

void DockerApiProcess::requestLivenessPoll()
{
	m_lastBackendPollMs.store(0, std::memory_order_release);
}

void DockerApiProcess::adoptRecoveredContainer()
{
	const static char fname[] = "DockerApiProcess::adoptRecoveredContainer() ";
	if (!containerId().empty())
		return;

	// Same ownership proof the agent's run operation applies: only a container
	// labeled for this app is adopted.
	nlohmann::json inspect;
	if (!this->inspectState(m_containerName, inspect))
		return;
	if (!inspect.is_object() || !HAS_JSON_FIELD(inspect, "labels") || !inspect.at("labels").is_object())
		return;
	const auto &labels = inspect.at("labels");
	if (jsonStringField(labels, DOCKER_LABEL_MANAGED) != "true" ||
		jsonStringField(labels, DOCKER_LABEL_APP) != legacyContainerName() ||
		jsonStringField(labels, DOCKER_LABEL_NODE) != dockerNodeIdentity())
		return;
	if (!HAS_JSON_FIELD(inspect, "running") || !inspect.at("running").is_boolean())
		return;

	const bool runningState = GET_JSON_BOOL_VALUE(inspect, "running");
	setContainerId(HAS_JSON_FIELD(inspect, "id") && inspect.at("id").is_string() ? jsonStringField(inspect, "id")
																				 : m_containerName);
	m_containerRunning.store(runningState, std::memory_order_release);
	m_hostPidVisible.store(AppProcess::running(), std::memory_order_release);
	LOG_INF << fname << "adopted recovered container <" << m_containerName << "> (running: <" << runningState
			<< ">) for application <" << legacyContainerName() << ">";
}

void DockerApiProcess::archiveContainerLogs(const std::string &containerId)
{
	const static char fname[] = "DockerApiProcess::archiveContainerLogs() ";
	if (m_stdoutFile.empty() || containerId.empty())
		return;
	try
	{
		auto resp = this->requestContainer(web::http::methods::GET,
										   Utility::stringFormat("/%s/logs", containerId.c_str()), {{"tail", "2000"}},
										   nullptr);
		if (resp->status_code == web::http::status_codes::OK)
		{
			const auto output = joinLogLines(nlohmann::json::parse(resp->text, nullptr, false));
			if (!output.empty())
			{
				std::ofstream out(m_stdoutFile, std::ios::app);
				out << output;
			}
		}
		else
			LOG_WAR << fname << "log fetch failed <" << resp->status_code << ">, archive skipped";
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << fname << "failed: " << ex.what();
	}
}

void DockerApiProcess::sweepOrphanContainers()
{
	const static char fname[] = "DockerApiProcess::sweepOrphanContainers() ";
	const auto unavailable = dockerUnavailableReason();
	if (!unavailable.empty())
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
											  std::string(CONTAINER_SERVICE_BASE) + "/list", "", header, {}, {}, 15);
		if (resp->status_code != web::http::status_codes::OK)
		{
			LOG_WAR << fname << "labeled container list failed <" << resp->status_code << ">, skipping sweep";
			return;
		}
		const auto containers = nlohmann::json::parse(resp->text, nullptr, false);
		if (!containers.is_array())
			return;

		for (const auto &container : containers)
		{
			if (!container.is_object())
				continue;
			const auto labels = HAS_JSON_FIELD(container, "labels") && container.at("labels").is_object()
									? container.at("labels")
									: nlohmann::json::object();
			const auto appName = jsonStringField(labels, DOCKER_LABEL_APP);
			if (appName.empty())
				continue;
			// Another node's container on the shared engine is not ours to judge;
			// the node that owns it runs its own sweep.
			if (jsonStringField(labels, DOCKER_LABEL_NODE) != dockerNodeIdentity())
				continue;
			const auto app = Configuration::instance()->getApp(appName, false);
			if (app && app->isContainerized())
				continue;

			const auto containerId = jsonStringField(container, "id");
			LOG_WAR << fname << "orphan container <" << containerId << "> of removed application <" << appName << ">"
					<< (deleteOrphans ? ", deleting" : "; set APPMESH_DOCKER_ORPHAN_SWEEP=delete to remove it");
			if (deleteOrphans && !containerId.empty())
			{
				std::map<std::string, std::string> deleteHeader;
				signContainerRequest(deleteHeader);
				const auto deleted = RestClient::request(dockerAgentBaseUrl(), web::http::methods::DEL,
														 Utility::stringFormat("%s/%s", CONTAINER_SERVICE_BASE, containerId.c_str()),
														 "", deleteHeader, {{"force", "1"}}, {}, 15);
				if (deleted->status_code >= web::http::status_codes::BadRequest &&
					deleted->status_code != web::http::status_codes::NotFound)
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
	const auto unavailable = dockerUnavailableReason();
	if (!unavailable.empty())
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
												  std::string(CONTAINER_SERVICE_BASE) + "/ping", "", header, {}, {}, 10);
			if (resp->status_code == web::http::status_codes::OK)
			{
				LOG_INF << fname << "Docker agent channel verified";
				return;
			}
			LOG_ERR << fname << "Docker agent self-check got status <" << resp->status_code
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
	nlohmann::json stopBody;
	stopBody["graceSeconds"] = grace;
	auto resp = this->requestContainer(web::http::methods::POST,
									   Utility::stringFormat("/%s/stop", containerId.c_str()), {}, &stopBody,
									   grace + DOCKER_REQUEST_TIMEOUT_SECONDS);
	if (resp->status_code >= web::http::status_codes::BadRequest && resp->status_code != web::http::status_codes::NotFound)
	{
		LOG_WAR << fname << "Graceful stop of container <" << containerId << "> failed <" << resp->text << ">";
		// Never fall back to the host PID (exit handling may have reused it); the kill + delete below is the backstop.
	}

	// Persist the container's final logs before the delete removes them.
	archiveContainerLogs(containerId);

	// Kill — unless the container already exited (every stop of a completed run
	// would otherwise log docker's "cannot kill ... is not running" noise).
	nlohmann::json state;
	const bool inspected = this->inspectState(containerId, state);
	if (!inspected || (HAS_JSON_FIELD(state, "running") && GET_JSON_BOOL_VALUE(state, "running")))
	{
		resp = this->requestContainer(web::http::methods::POST, Utility::stringFormat("/%s/kill", containerId.c_str()),
									  {}, nullptr);

		if (resp->status_code >= web::http::status_codes::BadRequest && resp->status_code != web::http::status_codes::NotFound)
		{
			LOG_WAR << fname << "Kill container <" << containerId << "> failed <" << resp->text << ">";
		}
	}

	// Delete
	resp = this->requestContainer(web::http::methods::DEL, Utility::stringFormat("/%s", containerId.c_str()),
								  {{"force", "1"}, {"volumes", "1"}}, nullptr);

	if (resp->status_code >= web::http::status_codes::BadRequest && resp->status_code != web::http::status_codes::NotFound)
	{
		LOG_WAR << fname << "Delete container <" << containerId << "> failed <" << resp->text << ">";
	}

	// Detach manually
	this->detach();
}

pid_t DockerApiProcess::startImpl(std::string cmd, std::string execUser, std::string workDir,
								  std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
								  const std::string &stdoutFile, const nlohmann::json &stdinFileContent, int maxStdoutSize,
								  bool stdinPipe)
{
	const static char fname[] = "DockerApiProcess::startImpl() ";
	LOG_DBG << fname << "Entered";
	(void)stdinPipe; // registration rejects pipe stdin for container apps
	m_stdoutFile = stdoutFile;

	// Fail here: with the service off, the forwarded 404 would read as "image missing".
	const auto unavailable = dockerUnavailableReason();
	if (!unavailable.empty())
	{
		LOG_WAR << fname << "cannot start container application: " << unavailable;
		setStartError(unavailable + " — this application runs in a Docker container");
		return ACE_INVALID_PID;
	}

	// Image presence: on-demand runs never pull, managed applications arm the pull as an intermediate run.
	auto resp = this->requestContainer(web::http::methods::GET, "/image", {{"ref", m_dockerImage}}, nullptr);
	if (resp->status_code == web::http::status_codes::NotFound)
	{
		const auto ownerApplication = owner().lock();
		if (ownerApplication && ownerApplication->isOneShot())
		{
			auto msg = std::string("image <") + m_dockerImage +
					   "> is not present locally; an on-demand run does not pull — register the application to "
					   "pull first or pre-pull the image";
			LOG_WAR << fname << msg;
			setStartError(msg);
			return ACE_INVALID_PID;
		}
		int pullTimeout = DEFAULT_PULL_TIMEOUT_SECONDS;
		const auto timeoutSetting = envMap.find(ENV_APPMESH_DOCKER_IMG_PULL_TIMEOUT);
		if (timeoutSetting != envMap.end())
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
		return ACE_INVALID_PID;
	}
	if (resp->status_code != web::http::status_codes::OK)
	{
		LOG_WAR << fname << "Docker image check failed with status <" << resp->status_code << ">: " << resp->text;
		setStartError(resp->text.empty() ? "Docker container service is unavailable" : resp->text);
		return ACE_INVALID_PID;
	}

	// Validate input metadata format
	if (!stdinFileContent.is_null() && !stdinFileContent.is_object())
	{
		auto msg = std::string("input error format of metadata, should be a JSON format for Docker container definition: ") +
				   JSON::dump(stdinFileContent);
		LOG_WAR << fname << msg;
		setStartError(msg);
		return ACE_INVALID_PID;
	}

	// First-class fields were compiled into metadata by the application; labels are stamped agent-side.
	auto createBody = stdinFileContent.is_object() ? stdinFileContent : nlohmann::json::object();

	// Set command
	if (cmd.length())
	{
		auto argv = Utility::str2argv(cmd);
		auto array = nlohmann::json::array();
		for (size_t i = 0; i < argv.size(); i++)
		{
			array.push_back(std::string(argv[i]));
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
		auto array = nlohmann::json::array();
		for (const auto &env : envMap)
		{
			if (isDaemonOnlyDockerEnv(env.first))
				continue;
			array.push_back(env.first + "=" + env.second);
		}
		createBody["Env"] = array;
	}

	// Configure host settings
	if (HAS_JSON_FIELD(createBody, "HostConfig") && !createBody.at("HostConfig").is_object())
	{
		setStartError("Docker HostConfig must be a JSON object");
		return ACE_INVALID_PID;
	}
	auto hostConfig = HAS_JSON_FIELD(createBody, "HostConfig") ? createBody.at("HostConfig")
															   : nlohmann::json::object();

	if (limit)
	{
		constexpr int64_t MB = 1024LL * 1024LL;
		if (limit->m_memoryMb > 0)
			hostConfig["Memory"] = static_cast<int64_t>(limit->m_memoryMb) * MB;
		if (limit->m_memoryVirtSpecified)
			hostConfig["MemorySwap"] = static_cast<int64_t>(limit->m_memoryVirtMb) * MB;
		if (limit->m_cpuShares > 0)
			hostConfig["CpuShares"] = (limit->m_cpuShares);
	}

	// Keep the stopped container until its final state/logs are inspected.
	hostConfig["AutoRemove"] = false;
	hostConfig["RestartPolicy"] = {{"Name", "no"}};
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
					return ACE_INVALID_PID;
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
	nlohmann::json runRequest;
	runRequest["name"] = m_containerName;
	runRequest["app"] = legacyContainerName();
	runRequest["legacyName"] = legacyContainerName();
	runRequest["adoptRunning"] = static_cast<bool>(ownerApplication) && !ownerApplication->isOneShot();
	runRequest["graceSeconds"] = stopGraceSeconds();
	runRequest["createBody"] = createBody;
	resp = this->requestContainer(web::http::methods::POST, "/run", {}, &runRequest);
	if (resp->status_code != web::http::status_codes::OK)
	{
		LOG_WAR << fname << "container run failed <" << resp->text << ">";
		setStartError(resp->text);
		this->detach();
		terminate();
		return this->getpid();
	}

	const auto runResponse = nlohmann::json::parse(resp->text, nullptr, false);
	if (!runResponse.is_object())
	{
		setStartError("container run response is not a JSON object");
		LOG_WAR << fname << startError() << ": " << resp->text.substr(0, 200);
		this->detach();
		terminate();
		return this->getpid();
	}
	// The replaced leftover's final logs precede this run's own output.
	const auto replacedLogs = jsonStringField(runResponse, "replacedLogs");
	if (!m_stdoutFile.empty() && !replacedLogs.empty())
	{
		std::ofstream out(m_stdoutFile, std::ios::app);
		out << replacedLogs;
	}

	const auto containerId = jsonStringField(runResponse, "id");
	setContainerId(containerId.empty() ? m_containerName : containerId);
	if (GET_JSON_BOOL_VALUE(runResponse, "adopted"))
		LOG_INF << fname << "adopted running orphan container <" << m_containerName << "> for application <"
				<< legacyContainerName() << ">";

	if (!GET_JSON_BOOL_VALUE(runResponse, "running"))
	{
		const int exitCode = HAS_JSON_FIELD(runResponse, "exitCode") && runResponse.at("exitCode").is_number_integer()
								 ? GET_JSON_INT_VALUE(runResponse, "exitCode")
								 : DOCKER_COMMAND_ERROR;
		LOG_INF << fname << "container <" << m_containerName
				<< "> completed before host PID inspection, exit code <" << exitCode << ">";
		reportEarlyExit(exitCode);
		return ACE_INVALID_PID;
	}

	const auto pid = HAS_JSON_FIELD(runResponse, "pid") && runResponse.at("pid").is_number_integer()
						 ? GET_JSON_INT64_VALUE(runResponse, "pid")
						 : 0;
	if (pid > 1 && pid <= std::numeric_limits<pid_t>::max())
	{
		this->attach(static_cast<pid_t>(pid));
		// A containerized daemon cannot see sibling containers' host PIDs;
		// Docker's own state becomes the liveness authority
		// (needsAlwaysExitPoll / backendLivenessPollDue).
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
	resolveStart(true, ACE_INVALID_PID);

	// The thread holds the only strong self reference until its request ends.
	auto self = std::dynamic_pointer_cast<DockerApiProcess>(shared_from_this());
	std::thread(
		[self, envMap, pullTimeoutSeconds, stdoutFile]()
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
				nlohmann::json body;
				body["ref"] = self->m_dockerImage;
				body["timeoutSeconds"] = pullTimeoutSeconds;
				const auto user = envMap.find(ENV_APPMESH_DOCKER_REGISTRY_USER);
				if (user != envMap.end() && !user->second.empty())
				{
					nlohmann::json auth;
					auth["username"] = user->second;
					const auto password = envMap.find(ENV_APPMESH_DOCKER_REGISTRY_PASSWORD);
					if (password != envMap.end())
						auth["password"] = password->second;
					const auto server = envMap.find(ENV_APPMESH_DOCKER_REGISTRY_SERVER);
					if (server != envMap.end() && !server->second.empty())
						auth["server"] = server->second;
					body["auth"] = auth;
				}

				const auto resp = self->requestContainer(web::http::methods::POST, "/image/ensure", {}, &body,
														 pullTimeoutSeconds + PULL_REQUEST_TIMEOUT_MARGIN_SECONDS);
				if (resp->status_code != web::http::status_codes::OK)
				{
					pullError = Utility::stringFormat("image pull failed with status <%ld>: %s", resp->status_code,
													  resp->text.substr(0, 512).c_str());
				}
				else
				{
					const auto result = nlohmann::json::parse(resp->text, nullptr, false);
					progressDump = jsonStringField(result, "progress");
					if (HAS_JSON_FIELD(result, "ok") && result.at("ok").is_boolean() && !result.at("ok").get<bool>())
						pullError = "image pull failed: " + jsonStringField(result, "error");
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
										   Utility::stringFormat("/%s/logs", containerId.c_str()), query, nullptr);
		if (resp->status_code != web::http::status_codes::OK)
		{
			// An error body is not application output; fall back to the archived stdout file.
			LOG_WAR << "DockerApiProcess::getOutputMsg() log fetch failed <" << resp->status_code << ">";
			return AppProcess::getOutputMsg(position, maxSize, readLine);
		}

		// The cursor advances only to fully delivered lines; truncated ones re-deliver on the next poll.
		std::vector<std::tuple<std::string, long, size_t, size_t>> lines; // payload, epoch ns, start, payload end
		const auto parsed = nlohmann::json::parse(resp->text, nullptr, false);
		if (parsed.is_object() && HAS_JSON_FIELD(parsed, "lines") && parsed.at("lines").is_array())
		{
			for (const auto &line : parsed.at("lines"))
			{
				if (!line.is_object() || !HAS_JSON_FIELD(line, "text"))
					continue;
				const auto ns = HAS_JSON_FIELD(line, "ns") && line.at("ns").is_number_integer()
									? static_cast<long>(GET_JSON_INT64_VALUE(line, "ns"))
									: -1L;
				lines.push_back(std::make_tuple(jsonStringField(line, "text"), ns, 0, 0));
			}
		}
		std::string output;
		for (auto &item : lines)
		{
			std::get<2>(item) = output.size();
			output += std::get<0>(item);
			std::get<3>(item) = output.size();
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
			for (const auto &item : lines)
			{
				const auto nanos = std::get<1>(item);
				if (nanos < 0 || nanos <= *position)
					continue;
				// Fully delivered: neither end truncated nor beginning cut into.
				if (std::get<2>(item) >= frontCut && std::get<3>(item) <= output.size())
					*position = nanos;
			}
		}
		return output;
	}

	return AppProcess::getOutputMsg(position, maxSize, readLine);
}

int DockerApiProcess::returnValue() const
{
	const static char fname[] = "DockerApiProcess::returnValue() ";

	const auto containerId = this->containerId();
	if (!containerId.empty())
	{
		nlohmann::json state;
		if (this->inspectState(containerId, state))
			return GET_JSON_INT_VALUE(state, "exitCode");

		LOG_WAR << fname << "Failed to get exit code for container <" << containerId << ">";
		return DOCKER_COMMAND_ERROR;
	}
	return AppProcess::returnValue();
}

const std::shared_ptr<CurlResponse> DockerApiProcess::requestContainer(const web::http::method &mtd, const std::string &path,
																	   std::map<std::string, std::string> query,
																	   nlohmann::json *body, long timeoutSeconds) const
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
		if (HAS_JSON_FIELD(logBody, "createBody") && logBody.at("createBody").is_object() &&
			HAS_JSON_FIELD(logBody.at("createBody"), "Env"))
			logBody["createBody"]["Env"] = "***";
		LOG_DBG << fname << path << " " << JSON::dump(logBody);
	}

	const auto restURL = dockerAgentBaseUrl();
	auto response = std::make_shared<CurlResponse>();
	std::string errorMsg = std::string("exception caught: ").append(path);
	const long effectiveTimeout = timeoutSeconds > 0 ? timeoutSeconds : DOCKER_REQUEST_TIMEOUT_SECONDS;

	// Idempotent GETs retry once (agent restart window); mutations never retry.
	const int maxAttempts = (mtd == web::http::methods::GET) ? 2 : 1;
	const auto requestStart = std::chrono::steady_clock::now();
	for (int attempt = 1; attempt <= maxAttempts; attempt++)
	{
		try
		{
			response = RestClient::request(restURL, mtd, wrapperPath, bodyContent, header, query, {}, effectiveTimeout);
			// A transport failure returns normally with status 0 (the error callback never raises); retry like the exception path.
			if (response->status_code != 0 || attempt == maxAttempts)
				break;
		}
		catch (const std::exception &ex)
		{
			errorMsg = ex.what();
			LOG_ERR << fname << path << " got exception: " << ex.what();
			if (attempt < maxAttempts)
				continue;
			response->status_code = web::http::status_codes::ServiceUnavailable;
			response->text = errorMsg;
		}
		catch (...)
		{
			LOG_ERR << fname << "Unknown exception on request <" << path << ">";
			if (attempt < maxAttempts)
				continue;
			response->status_code = web::http::status_codes::ServiceUnavailable;
			response->text = errorMsg;
		}
	}
	if (response->status_code == 0)
	{
		// Never leave a fake status 0 success behind.
		response->status_code = web::http::status_codes::ServiceUnavailable;
		response->text = "connection to the agent container service failed";
	}
	// Make a full-timeout stall visible with its duration.
	LOG_DBG << fname << path << " status <" << response->status_code << "> took <"
			<< std::chrono::duration<double>(std::chrono::steady_clock::now() - requestStart).count() << "s>";
	return response;
}

// The agent's inspect projection: {id, pid, running, exitCode, labels}. Also
// refreshes the cached running state and the backstop poll marker: this is the
// one backend consult the scheduler poll flows through.
bool DockerApiProcess::inspectState(const std::string &idOrName, nlohmann::json &stateOut) const
{
	auto resp = this->requestContainer(web::http::methods::GET, Utility::stringFormat("/%s", idOrName.c_str()), {}, nullptr);
	if (resp->status_code != web::http::status_codes::OK)
		return false;
	auto state = nlohmann::json::parse(resp->text, nullptr, false);
	if (!state.is_object() || !HAS_JSON_FIELD(state, "running") || !state.at("running").is_boolean())
	{
		LOG_WAR << "DockerApiProcess::inspectState() unparseable inspect response for <" << idOrName << ">";
		return false;
	}
	if (!HAS_JSON_FIELD(state, "exitCode") || !state.at("exitCode").is_number_integer())
		state["exitCode"] = DOCKER_COMMAND_ERROR;

	m_lastBackendPollMs.store(
		std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
			.count(),
		std::memory_order_release);
	m_containerRunning.store(GET_JSON_BOOL_VALUE(state, "running"), std::memory_order_release);
	stateOut = std::move(state);
	return true;
}

// The agent's log projection joined back into plain text (timestamps dropped).
std::string DockerApiProcess::joinLogLines(const nlohmann::json &logs)
{
	if (!logs.is_object() || !HAS_JSON_FIELD(logs, "lines") || !logs.at("lines").is_array())
		return {};
	std::string output;
	for (const auto &line : logs.at("lines"))
	{
		if (!line.is_object() || !HAS_JSON_FIELD(line, "text"))
			continue;
		output += jsonStringField(line, "text");
		output += '\n';
	}
	return output;
}
