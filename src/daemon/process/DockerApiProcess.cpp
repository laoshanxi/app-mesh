// src/daemon/process/DockerApiProcess.cpp
#include "DockerApiProcess.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>
#include <utility>

#include <json/json.h>

#include "../../common/DateTime.h"
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
	// Engine API feature floor this client is written against; the probe caps
	// the negotiated prefix at whatever dockerd actually serves.
	constexpr int DOCKER_API_TARGET_MINOR = 44;
	constexpr int DOCKER_API_MIN_MINOR = 24;

	// The pull progress dump is bounded so a many-layer pull cannot flood the
	// app stdout file; the tail carries the outcome.
	constexpr size_t PULL_PROGRESS_MAX_BYTES = 64 * 1024;

	// Concurrent pulls of the same reference: the first thread owns the pull,
	// later ones wait for the image to appear instead of stacking duplicates.
	std::mutex g_pullInFlightMutex;
	std::set<std::string> g_pullsInFlight;

	// docker emits RFC3339Nano log stamps; the parser resolves to microseconds,
	// so digits beyond six are dropped before parsing.
	std::string clampFractionalSeconds(const std::string &stamp)
	{
		const auto dot = stamp.find('.');
		if (dot == std::string::npos)
			return stamp;
		const auto digitsEnd = stamp.find_first_not_of("0123456789", dot + 1);
		const auto fractionEnd = digitsEnd == std::string::npos ? stamp.size() : digitsEnd;
		if (fractionEnd - (dot + 1) <= 6)
			return stamp;
		return stamp.substr(0, dot + 7) + (digitsEnd == std::string::npos ? std::string() : stamp.substr(digitsEnd));
	}

	std::string decodeDockerLogs(const std::string &raw)
	{
		std::string output;
		output.reserve(raw.size());
		size_t offset = 0;
		while (offset + 8 <= raw.size())
		{
			const auto byte = [&](size_t index)
			{ return static_cast<uint32_t>(static_cast<unsigned char>(raw[offset + index])); };
			if ((byte(0) != 1 && byte(0) != 2) || byte(1) != 0 || byte(2) != 0 || byte(3) != 0)
				return raw; // TTY containers return an unframed byte stream.

			const size_t length = (byte(4) << 24) | (byte(5) << 16) | (byte(6) << 8) | byte(7);
			offset += 8;
			if (length > raw.size() - offset)
				return raw;
			output.append(raw, offset, length);
			offset += length;
		}
		return offset == raw.size() ? output : raw;
	}

	// "registry:5000/team/app:1.2" -> {"registry:5000/team/app", "1.2"};
	// digest references keep the digest in the repository ("repo@sha256:...").
	std::pair<std::string, std::string> splitImageReference(const std::string &image)
	{
		if (const auto at = image.find('@'); at != std::string::npos)
			return {image.substr(0, at), image.substr(at + 1)};
		const auto lastColon = image.rfind(':');
		if (lastColon != std::string::npos && image.find('/', lastColon) == std::string::npos &&
			lastColon > image.rfind('/') + 1)
			return {image.substr(0, lastColon), image.substr(lastColon + 1)};
		return {image, "latest"};
	}

	// Base64 X-Registry-Auth payload from the daemon-side registry env vars.
	// Empty when no credentials are configured. The value never appears in logs.
	std::string buildRegistryAuthHeader(const std::map<std::string, std::string> &envMap)
	{
		const auto user = envMap.find(ENV_APPMESH_DOCKER_REGISTRY_USER);
		if (user == envMap.end() || user->second.empty())
			return {};

		Json::Value auth;
		auth["username"] = user->second;
		if (const auto password = envMap.find(ENV_APPMESH_DOCKER_REGISTRY_PASSWORD); password != envMap.end())
			auth["password"] = password->second;
		if (const auto server = envMap.find(ENV_APPMESH_DOCKER_REGISTRY_SERVER); server != envMap.end() && !server->second.empty())
			auth["serveraddress"] = server->second;
		return Utility::encode64(JSON::dump(auth));
	}

	// Registry credentials are daemon-side configuration; they must not leak
	// into the container environment. APP_DOCKER_OPTS belongs to the CLI backend.
	bool isDaemonOnlyDockerEnv(const std::string &name)
	{
		return name == ENV_APPMESH_DOCKER_REGISTRY_SERVER || name == ENV_APPMESH_DOCKER_REGISTRY_USER ||
			   name == ENV_APPMESH_DOCKER_REGISTRY_PASSWORD || name == ENV_APPMESH_DOCKER_PARAMS;
	}

	// PSK headers shared by every daemon->agent docker call.
	void signDockerRequest(std::map<std::string, std::string> &header)
	{
		auto uuid = Utility::shortID();
		header[DOCKER_REQUEST_ID_HEADER] = uuid;
		// Sign with the agent's current process proof; empty while the agent is down.
		if (const auto agent = Configuration::instance()->getApp(SEPARATE_AGENT_APP_NAME, false))
			header[HMAC_HTTP_HEADER] = agent->signProcessProof(uuid);
	}

	std::string dockerAgentBaseUrl()
	{
		return std::string("https://") + Configuration::instance()->getRestListenAddress() + ":" +
			   std::to_string(Configuration::instance()->getRestListenPort());
	}

	// Negotiated "/v1.xx" prefix, probed once per daemon run. Empty keeps the
	// server's default (latest) version: the pre-negotiation behavior.
	std::mutex g_versionMutex;
	bool g_versionProbed = false;
	std::string g_versionPrefix;

	const std::string &dockerApiVersionPrefix()
	{
		std::lock_guard guard(g_versionMutex);
		if (g_versionProbed)
			return g_versionPrefix;

		g_versionProbed = true;
		try
		{
			std::map<std::string, std::string> header;
			signDockerRequest(header);
			const auto resp = RestClient::request(dockerAgentBaseUrl(), web::http::methods::GET, "/appmesh/docker/version",
												  "", header, {}, 10);
			const auto version = JSON::parse(resp->text, nullptr);
			int major = 0, minor = 0;
			if (resp->statusCode == web::http::status_codes::OK && HAS_JSON_FIELD(version, "ApiVersion") &&
				version["ApiVersion"].isString() &&
				sscanf(version["ApiVersion"].asCString(), "%d.%d", &major, &minor) == 2)
			{
				if (major == 1 && minor > DOCKER_API_TARGET_MINOR)
					minor = DOCKER_API_TARGET_MINOR;
				if (major == 1 && minor >= DOCKER_API_MIN_MINOR)
					g_versionPrefix = Utility::stringFormat("/v1.%d", minor);
			}
		}
		catch (const std::exception &ex)
		{
			LOG_DBG << "DockerApiProcess dockerApiVersionPrefix() probe failed, using the server default: " << ex.what();
		}
		LOG_INF << "DockerApiProcess negotiated Docker Engine API prefix <"
				<< (g_versionPrefix.empty() ? "<server default>" : g_versionPrefix) << ">";
		return g_versionPrefix;
	}
} // namespace

DockerApiProcess::DockerApiProcess(std::weak_ptr<Application> owner, const std::string &appName,
								   const std::string &dockerImage)
	: DockerProcess(std::move(owner), appName, dockerImage)
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
	// The pull thread keeps this run alive exactly like the CLI pull child did.
	if (m_pullInFlight.load(std::memory_order_acquire))
		return true;
	{
		std::lock_guard guard(m_dockerMutex);
		if (!m_containerId.empty() && !m_hostPidVisible)
			return m_containerRunning.load(std::memory_order_acquire);
	}
	return AppProcess::running();
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

	// Docker decides: a still-running container only refreshes the cache; a
	// channel failure must not fabricate an exit (retried on the next tick).
	auto resp = requestDocker(web::http::methods::GET,
							  Utility::stringFormat("/containers/%s/json", containerId.c_str()), {}, {}, nullptr);
	if (resp->statusCode != web::http::status_codes::OK)
	{
		LOG_WAR << "DockerApiProcess::reportBackendExit() inspect failed <" << resp->statusCode << ">";
		return;
	}
	const auto inspect = JSON::parse(resp->text, nullptr);
	if (!inspect.isObject() || !HAS_JSON_FIELD(inspect, "State") || !inspect["State"].isObject() ||
		!HAS_JSON_FIELD(inspect["State"], "Running") || !inspect["State"]["Running"].isBool())
	{
		LOG_WAR << "DockerApiProcess::reportBackendExit() unparseable inspect response";
		return;
	}
	if (GET_JSON_BOOL_VALUE(inspect["State"], "Running"))
	{
		m_containerRunning.store(true, std::memory_order_release);
		return;
	}
	m_containerRunning.store(false, std::memory_order_release);
	if (HAS_JSON_FIELD(inspect["State"], "ExitCode") && inspect["State"]["ExitCode"].isIntegral())
		onExit(GET_JSON_INT_VALUE(inspect["State"], "ExitCode"));
	else
		onExit(DOCKER_COMMAND_ERROR);
}

std::optional<int> DockerApiProcess::containerHealthVerdict()
{
	const static char fname[] = "DockerApiProcess::containerHealthVerdict() ";
	const auto containerId = this->containerId();
	if (containerId.empty())
		return std::nullopt;

	// GET /containers/{id}/json — State.Health exists only when the image
	// defines a HEALTHCHECK; Docker executes it on its own schedule.
	auto resp = requestDocker(web::http::methods::GET,
							  Utility::stringFormat("/containers/%s/json", containerId.c_str()), {}, {}, nullptr);
	if (resp->statusCode != web::http::status_codes::OK)
	{
		LOG_WAR << fname << "container inspect failed <" << resp->statusCode << ">";
		return std::nullopt;
	}
	const auto inspect = JSON::parse(resp->text, nullptr);
	if (!inspect.isObject() || !HAS_JSON_FIELD(inspect, "State") || !inspect["State"].isObject() ||
		!HAS_JSON_FIELD(inspect["State"], "Health") || !inspect["State"]["Health"].isObject())
		return std::nullopt; // no image HEALTHCHECK: nothing Docker maintains to read

	const auto status = GET_JSON_STR_VALUE(inspect["State"]["Health"], "Status");
	if (status == "healthy")
		return 0;
	if (status == "unhealthy")
		return 1;
	if (status == "starting")
		// Docker's own start-period leniency: a probe still warming up must not
		// fail the application.
		return 0;
	LOG_WAR << fname << "unknown HEALTHCHECK status <" << status << ">";
	return std::nullopt;
}

std::optional<int> DockerApiProcess::execHealthProbe(const std::string &cmd)
{
	const static char fname[] = "DockerApiProcess::execHealthProbe() ";
	const auto containerId = this->containerId();
	if (containerId.empty() || cmd.empty())
		return std::nullopt;

	// POST /containers/{id}/exec
	Json::Value execCreate;
	execCreate["AttachStdout"] = true;
	execCreate["AttachStderr"] = true;
	auto cmdArray = Json::Value(Json::arrayValue);
	for (const auto &arg : Utility::str2argv(cmd))
		cmdArray.append(std::string(arg));
	execCreate["Cmd"] = std::move(cmdArray);

	auto resp = this->requestDocker(web::http::methods::POST,
									Utility::stringFormat("/containers/%s/exec", containerId.c_str()), {}, {}, &execCreate);
	if (resp->statusCode != web::http::status_codes::Created)
	{
		LOG_WAR << fname << "exec create failed <" << resp->statusCode << ">: " << resp->text.substr(0, 200);
		return std::nullopt;
	}
	const auto execId = GET_JSON_STR_VALUE(JSON::parse(resp->text, nullptr), "Id");
	if (execId.empty())
	{
		LOG_WAR << fname << "exec create response carried no Id";
		return std::nullopt;
	}

	// POST /exec/{id}/start — runs to completion; the buffered body holds the output
	Json::Value execStart;
	execStart["Detach"] = false;
	execStart["Tty"] = false;
	resp = this->requestDocker(web::http::methods::POST, Utility::stringFormat("/exec/%s/start", execId.c_str()), {}, {},
							   &execStart);
	if (resp->statusCode != web::http::status_codes::OK)
	{
		LOG_WAR << fname << "exec start failed <" << resp->statusCode << ">: " << resp->text.substr(0, 200);
		return std::nullopt;
	}

	// GET /exec/{id}/json — the probe verdict
	resp = this->requestDocker(web::http::methods::GET, Utility::stringFormat("/exec/%s/json", execId.c_str()), {}, {},
							   nullptr);
	if (resp->statusCode == web::http::status_codes::OK)
	{
		const auto inspect = JSON::parse(resp->text, nullptr);
		if (HAS_JSON_FIELD(inspect, "ExitCode") && inspect["ExitCode"].isIntegral())
			return GET_JSON_INT_VALUE(inspect, "ExitCode");
	}
	LOG_WAR << fname << "exec result unavailable: " << resp->text.substr(0, 200);
	return std::nullopt;
}

void DockerApiProcess::archiveContainerLogs(const std::string &containerId)
{
	const static char fname[] = "DockerApiProcess::archiveContainerLogs() ";
	if (m_stdoutFile.empty() || containerId.empty())
		return;
	try
	{
		auto resp = requestDocker(web::http::methods::GET,
								  Utility::stringFormat("/containers/%s/logs", containerId.c_str()),
								  {{"stdout", "true"}, {"stderr", "true"}, {"tail", "2000"}}, {}, nullptr);
		if (resp->statusCode == web::http::status_codes::OK)
		{
			const auto output = decodeDockerLogs(resp->text);
			if (!output.empty())
			{
				std::ofstream out(m_stdoutFile, std::ios::app);
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
	if (!Utility::isFileExist("/var/run/docker.sock"))
		return;

	const auto sweepMode = ::getenv("APPMESH_DOCKER_ORPHAN_SWEEP");
	const bool deleteOrphans = sweepMode != nullptr && ::strcmp(sweepMode, "delete") == 0;

	try
	{
		std::map<std::string, std::string> header;
		signDockerRequest(header);
		const auto resp =
			RestClient::request(dockerAgentBaseUrl(), web::http::methods::GET, "/appmesh/docker/containers/json", "",
								header, {{"all", "1"}, {"filters", R"({"label":["appmesh.managed=true"]})"}}, 15);
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
			const auto labels = container["Labels"];
			const auto appName = labels.isObject() ? GET_JSON_STR_VALUE(labels, DOCKER_LABEL_APP) : std::string();
			if (appName.empty())
				continue;
			const auto app = Configuration::instance()->getApp(appName, false);
			if (app && app->isContainerized())
				continue;

			const auto containerId = GET_JSON_STR_VALUE(container, "Id");
			LOG_WAR << fname << "orphan container <" << containerId << "> of removed application <" << appName << ">"
					<< (deleteOrphans ? ", deleting" : "; set APPMESH_DOCKER_ORPHAN_SWEEP=delete to remove it");
			if (deleteOrphans && !containerId.empty())
			{
				std::map<std::string, std::string> deleteHeader;
				signDockerRequest(deleteHeader);
				const auto deleted = RestClient::request(dockerAgentBaseUrl(), web::http::methods::DEL,
														 Utility::stringFormat("/appmesh/docker/containers/%s", containerId.c_str()),
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
	if (!Utility::isFileExist("/var/run/docker.sock"))
		return;

	// The agent binds its listener right after reading the PSK; a short retry
	// covers that boot race without holding startup for long.
	for (int attempt = 1; attempt <= 3; attempt++)
	{
		try
		{
			std::map<std::string, std::string> header;
			signDockerRequest(header);
			const auto resp = RestClient::request(dockerAgentBaseUrl(), web::http::methods::GET, "/appmesh/docker/_ping",
												  "", header, {}, 10);
			if (resp->statusCode == web::http::status_codes::OK)
			{
				LOG_INF << fname << "Docker agent channel verified";
				return;
			}
			LOG_ERR << fname << "Docker agent self-check got status <" << resp->statusCode
					<< ">: Docker applications will fail to start until the agent serves /appmesh/docker again <"
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

	// A pull in flight has no container; cancel lets its bounded request end silently.
	m_pullCancelled.store(true, std::memory_order_release);

	auto containerId = takeContainerId();
	if (containerId.empty())
	{
		// Image pulls are native child processes owned by AppProcess.
		AppProcess::terminateImpl();
		return;
	}

	// POST /containers/{id}/stop?t=<grace> — SIGTERM first. Docker returns as
	// soon as the container exits, so the grace is only the upper bound; 304
	// means it had already stopped.
	const auto grace = stopGraceSeconds();
	auto resp = this->requestDocker(web::http::methods::POST, Utility::stringFormat("/containers/%s/stop", containerId.c_str()),
									{{"t", std::to_string(grace)}}, {}, nullptr, grace + DOCKER_REQUEST_TIMEOUT_SECONDS);
	if (resp->statusCode >= web::http::status_codes::BadRequest && resp->statusCode != web::http::status_codes::NotFound &&
		resp->statusCode != web::http::status_codes::NotModified)
	{
		LOG_WAR << fname << "Graceful stop of container <" << containerId << "> failed <" << resp->text << ">";
		// Do not fall back to the host PID: exit handling may already have invalidated
		// or allowed reuse of it. The kill + forced delete below remain the backstop.
	}

	// Persist the container's final logs before the delete removes them.
	archiveContainerLogs(containerId);

	// POST /containers/{id}/kill — idempotent once stop did its job.
	resp = this->requestDocker(web::http::methods::POST, Utility::stringFormat("/containers/%s/kill", containerId.c_str()),
							   {{"signal", "SIGKILL"}}, {}, nullptr);

	if (resp->statusCode >= web::http::status_codes::BadRequest && resp->statusCode != web::http::status_codes::NotFound)
	{
		LOG_WAR << fname << "Kill container <" << containerId << "> failed <" << resp->text << ">";
	}

	// DELETE /containers/{id}?force=true
	resp = this->requestDocker(web::http::methods::DEL, Utility::stringFormat("/containers/%s", containerId.c_str()),
							   {{"force", "1"}}, {}, nullptr);

	if (resp->statusCode >= web::http::status_codes::BadRequest && resp->statusCode != web::http::status_codes::NotFound)
	{
		LOG_WAR << fname << "Delete container <" << containerId << "> failed <" << resp->text << ">";
	}

	// Detach manually
	this->detach();
}

// Delete a container by name only when App Mesh owns it (ownership label).
// Returns false when a foreign container occupies the name and must block start.
bool DockerApiProcess::deleteOwnedContainer(const std::string &containerName)
{
	const static char fname[] = "DockerApiProcess::deleteOwnedContainer() ";

	auto resp =
		this->requestDocker(web::http::methods::GET, Utility::stringFormat("/containers/%s/json", containerName.c_str()),
							{}, {}, nullptr);
	if (resp->statusCode == web::http::status_codes::NotFound)
		return true;

	if (resp->statusCode != web::http::status_codes::OK)
	{
		LOG_WAR << fname << "Inspect container <" << containerName << "> failed <" << resp->text << ">";
		return false;
	}

	const auto inspect = JSON::parse(resp->text, nullptr);
	std::string labeledApp;
	if (inspect.isObject() && HAS_JSON_FIELD(inspect, "Config") && inspect["Config"].isObject() &&
		HAS_JSON_FIELD(inspect["Config"], "Labels") && inspect["Config"]["Labels"].isObject())
		labeledApp = GET_JSON_STR_VALUE(inspect["Config"]["Labels"], DOCKER_LABEL_APP);

	if (labeledApp.empty())
	{
		// Pre-labeling container: only the pre-upgrade App Mesh could have named
		// a container after this app. Migrate it away loudly, never silently.
		LOG_WAR << fname << "Removing unlabeled container <" << containerName
				<< "> left by an older App Mesh version before starting app <" << legacyContainerName() << ">";
	}
	else if (labeledApp != legacyContainerName())
	{
		// An App Mesh container belonging to a different app: refuse so cleanup
		// can never cross that boundary.
		LOG_ERR << fname << "Container name <" << containerName << "> is owned by app <" << labeledApp << ">";
		return false;
	}

	resp = this->requestDocker(web::http::methods::DEL, Utility::stringFormat("/containers/%s", containerName.c_str()),
							   {{"force", "true"}, {"v", "true"}}, {}, nullptr);
	if (resp->statusCode >= web::http::status_codes::BadRequest && resp->statusCode != web::http::status_codes::NotFound)
	{
		LOG_WAR << fname << "Delete container <" << containerName << "> failed <" << resp->text << ">";
		return false;
	}
	return true;
}

pid_t DockerApiProcess::startImpl(std::string cmd, std::string execUser, std::string workDir,
								  std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
								  const std::string &stdoutFile, const Json::Value &stdinFileContent, int maxStdoutSize)
{
	const static char fname[] = "DockerApiProcess::startImpl() ";
	LOG_DBG << fname << "Entered";
	m_stdoutFile = stdoutFile;

	// GET /images/{name}/json - Check if image exists
	auto resp = this->requestDocker(web::http::methods::GET, Utility::stringFormat("/images/%s/json", m_dockerImage.c_str()),
									{}, {}, nullptr);

	if (resp->statusCode == web::http::status_codes::NotFound)
	{
		// On-demand runs (run/syncrun, workflow steps) must complete in one run:
		// the pull intermediate-run machinery belongs to managed applications.
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
		LOG_WAR << fname << "Docker REST request failed with status <" << resp->statusCode << ">: " << resp->text;
		setStartError(resp->text.empty() ? "Docker REST service is unavailable" : resp->text);
		return INVALID_PID;
	}

	// Clean both names App Mesh ever used for this app; refuses to touch a
	// container owned by anything else.
	if (!deleteOwnedContainer(m_containerName) || !deleteOwnedContainer(legacyContainerName()))
	{
		setStartError(Utility::stringFormat("container name <%s> is owned by another application or a foreign container",
											m_containerName.c_str()));
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

	// Build container creation body
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

	// Ownership labels: cleanup may only delete containers carrying them.
	if (!createBody["Labels"].isObject())
		createBody["Labels"] = Json::Value(Json::objectValue);
	createBody["Labels"][DOCKER_LABEL_MANAGED] = "true";
	createBody["Labels"][DOCKER_LABEL_APP] = legacyContainerName();

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

	// Keep the stopped container until App Mesh has inspected its final state/logs.
	// The next start or an explicit terminate removes it deterministically.
	hostConfig["AutoRemove"] = false;
	Json::Value restartPolicy;
	restartPolicy["Name"] = "no";
	hostConfig["RestartPolicy"] = restartPolicy;
	createBody["HostConfig"] = hostConfig;

	// Docker.HostSecurityPolicy: high-risk host-facing settings are audited or
	// rejected before the container ever exists.
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

	// POST /containers/create
	resp = this->requestDocker(web::http::methods::POST, "/containers/create", {{"name", m_containerName}}, {}, &createBody);

	if (resp->statusCode == web::http::status_codes::Created)
	{
		const auto createResponse = JSON::parse(resp->text, nullptr);
		const auto containerId = HAS_JSON_FIELD(createResponse, "Id") && createResponse["Id"].isString()
									 ? GET_JSON_STR_VALUE(createResponse, "Id")
									 : std::string();
		if (containerId.empty())
		{
			// A proxy can close before the last TLS data records arrive, leaving
			// the Id unparseable even though Docker created the container. The
			// create named it, so the name addresses it on every endpoint.
			LOG_WAR << fname << "create response carried no Id, using the container name: " << resp->text.substr(0, 120);
			setContainerId(m_containerName);
		}
		else
		{
			setContainerId(containerId);
		}
		const auto &containerRef = containerId.empty() ? m_containerName : containerId;

		// POST /containers/{id}/start
		resp = this->requestDocker(web::http::methods::POST,
								   Utility::stringFormat("/containers/%s/start", containerRef.c_str()), {}, {}, nullptr);

		if (resp->statusCode < web::http::status_codes::BadRequest)
		{
			// GET /containers/{id}/json
			resp = this->requestDocker(web::http::methods::GET,
									   Utility::stringFormat("/containers/%s/json", containerRef.c_str()), {}, {}, nullptr);

			if (resp->statusCode == web::http::status_codes::OK)
			{
				const auto inspectResponse = JSON::parse(resp->text, nullptr);
				if (!HAS_JSON_FIELD(inspectResponse, "State") || !inspectResponse["State"].isObject())
				{
					setStartError("Docker inspect response does not contain a valid process state");
					LOG_WAR << fname << startError() << ": " << resp->text;
				}
				else
				{
					const auto &state = inspectResponse["State"];
					if (!HAS_JSON_FIELD(state, "Pid") || !state["Pid"].isIntegral() || !HAS_JSON_FIELD(state, "Running") ||
						!state["Running"].isBool())
					{
						setStartError("Docker inspect response does not contain a valid process state");
						LOG_WAR << fname << startError() << ": " << resp->text;
					}
					else
					{
						if (!GET_JSON_BOOL_VALUE(state, "Running"))
						{
							const int exitCode = HAS_JSON_FIELD(state, "ExitCode") && state["ExitCode"].isIntegral()
													 ? GET_JSON_INT_VALUE(state, "ExitCode")
													 : DOCKER_COMMAND_ERROR;
							LOG_INF << fname << "container <" << m_containerName
									<< "> completed before host PID inspection, exit code <" << exitCode << ">";
							reportEarlyExit(exitCode);
							return INVALID_PID;
						}
						const auto pid = GET_JSON_INT64_VALUE(state, "Pid");
						if (pid > 1 && pid <= std::numeric_limits<pid_t>::max())
						{
							this->attach(static_cast<pid_t>(pid));
							// A containerized daemon cannot see sibling containers'
							// host PIDs; Docker's own state becomes the liveness
							// authority (needsAlwaysExitPoll / reportBackendExit).
							m_hostPidVisible = AppProcess::running();
							m_containerRunning.store(true, std::memory_order_release);
							LOG_INF << fname << "started pid <" << pid << "> (visible: " << m_hostPidVisible
									<< ") for container: " << m_containerName;
							return this->getpid();
						}
						setStartError("container reported running without a valid host pid");
					}
				}
			}
			else
			{
				const auto &errorMsg = resp->text;
				setStartError(errorMsg);
				LOG_WAR << fname << "Get container info failed <" << errorMsg << ">";
			}
		}
		else
		{
			const auto &errorMsg = resp->text;
			setStartError(errorMsg);
			LOG_WAR << fname << "Start container failed <" << errorMsg << ">";
		}
	}
	else
	{
		const auto &errorMsg = resp->text;
		setStartError(errorMsg);
		LOG_WAR << fname << "Create container failed <" << errorMsg << ">";
	}

	// Failed
	this->detach();
	terminate();
	return this->getpid();
}

void DockerApiProcess::startApiImagePull(std::map<std::string, std::string> envMap, int pullTimeoutSeconds,
										 const std::string &stdoutFile)
{
	const static char fname[] = "DockerApiProcess::startApiImagePull() ";

	const auto imageReference = splitImageReference(m_dockerImage);
	const std::string fromImage = imageReference.first;
	const std::string tag = imageReference.second;
	LOG_INF << fname << "pulling image <" << fromImage << ":" << tag << "> via the Docker Engine API, timeout <"
			<< pullTimeoutSeconds << ">s";

	m_pullCancelled.store(false, std::memory_order_release);
	m_pullInFlight.store(true, std::memory_order_release);
	// Accepted run without a PID — the exact handshake of an early container
	// exit; the pull thread owns the exit report.
	resolveStart(true, INVALID_PID);

	// The thread holds the only strong self reference until its bounded request
	// ends, so the run outlives an application stop that dropped every other ref.
	auto self = std::dynamic_pointer_cast<DockerApiProcess>(shared_from_this());
	std::thread(
		[self, envMap = std::move(envMap), fromImage, tag, pullTimeoutSeconds, stdoutFile]() mutable
		{
			const static char pullName[] = "DockerApiProcess::imagePullThread ";
			std::string pullError;
			std::string progressDump;
			size_t responseBytes = 0;

			// Only one thread pulls a given reference; concurrent runs wait for
			// the image to appear (bounded by their own pull timeout).
			const std::string imageRef = fromImage + ":" + tag;
			bool pullOwner = false;
			{
				std::lock_guard guard(g_pullInFlightMutex);
				pullOwner = g_pullsInFlight.insert(imageRef).second;
			}
			if (!pullOwner)
			{
				LOG_INF << pullName << "a concurrent pull of <" << imageRef << "> is in flight, waiting";
				const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(pullTimeoutSeconds);
				while (!self->m_pullCancelled.load(std::memory_order_acquire) &&
					   std::chrono::steady_clock::now() < deadline)
				{
					std::this_thread::sleep_for(std::chrono::seconds(2));
					const auto probe = self->requestDocker(
						web::http::methods::GET, Utility::stringFormat("/images/%s/json", self->m_dockerImage.c_str()),
						{}, {}, nullptr);
					if (probe->statusCode == web::http::status_codes::OK)
					{
						progressDump = "image pulled by a concurrent pull of " + imageRef + "\n";
						break;
					}
				}
				if (!progressDump.empty())
				{
					// The image exists; report success and let the engine restart into the container.
					if (!self->m_stdoutFile.empty() && !self->m_pullCancelled.load(std::memory_order_acquire))
					{
						std::ofstream out(self->m_stdoutFile, std::ios::app);
						out << progressDump;
					}
					LOG_INF << pullName << "image <" << imageRef << "> delivered by the concurrent pull";
					self->onExit(0);
					self->m_pullInFlight.store(false, std::memory_order_release);
					return;
				}
				// The concurrent pull did not deliver in time: run our own.
				std::lock_guard guard(g_pullInFlightMutex);
				pullOwner = g_pullsInFlight.insert(imageRef).second;
			}

			try
			{
				std::map<std::string, std::string> query = {{"fromImage", fromImage}, {"tag", tag}};
				std::map<std::string, std::string> header;
				if (auto auth = buildRegistryAuthHeader(envMap); !auth.empty())
					header[DOCKER_REGISTRY_AUTH_HEADER] = auth;

				const auto resp = self->requestDocker(web::http::methods::POST, "/images/create", std::move(query),
													  std::move(header), nullptr, pullTimeoutSeconds);
				responseBytes = resp->text.size();
				if (resp->statusCode != web::http::status_codes::OK)
				{
					pullError = Utility::stringFormat("image pull failed with status <%ld>: %s", resp->statusCode,
													  resp->text.substr(0, 512).c_str());
				}
				else
				{
					// NDJSON progress: one object per line, the final "error"
					// object (or a non-2xx above) marks failure.
					std::string line;
					std::istringstream stream(resp->text);
					std::string previous;
					while (std::getline(stream, line))
					{
						const auto entry = JSON::parse(line, nullptr);
						if (!entry.isObject())
							continue;
						auto message = GET_JSON_STR_VALUE(entry, "status");
						if (message.empty() && HAS_JSON_FIELD(entry, "error"))
						{
							pullError = "image pull failed: " + GET_JSON_STR_VALUE(entry, "error");
							break;
						}
						if (HAS_JSON_FIELD(entry, "progress"))
							message += " " + GET_JSON_STR_VALUE(entry, "progress");
						if (const auto id = GET_JSON_STR_VALUE(entry, "id"); !id.empty())
							message = id + ": " + message;
						if (message != previous)
						{
							progressDump += message + "\n";
							previous = message;
						}
					}
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

			if (progressDump.size() > PULL_PROGRESS_MAX_BYTES)
				progressDump = "...\n" + progressDump.substr(progressDump.size() - PULL_PROGRESS_MAX_BYTES);
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
				LOG_INF << pullName << "image <" << fromImage << ":" << tag << "> pulled, progress bytes <"
						<< progressDump.size() << ">, response bytes <" << responseBytes << ">, stdout file <"
						<< (stdoutFile.empty() ? "<none>" : stdoutFile) << ">";

			if (pullOwner)
			{
				std::lock_guard guard(g_pullInFlightMutex);
				g_pullsInFlight.erase(imageRef);
			}
			// Publish the exit before dropping in-flight: the poll-exit path can
			// never fire for this PID-less run, so this report is the only one.
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
		// Cursor semantics for this path: nanoseconds since epoch of the newest
		// line already delivered (0 = full history). Lines carry their own
		// RFC3339 timestamps so the cursor is exact up to the formatted
		// millisecond; the query advances one millisecond past the cursor
		// because docker's `since` is inclusive.
		std::string sinceQuery = "0";
		if (position && *position > 0)
		{
			const auto cursor = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
				std::chrono::system_clock::time_point{} + std::chrono::nanoseconds(*position) + std::chrono::milliseconds(1));
			sinceQuery = DateTime::formatRFC3339Time(cursor);
			if (sinceQuery.empty())
				sinceQuery = "0";
		}

		auto resp =
			this->requestDocker(web::http::methods::GET, Utility::stringFormat("/containers/%s/logs", containerId.c_str()),
								{{"stdout", "true"},
								 {"stderr", "true"},
								 {"timestamps", "true"},
								 {"since", sinceQuery},
								 {"tail", readLine ? "1" : "all"}},
								{}, nullptr);

		// Strip the timestamp prefix from every line and advance the cursor to
		// the newest one; with no lines the cursor stays where it was so the
		// next poll rescans exactly the empty tail (server-side filtered).
		std::string output;
		std::istringstream stream(decodeDockerLogs(resp->text));
		std::string line;
		while (std::getline(stream, line))
		{
			const auto prefixEnd = line.find(' ');
			if (prefixEnd != std::string::npos)
			{
				try
				{
					const auto lineTime = DateTime::parseISO8601DateTime(clampFractionalSeconds(line.substr(0, prefixEnd)));
					if (position)
					{
						const auto nanos =
							std::chrono::duration_cast<std::chrono::nanoseconds>(lineTime.time_since_epoch()).count();
						if (nanos > *position)
							*position = static_cast<long>(nanos);
					}
					line = line.substr(prefixEnd + 1);
				}
				catch (const std::exception &)
				{
					// Not a timestamped line (unparseable prefix): keep it verbatim.
				}
			}
			output += line;
			output += '\n';
		}
		if (readLine)
		{
			const auto newline = output.find('\n');
			if (newline != std::string::npos)
				output.resize(newline);
		}
		if (maxSize > 0 && output.size() > static_cast<size_t>(maxSize))
			output.resize(static_cast<size_t>(maxSize));
		else if (maxSize < 0 && output.size() > static_cast<size_t>(-maxSize))
			output.erase(0, output.size() - static_cast<size_t>(-maxSize));
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
		// GET /containers/{id}/json
		auto resp = requestDocker(web::http::methods::GET, Utility::stringFormat("/containers/%s/json", containerId.c_str()),
								  {}, {}, nullptr);

		if (resp->statusCode == web::http::status_codes::OK)
		{
			const auto inspectResponse = JSON::parse(resp->text, nullptr);
			if (HAS_JSON_FIELD(inspectResponse, "State") && inspectResponse["State"].isObject())
			{
				const auto &state = inspectResponse["State"];
				if (HAS_JSON_FIELD(state, "ExitCode") && state["ExitCode"].isIntegral())
					return GET_JSON_INT_VALUE(state, "ExitCode");
			}
			LOG_WAR << fname << "Failed to parse exit code from inspect response of container <" << containerId << ">";
		}

		LOG_WAR << fname << "Failed to get exit code for container <" << containerId << ">: " << resp->text;
		return DOCKER_COMMAND_ERROR;
	}
	else
	{
		return AppProcess::returnValue();
	}
}

const std::shared_ptr<HttpResponse> DockerApiProcess::requestDocker(const web::http::method &mtd, const std::string &path,
																	std::map<std::string, std::string> query,
																	std::map<std::string, std::string> header,
																	Json::Value *body, long timeoutSeconds) const
{
	const static char fname[] = "DockerApiProcess::requestDocker() ";

	auto wrapperPath = std::string("/appmesh/docker") + dockerApiVersionPrefix() + path;
	signDockerRequest(header);

	std::string bodyContent;
	if (body)
	{
		bodyContent = JSON::dump(*body);
		// Mask container Env in the logged copy — user env vars can hold secrets
		auto logBody = *body;
		if (logBody.isMember("Env"))
			logBody["Env"] = "***";
		LOG_DBG << fname << path << " " << JSON::dump(logBody);
	}

	const auto restURL = dockerAgentBaseUrl();
	auto response = std::make_shared<HttpResponse>();
	std::string errorMsg = std::string("exception caught: ").append(path);
	const long effectiveTimeout = timeoutSeconds > 0 ? timeoutSeconds : DOCKER_REQUEST_TIMEOUT_SECONDS;

	// Idempotent GETs retry once: a short agent restart window must not fail a
	// whole container start. Mutating calls never retry.
	const int maxAttempts = (mtd == web::http::methods::GET) ? 2 : 1;
	const auto requestStart = std::chrono::steady_clock::now();
	for (int attempt = 1; attempt <= maxAttempts; attempt++)
	{
		try
		{
			response = RestClient::request(restURL, mtd, wrapperPath, bodyContent, header, query, effectiveTimeout);
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
	// A blocking docker call stalls the calling thread up to the full timeout;
	// make the stall visible with its duration and where it ran from.
	LOG_INF << fname << path << " status <" << response->statusCode << "> took <"
			<< std::chrono::duration<double>(std::chrono::steady_clock::now() - requestStart).count() << "s>";
	return response;
}
