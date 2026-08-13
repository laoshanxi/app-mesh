// src/daemon/process/DockerApiProcess.cpp
#include "DockerApiProcess.h"

#include <cstdint>
#include <limits>
#include <utility>

#include <nlohmann/json.hpp>

#include "../../common/RestClient.h"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "../ResourceLimitation.h"
#include "../security/HMACVerifier.h"

namespace
{
	constexpr long DOCKER_REQUEST_TIMEOUT_SECONDS = 15;

	std::string decodeDockerLogs(const std::string &raw)
	{
		std::string output;
		output.reserve(raw.size());
		size_t offset = 0;
		while (offset + 8 <= raw.size())
		{
			const auto byte = [&](size_t index)
			{
				return static_cast<uint32_t>(static_cast<unsigned char>(raw[offset + index]));
			};
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
}

DockerApiProcess::DockerApiProcess(std::weak_ptr<Application> owner, const std::string &appName, const std::string &dockerImage)
	: DockerProcess(std::move(owner), appName, dockerImage)
{
	const static char fname[] = "DockerApiProcess::DockerApiProcess() ";
	LOG_DBG << fname << "Entered";
}

DockerApiProcess::~DockerApiProcess()
{
	const static char fname[] = "DockerApiProcess::~DockerApiProcess() ";
	LOG_DBG << fname << "Entered";

	// Destruction has no shared owner; skip lifecycle callbacks.
	DockerApiProcess::terminateImpl();
}

void DockerApiProcess::terminateImpl()
{
	const static char fname[] = "DockerApiProcess::terminate() ";

	auto containerId = takeContainerId();
	if (containerId.empty())
	{
		// Image pulls are native child processes owned by AppProcess.
		AppProcess::terminateImpl();
		return;
	}

	// POST /containers/{id}/kill
	auto resp = this->requestDocker(web::http::methods::POST,
									Utility::stringFormat("/containers/%s/kill", containerId.c_str()),
									{{"signal", "SIGKILL"}}, {}, nullptr);

	if (resp->status_code >= web::http::status_codes::BadRequest &&
		resp->status_code != web::http::status_codes::NotFound)
	{
		LOG_WAR << fname << "Kill container <" << containerId << "> failed <" << resp->text << ">";
		// Do not fall back to the host PID: exit handling may already have invalidated
		// or allowed reuse of it. The forced container delete below remains best-effort.
	}

	// DELETE /containers/{id}?force=true
	resp = this->requestDocker(web::http::methods::DEL,
							   Utility::stringFormat("/containers/%s", containerId.c_str()),
							   {{"force", "1"}}, {}, nullptr);

	if (resp->status_code >= web::http::status_codes::BadRequest &&
		resp->status_code != web::http::status_codes::NotFound)
	{
		LOG_WAR << fname << "Delete container <" << containerId << "> failed <" << resp->text << ">";
	}

	// Detach manually
	this->detach();
}

pid_t DockerApiProcess::startImpl(std::string cmd, std::string execUser, std::string workDir,
								  std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
								  const std::string &stdoutFile, const nlohmann::json &stdinFileContent, int maxStdoutSize)
{
	const static char fname[] = "DockerApiProcess::startImpl() ";
	LOG_DBG << fname << "Entered";

	// GET /images/{name}/json - Check if image exists
	auto resp = this->requestDocker(web::http::methods::GET,
									Utility::stringFormat("/images/%s/json", m_dockerImage.c_str()), {}, {}, nullptr);

	if (resp->status_code == web::http::status_codes::NotFound)
		return startImagePull(envMap, m_dockerImage, std::move(workDir), stdoutFile);
	if (resp->status_code != web::http::status_codes::OK)
	{
		LOG_WAR << fname << "Docker REST request failed with status <" << resp->status_code << ">: " << resp->text;
		setStartError(resp->text.empty() ? "Docker REST service is unavailable" : resp->text);
		return ACE_INVALID_PID;
	}

	// DELETE /containers/{id}?force=true - Clean existing container
	resp = this->requestDocker(web::http::methods::DEL,
							   Utility::stringFormat("/containers/%s", m_containerName.c_str()),
							   {{"force", "true"}, {"v", "true"}}, {}, nullptr);

	if (resp->status_code >= web::http::status_codes::BadRequest &&
		resp->status_code != web::http::status_codes::NotFound)
	{
		LOG_WAR << fname << "Delete container <" << m_containerName << "> failed <" << resp->text << ">";
	}

	// Validate input metadata format
	if (!stdinFileContent.is_null() && !stdinFileContent.is_object())
	{
		auto msg = std::string("input error format of metadata, should be a JSON format for Docker container definition: ") + stdinFileContent.dump();
		LOG_WAR << fname << msg;
		setStartError(msg);
		return ACE_INVALID_PID;
	}

	// Build container creation body
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
	auto hostConfig = HAS_JSON_FIELD(createBody, "HostConfig")
						  ? createBody.at("HostConfig")
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

	// Keep the stopped container until App Mesh has inspected its final state/logs.
	// The next start or an explicit terminate removes it deterministically.
	hostConfig["AutoRemove"] = false;
	hostConfig["RestartPolicy"] = {{"Name", "no"}};
	createBody["HostConfig"] = hostConfig;

	// POST /containers/create
	resp = this->requestDocker(web::http::methods::POST, "/containers/create",
							   {{"name", m_containerName}}, {}, &createBody);

	if (resp->status_code == web::http::status_codes::Created)
	{
		const auto createResponse = nlohmann::json::parse(resp->text, nullptr, false);
		const auto containerId = HAS_JSON_FIELD(createResponse, "Id") && createResponse.at("Id").is_string()
									 ? GET_JSON_STR_VALUE(createResponse, "Id")
									 : std::string();
		if (containerId.empty())
		{
			setStartError("Docker create response does not contain a valid container ID");
			LOG_WAR << fname << startError() << ": " << resp->text;
			setContainerId(m_containerName); // Docker endpoints also accept the container name.
			this->detach();
			terminate();
			return this->getpid();
		}
		setContainerId(containerId);

		// POST /containers/{id}/start
		resp = this->requestDocker(web::http::methods::POST,
								   Utility::stringFormat("/containers/%s/start", containerId.c_str()),
								   {}, {}, nullptr);

		if (resp->status_code < web::http::status_codes::BadRequest)
		{
			// GET /containers/{id}/json
			resp = this->requestDocker(web::http::methods::GET,
									   Utility::stringFormat("/containers/%s/json", containerId.c_str()),
									   {}, {}, nullptr);

			if (resp->status_code == web::http::status_codes::OK)
			{
				const auto inspectResponse = nlohmann::json::parse(resp->text, nullptr, false);
				if (!HAS_JSON_FIELD(inspectResponse, "State") || !inspectResponse.at("State").is_object())
				{
					setStartError("Docker inspect response does not contain a valid process state");
					LOG_WAR << fname << startError() << ": " << resp->text;
				}
				else
				{
					const auto &state = inspectResponse.at("State");
					if (!HAS_JSON_FIELD(state, "Pid") || !state.at("Pid").is_number_integer() ||
						!HAS_JSON_FIELD(state, "Running") || !state.at("Running").is_boolean())
					{
						setStartError("Docker inspect response does not contain a valid process state");
						LOG_WAR << fname << startError() << ": " << resp->text;
					}
					else
					{
						if (!GET_JSON_BOOL_VALUE(state, "Running"))
						{
							const int exitCode = HAS_JSON_FIELD(state, "ExitCode") && state.at("ExitCode").is_number_integer()
													 ? GET_JSON_INT_VALUE(state, "ExitCode")
													 : -200;
							LOG_INF << fname << "container <" << m_containerName
									<< "> completed before host PID inspection, exit code <" << exitCode << ">";
							reportEarlyExit(exitCode);
							return ACE_INVALID_PID;
						}
						const auto pid = GET_JSON_INT64_VALUE(state, "Pid");
						if (pid > 1 && pid <= std::numeric_limits<pid_t>::max())
						{
							this->attach(static_cast<pid_t>(pid));
							LOG_INF << fname << "started pid <" << pid << "> for container: " << m_containerName;
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

const std::string DockerApiProcess::getOutputMsg(long *position, int maxSize, bool readLine)
{
	const auto containerId = this->containerId();
	if (!containerId.empty())
	{
		// Get logs since timestamp (RFC3339 or UNIX timestamp)
		auto secondsUTC = 0L;
		if (position)
		{
			secondsUTC = *position;
		}

		auto resp = this->requestDocker(
			web::http::methods::GET,
			Utility::stringFormat("/containers/%s/logs", containerId.c_str()),
			{{"stdout", "true"}, {"stderr", "true"}, {"since", std::to_string(secondsUTC)}, {"tail", readLine ? "1" : "all"}},
			{}, nullptr);

		if (position)
		{
			*position = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
		}

		auto output = decodeDockerLogs(resp->text);
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
		auto resp = requestDocker(
			web::http::methods::GET,
			Utility::stringFormat("/containers/%s/json", containerId.c_str()),
			{}, {}, nullptr);

		if (resp->status_code == web::http::status_codes::OK)
		{
			const auto inspectResponse = nlohmann::json::parse(resp->text, nullptr, false);
			if (HAS_JSON_FIELD(inspectResponse, "State") && inspectResponse.at("State").is_object())
			{
				const auto &state = inspectResponse.at("State");
				if (HAS_JSON_FIELD(state, "ExitCode") && state.at("ExitCode").is_number_integer())
					return GET_JSON_INT_VALUE(state, "ExitCode");
			}
			LOG_WAR << fname << "Failed to parse exit code from inspect response of container <" << containerId << ">";
		}

		LOG_WAR << fname << "Failed to get exit code for container <" << containerId << ">: " << resp->text;
		return -200;
	}
	else
	{
		return AppProcess::returnValue();
	}
}

const std::shared_ptr<CurlResponse> DockerApiProcess::requestDocker(const web::http::method &mtd, const std::string &path,
																	std::map<std::string, std::string> query, std::map<std::string, std::string> header, nlohmann::json *body) const
{
	const static char fname[] = "DockerApiProcess::requestDocker() ";

	auto restURL = std::string("https://") + Configuration::instance()->getRestListenAddress() + ":" + std::to_string(Configuration::instance()->getRestListenPort());
	auto wrapperPath = std::string("/appmesh/docker") + path;
	auto uuid = Utility::shortID();
	header[DOCKER_REQUEST_ID_HEADER] = uuid;
	header[HMAC_HTTP_HEADER] = HMACVerifierSingleton::instance()->generateHMAC(uuid);

	std::string bodyContent;
	if (body)
	{
		bodyContent = body->dump();
		// Mask container Env in the logged copy — user env vars can hold secrets
		auto logBody = *body;
		if (logBody.contains("Env"))
			logBody["Env"] = "***";
		LOG_DBG << fname << path << "\n"
				<< logBody.dump(2);
	}

	auto response = std::make_shared<CurlResponse>();
	std::string errorMsg = std::string("exception caught: ").append(path);

	try
	{
		return RestClient::request(restURL, mtd, wrapperPath, bodyContent, header, query, {}, DOCKER_REQUEST_TIMEOUT_SECONDS);
	}
	catch (const std::exception &ex)
	{
		errorMsg = ex.what();
		LOG_ERR << fname << path << " got exception: " << ex.what();
	}
	catch (...)
	{
		LOG_ERR << fname << "Unknown exception on request <" << path << ">";
	}

	response->status_code = web::http::status_codes::ServiceUnavailable;
	response->text = errorMsg;
	return response;
}
