#include <thread>

#include <nlohmann/json.hpp>

#include "../../common/DateTime.h"
#include "../../common/RestClient.h"
#include "../../common/Utility.h"
#include "../../common/os/pstree.hpp"
#include "../Configuration.h"
#include "../ResourceLimitation.h"
#include "../security/HMACVerifier.h"
#include "DockerApiProcess.h"
#include "LinuxCgroup.h"

DockerApiProcess::DockerApiProcess(const std::string &appName, const std::string &dockerImage)
	: DockerProcess(appName, dockerImage)
{
	const static char fname[] = "DockerApiProcess::DockerApiProcess() ";
	LOG_DBG << fname << "Entered";
}

DockerApiProcess::~DockerApiProcess()
{
	const static char fname[] = "DockerApiProcess::~DockerApiProcess() ";
	LOG_DBG << fname << "Entered";

	DockerApiProcess::terminate();
}

// TODO: follow CLI "docker rm -f" to implement stop by REST
void DockerApiProcess::terminate()
{
	const static char fname[] = "DockerApiProcess::terminate() ";

	// get and clean container id
	std::string containerId = this->containerId();
	this->containerId("");

	// clean docker container
	if (!containerId.empty())
	{
		try
		{
			// POST /containers/{id}/kill
			auto resp = this->requestDocker(web::http::methods::POST, Utility::stringFormat("/containers/%s/kill", containerId.c_str()), {{"signal", "SIGKILL"}}, {}, nullptr);
			if (resp->status_code >= web::http::status_codes::BadRequest)
			{
				LOG_WAR << fname << "Kill container <" << containerId << "> failed <" << resp->text << ">";
				ACE_Process::terminate();
			}
			// DELETE /containers/{id}?force=true
			resp = this->requestDocker(web::http::methods::DEL, Utility::stringFormat("/containers/%s", containerId.c_str()), {{"force", "1"}}, {}, nullptr);
			if (resp->status_code >= web::http::status_codes::BadRequest)
			{
				LOG_WAR << fname << "Delete container <" << containerId << "> failed <" << resp->text << ">";
			}
		}
		catch (const std::exception &e)
		{
			LOG_WAR << fname << "Remove container failed <" << e.what() << ">";
		}
	}
	// detach manually
	this->detach();
}

// TODO: if need pull image, the first process will be docker pull command, the next start container process need to handle
int DockerApiProcess::spawnProcess(std::string cmd, std::string execUser, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, const std::string &stdoutFile, const nlohmann::json &stdinFileContent, const int maxStdoutSize)
{
	const static char fname[] = "DockerApiProcess::spawnProcess() ";
	LOG_DBG << fname << "Entered";

	// GET /images/{name}/json
	auto resp = this->requestDocker(web::http::methods::GET, Utility::stringFormat("/images/%s/json", m_dockerImage.c_str()), {}, {}, nullptr);
	// Check REST avialability
	if (resp->status_code == web::http::status_codes::BadGateway)
	{
		LOG_WAR << fname << "request docker wit code:" << resp->status_code << ", message: " << resp->text;
		return ACE_INVALID_PID;
	}
	if (resp->status_code != web::http::status_codes::OK)
	{
		// pull docker image
		return this->execPullDockerImage(envMap, m_dockerImage, stdoutFile, workDir);
	}

	// TODO: ACE_Process::terminate();
	// https://docs.docker.com/engine/api/v1.41/#operation/ContainerDelete
	// DELETE /containers/{id}?force=true
	resp = this->requestDocker(web::http::methods::DEL, Utility::stringFormat("/containers/%s", m_containerName.c_str()), {{"force", "true"}, {"v", "true"}}, {}, nullptr);
	if (resp->status_code >= web::http::status_codes::BadRequest)
	{
		LOG_WAR << fname << "Delete container <" << m_containerName << "> failed <" << resp->text << ">";
	}

	if (!stdinFileContent.is_null() && !stdinFileContent.is_object())
	{
		auto msg = std::string("input error format of metadata, should be a JSON format for Docker container definition: ") + stdinFileContent.dump();
		LOG_WAR << fname << msg;
		this->startError(msg);
		return ACE_INVALID_PID;
	}

	// https://docs.docker.com/engine/api/v1.41/#operation/ContainerCreate
	// POST /containers/create
	auto createBody = stdinFileContent;
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

	if (m_dockerImage.length())
		createBody["Image"] = std::string(m_dockerImage);
	if (workDir.length())
		createBody["WorkingDir"] = workDir;
	if (envMap.size())
	{
		auto array = nlohmann::json::array();
		for (const auto &env : envMap)
			array.push_back(env.first + "=" + env.second);
		createBody["Env"] = array;
	}

	auto hostConfig = HAS_JSON_FIELD(createBody, "HostConfig") ? createBody["HostConfig"] : nlohmann::json();
	if (limit != nullptr)
	{
		hostConfig["Memory"] = (limit->m_memoryMb);
		hostConfig["MemorySwap"] = (limit->m_memoryVirtMb);
		hostConfig["CpuShares"] = (limit->m_cpuShares);
	}
	hostConfig["AutoRemove"] = true;
	hostConfig["RestartPolicy"]["Name"] = "no";

	createBody["HostConfig"] = hostConfig;

	// POST /containers/create
	LOG_DBG << fname << "Creating Container: " << createBody.dump();
	resp = this->requestDocker(web::http::methods::POST, "/containers/create", {{"name", m_containerName}}, {}, &createBody);
	if (resp->status_code == web::http::status_codes::Created)
	{
		this->containerId(nlohmann::json::parse(resp->text).at("Id").get<std::string>());

		// POST /containers/{id}/start
		resp = this->requestDocker(web::http::methods::POST, Utility::stringFormat("/containers/%s/start", m_containerName.c_str()), {}, {}, nullptr);
		if (resp->status_code < web::http::status_codes::BadRequest)
		{
			// GET /containers/{id}/json
			resp = this->requestDocker(web::http::methods::GET, Utility::stringFormat("/containers/%s/json", m_containerName.c_str()), {}, {}, nullptr);
			if (resp->status_code == web::http::status_codes::OK)
			{
				auto pid = nlohmann::json::parse(resp->text)["State"]["Pid"].get<int>();
				// Success
				this->attach(pid);
				ACE_Process::child_id_ = pid;
				LOG_INF << fname << "started pid <" << pid << "> for container :" << m_containerName;
				return this->getpid();
			}
			else
			{
				const auto &errorMsg = resp->text;
				this->startError(errorMsg);
				LOG_WAR << fname << "Start container failed <" << errorMsg << ">";
			}
		}
		else
		{
			const auto &errorMsg = resp->text;
			this->startError(errorMsg);
			LOG_WAR << fname << "Start container failed <" << errorMsg << ">";
		}
	}
	else
	{
		const auto &errorMsg = resp->text;
		this->startError(errorMsg);
		LOG_WAR << fname << "Start container failed <" << errorMsg << ">";
	}

	// failed
	this->detach();
	terminate();
	return this->getpid();
}

const std::string DockerApiProcess::getOutputMsg(long *position, int maxSize, bool readLine)
{
	if (this->containerId().length())
	{
		// --since: RFC3339 OR UNIX timestamp
		auto secondsUTC = 0L;
		if (position)
			secondsUTC = *position;
		auto resp = this->requestDocker(
			web::http::methods::GET,
			Utility::stringFormat("/containers/%s/logs", this->containerId().c_str()),
			{{"stdout", "true"}, {"stderr", "true"}, {"since", std::to_string(secondsUTC)}, {"tail", readLine ? "1" : "all"}},
			{}, nullptr);
		if (position)
		{
			*position = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
		}
		return resp->text;
	}
	return std::string();
}

int DockerApiProcess::returnValue(void) const
{
	const static char fname[] = "DockerApiProcess::returnValue() ";

	if (this->containerId().length())
	{
		// https://docs.docker.com/engine/api/v1.41/#operation/ContainerInspect
		// GET /containers/{id}/json
		auto resp = const_cast<DockerApiProcess *>(this)->requestDocker(
			web::http::methods::GET,
			Utility::stringFormat("/containers/%s/json", this->containerId().c_str()),
			{}, {}, nullptr);
		if (resp->status_code == web::http::status_codes::OK)
		{
			try
			{
				return nlohmann::json::parse(resp->text).at("State").at("ExitCode").get<int>();
			}
			catch (...)
			{
			}
		}
		LOG_WAR << fname << "failed: " << resp->text;
		return -200;
	}
	else
	{
		return AppProcess::returnValue();
	}
}

const std::shared_ptr<CurlResponse> DockerApiProcess::requestDocker(const web::http::method &mtd, const std::string &path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, nlohmann::json *body)
{
	const static char fname[] = "DockerApiProcess::requestDocker() ";

	auto restURL = std::string("https://") + Configuration::instance()->getRestListenAddress() + ":" + std::to_string(Configuration::instance()->getRestListenPort());
	auto wrapperPath = std::string("/appmesh/docker") + path;
	auto uuid = Utility::createUUID();
	header[DOCKER_REQUEST_ID_HEADER] = uuid;
	header[HMAC_HTTP_HEADER] = HMACVerifierSingleton::instance()->generateHMAC(uuid);

	std::string bodyContent;
	if (body)
	{
		bodyContent = body->dump();
		LOG_DBG << fname << path << "\n"
				<< Utility::prettyJson(bodyContent);
	}

	std::string errorMsg = std::string("exception caught: ").append(path);
	auto response = std::make_shared<CurlResponse>();
	try
	{
		auto resp = RestClient::request(restURL, mtd, wrapperPath, bodyContent, header, query);
		if (resp->status_code != web::http::status_codes::OK)
			this->startError(resp->text);
		return resp;
	}
	catch (const std::exception &ex)
	{
		errorMsg = ex.what();
		LOG_ERR << fname << path << " got exception: " << ex.what();
	}
	catch (...)
	{
		LOG_ERR << fname << path << " exception";
	}
	response->status_code = web::http::status_codes::ServiceUnavailable;
	response->text = errorMsg;
	return response;
}
