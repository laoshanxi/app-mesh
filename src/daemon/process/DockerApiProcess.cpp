#include <thread>

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>

#include "../../common/DateTime.h"
#include "../../common/RestClient.h"
#include "../../common/Utility.h"
#include "../../common/os/pstree.hpp"
#include "../Configuration.h"
#include "../ResourceLimitation.h"
#include "DockerApiProcess.h"
#include "LinuxCgroup.h"

DockerApiProcess::DockerApiProcess(const std::string &dockerImage, const std::string &appName)
	: DockerProcess(dockerImage, appName)
{
	const static char fname[] = "DockerApiProcess::DockerApiProcess() ";
	LOG_DBG << fname << "Entered";
}

DockerApiProcess::~DockerApiProcess()
{
	const static char fname[] = "DockerApiProcess::~DockerApiProcess() ";
	LOG_DBG << fname << "Entered";

	DockerApiProcess::killgroup();
}

void DockerApiProcess::killgroup()
{
	const static char fname[] = "DockerApiProcess::killgroup() ";

	// get and clean container id
	std::string containerId = this->containerId();
	this->containerId("");

	// clean docker container
	if (!containerId.empty())
	{
		try
		{
			// DELETE /containers/{id}?force=true
			auto resp = this->requestDocker(web::http::methods::DEL, Utility::stringFormat("/containers/%s", containerId.c_str()), {{"force", "true"}}, {}, nullptr);
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

int DockerApiProcess::spawnProcess(std::string cmd, std::string execUser, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, const std::string &stdoutFile, const nlohmann::json &stdinFileContent, const int maxStdoutSize)
{
	const static char fname[] = "DockerApiProcess::spawnProcess() ";
	LOG_DBG << fname << "Entered";

	// GET /images/{name}/json
	if (this->requestDocker(web::http::methods::GET, Utility::stringFormat("/images/%s/json", m_dockerImage.c_str()), {}, {}, nullptr)->status_code != web::http::status_codes::OK)
	{
		// pull docker image
		return this->execPullDockerImage(envMap, m_dockerImage, stdoutFile, workDir);
	}

	// GET /containers/json
	// curl -g http://127.0.0.1:6058/containers/json'?filters={%22status%22:[%22exited%22]}'
	// https://stackoverflow.com/questions/39976683/docker-api-can-t-apply-json-filters
	/*
	auto filters = nlohmann::json();
	auto nameArray = nlohmann::json::array(1);
	nameArray[0] = std::string(m_containerName);
	filters["name"] = nameArray;
	auto resp = this->requestDocker(web::http::methods::GET, "/containers/json", {{"filters", filters.dump()}}, {}, nullptr);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto result = resp.extract_json().get();
		LOG_DBG << fname << "Get Container with filters <" << filters.dump() << "> return " << result.as_array().size();
		for (const auto &container : result.as_array())
		{
			this->containerId(container.at("Id").get<std::string>());
			killgroup();
		}
	}
	else
	{
		LOG_WAR << fname << "Get containers failed <" << resp.extract_utf8string().get() << ">";
	}
	*/
	// https://docs.docker.com/engine/api/v1.41/#operation/ContainerDelete
	// DELETE /containers/{id}?force=true
	auto resp = this->requestDocker(web::http::methods::DEL, Utility::stringFormat("/containers/%s", m_containerName.c_str()), {{"force", "true"}}, {}, nullptr);
	if (resp->status_code >= web::http::status_codes::BadRequest)
	{
		LOG_WAR << fname << "Delete container <" << m_containerName << "> failed <" << resp->text << ">";
	}

	if (!stdinFileContent.is_object())
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
		createBody["Cmd"] = array;
	}

	if (limit != nullptr)
	{
		auto hostConfig = nlohmann::json();
		hostConfig["Memory"] = (limit->m_memoryMb);
		hostConfig["MemorySwap"] = (limit->m_memoryVirtMb);
		hostConfig["CpuShares"] = (limit->m_cpuShares);
		createBody["HostConfig"] = hostConfig;
	}

	if (m_dockerImage.length())
		createBody["Image"] = std::string(m_dockerImage);
	// POST /containers/create
	LOG_DBG << fname << "Create Container: " << createBody.dump();
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
				LOG_INF << fname << "started pid <" << pid << "> for container :" << m_containerName;
				return this->getpid();
			}
			else
			{
				auto errorMsg = resp->text;
				this->startError(errorMsg);
				LOG_WAR << fname << "Start container failed <" << errorMsg << ">";
			}
		}
		else
		{
			auto errorMsg = resp->text;
			this->startError(errorMsg);
			LOG_WAR << fname << "Start container failed <" << errorMsg << ">";
		}
	}
	else
	{
		auto errorMsg = resp->text;
		this->startError(errorMsg);
		LOG_WAR << fname << "Start container failed <" << errorMsg << ">";
	}

	// failed
	this->detach();
	killgroup();
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

const std::shared_ptr<cpr::Response> DockerApiProcess::requestDocker(const web::http::method &mtd, const std::string &path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, nlohmann::json *body)
{
	const static char fname[] = "DockerApiProcess::requestDocker() ";

	auto restURL = Configuration::instance()->getDockerProxyAddress();
	std::string errorMsg = std::string("exception caught: ").append(path);
	auto response = std::make_shared<cpr::Response>();
	try
	{
		return RestClient::request(restURL, mtd, path, body, header, query);
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
