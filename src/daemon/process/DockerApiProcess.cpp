#include <thread>

#include <cpprest/http_client.h>

#include "../../common/DateTime.h"
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

void DockerApiProcess::killgroup(int timerId)
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
			auto resp = this->requestHttp(web::http::methods::DEL, Utility::stringFormat("/containers/%s", containerId.c_str()), {{"force", "true"}}, {}, nullptr);
			if (resp.status_code() >= web::http::status_codes::BadRequest)
			{
				LOG_WAR << fname << "Delete container <" << containerId << "> failed <" << resp.extract_utf8string().get() << ">";
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

int DockerApiProcess::spawnProcess(std::string cmd, std::string execUser, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, const std::string &stdoutFile, const web::json::value &stdinFileContent, const int maxStdoutSize)
{
	const static char fname[] = "DockerApiProcess::spawnProcess() ";
	LOG_DBG << fname << "Entered";

	// GET /images/{name}/json
	if (this->requestHttp(web::http::methods::GET, Utility::stringFormat("/images/%s/json", m_dockerImage.c_str()), {}, {}, nullptr).status_code() != web::http::status_codes::OK)
	{
		// pull docker image
		return this->execPullDockerImage(envMap, m_dockerImage, stdoutFile, workDir);
	}

	// GET /containers/json
	// curl -g http://127.0.0.1:6058/containers/json'?filters={%22status%22:[%22exited%22]}'
	// https://stackoverflow.com/questions/39976683/docker-api-can-t-apply-json-filters
	/*
	auto filters = web::json::value();
	auto nameArray = web::json::value::array(1);
	nameArray[0] = web::json::value::string(m_containerName);
	filters["name"] = nameArray;
	auto resp = this->requestHttp(web::http::methods::GET, "/containers/json", {{"filters", filters.serialize()}}, {}, nullptr);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		auto result = resp.extract_json().get();
		LOG_DBG << fname << "Get Container with filters <" << filters.serialize() << "> return " << result.as_array().size();
		for (const auto &container : result.as_array())
		{
			this->containerId(container.at("Id").as_string());
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
	auto resp = this->requestHttp(web::http::methods::DEL, Utility::stringFormat("/containers/%s", m_containerName.c_str()), {{"force", "true"}}, {}, nullptr);
	if (resp.status_code() >= web::http::status_codes::BadRequest)
	{
		LOG_WAR << fname << "Delete container <" << m_containerName << "> failed <" << resp.extract_utf8string().get() << ">";
	}

	// https://docs.docker.com/engine/api/v1.41/#operation/ContainerCreate
	// POST /containers/create
	auto createBody = stdinFileContent;
	if (cmd.length())
	{
		auto argv = Utility::str2argv(cmd);
		auto array = web::json::value::array(argv.size());
		for (size_t i = 0; i < argv.size(); i++)
		{
			array[i] = web::json::value::string(argv[i]);
		}
		createBody["Cmd"] = array;
	}
	if (m_dockerImage.length())
		createBody["Image"] = web::json::value::string(m_dockerImage);
	// POST /containers/create
	LOG_DBG << fname << "Create Container: " << createBody.serialize();
	resp = this->requestHttp(web::http::methods::POST, "/containers/create", {{"name", m_containerName}}, {}, &createBody);
	if (resp.status_code() == web::http::status_codes::Created)
	{
		this->containerId(resp.extract_json().get().at("Id").as_string());

		// POST /containers/{id}/start
		resp = this->requestHttp(web::http::methods::POST, Utility::stringFormat("/containers/%s/start", this->containerId().c_str()), {}, {}, nullptr);
		if (resp.status_code() < web::http::status_codes::BadRequest)
		{
			// GET /containers/{id}/json
			resp = this->requestHttp(web::http::methods::GET, Utility::stringFormat("/containers/%s/json", this->containerId().c_str()), {}, {}, nullptr);
			if (resp.status_code() == web::http::status_codes::OK)
			{
				auto pid = resp.extract_json().get()["State"]["Pid"].as_integer();
				// Success
				this->attach(pid);
				LOG_INF << fname << "started pid <" << pid << "> for container :" << this->containerId();
				return this->getpid();
			}
			else
			{
				auto errorMsg = resp.extract_utf8string().get();
				this->startError(errorMsg);
				LOG_WAR << fname << "Start container failed <" << errorMsg << ">";
			}
		}
		else
		{
			auto errorMsg = resp.extract_utf8string().get();
			this->startError(errorMsg);
			LOG_WAR << fname << "Start container failed <" << errorMsg << ">";
		}
	}
	else
	{
		auto errorMsg = resp.extract_utf8string().get();
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
		auto resp = this->requestHttp(
			web::http::methods::GET,
			Utility::stringFormat("/containers/%s/logs", this->containerId().c_str()),
			{{"stdout", "true"}, {"stderr", "true"}, {"since", std::to_string(secondsUTC)}, {"tail", readLine ? "1" : "all"}},
			{}, nullptr);
		if (position)
		{
			*position = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
		}
		return resp.extract_utf8string().get();
	}
	return std::string();
}

int DockerApiProcess::returnValue(void) const
{
	const static char fname[] = "DockerApiProcess::returnValue() ";

	// https://docs.docker.com/engine/api/v1.41/#operation/ContainerInspect
	// GET /containers/{id}/json
	auto resp = const_cast<DockerApiProcess *>(this)->requestHttp(
		web::http::methods::GET,
		Utility::stringFormat("/containers/%s/json", this->containerId().c_str()),
		{}, {}, nullptr);
	if (resp.status_code() == web::http::status_codes::OK)
	{
		return resp.extract_json().get().at("State").at("ExitCode").as_integer();
	}
	else
	{
		LOG_DBG << fname << "failed: " << resp.extract_utf8string(true).get();
	}
	return -200;
}

const web::http::http_response DockerApiProcess::requestHttp(const web::http::method &mtd, const std::string &path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, web::json::value *body)
{
	const static char fname[] = "DockerApiProcess::requestHttp() ";

	auto restURL = Configuration::instance()->getDockerProxyAddress();
	web::uri_builder uri;
	uri.set_host("127.0.0.1");
	uri.set_scheme("http");
	uri.set_port(6058);
	auto arr = Utility::splitString(restURL, ":");
	if (arr.size() == 2)
		uri.set_port(std::atoi(arr[1].c_str()));

	try
	{
		web::http::client::http_client client(uri.to_uri());

		// Build request URI and start the request.
		web::uri_builder builder(GET_STRING_T(path));
		std::for_each(query.begin(), query.end(), [&builder](const std::pair<std::string, std::string> &pair)
					  { builder.append_query(GET_STRING_T(pair.first), GET_STRING_T(pair.second)); });

		web::http::http_request request(mtd);
		for (const auto &h : header)
		{
			request.headers().add(h.first, h.second);
		}
		request.set_request_uri(builder.to_uri());
		if (body != nullptr)
		{
			request.set_body(*body);
		}

		// In case of REST server crash or block query timeout, will throw exception:
		// "Failed to read HTTP status line"
		web::http::http_response response = client.request(request).get();
		LOG_DBG << fname << mtd << " " << path << " return " << response.status_code();
		return response;
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << fname << path << " got exception: " << ex.what();
	}
	catch (...)
	{
		LOG_WAR << fname << path << " exception";
	}

	web::http::http_response response(web::http::status_codes::ResetContent);
	return response;
}
