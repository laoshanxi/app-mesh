// src/daemon/process/DockerApiProcess.h
#pragma once

#include <string>

#include <nlohmann/json.hpp>

#include "DockerProcess.h"

#define DOCKER_REQUEST_ID_HEADER "X-Request-ID"

struct CurlResponse;

// Docker API Object using Docker REST API
class DockerApiProcess : public DockerProcess
{
public:
	DockerApiProcess(const std::string &appName, const std::string &dockerImage);
	~DockerApiProcess();

	// Override with docker REST behavior
	void terminate() override;

	// Override with docker REST request
	int spawnProcess(std::string cmd, std::string execUser, std::string workDir,
					 std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
					 const std::string &stdoutFile = "", const nlohmann::json &stdinFileContent = EMPTY_STR_JSON,
					 int maxStdoutSize = 0) override;

	// Get stdout content from docker logs API
	const std::string getOutputMsg(long *position = nullptr, int maxSize = APP_STD_OUT_VIEW_DEFAULT_SIZE, bool readLine = false) override;

	// Get process exit code from container inspect API
	int returnValue() const override;

private:
	// Request Docker HTTP REST API
	const std::shared_ptr<CurlResponse> requestDocker(const web::http::method &mtd, const std::string &path,
													  std::map<std::string, std::string> query, std::map<std::string, std::string> header, nlohmann::json *body);
};
