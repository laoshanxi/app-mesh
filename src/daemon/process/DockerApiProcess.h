#pragma once

#include <string>

#include <nlohmann/json.hpp>

#include "DockerProcess.h"

#define DOCKER_REQUEST_ID_HEADER "X-Request-ID"

struct CurlResponse;

/// <summary>
/// Docker API Object
/// </summary>
class DockerApiProcess : public DockerProcess
{
public:
	/// <summary>
	/// Constructor
	/// </summary>
	/// <param name="dockerImage"></param>
	/// <param name="containerName"></param>
	DockerApiProcess(const std::string &appName, const std::string &dockerImage);
	virtual ~DockerApiProcess();

	/// <summary>
	/// override with docker REST behavior
	/// </summary>
	virtual void terminate() override;

	/// <summary>
	/// override with docker REST request
	/// </summary>
	/// <param name="cmd"></param>
	/// <param name="execUser"></param>
	/// <param name="workDir"></param>
	/// <param name="envMap"></param>
	/// <param name="limit"></param>
	/// <param name="stdoutFile"></param>
	/// <param name="stdinFileContent"></param>
	/// <param name="maxStdoutSize"></param>
	/// <returns></returns>
	virtual int spawnProcess(std::string cmd, std::string execUser, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, const std::string &stdoutFile = "", const nlohmann::json &stdinFileContent = EMPTY_STR_JSON, const int maxStdoutSize = 0) override;

	/// <summary>
	/// get all std out content from stdoutFile with given position
	/// </summary>
	/// <param name="position"></param>
	/// <param name="maxSize"></param>
	/// <param name="readLine"></param>
	/// <returns></returns>
	const std::string getOutputMsg(long *position = nullptr, int maxSize = APP_STD_OUT_VIEW_DEFAULT_SIZE, bool readLine = false) override;

	/// <summary>
	/// get process exit code
	/// </summary>
	/// <param name=""></param>
	/// <returns></returns>
	virtual int returnValue(void) const override;

private:
	/// <summary>
	/// Request Docker HTTP
	/// </summary>
	/// <param name="mtd"></param>
	/// <param name="path"></param>
	/// <param name="query"></param>
	/// <param name="header"></param>
	/// <param name="body"></param>
	/// <returns></returns>
	const std::shared_ptr<CurlResponse> requestDocker(const web::http::method &mtd, const std::string &path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, nlohmann::json *body);
};
