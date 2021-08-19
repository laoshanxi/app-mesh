#pragma once

#include <string>

#include <cpprest/http_msg.h>
#include <cpprest/json.h>

#include "DockerProcess.h"

/// <summary>
/// Docker Process Object
/// </summary>
class DockerApiProcess : public DockerProcess
{
public:
	/// <summary>
	/// constructor
	/// </summary>
	/// <param name="dockerImage"></param>
	/// <param name="appName"></param>
	DockerApiProcess(const std::string &dockerImage, const std::string &containerName);
	virtual ~DockerApiProcess();

	// override with docker behavior
	virtual void killgroup(int timerId = 0) override;
	virtual int spawnProcess(std::string cmd, std::string execUser, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, const std::string &stdoutFile = "", const web::json::value &stdinFileContent = EMPTY_STR_JSON, const int maxStdoutSize = 0) override;

	/// <summary>
	/// get all std out content from stdoutFile with given position
	/// </summary>
	/// <returns></returns>
	const std::string getOutputMsg(long *position = nullptr, int maxSize = APP_STD_OUT_VIEW_DEFAULT_SIZE, bool readLine = false) override;

private:
	web::http::http_response requestHttp(const web::http::method &mtd, const std::string &path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, web::json::value *body);
};
