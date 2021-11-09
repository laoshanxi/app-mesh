#pragma once

#include <string>

#include <cpprest/http_msg.h>
#include <cpprest/json.h>

#include "DockerProcess.h"

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
	DockerApiProcess(const std::string &dockerImage, const std::string &containerName);
	virtual ~DockerApiProcess();

	/// <summary>
	/// override with docker REST behavior
	/// </summary>
	/// <param name="timerId"></param>
	virtual void killgroup(int timerId = 0) override;

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
	virtual int spawnProcess(std::string cmd, std::string execUser, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, const std::string &stdoutFile = "", const web::json::value &stdinFileContent = EMPTY_STR_JSON, const int maxStdoutSize = 0) override;

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
	const web::http::http_response requestDocker(const web::http::method &mtd, const std::string &path, std::map<std::string, std::string> query, std::map<std::string, std::string> header, web::json::value *body);
};
