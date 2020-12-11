#pragma once

#include <map>
#include <string>
#include <ace/Process.h>
#include "../TimerHandler.h"

class LinuxCgroup;
class ResourceLimitation;
/// <summary>
/// Process Object, inherit from ACE_Process
/// Support:
///  1. cgroup
///  2. pipe
///  3. auto kill
///  4. timer kill
/// </summary>
class AppProcess : public ACE_Process, public TimerHandler
{
public:
	AppProcess();
	virtual ~AppProcess();

	virtual pid_t getpid(void) const;
	const std::string getuuid() const;
	virtual std::string containerId() const { return std::string(); };
	virtual void containerId(std::string containerId){};

	/// <summary>
	/// Attach a existing pid to AppProcess to manage
	/// </summary>
	/// <param name="pid">process id</param>
	void attach(int pid);
	/// <summary>
	/// avoid de-constructure kill process
	/// </summary>
	void detach(void);

	/// <summary>
	/// kill the process group
	/// </summary>
	/// <param name="timerId"></param>
	virtual void killgroup(int timerId = 0);

	/// <summary>
	/// set resource limitation
	/// </summary>
	/// <param name="limit"></param>
	virtual void setCgroup(std::shared_ptr<ResourceLimitation> &limit);
	/// <summary>
	/// kill after a time period
	/// </summary>
	/// <param name="timeoutSec">seconds</param>
	/// <param name="from"></param>
	void delayKill(std::size_t timeoutSec, const std::string from);

	/// <summary>
	/// start process
	/// </summary>
	/// <param name="cmd">full command line with arguments</param>
	/// <param name="user">Linux user name</param>
	/// <param name="workDir">working directory</param>
	/// <param name="envMap">environment variables</param>
	/// <param name="limit">cgroup limitation</param>
	/// <param name="stdoutFile">std out output file</param>
	/// <param name="stdinFileContent">std in string content</param>
	/// <returns>process id</returns>
	virtual int spawnProcess(std::string cmd, std::string user, std::string workDir,
							 std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
							 const std::string &stdoutFile = "", const std::string &stdinFileContent = "");
	/// <summary>
	/// get all std out content from stdoutFile
	/// </summary>
	/// <returns></returns>
	virtual const std::string fetchOutputMsg();
	/// <summary>
	/// get one line from stdoutFile
	/// </summary>
	virtual const std::string fetchLine();

	/// <summary>
	/// save last error
	/// </summary>
	/// <param name="err">error string</param>
	void startError(const std::string &err);
	/// <summary>
	/// get last error
	/// </summary>
	/// <returns></returns>
	const std::string startError() const;

protected:
	/// <summary>
	/// Parse command line, get cmdRoot and parameters
	/// </summary>
	/// <param name="cmd"></param>
	/// <returns>tuple: 1 cmdRoot, 2 parameters</returns>
	std::tuple<std::string, std::string> extractCommand(const std::string &cmd);

private:
	int m_delayKillTimerId;

	ACE_HANDLE m_stdinHandler;
	ACE_HANDLE m_stdoutHandler;
	std::string m_stdinFileName;
	std::string m_stdoutFileName;
	mutable std::recursive_mutex m_outFileMutex;
	std::shared_ptr<std::ifstream> m_stdoutReadStream;

	std::unique_ptr<LinuxCgroup> m_cgroup;
	std::shared_ptr<int> m_returnCode;
	std::string m_uuid;
	std::string m_startError;
};
